//! Runtime configuration for the `fingerprintd` service.
//!
//! Configuration is layered: built-in defaults are overlaid by an optional
//! `fingerprintd.toml` file, then by `FP_`-prefixed environment
//! variables. The merged result is validated by `serde` during extraction.

use std::{fmt, net::SocketAddr};

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};

/// A secret key loaded from configuration (the erasure admin credential or the
/// events API credential).
///
/// Wraps the raw key so it is never accidentally logged: its [`fmt::Debug`] is
/// redacted, so `Debug`-printing the containing [`Config`] does not leak it. It
/// serializes transparently (as the bare string) so figment can layer it from a
/// file or an `FP_` environment variable.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretKey(String);

impl SecretKey {
    /// The raw key bytes, for constant-time credential comparison.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Whether a non-empty key is present. An empty string is treated as "no
    /// key configured", so the gated endpoint stays disabled.
    pub(crate) fn is_configured(&self) -> bool {
        !self.0.is_empty()
    }
}

impl From<&str> for SecretKey {
    fn from(key: &str) -> Self {
        Self(key.to_string())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(REDACTED)")
    }
}

/// Default file consulted by [`Config::load`] when present.
const CONFIG_FILE: &str = "fingerprintd.toml";
/// Prefix for environment overrides, e.g. `FP_BIND_ADDR`.
const ENV_PREFIX: &str = "FP_";

/// Service configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Socket address the HTTP server binds to.
    pub bind_addr: SocketAddr,
    /// Lifetime, in seconds, of a challenge nonce before it expires. Reported
    /// to clients as `expires_in`; overridable via `FP_NONCE_TTL_SECS`.
    pub nonce_ttl_secs: u64,
    /// Cap on live (issued, not yet consumed or reaped) challenge nonces; past
    /// it the oldest is evicted. Overridable via `FP_NONCE_MAX_LIVE`.
    pub nonce_max_live: usize,
    /// Whether to trust edge-injected passive-signal headers (`CF-Connecting-IP`,
    /// `cf-bot-management-ja4`). Enable **only** when the service sits behind a
    /// trusted edge (Cloudflare) that injects these headers and an origin IP
    /// allowlist rejects direct client connections (architecture §4.2). Left `false` by
    /// default (fail-closed): a directly-reachable origin must not trust
    /// client-supplied copies of these headers, or a client could self-inject a
    /// browser-looking JA4 to forge consistency. Overridable via
    /// `FP_TRUST_EDGE_HEADERS`.
    pub trust_edge_headers: bool,
    /// Whether the client's known-answer integrity probe verdicts (the request's
    /// top-level `integrity`, see `fingerprintd::signals::ClientIntegrity`) may lower
    /// `/identify` confidence. The verdict is **always surfaced** as
    /// `signals.client_integrity`; this flag only enables the `noise` downgrade.
    /// Left `false` by default: legitimate privacy tooling (Brave farbling, canvas
    /// blockers) trips the same probes, so the band is surfaced-only until a
    /// real-traffic false-positive rate is known. Overridable via
    /// `FP_INTEGRITY_PENALTY_ENABLED`.
    pub integrity_penalty_enabled: bool,
    /// Allowed clock skew, in seconds, for the `/identify` request timestamp
    /// window (architecture §4.1). A request is accepted iff its `ts` (Unix
    /// milliseconds) is within `±ts_skew_secs` of server time; otherwise it is
    /// rejected with `401`, bounding how long a captured payload stays
    /// replayable on top of the one-time nonce. Overridable via
    /// `FP_TS_SKEW_SECS`.
    pub ts_skew_secs: u64,
    /// Cap on distinct visitors kept in the in-memory fingerprint library.
    /// Once exceeded, the oldest-seen visitor is evicted (and
    /// counted). Fail-safe generous default so a small workload is unaffected;
    /// bounds unbounded growth. Overridable via `FP_FUZZY_MAX_RECORDS`.
    pub fuzzy_max_records: usize,
    /// Time-to-live, in seconds, for an in-memory record: an entry not seen
    /// within this window is evicted on the next observe. `0`
    /// disables TTL eviction (the default). Overridable via
    /// `FP_FUZZY_RECORD_TTL_SECS`.
    pub fuzzy_record_ttl_secs: u64,
    /// Per-block visitor cap for the blocking index (fuzzy-matching §4). A block over
    /// this size drops (and counts) further insertions. Overridable via
    /// `FP_FUZZY_MAX_BLOCK`.
    pub fuzzy_max_block: usize,
    /// Cap on distinct tracked frequency values for `u_i` estimation.
    /// A new value beyond the cap is dropped (already-tracked values keep
    /// counting). Fail-safe generous default. Overridable via
    /// `FP_FUZZY_MAX_FREQUENCY_VALUES`.
    pub fuzzy_max_frequency_values: usize,
    /// Cap on distinct tracked agreement components for `m_i` estimation.
    /// A new component name beyond the cap is dropped (already-tracked names keep
    /// counting). Fail-safe generous default. Overridable via
    /// `FP_FUZZY_MAX_AGREEMENT_COMPONENTS`.
    pub fuzzy_max_agreement_components: usize,
    /// Optional pre-shared admin credential gating the GDPR erasure endpoint
    /// `DELETE /visitor/{id}` (architecture §7 RTBF). When set (and non-empty),
    /// the endpoint accepts an `Authorization: Bearer <admin_key>` request and
    /// erases the visitor. Left unset by default and **fail-closed**: with no key
    /// the endpoint is disabled entirely (`404`), and a configured key rejects a
    /// missing or wrong credential with `401` — erasure is never open.
    /// Overridable via `FP_ADMIN_KEY`.
    #[serde(default)]
    pub admin_key: Option<SecretKey>,
    /// Optional pre-shared credential gating the events API
    /// `GET /events/{request_id}`. Fail-closed like `admin_key`: unset or empty
    /// disables the endpoint (`404`); a configured key rejects a missing or wrong
    /// `Authorization: Bearer` credential with `401`. Overridable via `FP_API_KEY`.
    #[serde(default)]
    pub api_key: Option<SecretKey>,
    /// Lifetime, in seconds, of a stored identify event; past it
    /// `GET /events/{request_id}` answers `404`. Overridable via
    /// `FP_EVENT_TTL_SECS`.
    pub event_ttl_secs: u64,
    /// Cap on stored identify events; past it the oldest is evicted (and
    /// counted). Overridable via `FP_EVENT_MAX`.
    pub event_max: usize,
    /// Compliance retention window, in seconds: the maximum age (by `last_seen`) a
    /// visitor record is retained before a proactive background sweep purges it
    /// (architecture §7). `0` disables the sweep (the default). Distinct from
    /// and additive to the lazy
    /// `fuzzy_record_ttl_secs` eviction: this runs on a timer even without
    /// identify traffic. Overridable via `FP_RETENTION_SECS`.
    #[serde(default)]
    pub retention_secs: u64,
    /// Per-request deadline, in seconds; a request still running past it is
    /// answered `408 Request Timeout`. Overridable via `FP_REQUEST_TIMEOUT_SECS`.
    pub request_timeout_secs: u64,
    /// Global cap on requests processed concurrently; further requests wait for
    /// a slot. Overridable via `FP_MAX_CONCURRENT_REQUESTS`.
    pub max_concurrent_requests: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            nonce_ttl_secs: 30,
            nonce_max_live: fingerprintd::nonce::DEFAULT_MAX_LIVE,
            trust_edge_headers: false,
            integrity_penalty_enabled: false,
            ts_skew_secs: 30,
            // Fail-safe: match `EvictionPolicy::default()` — generous bounds that
            // leave small-workload behaviour identical while capping growth.
            fuzzy_max_records: 1_000_000,
            fuzzy_record_ttl_secs: 0,
            fuzzy_max_block: fingerprintd::fuzzy::blocking::DEFAULT_MAX_BLOCK,
            fuzzy_max_frequency_values: 1_000_000,
            fuzzy_max_agreement_components: 1024,
            admin_key: None,
            api_key: None,
            event_ttl_secs: 3600,
            event_max: 100_000,
            retention_secs: 0,
            request_timeout_secs: 10,
            max_concurrent_requests: 1024,
        }
    }
}

impl Config {
    /// Load configuration from defaults, an optional `fingerprintd.toml`, and
    /// `FP_`-prefixed environment variables (in increasing priority).
    pub fn load() -> Result<Self, Box<figment::Error>> {
        Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file(CONFIG_FILE))
            .merge(Env::prefixed(ENV_PREFIX))
            .extract()
            .map_err(Box::new)
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, SecretKey};
    use std::net::SocketAddr;

    #[test]
    fn secret_key_debug_is_redacted() {
        let key = SecretKey::from("super-secret-admin-key");
        // Neither the wrapped key nor a `Config` carrying it may leak the value.
        assert!(!format!("{key:?}").contains("super-secret-admin-key"));
        let cfg = Config {
            admin_key: Some(key),
            ..Config::default()
        };
        assert!(!format!("{cfg:?}").contains("super-secret-admin-key"));
    }

    #[test]
    fn default_binds_localhost_8080() {
        let cfg = Config::default();
        assert_eq!(
            cfg.bind_addr,
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    // `Jail::expect_with` fixes the closure error type to `figment::Error`.
    #[allow(clippy::result_large_err)]
    fn env_overrides_bind_addr() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("FP_BIND_ADDR", "0.0.0.0:9000");
            jail.set_env("FP_API_KEY", "events-key");
            jail.set_env("FP_ADMIN_KEY", "admin-key");
            jail.set_env("FP_TS_SKEW_SECS", "45");
            jail.set_env("FP_EVENT_TTL_SECS", "60");
            jail.set_env("FP_EVENT_MAX", "7");
            jail.set_env("FP_NONCE_MAX_LIVE", "9");
            jail.set_env("FP_REQUEST_TIMEOUT_SECS", "3");
            jail.set_env("FP_MAX_CONCURRENT_REQUESTS", "5");
            let cfg = Config::load().unwrap();
            assert_eq!(cfg.bind_addr, "0.0.0.0:9000".parse::<SocketAddr>().unwrap());
            assert_eq!(cfg.api_key.unwrap().as_bytes(), b"events-key");
            assert_eq!(cfg.admin_key.unwrap().as_bytes(), b"admin-key");
            assert_eq!(cfg.ts_skew_secs, 45);
            assert_eq!(cfg.event_ttl_secs, 60);
            assert_eq!(cfg.event_max, 7);
            assert_eq!(cfg.nonce_max_live, 9);
            assert_eq!(cfg.request_timeout_secs, 3);
            assert_eq!(cfg.max_concurrent_requests, 5);
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn crate_name_env_prefix_is_ignored() {
        figment::Jail::expect_with(|jail| {
            // Only `FP_` is read; the crate-name prefix is not.
            jail.set_env(concat!("FINGERPRINTD", "_BIND_ADDR"), "0.0.0.0:9000");
            jail.set_env(concat!("FINGERPRINTD", "_API_KEY"), "events-key");
            let cfg = Config::load().unwrap();
            assert_eq!(cfg.bind_addr, Config::default().bind_addr);
            assert!(cfg.api_key.is_none());
            Ok(())
        });
    }
}
