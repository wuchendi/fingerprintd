//! Runtime configuration for the `fingerprintd` service.
//!
//! Configuration is layered: built-in defaults are overlaid by an optional
//! `fingerprintd.toml` file, then by `FINGERPRINTD_`-prefixed environment
//! variables. The merged result is validated by `serde` during extraction.

use std::{fmt, net::SocketAddr};

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};

/// A secret key loaded from configuration (the nonce-probe HMAC key, the
/// GDPR-erasure admin credential).
///
/// Wraps the raw key so it is never accidentally logged: its [`fmt::Debug`] is
/// redacted, so `Debug`-printing the containing [`Config`] does not leak it. It
/// serializes transparently (as the bare string) so figment can layer it from a
/// file or `FINGERPRINTD_PROBE_KEY`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretKey(String);

impl SecretKey {
    /// The raw key bytes, for HMAC keying (`crate::probe`).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Whether a non-empty key is present. An empty string is treated as "no
    /// probe configured", so enforcement stays off (fail-closed only once a real
    /// key is provisioned).
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
/// Prefix for environment overrides, e.g. `FINGERPRINTD_BIND_ADDR`.
const ENV_PREFIX: &str = "FINGERPRINTD_";

/// Service configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Socket address the HTTP server binds to.
    pub bind_addr: SocketAddr,
    /// Lifetime, in seconds, of a challenge nonce before it expires. Reported
    /// to clients as `expires_in`; overridable via `FINGERPRINTD_NONCE_TTL_SECS`.
    pub nonce_ttl_secs: u64,
    /// Whether to trust edge-injected passive-signal headers (`CF-Connecting-IP`,
    /// `cf-bot-management-ja4`). Enable **only** when the service sits behind a
    /// trusted edge (Cloudflare) that injects these headers and an origin IP
    /// allowlist rejects direct client connections (architecture §4.2). Left `false` by
    /// default (fail-closed): a directly-reachable origin must not trust
    /// client-supplied copies of these headers, or a client could self-inject a
    /// browser-looking JA4 to forge consistency. Overridable via
    /// `FINGERPRINTD_TRUST_EDGE_HEADERS`.
    pub trust_edge_headers: bool,
    /// Whether the client's known-answer integrity probe verdicts (the request's
    /// top-level `integrity`, see `fp_core::signals::ClientIntegrity`) may lower
    /// `/identify` confidence. The verdict is **always surfaced** as
    /// `signals.client_integrity`; this flag only enables the `noise` downgrade.
    /// Left `false` by default: legitimate privacy tooling (Brave farbling, canvas
    /// blockers) trips the same probes, so the band is surfaced-only until a
    /// real-traffic false-positive rate is known. Overridable via
    /// `FINGERPRINTD_INTEGRITY_PENALTY_ENABLED`.
    pub integrity_penalty_enabled: bool,
    /// Optional pre-shared HMAC key for nonce-probe verification (architecture §4.1
    /// pt 3). When set (and non-empty), `GET /challenge` advertises the probe
    /// transform and `POST /identify` requires a correct `probe` field, rejecting
    /// a missing or forged one with `401`. Left unset by default: the probe is
    /// depth on top of the one-time nonce and needs a probe-capable client (WASM
    /// collector, deferred), so enforcing it before that ships would reject all
    /// legitimate traffic. Overridable via `FINGERPRINTD_PROBE_KEY`.
    #[serde(default)]
    pub probe_key: Option<SecretKey>,
    /// Optional pre-shared HMAC key for signing `/identify` responses (architecture
    /// §4.1). When set (and non-empty), each success carries `x-fp-timestamp`
    /// and `x-fp-signature` headers so a consumer can detect a tampered or forged
    /// response (`crate::signing`). Left unset by default (fail-open on an absent
    /// key): the response body is unchanged, so a non-verifying client is
    /// unaffected. Overridable via `FINGERPRINTD_RESPONSE_SIGNING_KEY`.
    #[serde(default)]
    pub response_signing_key: Option<SecretKey>,
    /// Whether to enforce the request timestamp window on `/identify` (architecture
    /// §4.1). When `true`, a request whose `ts` (Unix milliseconds) is absent or
    /// more than `ts_skew_secs` from server time is rejected with `401`, bounding
    /// how long a captured payload stays replayable on top of the one-time nonce.
    /// Left `false` by default (fail-open): a client that does not send a `ts` is
    /// unaffected. Overridable via `FINGERPRINTD_ENFORCE_TS_WINDOW`.
    pub enforce_ts_window: bool,
    /// Allowed clock skew, in seconds, for the request timestamp window when
    /// `enforce_ts_window` is on. A request is accepted iff its `ts` is
    /// within `±ts_skew_secs` of server time. Overridable via
    /// `FINGERPRINTD_TS_SKEW_SECS`.
    pub ts_skew_secs: u64,
    /// Cap on distinct visitors kept in the in-memory fingerprint library.
    /// Once exceeded, the oldest-seen visitor is evicted (and
    /// counted). Fail-safe generous default so a small workload is unaffected;
    /// bounds unbounded growth. Overridable via `FINGERPRINTD_FUZZY_MAX_RECORDS`.
    pub fuzzy_max_records: usize,
    /// Time-to-live, in seconds, for an in-memory record: an entry not seen
    /// within this window is evicted on the next observe. `0`
    /// disables TTL eviction (the default). Overridable via
    /// `FINGERPRINTD_FUZZY_RECORD_TTL_SECS`.
    pub fuzzy_record_ttl_secs: u64,
    /// Per-block visitor cap for the blocking index (fuzzy-matching §4). A block over
    /// this size drops (and counts) further insertions. Overridable via
    /// `FINGERPRINTD_FUZZY_MAX_BLOCK`.
    pub fuzzy_max_block: usize,
    /// Cap on distinct tracked frequency values for `u_i` estimation.
    /// A new value beyond the cap is dropped (already-tracked values keep
    /// counting). Fail-safe generous default. Overridable via
    /// `FINGERPRINTD_FUZZY_MAX_FREQUENCY_VALUES`.
    pub fuzzy_max_frequency_values: usize,
    /// Cap on distinct tracked agreement components for `m_i` estimation.
    /// A new component name beyond the cap is dropped (already-tracked names keep
    /// counting). Fail-safe generous default. Overridable via
    /// `FINGERPRINTD_FUZZY_MAX_AGREEMENT_COMPONENTS`.
    pub fuzzy_max_agreement_components: usize,
    /// Optional pre-shared admin credential gating the GDPR erasure endpoint
    /// `DELETE /visitor/{id}` (architecture §7 RTBF). When set (and non-empty),
    /// the endpoint accepts an `Authorization: Bearer <admin_key>` request and
    /// erases the visitor. Left unset by default and **fail-closed**: with no key
    /// the endpoint is disabled entirely (`404`), and a configured key rejects a
    /// missing or wrong credential with `401` — erasure is never open.
    /// Overridable via `FINGERPRINTD_ADMIN_KEY`.
    #[serde(default)]
    pub admin_key: Option<SecretKey>,
    /// Compliance retention window, in seconds: the maximum age (by `last_seen`) a
    /// visitor record is retained before a proactive background sweep purges it
    /// (architecture §7). `0` disables the sweep (the default), leaving
    /// behaviour unchanged. Distinct from and additive to the lazy
    /// `fuzzy_record_ttl_secs` eviction: this runs on a timer even without
    /// identify traffic. Overridable via `FINGERPRINTD_RETENTION_SECS`.
    #[serde(default)]
    pub retention_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            nonce_ttl_secs: 30,
            trust_edge_headers: false,
            integrity_penalty_enabled: false,
            probe_key: None,
            response_signing_key: None,
            enforce_ts_window: false,
            ts_skew_secs: 30,
            // Fail-safe: match `EvictionPolicy::default()` — generous bounds that
            // leave small-workload behaviour identical while capping growth.
            fuzzy_max_records: 1_000_000,
            fuzzy_record_ttl_secs: 0,
            fuzzy_max_block: crate::fuzzy::blocking::DEFAULT_MAX_BLOCK,
            fuzzy_max_frequency_values: 1_000_000,
            fuzzy_max_agreement_components: 1024,
            admin_key: None,
            retention_secs: 0,
        }
    }
}

impl Config {
    /// Load configuration from defaults, an optional `fingerprintd.toml`, and
    /// `FINGERPRINTD_`-prefixed environment variables (in increasing priority).
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
        let key = SecretKey::from("super-secret-probe-key");
        // Neither the wrapped key nor a `Config` carrying it may leak the value.
        assert!(!format!("{key:?}").contains("super-secret-probe-key"));
        let cfg = Config {
            probe_key: Some(key),
            ..Config::default()
        };
        assert!(!format!("{cfg:?}").contains("super-secret-probe-key"));
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
            jail.set_env("FINGERPRINTD_BIND_ADDR", "0.0.0.0:9000");
            let cfg = Config::load().unwrap();
            assert_eq!(cfg.bind_addr, "0.0.0.0:9000".parse::<SocketAddr>().unwrap());
            Ok(())
        });
    }
}
