//! Shared, request-scoped application state.

use std::{fmt, sync::Arc};

use crate::{
    config::{Config, SecretKey},
    fuzzy::{EvictionPolicy, FuzzyStore},
    nonce::{InMemoryNonceStore, NonceStore},
    probe::ProbeVerifier,
    signing::ResponseSigner,
};

/// State shared by every handler, cloned per request (all fields are `Arc` or
/// `Copy`, so cloning is cheap).
#[derive(Clone)]
pub struct AppState {
    /// Backing store for one-time challenge nonces.
    pub nonce_store: Arc<dyn NonceStore>,
    /// Weighted fuzzy matching engine and its fingerprint library.
    pub matcher: Arc<FuzzyStore>,
    /// Nonce lifetime advertised to clients as `expires_in`.
    pub nonce_ttl_secs: u64,
    /// Whether edge-injected passive-signal headers are trusted (architecture §4.2). When
    /// `false`, `/identify` ignores client-supplied `CF-Connecting-IP` /
    /// `cf-bot-management-ja4` copies (fail-closed).
    pub trust_edge_headers: bool,
    /// Whether a `noise` client-integrity verdict lowers `/identify` confidence
    /// (`Config::integrity_penalty_enabled`). The verdict is surfaced regardless.
    pub integrity_penalty_enabled: bool,
    /// Nonce-probe verifier. `Some` only when a `probe_key` is configured;
    /// then `/challenge` advertises the transform and `/identify` requires a
    /// correct probe. `None` disables probe enforcement (default).
    pub probe: Option<Arc<ProbeVerifier>>,
    /// Response signer. `Some` only when a `response_signing_key` is
    /// configured; then each `/identify` success carries `x-fp-timestamp` and
    /// `x-fp-signature` headers. `None` disables signing (default).
    pub signer: Option<Arc<ResponseSigner>>,
    /// Whether to enforce the request timestamp window on `/identify`. When
    /// `false`, `ts` is ignored (default).
    pub enforce_ts_window: bool,
    /// Allowed clock skew, in milliseconds, for the request timestamp window when
    /// `enforce_ts_window` is on. Derived from `config.ts_skew_secs`.
    pub ts_skew_ms: u64,
    /// Admin credential gating the GDPR erasure endpoint. `Some` only when a
    /// non-empty `admin_key` is configured; then `DELETE /visitor/{id}` is enabled
    /// and requires a matching `Authorization: Bearer` credential. `None` disables
    /// the endpoint entirely (fail-closed `404`).
    pub admin_key: Option<Arc<SecretKey>>,
    /// Compliance retention window in milliseconds: a record older than this
    /// by `last_seen` is purged by the background sweep. `0` disables the sweep.
    /// Derived from `config.retention_secs`.
    pub retention_ms: u64,
}

impl AppState {
    /// Build state from configuration, using the in-memory backends.
    pub fn from_config(config: &Config) -> Self {
        let ttl = std::time::Duration::from_secs(config.nonce_ttl_secs);
        let probe = config
            .probe_key
            .as_ref()
            .filter(|key| key.is_configured())
            .map(|key| Arc::new(ProbeVerifier::new(key.as_bytes())));
        let signer = config
            .response_signing_key
            .as_ref()
            .filter(|key| key.is_configured())
            .map(|key| Arc::new(ResponseSigner::new(key.as_bytes())));
        // Erasure is fail-closed: enabled only when a real (non-empty) admin key
        // is provisioned, mirroring the probe/signer opt-in.
        let admin_key = config
            .admin_key
            .as_ref()
            .filter(|key| key.is_configured())
            .map(|key| Arc::new(key.clone()));
        // Bound in-memory fuzzy growth. A `0` TTL means "off"
        // (unbounded); the caps are generous fail-safe defaults so a small
        // workload is unaffected.
        let policy = EvictionPolicy {
            max_records: Some(config.fuzzy_max_records),
            record_ttl_ms: (config.fuzzy_record_ttl_secs > 0)
                .then(|| config.fuzzy_record_ttl_secs.saturating_mul(1000)),
            max_frequency_values: Some(config.fuzzy_max_frequency_values),
            max_agreement_components: Some(config.fuzzy_max_agreement_components),
            // No dedicated knob yet: use the generous fail-safe default so the
            // cross-session velocity store is bounded but unaffected at small scale.
            max_velocity_keys: EvictionPolicy::default().max_velocity_keys,
            max_block: config.fuzzy_max_block,
        };
        Self {
            nonce_store: Arc::new(InMemoryNonceStore::new(ttl)),
            matcher: Arc::new(FuzzyStore::new_with_policy(policy)),
            nonce_ttl_secs: config.nonce_ttl_secs,
            trust_edge_headers: config.trust_edge_headers,
            integrity_penalty_enabled: config.integrity_penalty_enabled,
            probe,
            signer,
            enforce_ts_window: config.enforce_ts_window,
            ts_skew_ms: config.ts_skew_secs.saturating_mul(1000),
            admin_key,
            retention_ms: config.retention_secs.saturating_mul(1000),
        }
    }
}

impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `dyn NonceStore` is not `Debug`; expose only the plain field.
        f.debug_struct("AppState")
            .field("nonce_ttl_secs", &self.nonce_ttl_secs)
            .field("trust_edge_headers", &self.trust_edge_headers)
            .field("integrity_penalty_enabled", &self.integrity_penalty_enabled)
            .field("probe_enabled", &self.probe.is_some())
            .field("signing_enabled", &self.signer.is_some())
            .field("enforce_ts_window", &self.enforce_ts_window)
            .field("ts_skew_ms", &self.ts_skew_ms)
            .field("admin_key_enabled", &self.admin_key.is_some())
            .field("retention_ms", &self.retention_ms)
            .finish_non_exhaustive()
    }
}
