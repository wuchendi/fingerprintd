//! In-memory storage layer for the weighted fuzzy-matching engine
//! (DESIGN.md fuzzy-matching §3/§4/§9/§11).
//!
//! This is the storage substrate only — it holds the data model, the blocking
//! indexes for candidate generation, and the frequency material for parameter
//! estimation. It is deliberately **additive**: the P0 `/identify` exact-match
//! path is untouched, and the two-stage scoring/judgment (fuzzy-matching §5) is out of
//! scope here.
//!
//! Pieces, mapped to the fuzzy-matching spec's data-structure table (§11):
//! - [`component`] — salted, compliance-preserving stored representations (§3)
//!   and the cold-start stability priors (§2/§9).
//! - [`frequency`] — `value hash → count`, the material for `u_i` (§9).
//! - [`blocking`] — the `key → set<visitorId>` inverted index (§4).
//! - [`minhash`] — `MinHash`-`LSH` band keys for set components (§4 K3).
//! - [`record`] — the `visitorId → template` fingerprint library (§3).
//!
//! [`FuzzyStore`] wires them together: [`FuzzyStore::observe`] folds a raw
//! component observation into every index, and [`FuzzyStore::candidates`]
//! performs stage-one recall.

pub mod agreement;
pub mod blocking;
mod canonical;
pub mod component;
pub mod engine;
// The offline evaluation harness replays fixtures through a random-salt store; it
// is a native tuning tool, not edge compute, so the WASM build omits it.
#[cfg(feature = "rng")]
pub mod eval;
pub mod frequency;
pub mod minhash;
pub mod record;
pub mod velocity;

pub use agreement::AgreementStore;
pub use blocking::CandidateSource;
pub use component::{FieldSpec, Kind, classify};
pub use engine::{Decision, MatchOutcome};
pub use frequency::FrequencyStore;
pub use record::FingerprintStore;
pub use velocity::{VelocityBand, VelocityStore};

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
};

use serde_json::Value;

use self::{
    agreement::AgreementTable,
    blocking::{BlockingIndex, BlockingKey, DEFAULT_MAX_BLOCK},
    canonical::{all_scalar_key, canonical_scalar, group_key, object_entries, value_to_i64},
    component::{Salt, Stored},
    frequency::FrequencyTable,
    minhash::MinHashLsh,
    record::{FingerprintRecord, RecordStore},
    velocity::VelocityTable,
};

/// Capacity / TTL bounds for the in-memory fuzzy backends.
///
/// The in-memory store grows with every distinct visitor and value; left
/// unbounded that is an availability risk. This policy caps that growth with
/// **fail-safe** defaults: the [`Default`] bounds are generous, so a fresh
/// small workload behaves byte-for-byte as before — only unbounded growth is
/// added. `None` on an optional field means "unbounded".
///
/// The bounds are enforced by the concrete backends ([`RecordStore`],
/// [`FrequencyTable`], [`BlockingIndex`]) and every eviction/drop is counted
/// (never silent), matching the blocking `dropped()` precedent (fuzzy-matching §4).
/// Applies to a stateful native store built by [`FuzzyStore::new_with_policy`];
/// the stateless edge store ([`FuzzyStore::deterministic`]) is per-request and
/// needs no eviction, so it stays unbounded.
#[derive(Debug, Clone, Copy)]
pub struct EvictionPolicy {
    /// Retain at most this many visitors in the record library; `None` is
    /// unbounded. When exceeded, the oldest-`last_seen` visitor is evicted.
    pub max_records: Option<usize>,
    /// Drop record entries not seen within this window (ms) on the next
    /// observe; `None` disables TTL eviction.
    pub record_ttl_ms: Option<u64>,
    /// Cap on the number of *distinct* tracked frequency values; `None` is
    /// unbounded. A new value beyond the cap is dropped (already-tracked values
    /// keep counting).
    pub max_frequency_values: Option<usize>,
    /// Cap on the number of *distinct* tracked agreement components for `m_i`
    /// estimation (fuzzy-matching §9); `None` is unbounded. A new component name
    /// beyond the cap is dropped (already-tracked names keep counting).
    pub max_agreement_components: Option<usize>,
    /// Cap on the number of *distinct* tracked keys (client IPs) for the
    /// cross-session new-device velocity signal; `None` is unbounded. A new key
    /// beyond the cap is dropped (already-tracked keys keep counting).
    pub max_velocity_keys: Option<usize>,
    /// Per-block visitor cap for the blocking index (fuzzy-matching §4).
    pub max_block: usize,
}

impl Default for EvictionPolicy {
    fn default() -> Self {
        Self {
            max_records: Some(1_000_000),
            record_ttl_ms: None,
            max_frequency_values: Some(1_000_000),
            max_agreement_components: Some(1024),
            max_velocity_keys: Some(1_000_000),
            max_block: DEFAULT_MAX_BLOCK,
        }
    }
}

/// Aggregate store tying the record library, blocking indexes, and frequency
/// table together behind one observe/candidates surface.
///
/// The three storage backends are held as trait objects so each is injectable
/// (see [`FuzzyStore::from_backends`]); the in-memory implementations remain the
/// default and only shipped backend. The salt and `MinHash`-`LSH` family stay
/// concrete: they are deterministic key-derivation, not swappable storage.
pub struct FuzzyStore {
    /// Per-instance salt applied to every stored value.
    salt: Salt,
    /// The `visitorId → template` fingerprint library (§3).
    records: Box<dyn FingerprintStore>,
    /// The `key → set<visitorId>` blocking inverted index (§4).
    blocking: Box<dyn CandidateSource>,
    /// `MinHash`-`LSH` band-key generator for set components (§4 K3).
    minhash: MinHashLsh,
    /// Per-value frequency material for `u_i` estimation (§9).
    frequency: Box<dyn FrequencyStore>,
    /// Per-component agreement material for `m_i` estimation (§9): how often each
    /// component's stored value agreed across confirmed same-device revisits.
    agreement: Box<dyn AgreementStore>,
    /// Per-key new-device event material for the cross-session velocity signal:
    /// how many new devices each client IP produced within the trailing window.
    velocity: Box<dyn VelocityStore>,
    /// Serializes the [`FuzzyStore::identify`] read-modify-write so its
    /// evaluate-then-observe critical section is atomic.
    ///
    /// Each backend guards only its own `Mutex`, so without this the recall +
    /// per-candidate reads (`evaluate`) and the frequency/blocking/record writes
    /// (`observe`) of one `identify` are not one atomic step: a concurrent
    /// `identify`'s `observe` could interleave between them and perturb the
    /// scores non-deterministically. This `()`-guard makes the whole RMW a
    /// single critical section. It is deliberately **not** taken by the
    /// read-only [`FuzzyStore::score`] path, which performs no `observe` and must
    /// stay lock-light for the stateless edge host.
    identify_lock: std::sync::Mutex<()>,
}

impl fmt::Debug for FuzzyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The backends are trait objects (not `Debug`); expose the concrete,
        // deterministic key-derivation state and elide the storage internals.
        f.debug_struct("FuzzyStore")
            .field("salt", &self.salt)
            .field("minhash", &self.minhash)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "rng")]
impl Default for FuzzyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FuzzyStore {
    /// Build an empty store with a fresh random salt and permutation family,
    /// using the [`EvictionPolicy::default`] fail-safe bounds.
    #[cfg(feature = "rng")]
    pub fn new() -> Self {
        Self::new_with_policy(EvictionPolicy::default())
    }

    /// Build an empty store (random salt) whose in-memory backends enforce the
    /// given capacity / TTL [`EvictionPolicy`].
    ///
    /// [`FuzzyStore::new`] delegates here with the default (generous) policy, so
    /// a fresh small workload is unaffected while growth is bounded. The
    /// stateless edge path ([`FuzzyStore::deterministic`]) is intentionally not
    /// routed through here: it is per-request and stays unbounded.
    #[cfg(feature = "rng")]
    pub fn new_with_policy(policy: EvictionPolicy) -> Self {
        Self {
            salt: Salt::random(),
            records: Box::new(RecordStore::with_capacity(
                policy.max_records,
                policy.record_ttl_ms,
            )),
            blocking: Box::new(BlockingIndex::with_max_block(policy.max_block)),
            minhash: MinHashLsh::new(),
            frequency: Box::new(FrequencyTable::with_capacity(policy.max_frequency_values)),
            agreement: Box::new(AgreementTable::with_capacity(
                policy.max_agreement_components,
            )),
            velocity: Box::new(VelocityTable::with_capacity(policy.max_velocity_keys)),
            identify_lock: std::sync::Mutex::new(()),
        }
    }

    /// Build an empty store with a **deterministic** salt and permutation family
    /// derived from `secret`.
    ///
    /// Unlike [`FuzzyStore::new`] (per-instance random), this yields identical
    /// stored hashes and blocking keys across processes for the same secret —
    /// the contract a stateless edge host relies on so keys persisted on one
    /// request match those derived on another (WASM edge compute, `crates/fp-wasm`).
    pub fn deterministic(secret: &[u8]) -> Self {
        Self {
            salt: Salt::from_secret(secret),
            records: Box::new(RecordStore::new()),
            blocking: Box::new(BlockingIndex::new()),
            minhash: MinHashLsh::from_seed(secret),
            frequency: Box::new(FrequencyTable::new()),
            agreement: Box::new(AgreementTable::new()),
            velocity: Box::new(VelocityTable::new()),
            identify_lock: std::sync::Mutex::new(()),
        }
    }

    /// Assemble a store from explicitly supplied backends — the injection seam.
    ///
    /// [`FuzzyStore::new`] and [`FuzzyStore::deterministic`] wire the in-memory
    /// defaults ([`RecordStore`], [`BlockingIndex`], [`FrequencyTable`],
    /// [`AgreementTable`]), which remain the only shipped backend. This
    /// constructor lets a caller swap any of the five storage backends for an
    /// alternate implementation of [`FingerprintStore`] / [`CandidateSource`] /
    /// [`FrequencyStore`] / [`AgreementStore`] / [`VelocityStore`] (an externalized
    /// index, a test double) while keeping the same salt and `MinHash` family so
    /// key derivation is unchanged.
    pub fn from_backends(
        salt: Salt,
        minhash: MinHashLsh,
        records: Box<dyn FingerprintStore>,
        blocking: Box<dyn CandidateSource>,
        frequency: Box<dyn FrequencyStore>,
        agreement: Box<dyn AgreementStore>,
        velocity: Box<dyn VelocityStore>,
    ) -> Self {
        Self {
            salt,
            records,
            blocking,
            minhash,
            frequency,
            agreement,
            velocity,
            identify_lock: std::sync::Mutex::new(()),
        }
    }

    /// Fold a raw component observation for `visitor` into every index.
    ///
    /// Converts each recognized component to its stored form (updating the
    /// frequency table for scalar values), upserts the visitor's template with
    /// `now_ms` (Unix milliseconds), and inserts the derived blocking keys.
    /// Returns `true` when the visitor was newly recorded.
    pub fn observe(&self, visitor: &str, components: &Value, now_ms: u64) -> bool {
        let stored = self.stored_map(components);
        // Scalar values feed the frequency material for `u_i` (§9).
        for value in stored.values() {
            match value {
                Stored::Category(hash) => self.frequency.record(*hash),
                Stored::Numeric(n) => self.frequency.record(self.salt.hash(&n.to_string())),
                Stored::Set(_) => {}
            }
        }

        for key in self.blocking_keys(&stored) {
            self.blocking.insert(key, visitor);
        }
        self.records.observe(visitor, stored, now_ms)
    }

    /// Erase `visitor` entirely from the fingerprint library (GDPR right-to-be-
    /// forgotten): drop its record and purge it from every blocking block, under
    /// the [`FuzzyStore::identify`] lock so the removal is atomic against a
    /// concurrent `identify`. Returns `true` when a record existed.
    ///
    /// The aggregate [`frequency`] table is intentionally left untouched: it is a
    /// value-frequency aggregate with no per-visitor linkage, so it carries no
    /// personal data to erase and removing a visitor's contribution would corrupt
    /// the shared `u_i` estimates for unrelated visitors.
    pub fn erase(&self, visitor: &str) -> bool {
        let _guard = self
            .identify_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let existed = self.records.remove(visitor);
        self.blocking.remove_visitor(visitor);
        existed
    }

    /// Proactively purge every record older than `max_age_ms` (by `last_seen`)
    /// relative to `now_ms`, returning the number removed (compliance
    /// retention). Runs under the [`FuzzyStore::identify`] lock so it is atomic
    /// against a concurrent `identify`, and is additive to the lazy TTL sweep in
    /// [`FuzzyStore::observe`] — it ages records out even without observe traffic.
    ///
    /// Blocking-index rows for a purged visitor are left as harmless dangling
    /// keys: stage-one recall re-joins candidates against the record library, and
    /// a candidate with no record scores `-inf` and can never win, so a stale
    /// block entry changes no decision. Full block cleanup is reserved for the
    /// explicit [`FuzzyStore::erase`] path.
    pub fn purge_expired(&self, now_ms: u64, max_age_ms: u64) -> u64 {
        let _guard = self
            .identify_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.records.purge_older_than(now_ms, max_age_ms)
    }

    /// Stage-one candidate recall: the union of visitors sharing any blocking
    /// key with `components` (fuzzy-matching §4).
    pub fn candidates(&self, components: &Value) -> HashSet<String> {
        let stored = self.stored_map(components);
        self.blocking.candidates(&self.blocking_keys(&stored))
    }

    /// The blocking keys for `components`, hex-encoded (fuzzy-matching §4).
    ///
    /// The hex form of each [`blocking::BlockingKey`] a stateless host queries
    /// its externalized candidate index with. Key derivation depends on the salt
    /// and the `MinHash` permutation family, so a [`FuzzyStore::deterministic`]
    /// store yields keys that are stable across isolate instances.
    pub fn blocking_key_hexes(&self, components: &Value) -> Vec<String> {
        let stored = self.stored_map(components);
        self.blocking_keys(&stored)
            .iter()
            .map(hex::encode)
            .collect()
    }

    /// Names of the components in `components` that the schema stores (sorted),
    /// i.e. the ones that take part in matching. Missing, `null`, and
    /// type-mismatched values are excluded (fuzzy-matching §8).
    pub fn stored_component_names(&self, components: &Value) -> Vec<String> {
        self.stored_map(components).into_keys().collect()
    }

    /// Convert a raw JSON component object into its stored-form map, dropping
    /// missing or type-mismatched entries (fuzzy-matching §8). Shared by [`observe`],
    /// [`candidates`], and the stage-two scorer.
    ///
    /// [`observe`]: FuzzyStore::observe
    /// [`candidates`]: FuzzyStore::candidates
    fn stored_map(&self, components: &Value) -> BTreeMap<String, Stored> {
        let mut stored = BTreeMap::new();
        for (name, value) in object_entries(components) {
            if let Some(value) = self.to_stored(name, value) {
                stored.insert(name.clone(), value);
            }
        }
        stored
    }

    /// Snapshot of a visitor's stored template.
    pub fn record(&self, visitor: &str) -> Option<FingerprintRecord> {
        self.records.get(visitor)
    }

    /// Frequency material, for `u_i` estimation by the (future) scorer.
    pub fn frequency(&self) -> &dyn FrequencyStore {
        self.frequency.as_ref()
    }

    /// The blocking index (exposes drop accounting and direct queries).
    pub fn blocking(&self) -> &dyn CandidateSource {
        self.blocking.as_ref()
    }

    /// Convert one raw component value to its stored form per the schema.
    ///
    /// Returns `None` for a missing or type-mismatched value (fuzzy-matching §8: a
    /// missing component is simply not compared).
    fn to_stored(&self, name: &str, value: &Value) -> Option<Stored> {
        match classify(name).kind {
            Kind::Category => canonical_scalar(value).map(|s| Stored::Category(self.salt.hash(&s))),
            Kind::Numeric => value_to_i64(value).map(Stored::Numeric),
            Kind::Set => value.as_array().map(|items| {
                Stored::Set(self.salt.hash_set(items.iter().filter_map(Value::as_str)))
            }),
        }
    }

    /// Derive the blocking keys (K1, K2, and the `MinHash` bands) for a stored
    /// component map (fuzzy-matching §4). A composite key is emitted only when all of
    /// its members are present, so recall relies on the union of independent keys.
    fn blocking_keys(&self, stored: &BTreeMap<String, Stored>) -> Vec<BlockingKey> {
        let mut keys = Vec::new();
        // K0 — catch-all over every present scalar value, so two probes whose
        // scalar components are byte-identical always recall each other (the
        // exact-match subset). Fragile by design; recall of *drifted* probes
        // relies on the independent K1/K2/font keys below (fuzzy-matching §4 redundancy).
        if let Some(key) = all_scalar_key(stored) {
            keys.push(key);
        }
        if let Some(key) = group_key(stored, b"K1", &["webgl", "platform", "timezone"]) {
            keys.push(key);
        }
        if let Some(key) = group_key(stored, b"K2", &["audio", "cpu_cores", "device_memory"]) {
            keys.push(key);
        }
        if let Some(Stored::Set(fonts)) = stored.get("fonts") {
            keys.extend(self.minhash.band_keys(fonts));
        }
        keys
    }
}

#[cfg(test)]
mod tests {
    use super::{EvictionPolicy, FuzzyStore};
    use serde_json::json;

    /// A full high-stability probe that populates both K1 and K2 keys.
    fn full_probe() -> serde_json::Value {
        json!({
            "webgl": "ANGLE (Intel)",
            "platform": "Linux x86_64",
            "timezone": "Asia/Shanghai",
            "audio": "124.04",
            "cpu_cores": 8,
            "device_memory": 8,
            "fonts": ["Arial", "Helvetica", "Courier", "Times", "Verdana"],
            "user_agent": "Chrome/120",
        })
    }

    #[test]
    fn observe_populates_record_and_recalls_self() {
        let store = FuzzyStore::new();
        let probe = full_probe();
        assert!(store.observe("v1", &probe, 1_000));

        let record = store.record("v1").unwrap();
        assert_eq!(record.observation_count, 1);
        assert_eq!(record.first_seen, 1_000);
        // The stored template keeps a value per recognized component.
        assert!(record.components.contains_key("webgl"));
        assert!(record.components.contains_key("fonts"));

        // The same probe recalls the visitor via its blocking keys.
        assert!(store.candidates(&probe).contains("v1"));
    }

    #[test]
    fn recall_survives_a_changed_ua_and_one_font() {
        let store = FuzzyStore::new();
        store.observe("v1", &full_probe(), 1_000);

        // Browser auto-upgraded (UA changed) and one font added: the high-stable
        // K1/K2 keys are unchanged and MinHash still shares bands -> recalled.
        let mut drifted = full_probe();
        drifted["user_agent"] = json!("Chrome/121");
        drifted["fonts"] = json!(["Arial", "Helvetica", "Courier", "Times", "Segoe"]);
        assert!(store.candidates(&drifted).contains("v1"));
    }

    #[test]
    fn unrelated_probe_is_not_recalled() {
        let store = FuzzyStore::new();
        store.observe("v1", &full_probe(), 1_000);

        let other = json!({
            "webgl": "Apple GPU",
            "platform": "iPhone",
            "timezone": "America/New_York",
            "audio": "35.7",
            "cpu_cores": 6,
            "device_memory": 4,
            "fonts": ["SF Pro", "Menlo", "Georgia", "Palatino"],
            "user_agent": "Safari/17",
        });
        assert!(!store.candidates(&other).contains("v1"));
    }

    #[test]
    fn frequency_tracks_category_values() {
        let store = FuzzyStore::new();
        store.observe("v1", &full_probe(), 1_000);
        store.observe("v2", &full_probe(), 2_000);

        // "Linux x86_64" seen twice for the platform component.
        let hash = store.salt.hash("Linux x86_64");
        assert_eq!(store.frequency().count(hash), 2);
    }

    #[test]
    fn missing_components_are_skipped_not_stored() {
        let store = FuzzyStore::new();
        // canvas null (privacy browser) must not be stored as a matchable value.
        store.observe("v1", &json!({ "webgl": "x", "canvas": null }), 1_000);
        let record = store.record("v1").unwrap();
        assert!(record.components.contains_key("webgl"));
        assert!(!record.components.contains_key("canvas"));
    }

    #[test]
    fn stored_component_names_lists_only_storable_components() {
        let store = FuzzyStore::new();
        let names = store.stored_component_names(&json!({
            "webgl": "ANGLE (Intel)",
            "screen": "1920x1080",
            "fonts": ["Arial"],
            "canvas": null,
            "touchSupport": { "maxTouchPoints": 5 },
        }));
        // Sorted; null and object values are not stored.
        assert_eq!(names, ["fonts", "screen", "webgl"]);
    }

    #[test]
    fn new_with_policy_bounds_the_record_library() {
        // A tight record cap of 2: after observing three distinct visitors, the
        // oldest is evicted so the library never exceeds the cap.
        let policy = EvictionPolicy {
            max_records: Some(2),
            ..EvictionPolicy::default()
        };
        let store = FuzzyStore::new_with_policy(policy);
        store.observe("v1", &full_probe(), 1_000);
        store.observe("v2", &full_probe(), 2_000);
        store.observe("v3", &full_probe(), 3_000);

        assert!(store.record("v1").is_none()); // oldest, evicted
        assert!(store.record("v2").is_some());
        assert!(store.record("v3").is_some());
    }

    #[test]
    fn erase_removes_record_and_blocking_so_device_is_new_again() {
        let store = FuzzyStore::new();
        let probe = full_probe();
        store.observe("v1", &probe, 1_000);
        assert!(store.candidates(&probe).contains("v1"));

        // Erase reports the record existed and drops it plus its blocking rows.
        assert!(store.erase("v1"));
        assert!(store.record("v1").is_none());
        assert!(!store.candidates(&probe).contains("v1"));
        // Idempotent: a second erase finds nothing.
        assert!(!store.erase("v1"));

        // Re-identifying the same device now sees no candidate → a new device.
        let outcome = store.identify(&probe, 2_000);
        assert!(outcome.is_new_device);
    }

    #[test]
    fn purge_expired_drops_aged_records_under_lock() {
        let store = FuzzyStore::new();
        store.observe("old", &full_probe(), 1_000);
        store.observe("fresh", &full_probe(), 9_000);

        // At t=10_000 with a 5_000 ms retention, `old` ages out and `fresh` stays.
        assert_eq!(store.purge_expired(10_000, 5_000), 1);
        assert!(store.record("old").is_none());
        assert!(store.record("fresh").is_some());
        // Nothing left to age out on a repeat sweep.
        assert_eq!(store.purge_expired(10_000, 5_000), 0);
    }

    #[test]
    fn non_object_probe_records_visitor_with_no_components() {
        let store = FuzzyStore::new();
        assert!(store.observe("v1", &json!("not-an-object"), 1_000));
        assert!(store.record("v1").unwrap().components.is_empty());
    }

    /// A test-only [`FingerprintStore`] that counts writes while delegating the
    /// actual storage to an inner in-memory [`RecordStore`]. It exists to prove
    /// [`FuzzyStore::from_backends`] injects the record backend the engine then
    /// writes through.
    #[derive(Debug)]
    struct CountingRecordStore {
        inner: super::record::RecordStore,
        observes: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl super::FingerprintStore for CountingRecordStore {
        fn observe(
            &self,
            visitor: &str,
            components: std::collections::BTreeMap<String, super::component::Stored>,
            now_ms: u64,
        ) -> bool {
            self.observes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.observe(visitor, components, now_ms)
        }

        fn get(&self, visitor: &str) -> Option<super::record::FingerprintRecord> {
            self.inner.get(visitor)
        }

        fn remove(&self, visitor: &str) -> bool {
            self.inner.remove(visitor)
        }
    }

    /// The seam works: a non-default record backend injected via
    /// [`FuzzyStore::from_backends`] is the one every write goes through, while
    /// matching still recalls and identifies correctly against it.
    #[test]
    fn injected_record_backend_is_actually_used() {
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };

        let observes = Arc::new(AtomicU64::new(0));
        let store = FuzzyStore::from_backends(
            super::Salt::from_secret(b"seam-test"),
            super::MinHashLsh::from_seed(b"seam-test"),
            Box::new(CountingRecordStore {
                inner: super::record::RecordStore::new(),
                observes: Arc::clone(&observes),
            }),
            Box::new(super::BlockingIndex::new()),
            Box::new(super::FrequencyTable::new()),
            Box::new(super::AgreementTable::new()),
            Box::new(super::VelocityTable::new()),
        );

        // A direct observation writes through the swapped backend...
        assert!(store.observe("v1", &full_probe(), 1_000));
        assert_eq!(observes.load(Ordering::Relaxed), 1);
        // ...and the record it stored is recalled and readable through the seam.
        assert!(store.candidates(&full_probe()).contains("v1"));
        assert_eq!(store.record("v1").unwrap().observation_count, 1);

        // identify() persists a confirmed match by folding it back in, so the
        // injected backend's write path is exercised end to end.
        let matched = store.identify(&full_probe(), 2_000);
        assert_eq!(matched.decision, super::Decision::Match);
        assert_eq!(matched.visitor_id, "v1");
        assert_eq!(observes.load(Ordering::Relaxed), 2);
    }
}
