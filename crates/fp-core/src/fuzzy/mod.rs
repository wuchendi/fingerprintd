//! The weighted fuzzy-matching engine (DESIGN.md fuzzy-matching §3–§11).
//!
//! It resolves a raw component observation to a `visitor_id` in two stages:
//! stage one recalls candidates from blocking indexes (§4), stage two scores
//! each candidate with the Fellegi–Sunter model and applies the double-threshold
//! decision, template drift, and confidence fusion (§5–§8, in [`engine`]).
//!
//! Pieces, mapped to the fuzzy-matching spec's data-structure table (§11):
//! - [`component`] — the closed component schema with its stability and
//!   rarity priors (§2/§9), and the salted, compliance-preserving stored
//!   representations (§3).
//! - [`components`] — the typed [`Components`] payload every entry point takes.
//! - [`frequency`] — per-component `value hash → count`, the material for `u_i` (§9).
//! - [`agreement`] — per-component same-device agreement counts, the material
//!   for `m_i` (§9).
//! - [`blocking`] — the `key → set<visitor_id>` inverted index (§4).
//! - [`minhash`] — `MinHash`-`LSH` band keys for set components (§4 K3).
//! - [`record`] — the `visitor_id → template` fingerprint library (§3).
//! - [`velocity`] — per-IP distinct new-device counts behind the cross-session
//!   velocity band.
//! - [`engine`] — scoring, decision, drift, and confidence.
//!
//! [`FuzzyStore`] wires them together: [`FuzzyStore::identify`] scores and
//! persists an observation, [`FuzzyStore::score`] scores without mutating, [`FuzzyStore::observe`] folds
//! an observation into every index, and [`FuzzyStore::candidates`] performs
//! stage-one recall.
//!
//! A stateless host keeps only the salted [`StoredComponents`] wire form:
//! [`FuzzyStore::stored_form`] produces it, [`FuzzyStore::blocking_key_hexes_stored`]
//! derives its index keys, [`FuzzyStore::observe_stored`] loads recalled
//! templates into a transient store for [`FuzzyStore::score`], and
//! [`StoredComponents::merged`] drifts a template exactly as `observe` does.

pub mod agreement;
pub mod blocking;
mod canonical;
pub mod component;
pub mod components;
pub mod engine;
// The offline evaluation harness replays fixtures through a random-salt store; it
// is a native tuning tool, not edge compute, so the WASM build omits it.
#[cfg(feature = "rng")]
pub mod eval;
pub mod frequency;
pub mod minhash;
pub mod record;
pub mod velocity;

pub use component::{COMPONENT_KEYS, Component, Kind, Stability, Stored, StoredComponents};
pub use components::{ComponentValue, Components};
pub use engine::{
    Decision, IdentifyContext, MatchOutcome, TEMPLATE_JUMP_MAX_HIGH_CHANGES, is_template_jump,
};
pub use velocity::{VELOCITY_PENALTY, VelocityBand, velocity_penalty};

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use self::{
    agreement::AgreementTable,
    blocking::{BlockingIndex, BlockingKey, DEFAULT_MAX_BLOCK},
    canonical::{all_scalar_key, group_key},
    component::{Salt, set_digest},
    frequency::FrequencyTable,
    minhash::MinHashLsh,
    record::{FingerprintRecord, RecordStore, Tombstones},
    velocity::VelocityTable,
};

/// Capacity / TTL bounds for the in-memory fuzzy store.
///
/// The in-memory store grows with every distinct visitor and value; left
/// unbounded that is an availability risk. This policy caps that growth with
/// **fail-safe** defaults: the [`Default`] bounds are generous, so a small
/// workload never hits them. `None` on an optional field means "unbounded".
///
/// Every eviction/drop is counted (never silent), matching the blocking
/// `dropped()` precedent (fuzzy-matching §4). Applies to a stateful native
/// store built by [`FuzzyStore::new_with_policy`]; the stateless edge store
/// ([`FuzzyStore::deterministic`]) is per-request and needs no eviction, so it
/// stays unbounded.
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

/// The mutable matching state, guarded as one unit by [`FuzzyStore`]'s lock.
#[derive(Debug, Default)]
struct State {
    /// The `visitor_id → template` fingerprint library (§3).
    records: RecordStore,
    /// The `key → set<visitor_id>` blocking inverted index (§4).
    blocking: BlockingIndex,
    /// Per-value frequency material for `u_i` estimation (§9).
    frequency: FrequencyTable,
    /// Per-component same-device agreement material for `m_i` estimation (§9).
    agreement: AgreementTable,
    /// Per-IP distinct new-device ids behind the cross-session velocity signal.
    /// Only `identify` (behind the `rng` feature) reads it.
    #[cfg_attr(not(feature = "rng"), allow(dead_code))]
    velocity: VelocityTable,
    /// Erased visitor ids, never minted or written back again.
    tombstones: Tombstones,
    /// Bumped by every write, so an identify can tell whether the state it
    /// scored against changed before its write-back.
    generation: u64,
}

impl State {
    /// Mark the state as changed.
    fn bump(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    /// Drop `visitor`'s membership from every block it is indexed under.
    fn unindex(&mut self, visitor: &str, record: &FingerprintRecord) {
        for key in &record.keys {
            self.blocking.remove(key, visitor);
        }
    }
}

/// The in-memory matching store: record library, blocking index, and the
/// frequency / agreement / velocity material behind one observe/identify
/// surface.
///
/// All mutable state sits behind one [`RwLock`]: recall and scoring run under
/// a shared read guard (borrowing candidate templates in place), and every
/// write — observe, erase, purge, and the identify write-back — takes the
/// exclusive guard only for the write itself. The salt and `MinHash`-`LSH`
/// family are immutable key-derivation inputs and live outside the lock.
#[derive(Debug)]
pub struct FuzzyStore {
    /// Per-instance salt applied to every stored value.
    salt: Salt,
    /// `MinHash`-`LSH` band-key generator for set components (§4 K3).
    minhash: MinHashLsh,
    /// The mutable matching state.
    state: RwLock<State>,
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

    /// Build an empty store (random salt) that enforces the given capacity /
    /// TTL [`EvictionPolicy`].
    ///
    /// [`FuzzyStore::new`] delegates here with the default (generous) policy, so
    /// a fresh small workload is unaffected while growth is bounded. The
    /// stateless edge path ([`FuzzyStore::deterministic`]) is intentionally not
    /// routed through here: it is per-request and stays unbounded.
    #[cfg(feature = "rng")]
    pub fn new_with_policy(policy: EvictionPolicy) -> Self {
        Self {
            salt: Salt::random(),
            minhash: MinHashLsh::new(),
            state: RwLock::new(State {
                records: RecordStore::with_capacity(policy.max_records, policy.record_ttl_ms),
                blocking: BlockingIndex::with_max_block(policy.max_block),
                frequency: FrequencyTable::with_capacity(policy.max_frequency_values),
                agreement: AgreementTable::with_capacity(policy.max_agreement_components),
                velocity: VelocityTable::with_capacity(policy.max_velocity_keys),
                tombstones: Tombstones::default(),
                generation: 0,
            }),
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
            minhash: MinHashLsh::from_seed(secret),
            state: RwLock::new(State::default()),
        }
    }

    /// Shared access to the matching state, recovering from poisoning (every
    /// write leaves the state consistent before it can panic out).
    fn read(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Exclusive access to the matching state, recovering from poisoning.
    fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Fold a component observation for `visitor` into every index.
    ///
    /// Converts each present component to its stored form (updating the
    /// frequency table), upserts the visitor's template with `now_ms` (Unix
    /// milliseconds), enforces the record cap / TTL, and resyncs the visitor's
    /// blocking memberships to the keys of its merged template. Returns `true`
    /// when the visitor was newly recorded. An erased (tombstoned) visitor is
    /// never re-recorded: the call is a no-op returning `false`.
    pub fn observe(&self, visitor: &str, components: &Components, now_ms: u64) -> bool {
        let stored = self.stored_map(components);
        self.observe_locked(&mut self.write(), visitor, stored, now_ms)
    }

    /// [`FuzzyStore::observe`] for an observation already in its salted stored
    /// form — how a stateless host loads the candidate templates it persisted
    /// (and recalled) into a transient store before [`FuzzyStore::score`].
    /// `stored` must have been produced under this store's salt.
    pub fn observe_stored(&self, visitor: &str, stored: StoredComponents, now_ms: u64) -> bool {
        self.observe_locked(&mut self.write(), visitor, stored.into_map(), now_ms)
    }

    /// [`FuzzyStore::observe`] against an already-held write guard.
    fn observe_locked(
        &self,
        state: &mut State,
        visitor: &str,
        stored: BTreeMap<String, Stored>,
        now_ms: u64,
    ) -> bool {
        if state.tombstones.contains(visitor) {
            return false;
        }
        state.bump();
        // Every stored value feeds its component's frequency material for
        // `u_i` (§9); a set is counted as a whole via its digest. Frequency
        // counts DEVICES, not visits: a revisit only counts the components
        // whose value changed, or a device's own values would read as common
        // after a few revisits and it would stop matching itself.
        let previous = state.records.get(visitor);
        for (name, value) in &stored {
            if previous.is_some_and(|record| record.components.get(name) == Some(value)) {
                continue;
            }
            let hash = match value {
                Stored::Category(hash) => *hash,
                Stored::Numeric(n) => self.salt.hash(&n.to_string()),
                Stored::Set(set) => set_digest(set),
            };
            state.frequency.record(name, hash);
        }

        let is_new = state.records.upsert(visitor, stored, now_ms).1;
        // Evict before indexing so freed block slots are available to `visitor`.
        for (id, record) in state.records.evict(visitor, now_ms) {
            state.unindex(&id, &record);
        }

        let State {
            records, blocking, ..
        } = state;
        let Some(record) = records.get_mut(visitor) else {
            return is_new;
        };
        let derived: BTreeSet<BlockingKey> =
            self.blocking_keys(&record.components).into_iter().collect();
        for stale in record.keys.difference(&derived) {
            blocking.remove(stale, visitor);
        }
        // Keys already held stay; new ones are kept only if the block admits them.
        let keys = derived
            .into_iter()
            .filter(|key| record.keys.contains(key) || blocking.insert(*key, visitor))
            .collect();
        record.keys = keys;
        is_new
    }

    /// Erase `visitor` entirely from the fingerprint library (GDPR right-to-be-
    /// forgotten): drop its record and its membership in every block it is
    /// indexed under, in one exclusive critical section, and tombstone the id so
    /// it is never minted or recorded again (see [`record::TOMBSTONE_CAP`]).
    /// Returns `true` when a record existed.
    ///
    /// The aggregate [`frequency`] table is intentionally left untouched: it is a
    /// value-frequency aggregate with no per-visitor linkage, so it carries no
    /// personal data to erase and removing a visitor's contribution would corrupt
    /// the shared `u_i` estimates for unrelated visitors.
    pub fn erase(&self, visitor: &str) -> bool {
        let mut state = self.write();
        let Some(record) = state.records.remove(visitor) else {
            return false;
        };
        state.unindex(visitor, &record);
        state.tombstones.insert(visitor);
        state.bump();
        true
    }

    /// Proactively purge every record older than `max_age_ms` (by `last_seen`)
    /// relative to `now_ms`, with its blocking memberships, returning the number
    /// removed (compliance retention). Additive to the lazy TTL sweep in
    /// [`FuzzyStore::observe`] — it ages records out even without observe
    /// traffic. Pops only expired entries from the front of the `last_seen`
    /// order.
    pub fn purge_expired(&self, now_ms: u64, max_age_ms: u64) -> u64 {
        let mut state = self.write();
        let purged = state.records.purge_older_than(now_ms, max_age_ms);
        for (id, record) in &purged {
            state.unindex(id, record);
        }
        if !purged.is_empty() {
            state.bump();
        }
        purged.len() as u64
    }

    /// Records evicted so far by the record cap, the TTL, or a retention purge.
    pub fn evicted(&self) -> u64 {
        self.read().records.evicted()
    }

    /// Blocking insertions dropped so far at a full block (fuzzy-matching §4).
    pub fn dropped(&self) -> u64 {
        self.read().blocking.dropped()
    }

    /// Total `(key, visitor)` memberships in the blocking index. Never exceeds
    /// the sum of the live records' key counts.
    pub fn blocking_rows(&self) -> usize {
        self.read().blocking.rows()
    }

    /// Stage-one candidate recall: the union of visitors sharing any blocking
    /// key with `components` (fuzzy-matching §4).
    pub fn candidates(&self, components: &Components) -> HashSet<String> {
        let keys = self.blocking_keys(&self.stored_map(components));
        self.read()
            .blocking
            .candidates(&keys)
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    /// The blocking keys for `components`, hex-encoded (fuzzy-matching §4).
    ///
    /// The hex form of each [`blocking::BlockingKey`] a stateless host queries
    /// its externalized candidate index with. Key derivation depends on the salt
    /// and the `MinHash` permutation family, so a [`FuzzyStore::deterministic`]
    /// store yields keys that are stable across isolate instances.
    pub fn blocking_key_hexes(&self, components: &Components) -> Vec<String> {
        self.blocking_key_hexes_stored(&self.stored_form(components))
    }

    /// The blocking keys of an already-stored fingerprint (e.g. a persisted
    /// template), hex-encoded — identical to [`FuzzyStore::blocking_key_hexes`]
    /// over the components it was stored from.
    pub fn blocking_key_hexes_stored(&self, stored: &StoredComponents) -> Vec<String> {
        self.blocking_keys(stored.as_map())
            .iter()
            .map(hex::encode)
            .collect()
    }

    /// The salted stored form of `components` (fuzzy-matching §3): what the
    /// record library keeps for them, and the only form a stateless host may
    /// persist. Absent components are omitted (fuzzy-matching §8).
    pub fn stored_form(&self, components: &Components) -> StoredComponents {
        self.stored_map(components).into()
    }

    /// Convert the present components into their stored form, in schema order
    /// (fuzzy-matching §8: an absent component is simply not compared).
    fn stored_entries(&self, components: &Components) -> Vec<(Component, Stored)> {
        components
            .entries()
            .map(|(component, value)| (component, self.to_stored(value)))
            .collect()
    }

    /// The stored-form map keyed by component name, the shape the record
    /// library and the blocking keys use. Shared by [`observe`], [`candidates`],
    /// and the stage-two scorer.
    ///
    /// [`observe`]: FuzzyStore::observe
    /// [`candidates`]: FuzzyStore::candidates
    fn stored_map(&self, components: &Components) -> BTreeMap<String, Stored> {
        self.stored_entries(components)
            .into_iter()
            .map(|(component, stored)| (component.name().to_owned(), stored))
            .collect()
    }

    /// Snapshot of a visitor's stored template.
    pub fn record(&self, visitor: &str) -> Option<FingerprintRecord> {
        self.read().records.get(visitor).cloned()
    }

    /// Convert one present component value to its salted stored form (§3).
    fn to_stored(&self, value: ComponentValue<'_>) -> Stored {
        match value {
            ComponentValue::Category(s) => Stored::Category(self.salt.hash(s)),
            ComponentValue::Numeric(n) => Stored::Numeric(n),
            ComponentValue::Set(items) => Stored::Set(self.salt.hash_set(items)),
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
    use super::{Components, EvictionPolicy, FuzzyStore};
    use serde_json::json;

    fn components(value: serde_json::Value) -> Components {
        serde_json::from_value(value).unwrap()
    }

    /// A full high-stability probe that populates both K1 and K2 keys.
    fn full_probe() -> Components {
        components(json!({
            "webgl": "ANGLE (Intel)",
            "platform": "Linux x86_64",
            "timezone": "Asia/Shanghai",
            "audio": "124.04",
            "cpu_cores": 8,
            "device_memory": 8,
            "fonts": ["Arial", "Helvetica", "Courier", "Times", "Verdana"],
            "canvas": "c0ffee",
        }))
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
    fn recall_survives_a_changed_canvas_and_one_font() {
        let store = FuzzyStore::new();
        store.observe("v1", &full_probe(), 1_000);

        // Canvas re-noised and one font added: the high-stable K1/K2 keys are
        // unchanged and MinHash still shares bands -> recalled.
        let mut drifted = full_probe();
        drifted.canvas = Some("beef".into());
        drifted.fonts = Some(
            ["Arial", "Helvetica", "Courier", "Times", "Segoe"]
                .map(String::from)
                .to_vec(),
        );
        assert!(store.candidates(&drifted).contains("v1"));
    }

    #[test]
    fn unrelated_probe_is_not_recalled() {
        let store = FuzzyStore::new();
        store.observe("v1", &full_probe(), 1_000);

        let other = components(json!({
            "webgl": "Apple GPU",
            "platform": "iPhone",
            "timezone": "America/New_York",
            "audio": "35.7",
            "cpu_cores": 6,
            "device_memory": 4,
            "fonts": ["SF Pro", "Menlo", "Georgia", "Palatino"],
            "canvas": "f00d",
        }));
        assert!(!store.candidates(&other).contains("v1"));
    }

    #[test]
    fn frequency_tracks_category_values() {
        let store = FuzzyStore::new();
        store.observe("v1", &full_probe(), 1_000);
        store.observe("v2", &full_probe(), 2_000);

        // "Linux x86_64" seen twice for the platform component.
        let hash = store.salt.hash("Linux x86_64");
        let state = store.read();
        assert_eq!(state.frequency.count("platform", hash), 2);
        assert_eq!(state.frequency.total("platform"), 2);
    }

    #[test]
    fn missing_components_are_skipped_not_stored() {
        let store = FuzzyStore::new();
        // canvas null (privacy browser) must not be stored as a matchable value.
        store.observe(
            "v1",
            &components(json!({ "webgl": "x", "canvas": null })),
            1_000,
        );
        let record = store.record("v1").unwrap();
        assert!(record.components.contains_key("webgl"));
        assert!(!record.components.contains_key("canvas"));
    }

    #[test]
    fn stored_form_omits_absent_components_and_raw_values() {
        let store = FuzzyStore::deterministic(b"s");
        let stored = store.stored_form(&components(json!({
            "webgl": "ANGLE (Intel)",
            "cpu_cores": 8,
            "fonts": ["Arial"],
            "canvas": null,
        })));
        let names: Vec<&String> = stored.as_map().keys().collect();
        assert_eq!(names, ["cpu_cores", "fonts", "webgl"]);
        let wire = serde_json::to_string(&stored).unwrap();
        assert!(
            !wire.contains("ANGLE (Intel)") && !wire.contains("Arial"),
            "{wire}"
        );
        assert_eq!(stored.as_map()["cpu_cores"], super::Stored::Numeric(8));
    }

    /// The stored wire form round-trips and has the documented shape.
    #[test]
    fn stored_form_wire_round_trips() {
        let store = FuzzyStore::deterministic(b"s");
        let stored = store.stored_form(&full_probe());
        let wire = serde_json::to_value(&stored).unwrap();
        let webgl = wire["webgl"]["category"].as_str().unwrap();
        assert_eq!(webgl.len(), 64);
        assert!(
            webgl
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_eq!(wire["cpu_cores"], json!({ "numeric": 8 }));
        assert_eq!(wire["fonts"]["set"].as_array().unwrap().len(), 5);
        let back: super::StoredComponents = serde_json::from_value(wire).unwrap();
        assert_eq!(back, stored);
    }

    /// The stored wire form is closed: unknown names, wrong kinds, malformed
    /// hashes, and unknown tags are rejected.
    #[test]
    fn stored_form_wire_rejects_malformed_input() {
        let hash = "ab".repeat(32);
        for bad in [
            json!({ "user_agent": { "category": hash } }),
            json!({ "webgl": { "numeric": 1 } }),
            json!({ "fonts": { "category": hash } }),
            json!({ "webgl": { "category": "abc" } }),
            json!({ "webgl": { "category": "zz".repeat(32) } }),
            json!({ "webgl": { "raw": "ANGLE" } }),
            json!({ "webgl": { "category": hash, "numeric": 1 } }),
            json!({ "cpu_cores": { "numeric": 8.5 } }),
            json!({ "webgl": "ANGLE" }),
        ] {
            assert!(
                serde_json::from_value::<super::StoredComponents>(bad.clone()).is_err(),
                "{bad}"
            );
        }
    }

    /// Keys from a stored form equal keys from the components it came from.
    #[test]
    fn blocking_keys_from_stored_form_match_components() {
        let store = FuzzyStore::deterministic(b"s");
        let probe = full_probe();
        assert_eq!(
            store.blocking_key_hexes_stored(&store.stored_form(&probe)),
            store.blocking_key_hexes(&probe)
        );
    }

    /// Loading a stored form, then observing a partial drift, yields the same
    /// template as `merged` and as observing the raw components.
    #[test]
    fn stored_observe_and_merge_mirror_native_observe() {
        let native = FuzzyStore::deterministic(b"s");
        let edge = FuzzyStore::deterministic(b"s");
        let drift = components(json!({ "canvas": "beef", "fonts": ["Arial"] }));

        native.observe("v", &full_probe(), 1);
        native.observe("v", &drift, 2);

        let template = edge.stored_form(&full_probe());
        let observation = edge.stored_form(&drift);
        assert!(edge.observe_stored("v", template.clone(), 1));
        assert!(!edge.observe_stored("v", observation.clone(), 2));

        let expected = native.record("v").unwrap().components;
        assert_eq!(edge.record("v").unwrap().components, expected);
        assert_eq!(template.merged(&observation).into_map(), expected);
        assert_eq!(
            native.record("v").unwrap().keys,
            edge.record("v").unwrap().keys
        );
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
        let outcome = store.identify(&super::IdentifyContext {
            components: &probe,
            now_ms: 2_000,
            client_ip: None,
        });
        assert!(outcome.is_new_device);
        // The erased id is tombstoned: it is never recorded again.
        assert!(!store.observe("v1", &probe, 3_000));
        assert!(store.record("v1").is_none());
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
    fn empty_probe_records_visitor_with_no_components() {
        let store = FuzzyStore::new();
        assert!(store.observe("v1", &Components::default(), 1_000));
        assert!(store.record("v1").unwrap().components.is_empty());
    }

    /// Cap eviction, TTL eviction, retention purge, and erase each leave the
    /// removed visitor in no block at all, and every live record's key list is
    /// exactly its memberships.
    #[test]
    fn removed_visitors_are_absent_from_every_block() {
        let store = FuzzyStore::new_with_policy(EvictionPolicy {
            max_records: Some(3),
            record_ttl_ms: Some(1_000),
            ..EvictionPolicy::default()
        });
        let mut other = full_probe();
        other.webgl = Some("Other GPU".into());
        store.observe("capped", &full_probe(), 1);
        store.observe("ttl", &other, 2);
        store.observe("erased", &full_probe(), 700);
        store.observe("purged", &other, 900);
        // `capped` is the oldest of four under a cap of three.
        assert!(store.record("capped").is_none());
        // At t=1_600 `ttl` (age 1_598) expires; `erased`/`purged` survive.
        store.observe("live", &full_probe(), 1_600);
        assert!(store.record("ttl").is_none());
        assert!(store.erase("erased"));
        assert_eq!(store.purge_expired(1_600, 600), 1);

        let state = store.read();
        for gone in ["capped", "ttl", "erased", "purged"] {
            assert!(!state.blocking.indexes(gone), "{gone} still indexed");
        }
        let live = state.records.get("live").unwrap();
        assert_eq!(state.blocking.rows(), live.keys.len());
        assert_eq!(live.keys.len(), store.blocking_keys(&live.components).len());
    }

    /// Keys follow the merged template: a later partial observation keeps the
    /// template's other components, so its keys still include them.
    #[test]
    fn keys_track_the_merged_template() {
        let store = FuzzyStore::new();
        store.observe("v", &full_probe(), 1_000);
        let full_keys = store.record("v").unwrap().keys;
        store.observe("v", &components(json!({ "canvas": "beef" })), 2_000);
        let record = store.record("v").unwrap();
        assert_eq!(
            record.keys,
            store
                .blocking_keys(&record.components)
                .into_iter()
                .collect()
        );
        // K1/K2/font bands are unchanged; only the catch-all K0 moved.
        assert_eq!(
            record.keys.intersection(&full_keys).count(),
            full_keys.len() - 1
        );
        assert_eq!(store.blocking_rows(), record.keys.len());
    }
}
