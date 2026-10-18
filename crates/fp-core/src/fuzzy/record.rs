//! The fingerprint library: `visitor_id → template` records (fuzzy-matching §3/§11).
//!
//! Each visitor keeps the most recent stored value per component (the template
//! that drift refreshes, fuzzy-matching §7), an immutable snapshot of the values
//! it was first recorded with, a per-component freshness timestamp, `first_seen` / `last_seen`, and an `observation_count`. Timestamps
//! are supplied by the caller (Unix milliseconds) so the store stays clock-free
//! and deterministic under test.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use super::{blocking::BlockingKey, component::Stored};

/// A stored fingerprint template for one visitor (fuzzy-matching §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintRecord {
    /// Most recent stored value per component name.
    pub components: BTreeMap<String, Stored>,
    /// The stored values of the observation that created this record. Never
    /// overwritten by drift, so the template's origin stays auditable however
    /// far later observations walk it.
    pub first_observation: BTreeMap<String, Stored>,
    /// Last-updated timestamp (Unix ms) per component — freshness for drift (§7).
    pub freshness: BTreeMap<String, u64>,
    /// When the visitor was first recorded (Unix ms).
    pub first_seen: u64,
    /// When the visitor was most recently observed (Unix ms).
    pub last_seen: u64,
    /// Number of observations folded into this record.
    pub observation_count: u64,
    /// The blocking keys this visitor is currently indexed under (§4): the keys
    /// derived from `components`, minus any dropped at a full block. Removing
    /// the visitor removes exactly these memberships.
    pub keys: BTreeSet<BlockingKey>,
}

/// In-memory `visitor_id → record` fingerprint library (fuzzy-matching §11).
///
/// Bounded, fail-safe growth: an optional record cap evicts the least-recently
/// seen (smallest `last_seen`) visitor once exceeded, and an optional TTL drops
/// entries not seen within the window on the next `observe`. A `last_seen`
/// ordered index makes both O(log n) per removed record — eviction pops from
/// the front instead of scanning the library. Every eviction is counted via
/// [`RecordStore::evicted`], never silent (matching the blocking `dropped()`
/// precedent, fuzzy-matching §4).
#[derive(Debug, Default)]
pub struct RecordStore {
    /// `visitor_id → template`.
    records: HashMap<String, FingerprintRecord>,
    /// `(last_seen, visitor_id)` for every record, oldest first.
    by_last_seen: BTreeSet<(u64, String)>,
    /// Retain at most this many visitors; `None` is unbounded.
    max_records: Option<usize>,
    /// Drop entries whose `now_ms - last_seen` exceeds this on observe; `None`
    /// is unbounded.
    record_ttl_ms: Option<u64>,
    /// Count of records evicted by cap, TTL, or retention purge.
    evicted: u64,
}

impl RecordStore {
    /// Create an empty, unbounded store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty store bounded by an optional record cap and TTL.
    ///
    /// `max_records` caps the number of retained visitors (evicting the oldest
    /// `last_seen` when exceeded); `record_ttl_ms` drops entries not seen within
    /// the window on the next `observe`. `None` for either means unbounded.
    pub fn with_capacity(max_records: Option<usize>, record_ttl_ms: Option<u64>) -> Self {
        Self {
            max_records,
            record_ttl_ms,
            ..Self::default()
        }
    }

    /// Fold an observation into `visitor`'s record, creating it if new, and
    /// return the record with whether it was newly created.
    ///
    /// A new record snapshots `components` as its `first_observation`. The
    /// supplied `components` overwrite the visitor's recent values and bump
    /// their freshness to `now_ms`; `last_seen` and `observation_count` advance.
    /// Components not present in this observation retain their prior value and
    /// freshness. The record's `keys` are left for the caller to resync against
    /// the merged template.
    pub fn upsert(
        &mut self,
        visitor: &str,
        components: BTreeMap<String, Stored>,
        now_ms: u64,
    ) -> (&mut FingerprintRecord, bool) {
        let is_new = !self.records.contains_key(visitor);
        let record = self
            .records
            .entry(visitor.to_owned())
            .or_insert_with(|| FingerprintRecord {
                components: BTreeMap::new(),
                first_observation: components.clone(),
                freshness: BTreeMap::new(),
                first_seen: now_ms,
                last_seen: now_ms,
                observation_count: 0,
                keys: BTreeSet::new(),
            });
        if !is_new {
            self.by_last_seen
                .remove(&(record.last_seen, visitor.to_owned()));
        }
        self.by_last_seen.insert((now_ms, visitor.to_owned()));
        for (name, value) in components {
            record.freshness.insert(name.clone(), now_ms);
            record.components.insert(name, value);
        }
        record.last_seen = now_ms;
        record.observation_count += 1;
        (record, is_new)
    }

    /// Enforce the TTL then the record cap, returning the evicted records (with
    /// their ids) so the caller can drop their index memberships.
    ///
    /// `visitor` — the one just observed — is never evicted. TTL pops expired
    /// entries from the front of the `last_seen` order; the cap then pops the
    /// oldest entries until within `max_records`.
    pub fn evict(&mut self, visitor: &str, now_ms: u64) -> Vec<(String, FingerprintRecord)> {
        let mut out = Vec::new();
        if let Some(ttl) = self.record_ttl_ms {
            out.extend(self.pop_older_than(now_ms, ttl, Some(visitor)));
        }
        if let Some(cap) = self.max_records {
            while self.records.len() > cap {
                let Some(oldest) = self
                    .by_last_seen
                    .iter()
                    .find(|(_, id)| id.as_str() != visitor)
                    .map(|(_, id)| id.clone())
                else {
                    break;
                };
                if let Some(record) = self.remove(&oldest) {
                    out.push((oldest, record));
                }
            }
        }
        self.evicted += out.len() as u64;
        out
    }

    /// Remove every record whose `last_seen` is older than `max_age_ms` relative
    /// to `now_ms`, returning them and counting them as evictions (compliance
    /// retention). Runs without observe traffic, so a record ages out on
    /// schedule even when the visitor never returns.
    pub fn purge_older_than(
        &mut self,
        now_ms: u64,
        max_age_ms: u64,
    ) -> Vec<(String, FingerprintRecord)> {
        let out = self.pop_older_than(now_ms, max_age_ms, None);
        self.evicted += out.len() as u64;
        out
    }

    /// Pop records with `now_ms - last_seen > max_age_ms` from the front of the
    /// `last_seen` order, skipping `keep`.
    fn pop_older_than(
        &mut self,
        now_ms: u64,
        max_age_ms: u64,
        keep: Option<&str>,
    ) -> Vec<(String, FingerprintRecord)> {
        let mut out = Vec::new();
        let mut kept = None;
        while let Some((last_seen, id)) = self.by_last_seen.pop_first() {
            if now_ms.saturating_sub(last_seen) <= max_age_ms {
                self.by_last_seen.insert((last_seen, id));
                break;
            }
            if keep == Some(id.as_str()) {
                kept = Some((last_seen, id));
                continue;
            }
            if let Some(record) = self.records.remove(&id) {
                out.push((id, record));
            }
        }
        if let Some(entry) = kept {
            self.by_last_seen.insert(entry);
        }
        out
    }

    /// Total records evicted by cap, TTL, or retention purge so far.
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Remove `visitor`'s record entirely (GDPR right-to-be-forgotten),
    /// returning it when it existed. Idempotent.
    pub fn remove(&mut self, visitor: &str) -> Option<FingerprintRecord> {
        let record = self.records.remove(visitor)?;
        self.by_last_seen
            .remove(&(record.last_seen, visitor.to_owned()));
        Some(record)
    }

    /// `visitor`'s record, if present.
    pub fn get(&self, visitor: &str) -> Option<&FingerprintRecord> {
        self.records.get(visitor)
    }

    /// Mutable access for resyncing `visitor`'s `keys`; callers must not
    /// change `last_seen`, which the eviction order indexes.
    pub(super) fn get_mut(&mut self, visitor: &str) -> Option<&mut FingerprintRecord> {
        self.records.get_mut(visitor)
    }

    /// Number of distinct visitors recorded.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the library holds no visitors.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Most erased visitor ids remembered by [`Tombstones`]. Past it the oldest
/// tombstone is forgotten (and counted); a forgotten id can then only recur by
/// a fresh 128-bit random draw colliding with it.
pub const TOMBSTONE_CAP: usize = 100_000;

/// Bounded FIFO set of erased visitor ids.
///
/// Minting never hands out a remembered id and no write-back targets one, so an
/// erased id cannot be resurrected while its tombstone is held. Holds at most
/// [`TOMBSTONE_CAP`] ids; each forgotten one is counted in
/// [`Tombstones::evicted`].
#[derive(Debug, Default)]
pub struct Tombstones {
    ids: HashSet<String>,
    order: VecDeque<String>,
    evicted: u64,
}

impl Tombstones {
    /// Remember `visitor` as erased, forgetting the oldest tombstone past the cap.
    pub fn insert(&mut self, visitor: &str) {
        if !self.ids.insert(visitor.to_owned()) {
            return;
        }
        self.order.push_back(visitor.to_owned());
        while self.order.len() > TOMBSTONE_CAP {
            if let Some(oldest) = self.order.pop_front() {
                self.ids.remove(&oldest);
                self.evicted += 1;
            }
        }
    }

    /// Whether `visitor` was erased and is still remembered.
    pub fn contains(&self, visitor: &str) -> bool {
        self.ids.contains(visitor)
    }

    /// Number of remembered tombstones.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether no tombstone is held.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Tombstones forgotten at the cap so far.
    pub fn evicted(&self) -> u64 {
        self.evicted
    }
}

#[cfg(test)]
mod tests {
    use super::{RecordStore, TOMBSTONE_CAP, Tombstones};
    use crate::fuzzy::component::{Salt, Stored};
    use std::collections::BTreeMap;

    fn category(salt: &Salt, name: &str, value: &str) -> BTreeMap<String, Stored> {
        let mut map = BTreeMap::new();
        map.insert(name.to_string(), Stored::Category(salt.hash(value)));
        map
    }

    /// Upsert then enforce the bounds, as the store does on every observe.
    fn observe(store: &mut RecordStore, visitor: &str, map: BTreeMap<String, Stored>, now: u64) {
        store.upsert(visitor, map, now);
        store.evict(visitor, now);
    }

    #[test]
    fn first_observation_creates_record() {
        let salt = Salt::random();
        let mut store = RecordStore::new();
        let (_, is_new) = store.upsert("v1", category(&salt, "canvas", "Chrome/120"), 1_000);
        assert!(is_new);

        let record = store.get("v1").unwrap();
        assert_eq!(record.first_seen, 1_000);
        assert_eq!(record.last_seen, 1_000);
        assert_eq!(record.observation_count, 1);
        assert_eq!(record.freshness.get("canvas"), Some(&1_000));
    }

    #[test]
    fn revisit_updates_recent_value_and_advances_counters() {
        let salt = Salt::random();
        let mut store = RecordStore::new();
        store.upsert("v1", category(&salt, "canvas", "Chrome/120"), 1_000);
        let (_, is_new) = store.upsert("v1", category(&salt, "canvas", "Chrome/121"), 2_000);
        assert!(!is_new);

        let record = store.get("v1").unwrap();
        assert_eq!(record.first_seen, 1_000); // unchanged
        assert_eq!(record.last_seen, 2_000); // advanced
        assert_eq!(record.observation_count, 2);
        assert_eq!(
            record.components.get("canvas"),
            Some(&Stored::Category(salt.hash("Chrome/121")))
        );
        assert_eq!(record.freshness.get("canvas"), Some(&2_000));
        // The creating observation's snapshot is not drifted.
        assert_eq!(
            record.first_observation.get("canvas"),
            Some(&Stored::Category(salt.hash("Chrome/120")))
        );
    }

    #[test]
    fn absent_components_retain_prior_freshness() {
        let salt = Salt::random();
        let mut store = RecordStore::new();
        let mut both = category(&salt, "canvas", "Chrome/120");
        both.insert("tz".to_string(), Stored::Category(salt.hash("UTC")));
        store.upsert("v1", both, 1_000);

        // Second observation carries only `canvas`; `tz` keeps its old freshness.
        store.upsert("v1", category(&salt, "canvas", "Chrome/121"), 2_000);
        let record = store.get("v1").unwrap();
        assert_eq!(record.freshness.get("canvas"), Some(&2_000));
        assert_eq!(record.freshness.get("tz"), Some(&1_000));
    }

    #[test]
    fn cap_evicts_oldest_and_counts() {
        let salt = Salt::random();
        // Cap of 3; observe 5 distinct visitors with strictly increasing
        // `last_seen`, so v1/v2 (oldest) are evicted and v3/v4/v5 survive.
        let mut store = RecordStore::with_capacity(Some(3), None);
        for i in 1..=5u64 {
            observe(
                &mut store,
                &format!("v{i}"),
                category(&salt, "canvas", "x"),
                i * 1_000,
            );
        }
        assert_eq!(store.len(), 3);
        assert_eq!(store.evicted(), 2);
        assert!(store.get("v1").is_none());
        assert!(store.get("v2").is_none());
        assert!(store.get("v3").is_some());
        assert!(store.get("v4").is_some());
        assert!(store.get("v5").is_some());
    }

    #[test]
    fn cap_eviction_follows_last_seen_not_insertion_order() {
        let salt = Salt::random();
        let mut store = RecordStore::with_capacity(Some(2), None);
        observe(&mut store, "a", category(&salt, "canvas", "x"), 1_000);
        observe(&mut store, "b", category(&salt, "canvas", "x"), 2_000);
        // `a` revisits, so `b` is now the oldest and is the one evicted.
        observe(&mut store, "a", category(&salt, "canvas", "x"), 3_000);
        observe(&mut store, "c", category(&salt, "canvas", "x"), 4_000);
        assert!(store.get("a").is_some());
        assert!(store.get("b").is_none());
        assert!(store.get("c").is_some());
    }

    #[test]
    fn cap_never_evicts_the_just_observed_visitor() {
        let salt = Salt::random();
        let mut store = RecordStore::with_capacity(Some(1), None);
        observe(&mut store, "a", category(&salt, "canvas", "x"), 5_000);
        // `b` arrives with an older timestamp than `a`, yet `a` is evicted.
        store.upsert("b", category(&salt, "canvas", "x"), 1_000);
        let evicted = store.evict("b", 1_000);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].0, "a");
        assert!(store.get("b").is_some());
    }

    #[test]
    fn ttl_drops_stale_entry_on_later_observe() {
        let salt = Salt::random();
        // TTL of 1_000 ms, no cap. v1 seen at t=1_000; a later observe at
        // t=3_000 (age 2_000 > 1_000) evicts it while recording v2.
        let mut store = RecordStore::with_capacity(None, Some(1_000));
        observe(&mut store, "v1", category(&salt, "canvas", "x"), 1_000);
        assert_eq!(store.len(), 1);
        observe(&mut store, "v2", category(&salt, "canvas", "y"), 3_000);
        assert!(store.get("v1").is_none());
        assert!(store.get("v2").is_some());
        assert_eq!(store.evicted(), 1);
    }

    #[test]
    fn remove_erases_record_and_reports_prior_existence() {
        let salt = Salt::random();
        let mut store = RecordStore::new();
        store.upsert("v1", category(&salt, "canvas", "x"), 1_000);

        assert!(store.remove("v1").is_some());
        assert!(store.get("v1").is_none());
        // Erasing an absent visitor is an idempotent no-op.
        assert!(store.remove("v1").is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn purge_older_than_drops_only_aged_records_and_counts() {
        let salt = Salt::random();
        let mut store = RecordStore::new();
        store.upsert("old", category(&salt, "canvas", "x"), 1_000);
        store.upsert("fresh", category(&salt, "canvas", "y"), 9_000);

        // At t=10_000 with a 5_000 ms retention: `old` (age 9_000) is purged,
        // `fresh` (age 1_000) is retained. The purge counts as an eviction.
        let purged = store.purge_older_than(10_000, 5_000);
        assert_eq!(purged.len(), 1);
        assert_eq!(purged[0].0, "old");
        assert!(store.get("old").is_none());
        assert!(store.get("fresh").is_some());
        assert_eq!(store.evicted(), 1);

        assert_eq!(store.purge_older_than(10_000, 5_000), Vec::new());
    }

    #[test]
    fn distinct_visitors_are_separate() {
        let salt = Salt::random();
        let mut store = RecordStore::new();
        store.upsert("v1", category(&salt, "canvas", "x"), 1);
        store.upsert("v2", category(&salt, "canvas", "y"), 1);
        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());
    }

    #[test]
    fn tombstones_are_fifo_bounded_and_count_evictions() {
        let mut tombstones = Tombstones::default();
        for i in 0..TOMBSTONE_CAP + 2 {
            tombstones.insert(&format!("v{i}"));
        }
        tombstones.insert("v5"); // already held: no duplicate
        assert_eq!(tombstones.len(), TOMBSTONE_CAP);
        assert_eq!(tombstones.evicted(), 2);
        assert!(!tombstones.contains("v0"));
        assert!(!tombstones.contains("v1"));
        assert!(tombstones.contains("v2"));
        assert!(tombstones.contains(&format!("v{}", TOMBSTONE_CAP + 1)));
    }
}
