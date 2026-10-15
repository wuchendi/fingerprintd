//! Per-component value frequency counts — the material for estimating `u_i`
//! (fuzzy-matching §9/§11).
//!
//! `u_i = P(agree | different device)` is the rarity of a value: common values
//! (Chrome-on-Windows) carry little evidence when they agree, rare values carry
//! a lot. The estimate is the value's observed frequency among the sightings of
//! THAT component — counts are keyed by `(component, value)` and each component
//! has its own denominator, so a value shared by every device reads as common
//! rather than diluted by the number of components.

use std::{
    collections::HashMap,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use super::component::Hash32;

/// Storage contract for the per-component frequency material behind `u_i` estimation
/// (fuzzy-matching §9/§11).
///
/// The in-memory [`FrequencyTable`] is the single-instance implementation. An
/// externalized backend (a shared counter store, a later step) lives behind the
/// same contract, so the engine records sightings and reads counts without
/// knowing where the frequency material is kept. Only the raw counting surface
/// is exposed here; the smoothed `u_i` estimate lives in the scorer.
pub trait FrequencyStore: Send + Sync {
    /// Record one sighting of `value` for `component`.
    fn record(&self, component: &str, value: Hash32);

    /// Sightings recorded for `value` under `component`.
    fn count(&self, component: &str, value: Hash32) -> u64;

    /// Sightings recorded for `component` (its frequency denominator).
    fn total(&self, component: &str) -> u64;
}

/// `(component, value hash) → count`, with a running total per component, for
/// `u_i` estimation (fuzzy-matching §9).
///
/// Updated incrementally as fingerprints are observed. The counter maps a
/// component's salted value hash to its number of sightings; the component's
/// total is the denominator of the frequency estimate.
///
/// Growth is bounded, fail-safe: an optional cap on the number of *distinct*
/// tracked values drops a never-before-seen value once the cap is reached
/// (already-tracked values keep counting), so the table cannot grow without
/// limit. The default cap is generous, so a small workload is unaffected; every
/// drop is counted via [`FrequencyTable::dropped`], never silent.
#[derive(Debug, Default)]
pub struct FrequencyTable {
    counts: Mutex<Counts>,
    /// Cap on distinct tracked values; `None` is unbounded.
    max_values: Option<usize>,
    /// Count of new values dropped at the distinct-value cap (not silent).
    dropped: AtomicU64,
}

/// Inner counter state guarded by the table's mutex.
#[derive(Debug, Default)]
struct Counts {
    /// Sightings per `(component, salted value hash)`.
    per_value: HashMap<(String, Hash32), u64>,
    /// Sightings per component.
    totals: HashMap<String, u64>,
}

impl FrequencyTable {
    /// Create an empty, unbounded table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty table bounded by a cap on distinct tracked values.
    ///
    /// `max_frequency_values` caps how many *distinct* `(component, value)`
    /// pairs the table tracks; a new pair beyond the cap is dropped and counted.
    /// `None` is unbounded.
    pub fn with_capacity(max_frequency_values: Option<usize>) -> Self {
        Self {
            counts: Mutex::new(Counts::default()),
            max_values: max_frequency_values,
            dropped: AtomicU64::new(0),
        }
    }

    /// Record one sighting of `value` for `component`.
    ///
    /// An already-tracked pair always increments. A never-before-seen pair is
    /// tracked unless the distinct-value cap is reached, in which case it is
    /// dropped (not inserted, not counted toward the component total) and
    /// tallied in [`FrequencyTable::dropped`].
    pub fn record(&self, component: &str, value: Hash32) {
        let mut counts = self.lock();
        let key = (component.to_owned(), value);
        if let Some(existing) = counts.per_value.get_mut(&key) {
            *existing += 1;
        } else if let Some(cap) = self.max_values
            && counts.per_value.len() >= cap
        {
            drop(counts);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        } else {
            counts.per_value.insert(key, 1);
        }
        *counts.totals.entry(component.to_owned()).or_insert(0) += 1;
    }

    /// Total new values dropped at the distinct-value cap so far.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Sightings recorded for `value` under `component`.
    pub fn count(&self, component: &str, value: Hash32) -> u64 {
        self.lock()
            .per_value
            .get(&(component.to_owned(), value))
            .copied()
            .unwrap_or(0)
    }

    /// Sightings recorded for `component` (its frequency denominator).
    pub fn total(&self, component: &str) -> u64 {
        self.lock().totals.get(component).copied().unwrap_or(0)
    }

    /// Lock the counter, recovering the guard if a prior holder panicked.
    fn lock(&self) -> std::sync::MutexGuard<'_, Counts> {
        self.counts.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl FrequencyStore for FrequencyTable {
    fn record(&self, component: &str, value: Hash32) {
        FrequencyTable::record(self, component, value);
    }

    fn count(&self, component: &str, value: Hash32) -> u64 {
        FrequencyTable::count(self, component, value)
    }

    fn total(&self, component: &str) -> u64 {
        FrequencyTable::total(self, component)
    }
}

#[cfg(test)]
mod tests {
    use super::FrequencyTable;
    use crate::fuzzy::component::Salt;

    #[test]
    fn counts_and_totals_track_sightings_per_component() {
        let salt = Salt::random();
        let table = FrequencyTable::new();
        let common = salt.hash("Chrome/Windows");
        let rare = salt.hash("Lynx/Plan9");

        table.record("ua", common);
        table.record("ua", common);
        table.record("ua", common);
        table.record("ua", rare);

        assert_eq!(table.count("ua", common), 3);
        assert_eq!(table.count("ua", rare), 1);
        assert_eq!(table.total("ua"), 4);
        assert_eq!(table.total("other"), 0);
    }

    #[test]
    fn the_same_value_in_two_components_is_counted_separately() {
        // `true` is the value of many boolean components; each must keep its
        // own count and denominator so a universal value reads as universal.
        let salt = Salt::random();
        let table = FrequencyTable::new();
        let yes = salt.hash("true");
        for _ in 0..4 {
            table.record("sessionStorage", yes);
            table.record("localStorage", yes);
        }

        assert_eq!(table.count("sessionStorage", yes), 4);
        assert_eq!(table.total("sessionStorage"), 4);
        assert_eq!(table.total("localStorage"), 4);
    }

    #[test]
    fn distinct_value_cap_drops_overflow_but_keeps_counting_tracked() {
        let salt = Salt::random();
        // Cap of 2 distinct pairs. Record two values (fills the cap), then a
        // third distinct value that overflows, and re-record a tracked one.
        let table = FrequencyTable::with_capacity(Some(2));
        let a = salt.hash("a");
        let b = salt.hash("b");
        let c = salt.hash("c");

        table.record("k", a);
        table.record("k", b);
        table.record("k", c); // over cap -> dropped
        table.record("k", c); // still a new value -> dropped again
        table.record("k", a); // already tracked -> counts

        assert_eq!(table.count("k", a), 2);
        assert_eq!(table.count("k", b), 1);
        assert_eq!(table.count("k", c), 0); // never tracked
        assert_eq!(table.dropped(), 2);
        // Only the tracked sightings feed the denominator (3 = a×2 + b×1).
        assert_eq!(table.total("k"), 3);
    }
}
