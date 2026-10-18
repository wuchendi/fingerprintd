//! Per-key distinct new-device count — the material for the cross-session
//! velocity signal.
//!
//! A per-session engine mints a fresh `visitor_id` for every re-seeded launch of
//! a fingerprint-cloaking browser, so a farm churning out new devices is
//! invisible one request at a time. Keyed on the client IP, this store counts how
//! many *distinct* new visitor ids one key produced inside a trailing window; a
//! high count is the fresh-seed-per-launch farm's cross-session footprint. It
//! feeds a risk *band* surfaced alongside `ip_risk`, never the `visitor_id`.

use std::collections::HashMap;

/// Trailing window (seconds) the distinct new-device count is taken over.
///
/// TUNING PLACEHOLDER (a policy guess, not a measured claim): one hour of
/// history. Wider windows catch slower farms at the cost of memory per key;
/// narrower ones react faster but miss a paced attacker.
pub const WINDOW: u64 = 3600;
/// Distinct new-device count (within [`WINDOW`]) at or above which the key is [`VelocityBand::Medium`].
///
/// TUNING PLACEHOLDER: a handful of fresh devices from one IP in an hour is
/// mildly suspicious — plausible for a shared NAT, worth flagging but not acting on.
pub const MEDIUM: u64 = 5;
/// Distinct new-device count (within [`WINDOW`]) at or above which the key is [`VelocityBand::High`].
///
/// TUNING PLACEHOLDER: this many fresh devices from one IP in an hour is the
/// fresh-seed-per-launch farm's footprint and earns the confidence downgrade.
pub const HIGH: u64 = 20;
/// Most distinct visitor ids tracked per key. Kept above [`HIGH`] so the cap
/// never hides a High band; past it the oldest-seen id is dropped.
pub const MAX_IDS_PER_KEY: usize = 64;
/// Confidence downgrade for a [`VelocityBand::High`] key — see [`velocity_penalty`].
///
/// TUNING PLACEHOLDER (a policy guess, not a measured claim): fused the same way
/// as the passive-signal adjustment (`signals.rs` `confidence_adjustment`), it
/// lowers decision confidence for a `NewDevice` verdict without touching the
/// `visitor_id` or the decision itself.
pub const VELOCITY_PENALTY: f64 = 0.3;

/// The confidence penalty a host subtracts for `band`: [`VELOCITY_PENALTY`] for
/// [`VelocityBand::High`], `0` otherwise. Pure, so a stateless host that counts
/// distinct visitors itself applies the identical penalty.
pub fn velocity_penalty(band: VelocityBand) -> f64 {
    match band {
        VelocityBand::High => VELOCITY_PENALTY,
        VelocityBand::Low | VelocityBand::Medium => 0.0,
    }
}

/// `key → (visitor id → last-seen unix-seconds)` for the cross-session
/// distinct new-device count.
///
/// Each key (a client IP) tracks the new visitor ids minted for it with the
/// time each was last recorded. Recording the same id again only refreshes its
/// time, so it counts once. Entries older than [`WINDOW`] are pruned on every
/// record and count, and at most [`MAX_IDS_PER_KEY`] ids are kept per key (the
/// oldest is dropped first).
///
/// Key growth is bounded, fail-safe: an optional cap on the number of
/// *distinct* tracked keys drops a never-before-seen key once the cap is
/// reached (already-tracked keys keep counting). Every drop is counted via
/// [`VelocityTable::dropped`], never silent.
#[derive(Debug, Default)]
pub struct VelocityTable {
    events: HashMap<String, HashMap<String, u64>>,
    /// Cap on distinct tracked keys; `None` is unbounded.
    max_keys: Option<usize>,
    /// Count of new keys dropped at the distinct-key cap (not silent).
    dropped: u64,
}

impl VelocityTable {
    /// Create an empty, unbounded table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty table bounded by a cap on distinct tracked keys.
    ///
    /// `max_keys` caps how many *distinct* keys the table tracks; a new key
    /// beyond the cap is dropped and counted. `None` is unbounded.
    pub fn with_capacity(max_keys: Option<usize>) -> Self {
        Self {
            max_keys,
            ..Self::default()
        }
    }

    /// Record that `visitor` was minted as a new device for `key` at `now`
    /// (Unix seconds).
    ///
    /// An already-tracked key always records. A never-before-seen key is tracked
    /// unless the distinct-key cap is reached, in which case it is dropped (not
    /// inserted, not counted) and tallied in [`VelocityTable::dropped`].
    pub fn record(&mut self, key: &str, visitor: &str, now: u64) {
        if !self.events.contains_key(key) {
            if let Some(cap) = self.max_keys
                && self.events.len() >= cap
            {
                self.dropped += 1;
                return;
            }
            self.events.insert(key.to_owned(), HashMap::new());
        }
        let Some(ids) = self.events.get_mut(key) else {
            return;
        };
        prune(ids, now, WINDOW);
        ids.insert(visitor.to_owned(), now);
        if ids.len() > MAX_IDS_PER_KEY
            && let Some(oldest) = ids
                .iter()
                .min_by_key(|(_, t)| **t)
                .map(|(id, _)| id.clone())
        {
            ids.remove(&oldest);
        }
    }

    /// Total new keys dropped at the distinct-key cap so far.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Number of distinct visitor ids recorded for `key` within the trailing
    /// `window` seconds ending at `now`; `0` if the key was never tracked. Ids
    /// older than `now - window` are pruned on access.
    pub fn count(&mut self, key: &str, now: u64, window: u64) -> u64 {
        let Some(ids) = self.events.get_mut(key) else {
            return 0;
        };
        prune(ids, now, window);
        ids.len() as u64
    }
}

/// Drop ids last recorded before `now - window`.
fn prune(ids: &mut HashMap<String, u64>, now: u64, window: u64) {
    let cutoff = now.saturating_sub(window);
    ids.retain(|_, t| *t >= cutoff);
}

/// Coarse new-device production-rate band for one key (surfaced alongside
/// `ip_risk`, never folded into identity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VelocityBand {
    /// Below [`MEDIUM`] new devices in the window — the neutral, cold-start band.
    Low,
    /// At or above [`MEDIUM`] but below [`HIGH`] — mildly suspicious.
    Medium,
    /// At or above [`HIGH`] — the fresh-seed-per-launch farm's footprint.
    High,
}

impl VelocityBand {
    /// Stable wire label for the response body.
    pub fn as_str(self) -> &'static str {
        match self {
            VelocityBand::Low => "low",
            VelocityBand::Medium => "medium",
            VelocityBand::High => "high",
        }
    }

    /// Parse a wire label (`"low"|"medium"|"high"`) back into its band.
    pub fn from_label(label: &str) -> Option<VelocityBand> {
        [VelocityBand::Low, VelocityBand::Medium, VelocityBand::High]
            .into_iter()
            .find(|band| band.as_str() == label)
    }

    /// Classify a per-IP distinct new-device `count` (within [`WINDOW`]) into its band
    /// using the documented [`MEDIUM`] / [`HIGH`] thresholds.
    pub fn classify(count: u64) -> VelocityBand {
        if count >= HIGH {
            VelocityBand::High
        } else if count >= MEDIUM {
            VelocityBand::Medium
        } else {
            VelocityBand::Low
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HIGH, MAX_IDS_PER_KEY, MEDIUM, VELOCITY_PENALTY, VelocityBand, VelocityTable, WINDOW,
        velocity_penalty,
    };

    #[test]
    fn band_labels_round_trip() {
        for band in [VelocityBand::Low, VelocityBand::Medium, VelocityBand::High] {
            assert_eq!(VelocityBand::from_label(band.as_str()), Some(band));
        }
        assert_eq!(VelocityBand::from_label("HIGH"), None);
    }

    #[test]
    fn counts_distinct_ids_within_the_window() {
        let mut table = VelocityTable::new();
        for (i, t) in [1_000, 1_100, 1_200, 1_300, 1_400].into_iter().enumerate() {
            table.record("ip", &format!("v{i}"), t);
        }
        assert_eq!(table.count("ip", 1_400, WINDOW), 5);
    }

    #[test]
    fn the_same_id_counts_once() {
        let mut table = VelocityTable::new();
        table.record("ip", "v1", 1_000);
        table.record("ip", "v1", 1_010);
        table.record("ip", "v2", 1_020);
        assert_eq!(table.count("ip", 1_020, WINDOW), 2);
    }

    #[test]
    fn ids_beyond_the_window_are_pruned() {
        let mut table = VelocityTable::new();
        table.record("ip", "old1", 1_000);
        table.record("ip", "old2", 2_000);
        let now = 1_000 + WINDOW + 5_000;
        table.record("ip", "a", now - 100);
        table.record("ip", "b", now - 50);
        table.record("ip", "c", now);
        assert_eq!(table.count("ip", now, WINDOW), 3);
    }

    #[test]
    fn ids_per_key_are_capped_above_high() {
        assert!(MAX_IDS_PER_KEY as u64 >= HIGH);
        let mut table = VelocityTable::new();
        for i in 0..(MAX_IDS_PER_KEY as u64 + 10) {
            table.record("ip", &format!("v{i}"), 1_000 + i);
        }
        assert_eq!(table.count("ip", 1_100, WINDOW), MAX_IDS_PER_KEY as u64);
    }

    #[test]
    fn unseen_key_returns_zero() {
        let mut table = VelocityTable::new();
        assert_eq!(table.count("nope", 1_000, WINDOW), 0);
    }

    #[test]
    fn distinct_key_cap_drops_overflow_but_keeps_counting_tracked() {
        let mut table = VelocityTable::with_capacity(Some(2));

        table.record("a", "v1", 1_000);
        table.record("b", "v2", 1_000);
        table.record("c", "v3", 1_000); // over cap -> dropped
        table.record("c", "v4", 1_000); // still a new key -> dropped again
        table.record("a", "v5", 1_100); // already tracked -> counts

        assert_eq!(table.count("a", 1_100, WINDOW), 2);
        assert_eq!(table.count("b", 1_100, WINDOW), 1);
        assert_eq!(table.count("c", 1_100, WINDOW), 0); // never tracked
        assert_eq!(table.dropped(), 2);
    }

    #[test]
    fn classify_uses_documented_thresholds() {
        assert_eq!(VelocityBand::classify(0), VelocityBand::Low);
        assert_eq!(VelocityBand::classify(MEDIUM - 1), VelocityBand::Low);
        assert_eq!(VelocityBand::classify(MEDIUM), VelocityBand::Medium);
        assert_eq!(VelocityBand::classify(HIGH - 1), VelocityBand::Medium);
        assert_eq!(VelocityBand::classify(HIGH), VelocityBand::High);
        assert_eq!(VelocityBand::Low.as_str(), "low");
        assert_eq!(VelocityBand::Medium.as_str(), "medium");
        assert_eq!(VelocityBand::High.as_str(), "high");
    }

    #[test]
    fn penalty_applies_only_to_high() {
        assert!(velocity_penalty(VelocityBand::Low).abs() < f64::EPSILON);
        assert!(velocity_penalty(VelocityBand::Medium).abs() < f64::EPSILON);
        assert!((velocity_penalty(VelocityBand::High) - VELOCITY_PENALTY).abs() < f64::EPSILON);
    }
}
