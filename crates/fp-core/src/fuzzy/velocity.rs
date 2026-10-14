//! Per-key new-device production rate — the material for the cross-session
//! velocity signal (PLAN-004 / red-team hardening).
//!
//! A per-session engine mints a fresh `visitorId` for every re-seeded launch of
//! a fingerprint-cloaking browser, so a farm churning out new devices is
//! invisible one request at a time. Keyed on the client IP, this store counts how
//! many *new devices* one key produced inside a trailing window; a high rate is
//! the fresh-seed-per-launch farm's cross-session footprint. It feeds a risk
//! *band* surfaced alongside `ip_risk`, never the `visitorId`.

use std::{
    collections::HashMap,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

/// Trailing window (seconds) the new-device rate is counted over.
///
/// TUNING PLACEHOLDER (a policy guess, not a measured claim): one hour of
/// history. Wider windows catch slower farms at the cost of memory per key;
/// narrower ones react faster but miss a paced attacker.
pub const WINDOW: u64 = 3600;
/// New-device count (within [`WINDOW`]) at or above which the key is [`VelocityBand::Medium`].
///
/// TUNING PLACEHOLDER: a handful of fresh devices from one IP in an hour is
/// mildly suspicious — plausible for a shared NAT, worth flagging but not acting on.
pub const MEDIUM: u64 = 5;
/// New-device count (within [`WINDOW`]) at or above which the key is [`VelocityBand::High`].
///
/// TUNING PLACEHOLDER: this many fresh devices from one IP in an hour is the
/// fresh-seed-per-launch farm's footprint and earns the confidence downgrade.
pub const HIGH: u64 = 20;

/// Per-JA4-**class** new-device count (within [`WINDOW`]) at or above which the
/// class key is [`VelocityBand::Medium`].
///
/// TUNING PLACEHOLDER — and deliberately *orders of magnitude* above the per-IP
/// [`MEDIUM`]: a JA4 class is the coarse `(protocol, tls_version, sni, alpn)`
/// shape shared by **every** real client of that browser family (JA4 is
/// low-entropy), so a legitimate per-class new-device count is naturally far
/// higher than a per-IP one. This value MUST be calibrated against real
/// per-class traffic volume before the band drives any action; using the per-IP
/// thresholds here would flag all normal Chrome traffic.
pub const JA4_MEDIUM: u64 = 100;
/// Per-JA4-**class** new-device count (within [`WINDOW`]) at or above which the
/// class key is [`VelocityBand::High`] — the proxy-pool farm's cross-IP
/// footprint. TUNING PLACEHOLDER, far above the per-IP [`HIGH`] (see
/// [`JA4_MEDIUM`] for why).
pub const JA4_HIGH: u64 = 400;

/// Storage contract for the per-key new-device event material behind the
/// cross-session velocity signal.
///
/// The in-memory [`VelocityTable`] is the single-instance implementation. An
/// externalized backend (a shared event store, a later step) lives behind the
/// same contract, so the engine records new-device events and reads counts
/// without knowing where the material is kept. Time is caller-supplied — the core
/// never reads a wall clock, so scoring stays deterministic.
pub trait VelocityStore: Send + Sync {
    /// Record one new-device event for `key` at `now` (Unix seconds).
    fn record(&self, key: &str, now: u64);

    /// Number of events for `key` within the trailing `window` seconds ending at
    /// `now`. Expired events (older than `now - window`) are pruned on access.
    fn count(&self, key: &str, now: u64, window: u64) -> u64;
}

/// `key → event unix-seconds` for the cross-session new-device rate.
///
/// Updated incrementally as new devices are minted. Each key (a client IP) maps
/// to the timestamps of the new-device events seen for it; a `count` prunes the
/// timestamps that have aged past the window and returns the rest.
///
/// Growth is bounded, fail-safe: an optional cap on the number of *distinct*
/// tracked keys drops a never-before-seen key once the cap is reached
/// (already-tracked keys keep counting), so the table cannot grow without limit.
/// The default cap is generous, so a small workload is unaffected; every drop is
/// counted via [`VelocityTable::dropped`], never silent.
#[derive(Debug, Default)]
pub struct VelocityTable {
    events: Mutex<HashMap<String, Vec<u64>>>,
    /// Cap on distinct tracked keys; `None` is unbounded.
    max_keys: Option<usize>,
    /// Count of new keys dropped at the distinct-key cap (not silent).
    dropped: AtomicU64,
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
            events: Mutex::new(HashMap::new()),
            max_keys,
            dropped: AtomicU64::new(0),
        }
    }

    /// Record one new-device event for `key` at `now` (Unix seconds).
    ///
    /// An already-tracked key always appends. A never-before-seen key is tracked
    /// unless the distinct-key cap is reached, in which case it is dropped (not
    /// inserted, not counted) and tallied in [`VelocityTable::dropped`].
    pub fn record(&self, key: &str, now: u64) {
        let mut events = self.lock();
        if let Some(entry) = events.get_mut(key) {
            entry.push(now);
            return;
        }
        if let Some(cap) = self.max_keys
            && events.len() >= cap
        {
            drop(events);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        events.insert(key.to_owned(), vec![now]);
    }

    /// Total new keys dropped at the distinct-key cap so far.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Number of events for `key` within the trailing `window` seconds ending at
    /// `now`; `0` if the key was never tracked. Events older than `now - window`
    /// are pruned from the key's list on access.
    pub fn count(&self, key: &str, now: u64, window: u64) -> u64 {
        let mut events = self.lock();
        let Some(list) = events.get_mut(key) else {
            return 0;
        };
        let cutoff = now.saturating_sub(window);
        list.retain(|&t| t >= cutoff);
        list.len() as u64
    }

    /// Lock the events map, recovering the guard if a prior holder panicked.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<u64>>> {
        self.events.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl VelocityStore for VelocityTable {
    fn record(&self, key: &str, now: u64) {
        VelocityTable::record(self, key, now);
    }

    fn count(&self, key: &str, now: u64, window: u64) -> u64 {
        VelocityTable::count(self, key, now, window)
    }
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

    /// Classify a new-device `count` into a band against explicit
    /// `medium` / `high` thresholds. Shared by the per-IP key ([`classify`](Self::classify)) and
    /// the per-JA4-class key ([`classify_ja4`](Self::classify_ja4)), whose thresholds differ by
    /// orders of magnitude.
    pub fn classify_with(count: u64, medium: u64, high: u64) -> VelocityBand {
        if count >= high {
            VelocityBand::High
        } else if count >= medium {
            VelocityBand::Medium
        } else {
            VelocityBand::Low
        }
    }

    /// Classify a per-IP new-device `count` (within [`WINDOW`]) into its band
    /// using the documented [`MEDIUM`] / [`HIGH`] thresholds.
    pub fn classify(count: u64) -> VelocityBand {
        Self::classify_with(count, MEDIUM, HIGH)
    }

    /// Classify a per-JA4-**class** new-device `count` (within [`WINDOW`]) using
    /// the far-higher [`JA4_MEDIUM`] / [`JA4_HIGH`] thresholds — a JA4 class is
    /// shared by every real client of a browser family, so per-class counts are
    /// legitimately far higher than per-IP ones.
    pub fn classify_ja4(count: u64) -> VelocityBand {
        Self::classify_with(count, JA4_MEDIUM, JA4_HIGH)
    }
}

#[cfg(test)]
mod tests {
    use super::{HIGH, MEDIUM, VelocityBand, VelocityTable, WINDOW};

    #[test]
    fn counts_events_within_the_window() {
        let table = VelocityTable::new();
        // Five events, all inside the window ending at `now`.
        for t in [1_000, 1_100, 1_200, 1_300, 1_400] {
            table.record("ip", t);
        }
        assert_eq!(table.count("ip", 1_400, WINDOW), 5);
    }

    #[test]
    fn events_beyond_the_window_are_pruned() {
        let table = VelocityTable::new();
        // Two old events and three recent ones; at `now` the old pair has aged out.
        table.record("ip", 1_000);
        table.record("ip", 2_000);
        let now = 1_000 + WINDOW + 5_000;
        table.record("ip", now - 100);
        table.record("ip", now - 50);
        table.record("ip", now);
        assert_eq!(table.count("ip", now, WINDOW), 3);
    }

    #[test]
    fn unseen_key_returns_zero() {
        let table = VelocityTable::new();
        assert_eq!(table.count("nope", 1_000, WINDOW), 0);
    }

    #[test]
    fn distinct_key_cap_drops_overflow_but_keeps_counting_tracked() {
        // Cap of 2 distinct keys. Record two keys (fills the cap), then a third
        // distinct key that overflows, and re-record a tracked one.
        let table = VelocityTable::with_capacity(Some(2));

        table.record("a", 1_000);
        table.record("b", 1_000);
        table.record("c", 1_000); // over cap -> dropped
        table.record("c", 1_000); // still a new key -> dropped again
        table.record("a", 1_100); // already tracked -> counts

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
    fn classify_ja4_uses_the_far_higher_thresholds() {
        use super::{JA4_HIGH, JA4_MEDIUM};

        // The JA4-class band rises with per-class new-device count, crossing the
        // documented placeholder thresholds.
        assert_eq!(VelocityBand::classify_ja4(0), VelocityBand::Low);
        assert_eq!(
            VelocityBand::classify_ja4(JA4_MEDIUM - 1),
            VelocityBand::Low
        );
        assert_eq!(VelocityBand::classify_ja4(JA4_MEDIUM), VelocityBand::Medium);
        assert_eq!(
            VelocityBand::classify_ja4(JA4_HIGH - 1),
            VelocityBand::Medium
        );
        assert_eq!(VelocityBand::classify_ja4(JA4_HIGH), VelocityBand::High);

        // The JA4 thresholds are far above the per-IP ones: a count that is
        // already High for an IP is still the neutral Low band for a JA4 class.
        const { assert!(JA4_MEDIUM > HIGH) };
        assert_eq!(VelocityBand::classify_ja4(HIGH), VelocityBand::Low);
    }
}
