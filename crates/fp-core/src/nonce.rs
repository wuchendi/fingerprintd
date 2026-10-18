//! One-time nonce issuance and consumption — the anti-replay primitive.
//!
//! A nonce is minted by `GET /challenge` and must be presented on the matching
//! `POST /identify`. Consumption is **one-time**: the first [`NonceStore::consume`]
//! of a live nonce succeeds and burns it; any later attempt — or a stale one —
//! is rejected. This makes a captured `identify` payload unreplayable.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use rand::{Rng, rng};

/// Default cap on entries held by [`InMemoryNonceStore::new`].
pub const DEFAULT_MAX_LIVE: usize = 1_000_000;

/// Result of attempting to consume a nonce.
///
/// Only [`NonceOutcome::Valid`] authorizes an `identify`; every other variant
/// maps to `401` at the HTTP layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceOutcome {
    /// The nonce was live and unused; it is now burned.
    Valid,
    /// The nonce existed but its TTL had elapsed (regardless of prior use).
    Expired,
    /// The nonce was already consumed once (replay attempt).
    Reused,
    /// The nonce was never issued by this store, or was reaped or evicted.
    Unknown,
}

/// Abstraction over a nonce backing store.
///
/// [`InMemoryNonceStore`] covers a single instance. Replay protection across
/// multiple service instances needs a shared backend (e.g. Redis with native
/// TTLs and an atomic set-if-unused) implementing this same contract.
// `async_trait` expands each method to a boxed future with a bare `#[must_use]`
// on top of the already-must_use `Pin<Box<dyn Future>>`; the lint fires inside
// the macro output and cannot be fixed at the call site.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait NonceStore: Send + Sync {
    /// Mint a fresh single-use nonce with the store's configured TTL.
    async fn issue(&self) -> String;

    /// Attempt to consume `nonce`, burning it on success. See [`NonceOutcome`].
    async fn consume(&self, nonce: &str) -> NonceOutcome;
}

/// A minted nonce and its lifecycle bookkeeping.
#[derive(Debug)]
struct Entry {
    /// Instant at or after which the nonce is considered expired.
    expires_at: Instant,
    /// Whether the nonce has already been consumed once.
    used: bool,
}

/// Entry map plus its insertion-ordered expiry queue.
///
/// Every map key has exactly one queue element and vice versa: entries leave
/// the map only when their queue element is popped (reaped or evicted).
/// Consumed entries stay until then so a replay reads `Reused`.
#[derive(Debug, Default)]
struct State {
    /// nonce -> lifecycle entry.
    entries: HashMap<String, Entry>,
    /// `(expires_at, nonce)` in issue order, oldest at the front.
    queue: VecDeque<(Instant, String)>,
}

/// In-memory [`NonceStore`]: a `Mutex`-guarded map with a bounded,
/// insertion-ordered expiry queue.
///
/// Each issue reaps expired entries from the queue front only (amortized
/// O(1), no full-map scan), then evicts the oldest entries while the store is
/// at `max_live`. Because `issue_with_ttl` accepts per-call TTLs, the queue is
/// ordered by issue time, not strictly by expiry: a longer-lived entry at the
/// front holds already-expired entries behind it until it expires or is
/// evicted. Those entries still consume as `Expired`, and memory stays bounded
/// by `max_live` regardless.
#[derive(Debug)]
pub struct InMemoryNonceStore {
    /// Default TTL applied by [`InMemoryNonceStore::issue`].
    ttl: Duration,
    /// Maximum number of entries held at once (at least 1).
    max_live: usize,
    /// Map and expiry queue.
    state: Mutex<State>,
    /// Total entries evicted by the capacity cap before expiry.
    evicted: AtomicU64,
}

impl InMemoryNonceStore {
    /// Create a store whose issued nonces live for `ttl`, holding at most
    /// [`DEFAULT_MAX_LIVE`] entries.
    pub fn new(ttl: Duration) -> Self {
        Self::with_capacity(ttl, DEFAULT_MAX_LIVE)
    }

    /// Create a store whose issued nonces live for `ttl`, holding at most
    /// `max_live` entries (clamped to at least 1). Past the cap the oldest
    /// entries are evicted and consume as [`NonceOutcome::Unknown`].
    pub fn with_capacity(ttl: Duration, max_live: usize) -> Self {
        Self {
            ttl,
            max_live: max_live.max(1),
            state: Mutex::new(State::default()),
            evicted: AtomicU64::new(0),
        }
    }

    /// Total entries evicted by the capacity cap before they expired.
    pub fn evicted(&self) -> u64 {
        self.evicted.load(Ordering::Relaxed)
    }

    /// Mint a nonce with an explicit `ttl`, overriding the store default.
    ///
    /// This is the deterministic test seam for expiry: passing
    /// `Duration::ZERO` yields a nonce whose `expires_at` is already in the
    /// past by the time it is consumed, so the expired-nonce path is exercised
    /// without sleeping.
    pub fn issue_with_ttl(&self, ttl: Duration) -> String {
        let nonce = generate_nonce();
        let now = Instant::now();
        let expires_at = now + ttl;
        let mut state = self.lock();
        // Reap and evict BEFORE inserting, so a just-minted zero-TTL nonce is
        // still present to be consumed as `Expired`.
        while let Some((front_expires_at, _)) = state.queue.front() {
            if now < *front_expires_at {
                break;
            }
            state.pop_front();
        }
        let mut evicted = 0u64;
        while state.entries.len() >= self.max_live && state.pop_front() {
            evicted += 1;
        }
        state.queue.push_back((expires_at, nonce.clone()));
        state.entries.insert(
            nonce.clone(),
            Entry {
                expires_at,
                used: false,
            },
        );
        drop(state);
        if evicted > 0 {
            let previous = self.evicted.fetch_add(evicted, Ordering::Relaxed);
            let total = previous + evicted;
            // Log on the first eviction and whenever the total crosses a power
            // of two, so a sustained flood stays visible without log spam.
            if previous == 0 || total.ilog2() > previous.ilog2() {
                tracing::warn!(
                    evicted_total = total,
                    max_live = self.max_live,
                    "nonce store at capacity; evicting oldest nonces"
                );
            }
        }
        nonce
    }

    /// Lock the state, recovering the guard if a prior holder panicked.
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Number of entries currently held. Test-only observability hook used to
    /// assert reaping and eviction shrank the map.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().entries.len()
    }
}

impl State {
    /// Drop the oldest queued entry from the queue and map. Returns `false`
    /// when the queue is empty.
    fn pop_front(&mut self) -> bool {
        match self.queue.pop_front() {
            Some((_, nonce)) => {
                self.entries.remove(&nonce);
                true
            }
            None => false,
        }
    }
}

#[async_trait]
impl NonceStore for InMemoryNonceStore {
    async fn issue(&self) -> String {
        self.issue_with_ttl(self.ttl)
    }

    async fn consume(&self, nonce: &str) -> NonceOutcome {
        let mut state = self.lock();
        match state.entries.get_mut(nonce) {
            None => NonceOutcome::Unknown,
            // Expiry is checked before use so a stale-but-unused nonce is still
            // rejected as expired.
            Some(entry) if Instant::now() >= entry.expires_at => NonceOutcome::Expired,
            Some(entry) if entry.used => NonceOutcome::Reused,
            Some(entry) => {
                entry.used = true;
                NonceOutcome::Valid
            }
        }
    }
}

/// Generate a 128-bit random nonce as a lowercase hex string.
fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::{InMemoryNonceStore, NonceOutcome, NonceStore};
    use std::time::Duration;

    #[tokio::test]
    async fn valid_then_reused() {
        let store = InMemoryNonceStore::new(Duration::from_secs(30));
        let nonce = store.issue().await;
        assert_eq!(store.consume(&nonce).await, NonceOutcome::Valid);
        assert_eq!(store.consume(&nonce).await, NonceOutcome::Reused);
    }

    #[tokio::test]
    async fn unknown_nonce() {
        let store = InMemoryNonceStore::new(Duration::from_secs(30));
        assert_eq!(store.consume("never-issued").await, NonceOutcome::Unknown);
    }

    #[tokio::test]
    async fn expired_before_use() {
        let store = InMemoryNonceStore::new(Duration::from_secs(30));
        // Zero TTL: expired by the time we consume, without sleeping.
        let nonce = store.issue_with_ttl(Duration::ZERO);
        assert_eq!(store.consume(&nonce).await, NonceOutcome::Expired);
    }

    #[tokio::test]
    async fn issued_nonces_are_unique() {
        let store = InMemoryNonceStore::new(Duration::from_secs(30));
        assert_ne!(store.issue().await, store.issue().await);
    }

    #[tokio::test]
    async fn expired_entries_are_reaped_on_issue() {
        let store = InMemoryNonceStore::new(Duration::from_secs(30));
        // First nonce is born expired.
        let first = store.issue_with_ttl(Duration::ZERO);
        // Issuing the second nonce reaps `first` from the queue front.
        let second = store.issue_with_ttl(Duration::from_secs(30));
        assert_eq!(store.len(), 1);
        assert_eq!(store.consume(&first).await, NonceOutcome::Unknown);
        assert_eq!(store.consume(&second).await, NonceOutcome::Valid);
    }

    #[tokio::test]
    async fn issuing_past_capacity_evicts_oldest() {
        let store = InMemoryNonceStore::with_capacity(Duration::from_secs(30), 3);
        let mut nonces = Vec::new();
        for _ in 0..5 {
            nonces.push(store.issue().await);
            assert!(store.len() <= 3);
        }
        assert_eq!(store.len(), 3);
        assert_eq!(store.evicted(), 2);
        assert_eq!(store.consume(&nonces[0]).await, NonceOutcome::Unknown);
        assert_eq!(store.consume(&nonces[1]).await, NonceOutcome::Unknown);
        for nonce in &nonces[2..] {
            assert_eq!(store.consume(nonce).await, NonceOutcome::Valid);
        }
    }

    #[tokio::test]
    async fn used_entries_count_toward_capacity() {
        let store = InMemoryNonceStore::with_capacity(Duration::from_secs(30), 2);
        let first = store.issue().await;
        assert_eq!(store.consume(&first).await, NonceOutcome::Valid);
        assert_eq!(store.consume(&first).await, NonceOutcome::Reused);
        store.issue().await;
        store.issue().await;
        assert_eq!(store.len(), 2);
        assert_eq!(store.evicted(), 1);
        assert_eq!(store.consume(&first).await, NonceOutcome::Unknown);
    }

    #[tokio::test]
    async fn reaping_pops_only_expired_front_entries() {
        let store = InMemoryNonceStore::new(Duration::from_secs(30));
        let a = store.issue_with_ttl(Duration::ZERO);
        let b = store.issue_with_ttl(Duration::ZERO);
        let live = store.issue_with_ttl(Duration::from_secs(30));
        // Issuing `live` reaped `a` and `b` from the front of the queue.
        assert_eq!(store.len(), 1);
        let expired_behind_live = store.issue_with_ttl(Duration::ZERO);
        // A live front entry stops the reap; the expired one behind it waits.
        store.issue_with_ttl(Duration::from_secs(30));
        assert_eq!(store.len(), 3);
        assert_eq!(store.evicted(), 0);
        assert_eq!(store.consume(&a).await, NonceOutcome::Unknown);
        assert_eq!(store.consume(&b).await, NonceOutcome::Unknown);
        assert_eq!(
            store.consume(&expired_behind_live).await,
            NonceOutcome::Expired
        );
        assert_eq!(store.consume(&live).await, NonceOutcome::Valid);
    }
}
