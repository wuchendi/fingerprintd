//! One-time nonce issuance and consumption — the anti-replay primitive.
//!
//! A nonce is minted by `GET /challenge` and must be presented on the matching
//! `POST /identify`. Consumption is **one-time**: the first [`NonceStore::consume`]
//! of a live nonce succeeds and burns it; any later attempt — or a stale one —
//! is rejected. This makes a captured `identify` payload unreplayable.

use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use rand::{Rng, rng};

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
    /// The nonce was never issued by this store.
    Unknown,
}

/// Abstraction over a nonce backing store.
///
/// The in-memory [`InMemoryNonceStore`] is the P0 implementation. A
/// distributed backend lives behind the same contract:
/// `// TODO(P2): RedisNonceStore` — a Redis-backed adapter keying nonces with a
/// native TTL and an atomic set-if-unused, so replay protection holds across
/// multiple service instances. It is intentionally not implemented here (no
/// `redis` dependency, and tests must not require a running server).
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

/// In-memory [`NonceStore`]: a `Mutex`-guarded map with per-entry expiry.
///
/// Suitable for a single instance (P0). Horizontal scaling requires the shared
/// Redis backend noted on [`NonceStore`].
#[derive(Debug)]
pub struct InMemoryNonceStore {
    /// Default TTL applied by [`InMemoryNonceStore::issue`].
    ttl: Duration,
    /// nonce -> lifecycle entry.
    entries: Mutex<HashMap<String, Entry>>,
}

impl InMemoryNonceStore {
    /// Create a store whose issued nonces live for `ttl`.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Mint a nonce with an explicit `ttl`, overriding the store default.
    ///
    /// This is the deterministic test seam for expiry: passing
    /// `Duration::ZERO` yields a nonce whose `expires_at` is already in the
    /// past by the time it is consumed, so the expired-nonce path is exercised
    /// without sleeping.
    pub fn issue_with_ttl(&self, ttl: Duration) -> String {
        let nonce = generate_nonce();
        let entry = Entry {
            expires_at: Instant::now() + ttl,
            used: false,
        };
        let mut entries = self.lock();
        // Lazy reap: drop every already-expired entry BEFORE inserting the new
        // one. Sweeping at issue time (not consume time) bounds memory to nonces
        // issued within one live TTL window without a background task, and
        // running it before the insert leaves the just-minted nonce untouched —
        // so a zero-TTL nonce is still present to be consumed as `Expired`.
        entries.retain(|_, e| Instant::now() < e.expires_at);
        entries.insert(nonce.clone(), entry);
        nonce
    }

    /// Lock the entry map, recovering the guard if a prior holder panicked.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Number of entries currently held. Test-only observability hook used to
    /// assert the lazy reaper shrank the map.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }
}

#[async_trait]
impl NonceStore for InMemoryNonceStore {
    async fn issue(&self) -> String {
        self.issue_with_ttl(self.ttl)
    }

    async fn consume(&self, nonce: &str) -> NonceOutcome {
        let mut entries = self.lock();
        match entries.get_mut(nonce) {
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
        // Issuing the second nonce triggers the lazy sweep, dropping `first`.
        let second = store.issue_with_ttl(Duration::from_secs(30));
        assert_eq!(store.len(), 1);
        assert_eq!(store.consume(&first).await, NonceOutcome::Unknown);
        assert_eq!(store.consume(&second).await, NonceOutcome::Valid);
    }
}
