//! Bounded, time-limited in-memory store of identify events.
//!
//! Every successful `/identify` stores its exact response body under its
//! `request_id`, so a backend can later fetch the verdict server-to-server via
//! `GET /events/{request_id}` instead of trusting a client-relayed copy.
//!
//! Every event shares one TTL, so insertion order is expiry order: a FIFO queue
//! of `(expires_at, request_id)` reaps expired events from the front on each
//! insert (no full scan), and the same front is evicted when the cap is hit.
//!
//! Events are also indexed by `visitor_id`, so erasing a visitor removes all of
//! its events at once ([`EventStore::remove_visitor`]). Erased events leave
//! their queue entries behind as tombstones, skipped when they reach the front;
//! tombstones count toward the cap, so the queue never exceeds `max_events`.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use axum::body::Bytes;

/// Upper bound on the TTL (100 years), so `now + ttl` cannot overflow.
const MAX_TTL: Duration = Duration::from_hours(100 * 365 * 24);

/// In-memory identify-event store with a fixed TTL and a live-entry cap.
pub struct EventStore {
    ttl: Duration,
    max_events: usize,
    state: Mutex<State>,
    evicted: AtomicU64,
}

/// One stored identify event.
struct Event {
    expires_at: Instant,
    visitor_id: String,
    body: Bytes,
}

#[derive(Default)]
struct State {
    /// `request_id → event`.
    events: HashMap<String, Event>,
    /// `(expires_at, request_id)` in insertion (= expiry) order. An id no
    /// longer in `events` is a tombstone left by [`EventStore::remove_visitor`].
    order: VecDeque<(Instant, String)>,
    /// `visitor_id → request_ids` of its stored events; never holds an empty set.
    by_visitor: HashMap<String, HashSet<String>>,
}

impl EventStore {
    /// A store whose events live for `ttl` and which holds at most `max_events`
    /// at once (`0` stores nothing). A TTL above 100 years is clamped.
    pub fn new(ttl: Duration, max_events: usize) -> Self {
        Self {
            ttl: ttl.min(MAX_TTL),
            max_events,
            state: Mutex::new(State::default()),
            evicted: AtomicU64::new(0),
        }
    }

    /// Store `body` for `visitor_id` under `request_id` at time `now`, first
    /// reaping expired events, then evicting the oldest queue entries past the
    /// cap.
    pub fn insert(&self, request_id: String, visitor_id: String, body: Bytes, now: Instant) {
        if self.max_events == 0 {
            return;
        }
        let expires_at = now + self.ttl;
        let mut state = self.lock();
        while state.order.front().is_some_and(|(at, _)| *at <= now) {
            state.pop_front();
        }
        while state.order.len() >= self.max_events {
            if state.pop_front() {
                self.evicted.fetch_add(1, Ordering::Relaxed);
            }
        }
        state.order.push_back((expires_at, request_id.clone()));
        state
            .by_visitor
            .entry(visitor_id.clone())
            .or_default()
            .insert(request_id.clone());
        state.events.insert(
            request_id,
            Event {
                expires_at,
                visitor_id,
                body,
            },
        );
    }

    /// The body stored under `request_id`, or `None` if unknown or expired at
    /// time `now`.
    pub fn get(&self, request_id: &str, now: Instant) -> Option<Bytes> {
        let state = self.lock();
        let event = state.events.get(request_id)?;
        (event.expires_at > now).then(|| event.body.clone())
    }

    /// Remove every stored event of `visitor_id`, returning how many were
    /// removed.
    pub fn remove_visitor(&self, visitor_id: &str) -> usize {
        let mut state = self.lock();
        let Some(request_ids) = state.by_visitor.remove(visitor_id) else {
            return 0;
        };
        for request_id in &request_ids {
            state.events.remove(request_id);
        }
        request_ids.len()
    }

    /// Number of stored events (expired ones not yet reaped included).
    pub fn len(&self) -> usize {
        self.lock().events.len()
    }

    /// Whether no event is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of live events evicted because the cap was reached.
    pub fn evicted(&self) -> u64 {
        self.evicted.load(Ordering::Relaxed)
    }

    /// Lock the state, recovering from a poisoned mutex (the state stays
    /// structurally valid across every critical section).
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl fmt::Debug for EventStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Bodies are per-visitor data: expose only sizes.
        f.debug_struct("EventStore")
            .field("ttl", &self.ttl)
            .field("max_events", &self.max_events)
            .field("live", &self.len())
            .field("evicted", &self.evicted())
            .finish_non_exhaustive()
    }
}

impl State {
    /// Pop the front queue entry, dropping its event and index entry. Returns
    /// whether a stored event was removed (`false` for a tombstone).
    fn pop_front(&mut self) -> bool {
        let Some((_, request_id)) = self.order.pop_front() else {
            return false;
        };
        let Some(event) = self.events.remove(&request_id) else {
            return false;
        };
        if let Some(ids) = self.by_visitor.get_mut(&event.visitor_id) {
            ids.remove(&request_id);
            if ids.is_empty() {
                self.by_visitor.remove(&event.visitor_id);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::EventStore;
    use axum::body::Bytes;
    use std::collections::HashSet;
    use std::time::{Duration, Instant};

    fn body(text: &'static str) -> Bytes {
        Bytes::from_static(text.as_bytes())
    }

    #[test]
    fn stored_event_is_returned_until_it_expires() {
        let store = EventStore::new(Duration::from_secs(10), 8);
        let t0 = Instant::now();
        store.insert("a".into(), "v".into(), body("{\"a\":1}"), t0);
        assert_eq!(store.get("a", t0), Some(body("{\"a\":1}")));
        assert_eq!(
            store.get("a", t0 + Duration::from_secs(9)),
            Some(body("{\"a\":1}"))
        );
        assert_eq!(store.get("a", t0 + Duration::from_secs(10)), None);
        assert_eq!(store.get("unknown", t0), None);
    }

    #[test]
    fn insert_reaps_expired_events_without_counting_them_as_evicted() {
        let store = EventStore::new(Duration::from_secs(1), 2);
        let t0 = Instant::now();
        store.insert("a".into(), "v".into(), body("a"), t0);
        store.insert("b".into(), "v".into(), body("b"), t0);
        let later = t0 + Duration::from_secs(2);
        store.insert("c".into(), "v".into(), body("c"), later);
        store.insert("d".into(), "v".into(), body("d"), later);
        assert_eq!(store.evicted(), 0);
        assert_eq!(store.get("c", later), Some(body("c")));
        assert_eq!(store.get("d", later), Some(body("d")));
    }

    #[test]
    fn cap_evicts_the_oldest_event_and_counts_it() {
        let store = EventStore::new(Duration::from_mins(1), 2);
        let t0 = Instant::now();
        store.insert("a".into(), "v".into(), body("a"), t0);
        store.insert("b".into(), "v".into(), body("b"), t0);
        store.insert("c".into(), "v".into(), body("c"), t0);
        assert_eq!(store.get("a", t0), None);
        assert_eq!(store.get("b", t0), Some(body("b")));
        assert_eq!(store.get("c", t0), Some(body("c")));
        assert_eq!(store.evicted(), 1);
    }

    #[test]
    fn zero_cap_stores_nothing() {
        let store = EventStore::new(Duration::from_mins(1), 0);
        let t0 = Instant::now();
        store.insert("a".into(), "v".into(), body("a"), t0);
        assert_eq!(store.get("a", t0), None);
    }

    /// Number of visitor index entries and total indexed request ids.
    fn index_sizes(store: &EventStore) -> (usize, usize) {
        let state = store.lock();
        (
            state.by_visitor.len(),
            state.by_visitor.values().map(HashSet::len).sum(),
        )
    }

    #[test]
    fn remove_visitor_drops_only_that_visitors_events() {
        let store = EventStore::new(Duration::from_mins(1), 8);
        let t0 = Instant::now();
        store.insert("a1".into(), "a".into(), body("a1"), t0);
        store.insert("b1".into(), "b".into(), body("b1"), t0);
        store.insert("a2".into(), "a".into(), body("a2"), t0);
        assert_eq!(store.remove_visitor("a"), 2);
        assert_eq!(store.get("a1", t0), None);
        assert_eq!(store.get("a2", t0), None);
        assert_eq!(store.get("b1", t0), Some(body("b1")));
        assert_eq!(store.len(), 1);
        assert_eq!(index_sizes(&store), (1, 1));
        // Idempotent.
        assert_eq!(store.remove_visitor("a"), 0);
        assert_eq!(store.remove_visitor("unknown"), 0);
    }

    #[test]
    fn cap_eviction_drops_the_visitor_index_entry() {
        let store = EventStore::new(Duration::from_mins(1), 2);
        let t0 = Instant::now();
        store.insert("a1".into(), "a".into(), body("a1"), t0);
        store.insert("a2".into(), "a".into(), body("a2"), t0);
        store.insert("b1".into(), "b".into(), body("b1"), t0);
        assert_eq!(index_sizes(&store), (2, 2));
        store.insert("b2".into(), "b".into(), body("b2"), t0);
        // Every event of `a` evicted → its index entry is gone.
        assert_eq!(index_sizes(&store), (1, 2));
        assert_eq!(store.remove_visitor("a"), 0);
        assert_eq!(store.evicted(), 2);
    }

    #[test]
    fn ttl_reap_drops_the_visitor_index_entry() {
        let store = EventStore::new(Duration::from_secs(1), 8);
        let t0 = Instant::now();
        store.insert("a1".into(), "a".into(), body("a1"), t0);
        store.insert("a2".into(), "a".into(), body("a2"), t0);
        let later = t0 + Duration::from_secs(2);
        store.insert("b1".into(), "b".into(), body("b1"), later);
        assert_eq!(store.len(), 1);
        assert_eq!(index_sizes(&store), (1, 1));
        assert_eq!(store.evicted(), 0);
    }

    #[test]
    fn tombstones_are_bounded_by_the_cap_and_not_counted_as_evicted() {
        let store = EventStore::new(Duration::from_mins(1), 2);
        let t0 = Instant::now();
        store.insert("a1".into(), "a".into(), body("a1"), t0);
        store.insert("a2".into(), "a".into(), body("a2"), t0);
        assert_eq!(store.remove_visitor("a"), 2);
        store.insert("b1".into(), "b".into(), body("b1"), t0);
        store.insert("b2".into(), "b".into(), body("b2"), t0);
        assert_eq!(store.lock().order.len(), 2);
        assert_eq!(store.evicted(), 0);
        assert_eq!(store.get("b1", t0), Some(body("b1")));
        assert_eq!(store.get("b2", t0), Some(body("b2")));
        // Index size never exceeds the stored events.
        assert_eq!(index_sizes(&store), (1, store.len()));
    }
}
