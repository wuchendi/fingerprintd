//! Store bounds: removing a visitor (cap eviction, TTL eviction, retention
//! purge, erase) frees its blocking memberships, so a hot block never starves
//! new visitors and the index never outgrows the live library.

#![allow(clippy::unwrap_used)] // test-only: a failed lookup must abort loudly

use std::collections::BTreeMap;

use fingerprintd::fuzzy::{Components, EvictionPolicy, FuzzyStore, record::RecordStore};
use serde_json::json;

/// Per-block cap used by every hot-block scenario.
const K: usize = 4;

fn probe() -> Components {
    serde_json::from_value(json!({
        "webgl": "ANGLE (Intel)",
        "platform": "Linux x86_64",
        "timezone": "Asia/Shanghai",
        "audio": "124.04",
        "cpu_cores": 8,
        "device_memory": 8,
        "fonts": ["Arial", "Helvetica", "Courier", "Times", "Verdana"],
        "canvas": "c0ffee",
    }))
    .unwrap()
}

fn store(policy: EvictionPolicy) -> FuzzyStore {
    FuzzyStore::new_with_policy(EvictionPolicy {
        max_block: K,
        ..policy
    })
}

/// Fill every block of `probe()` with `K` visitors `v0..v{K-1}` seen at `t = 1..=K`.
fn fill(store: &FuzzyStore) {
    for i in 0..K {
        store.observe(&format!("v{i}"), &probe(), 1 + i as u64);
    }
    assert_eq!(store.candidates(&probe()).len(), K);
}

fn assert_only_newcomer(store: &FuzzyStore) {
    let recalled = store.candidates(&probe());
    assert!(recalled.contains("new"), "newcomer starved: {recalled:?}");
    for i in 0..K {
        assert!(!recalled.contains(&format!("v{i}")), "v{i} still indexed");
    }
}

#[test]
fn cap_eviction_frees_the_hot_block() {
    let store = store(EvictionPolicy {
        max_records: Some(K),
        ..EvictionPolicy::default()
    });
    fill(&store);
    // Each newcomer evicts the oldest visitor; the last one evicts the last
    // filler, so the block holds only the newcomers.
    for i in 0..K - 1 {
        store.observe(&format!("n{i}"), &probe(), 100 + i as u64);
    }
    store.observe("new", &probe(), 200);
    assert_only_newcomer(&store);
    assert_eq!(store.dropped(), 0);
}

#[test]
fn ttl_eviction_frees_the_hot_block() {
    let store = store(EvictionPolicy {
        record_ttl_ms: Some(10),
        ..EvictionPolicy::default()
    });
    fill(&store);
    store.observe("new", &probe(), 1_000);
    assert_only_newcomer(&store);
    assert_eq!(store.candidates(&probe()).len(), 1);
    assert_eq!(store.dropped(), 0);
}

#[test]
fn retention_purge_frees_the_hot_block() {
    let store = store(EvictionPolicy::default());
    fill(&store);
    assert_eq!(store.purge_expired(1_000, 10), K as u64);
    store.observe("new", &probe(), 1_000);
    assert_only_newcomer(&store);
    assert_eq!(store.candidates(&probe()).len(), 1);
    assert_eq!(store.dropped(), 0);
}

#[test]
fn erase_frees_the_hot_block() {
    let store = store(EvictionPolicy::default());
    fill(&store);
    for i in 0..K {
        assert!(store.erase(&format!("v{i}")));
    }
    store.observe("new", &probe(), 1_000);
    assert_only_newcomer(&store);
    assert_eq!(store.candidates(&probe()).len(), 1);
    assert_eq!(store.dropped(), 0);
}

#[test]
fn removed_visitors_leave_no_index_rows() {
    let store = store(EvictionPolicy {
        max_records: Some(2),
        record_ttl_ms: Some(1_000),
        ..EvictionPolicy::default()
    });
    let per_record = store.blocking_key_hexes(&probe()).len();

    // Cap: three visitors, cap 2 → one evicted, its rows gone.
    store.observe("a", &probe(), 1);
    store.observe("b", &probe(), 2);
    store.observe("c", &probe(), 3);
    assert_eq!(store.evicted(), 1);
    assert_eq!(store.blocking_rows(), 2 * per_record);

    // Erase: one live record left.
    assert!(store.erase("b"));
    assert_eq!(store.blocking_rows(), per_record);

    // TTL: `c` ages out when `d` is observed far later.
    store.observe("d", &probe(), 10_000);
    assert!(store.record("c").is_none());
    assert_eq!(store.blocking_rows(), per_record);

    // Retention purge: nothing live, nothing indexed.
    assert_eq!(store.purge_expired(100_000, 10), 1);
    assert_eq!(store.blocking_rows(), 0);
    assert!(store.candidates(&probe()).is_empty());
}

#[test]
fn drifting_visitor_keeps_only_its_current_keys() {
    let store = FuzzyStore::new();
    for i in 0..100u64 {
        let mut drifted = probe();
        // Fonts and the K2 group values change every observation.
        drifted.fonts = Some((0..5).map(|f| format!("Font-{i}-{f}")).collect());
        drifted.audio = Some(format!("{i}.5"));
        store.observe("v", &drifted, 1_000 + i);

        let record = store.record("v").unwrap();
        assert_eq!(record.keys.len(), store.blocking_key_hexes(&drifted).len());
        assert_eq!(store.blocking_rows(), record.keys.len());
    }
    let mut last = probe();
    last.fonts = Some((0..5).map(|f| format!("Font-99-{f}")).collect());
    last.audio = Some("99.5".into());
    assert!(store.candidates(&last).contains("v"));
}

#[test]
fn rows_never_exceed_live_records_times_keys_per_record() {
    let store = store(EvictionPolicy {
        max_records: Some(50),
        ..EvictionPolicy::default()
    });
    let mut max_keys = 0;
    for i in 0..500u64 {
        let mut p = probe();
        p.webgl = Some(format!("GPU {}", i % 70));
        p.fonts = Some((0..5).map(|f| format!("F{}-{f}", i % 13)).collect());
        max_keys = max_keys.max(store.blocking_key_hexes(&p).len());
        store.observe(&format!("v{}", i % 120), &p, i);
        assert!(store.blocking_rows() <= 50 * max_keys);
    }
}

#[test]
fn cap_eviction_at_ten_thousand_records_stays_fast() {
    let mut records = RecordStore::with_capacity(Some(10_000), None);
    let start = std::time::Instant::now();
    for i in 0..100_000u64 {
        let id = format!("v{i}");
        records.upsert(&id, BTreeMap::new(), i);
        records.evict(&id, i);
    }
    assert_eq!(records.len(), 10_000);
    assert_eq!(records.evicted(), 90_000);
    // A per-eviction scan of 10k records (9e8 visits) would take far longer.
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
}
