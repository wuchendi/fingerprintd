//! End-to-end behavior tests for the fuzzy-matching engine, exercising only the
//! crate's public API (`FuzzyStore::{new, identify, score}`, `IdentifyContext`,
//! `Decision`, `MatchOutcome`, `VelocityBand`). The private-internal unit tests
//! stay inline in `src/fuzzy/engine.rs`.

use fingerprintd::fuzzy::{
    Components, Decision, FuzzyStore, IdentifyContext, MatchOutcome, VelocityBand,
};
use serde_json::{Value, json};

#[allow(clippy::expect_used)] // test-only: a malformed literal must abort loudly
fn components(value: Value) -> Components {
    serde_json::from_value(value).expect("schema components")
}

fn identify(store: &FuzzyStore, components: &Components, now_ms: u64) -> MatchOutcome {
    identify_from(store, components, now_ms, None)
}

fn identify_from(
    store: &FuzzyStore,
    components: &Components,
    now_ms: u64,
    client_ip: Option<&str>,
) -> MatchOutcome {
    store.identify(&IdentifyContext {
        components,
        now_ms,
        client_ip,
    })
}

/// A full, high-signal probe (8 components across all three kinds).
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

/// A distinct full probe per index: every high-stability discriminant differs,
/// so each recalls no prior device and is minted as a brand-new device — the
/// fresh-seed-per-launch farm's per-session footprint.
fn distinct_probe(i: u64) -> Components {
    components(json!({
        "webgl": format!("ANGLE (Vendor {i})"),
        "platform": format!("Platform-{i}"),
        "timezone": format!("Zone/{i}"),
        "audio": format!("12{i}.5"),
        "cpu_cores": 4 + i,
        "device_memory": 4 + i,
        "fonts": [
            format!("F{i}a"), format!("F{i}b"), format!("F{i}c"),
            format!("F{i}d"), format!("F{i}e"),
        ],
        "canvas": format!("canvas-{i}"),
    }))
}

/// (a) De-avalanche: a re-noised canvas plus one changed font must not
/// mint a new device — the stable components carry the match (fuzzy-matching §5/§8).
#[test]
fn a_single_component_drift_stays_the_same_device() {
    let store = FuzzyStore::new();
    let first = identify(&store, &full_probe(), 1_000);
    assert!(first.is_new_device);

    // Canvas re-noised and one font swapped: everything stable is unchanged,
    // so the FS score clears T_hi and the id is preserved.
    let mut drifted = full_probe();
    drifted.canvas = Some("beef".into());
    drifted.fonts = Some(
        ["Arial", "Helvetica", "Courier", "Times", "Segoe"]
            .map(String::from)
            .to_vec(),
    );
    let second = identify(&store, &drifted, 2_000);

    assert_eq!(second.decision, Decision::Match);
    assert!(!second.is_new_device);
    assert_eq!(second.visitor_id, first.visitor_id);
    assert!(
        second.confidence > 0.7,
        "confidence was {}",
        second.confidence
    );
}

/// (d) Missing components: a null canvas (privacy browser) is never a
/// matchable value, so two distinct privacy devices do not collide on it; and
/// a match built from fewer components is less confident (fuzzy-matching §6/§8).
#[test]
fn d_missing_components_neither_collide_nor_inflate_confidence() {
    // A null canvas must not link two otherwise-distinct privacy devices.
    let privacy = FuzzyStore::new();
    let a = identify(
        &privacy,
        &components(
            json!({ "webgl": "GPU-A", "platform": "Linux", "timezone": "UTC", "canvas": null }),
        ),
        1_000,
    );
    let b = identify(
        &privacy,
        &components(
            json!({ "webgl": "GPU-B", "platform": "Windows", "timezone": "GMT", "canvas": null }),
        ),
        2_000,
    );
    assert!(a.is_new_device && b.is_new_device);
    assert_ne!(a.visitor_id, b.visitor_id);

    // Completeness: a full match is more confident than a match resting on
    // only a few components.
    let store = FuzzyStore::new();
    identify(&store, &full_probe(), 1_000);
    let full = identify(&store, &full_probe(), 2_000);
    assert_eq!(full.decision, Decision::Match);

    // A sparse probe carrying only three of the stable components.
    let sparse = components(json!({
        "webgl": "ANGLE (Intel)",
        "platform": "Linux x86_64",
        "timezone": "Asia/Shanghai",
    }));
    let partial = identify(&store, &sparse, 3_000);
    assert!(partial.compared_components < full.compared_components);
    assert!(
        partial.confidence < full.confidence,
        "partial {} should be below full {}",
        partial.confidence,
        full.confidence,
    );
}

/// Fresh-seed-per-launch farming footprint — pinned regression
/// baseline. The `CloakBrowser` adversary re-seeds its fingerprint on every
/// launch, so successive sessions present fully distinct high-stability
/// components (webgl/platform/timezone/…). Each one lands in its own blocking
/// keys, recalls no prior device, and is minted as a brand-new device. That is
/// exactly the footprint of an account farm — many "new devices" in quick
/// succession — and it is invisible to this per-session engine by design. The
/// cross-session velocity signal is what catches this pattern; this
/// test documents the current per-session behaviour so the gap is a visible
/// baseline, not folklore.
#[test]
fn fresh_seed_per_launch_each_mints_a_new_device() {
    use std::collections::HashSet;

    let store = FuzzyStore::new();
    // Three launches of the same stealth build, each with a freshly re-seeded
    // fingerprint: every high-stability discriminant differs, so the blocking
    // keys are disjoint and no launch recalls another.
    let launches = [
        components(json!({
            "webgl": "ANGLE (NVIDIA GeForce RTX 3060)",
            "platform": "Win32",
            "timezone": "America/Chicago",
            "audio": "124.11",
            "cpu_cores": 12,
            "device_memory": 16,
            "fonts": ["Arial", "Calibri", "Segoe UI", "Tahoma"],
        })),
        components(json!({
            "webgl": "ANGLE (AMD Radeon RX 6800)",
            "platform": "MacIntel",
            "timezone": "Europe/Berlin",
            "audio": "121.37",
            "cpu_cores": 8,
            "device_memory": 8,
            "fonts": ["Helvetica", "SF Pro", "Menlo", "Geneva"],
        })),
        components(json!({
            "webgl": "ANGLE (Intel Iris Xe)",
            "platform": "Linux x86_64",
            "timezone": "Asia/Tokyo",
            "audio": "119.82",
            "cpu_cores": 4,
            "device_memory": 4,
            "fonts": ["Roboto", "Noto Sans", "Ubuntu", "DejaVu Sans"],
        })),
    ];

    let mut ids = HashSet::new();
    for (i, probe) in launches.iter().enumerate() {
        let out = identify(&store, probe, 1_000 + i as u64 * 1_000);
        assert_eq!(out.decision, Decision::NewDevice, "launch {i}");
        assert!(out.is_new_device, "launch {i} should mint a new device");
        assert!(
            ids.insert(out.visitor_id),
            "launch {i} produced a duplicate visitor_id",
        );
    }
    // Every re-seeded launch is a distinct "new device" to this engine.
    assert_eq!(ids.len(), launches.len());
}

/// A `None` client IP is neutral: no event is recorded, the band stays
/// [`VelocityBand::Low`].
#[test]
fn no_client_ip_stays_low_and_neutral() {
    let store = FuzzyStore::new();
    let probe = distinct_probe(1);
    let out = identify_from(&store, &probe, 1_000_000, None);
    assert_eq!(out.new_device_velocity, VelocityBand::Low);
    assert!((out.confidence - 0.5).abs() < 1e-9);

    // A brand-new IP that later mints a single device is Low (below MEDIUM).
    let other = distinct_probe(2);
    let banded = identify_from(&store, &other, 1_000_100, Some("198.51.100.7"));
    assert_eq!(banded.new_device_velocity, VelocityBand::Low);
}

/// Cold-start invariance: on a fresh store, the first `identify` is a
/// `NewDevice` whose velocity band defaults to [`VelocityBand::Low`] — an empty
/// velocity store is neutral — with or without a client IP.
#[test]
fn cold_start_is_neutral() {
    let probe = full_probe();

    let no_ip = identify(&FuzzyStore::new(), &probe, 1_000);
    let with_ip = identify_from(&FuzzyStore::new(), &probe, 1_000, Some("198.51.100.7"));

    for out in [&no_ip, &with_ip] {
        assert_eq!(out.decision, Decision::NewDevice);
        assert!(out.is_new_device);
        assert_eq!(out.new_device_velocity, VelocityBand::Low);
    }
    assert!((no_ip.confidence - with_ip.confidence).abs() < f64::EPSILON);
}

/// A realistic SDK-shaped phone payload (real Android Chrome value shapes):
/// `n` varies every device-distinctive component (GPU, canvas, audio, the
/// hashed `FingerprintJS` objects, screen), while the low-entropy values every
/// phone in one city shares stay identical — locale,
/// timezone, platform, cores, memory, the constant Android font probe, no
/// plugins.
fn phone(n: u64) -> Components {
    let h = |tag: &str| format!("{tag}{n:0>31}");
    components(json!({
        "user_agent_data": h("u"), "font_preferences": h("f"), "screen_frame": h("s"),
        "math": h("m"), "canvas": h("c"), "webgl_extensions": h("x"),
        "touch_support": h("t"), "dom_blockers": h("d"),
        "webgl": format!("Google Inc. (Vendor {})|ANGLE (GPU {n})", n % 7),
        "audio": format!("124.{n}"),
        "screen": format!("{}x{}", 800 + n % 50, 380 + n % 20),
        "languages": "zh-CN", "timezone": "Asia/Shanghai",
        "platform": "Linux armv81", "cpu_cores": 8, "device_memory": 8,
        "fonts": ["sans-serif-thin"], "plugins": [],
    }))
}

/// A device that shares only the city-wide common values with the library must
/// never be merged into an existing visitor, however many look-alikes the
/// library holds: agreeing on what every phone agrees on is no evidence.
#[test]
fn stranger_sharing_only_common_values_is_new_device_at_any_library_size() {
    for size in [1_u64, 10, 100, 500] {
        let store = FuzzyStore::new();
        for n in 0..size {
            store.observe(&format!("p{n}"), &phone(n), 1_000);
        }
        let out = identify(&store, &phone(1_000_000), 2_000);
        assert_eq!(
            out.decision,
            Decision::NewDevice,
            "library of {size}: stranger scored {:?} against {:?}",
            out.score,
            out.visitor_id
        );
    }
}

/// The fix must not cost recall: the same phone revisiting is still matched,
/// from a library holding only itself up to one crowded with look-alikes.
#[test]
fn same_phone_revisit_matches_at_any_library_size() {
    for size in [0_u64, 10, 100, 500] {
        let store = FuzzyStore::new();
        for n in 0..size {
            store.observe(&format!("p{n}"), &phone(n), 1_000);
        }
        let first = identify(&store, &phone(1_000_000), 2_000);
        let again = identify(&store, &phone(1_000_000), 3_000);
        assert_eq!(
            again.decision,
            Decision::Match,
            "library of {size}: {:?}",
            again.score
        );
        assert_eq!(again.visitor_id, first.visitor_id);
    }
}
