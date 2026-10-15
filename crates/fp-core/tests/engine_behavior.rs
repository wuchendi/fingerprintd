//! End-to-end behavior tests for the fuzzy-matching engine, exercising only the
//! crate's public API (`FuzzyStore::{new, identify, identify_with_ip, score}`,
//! `Decision`, `MatchOutcome`, `VelocityBand`). The private-internal unit tests
//! stay inline in `src/fuzzy/engine.rs`.

use fingerprintd::fuzzy::{Decision, FuzzyStore, VelocityBand};
use serde_json::{Value, json};

/// A full, high-signal probe (8 components across all three kinds).
fn full_probe() -> Value {
    json!({
        "webgl": "ANGLE (Intel)",
        "platform": "Linux x86_64",
        "timezone": "Asia/Shanghai",
        "audio": "124.04",
        "cpu_cores": 8,
        "device_memory": 8,
        "fonts": ["Arial", "Helvetica", "Courier", "Times", "Verdana"],
        "user_agent": "Chrome/120",
    })
}

/// A distinct full probe per index: every high-stability discriminant differs,
/// so each recalls no prior device and is minted as a brand-new device — the
/// fresh-seed-per-launch farm's per-session footprint.
fn distinct_probe(i: u64) -> Value {
    json!({
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
        "user_agent": format!("Agent/{i}"),
    })
}

/// (a) De-avalanche: a single browser upgrade plus one changed font must not
/// mint a new device — the stable components carry the match (fuzzy-matching §5/§8).
#[test]
fn a_single_component_drift_stays_the_same_device() {
    let store = FuzzyStore::new();
    let first = store.identify(&full_probe(), 1_000);
    assert!(first.is_new_device);

    // Browser auto-upgraded (UA) and one font swapped: everything stable is
    // unchanged, so the FS score clears T_hi and the id is preserved.
    let mut drifted = full_probe();
    drifted["user_agent"] = json!("Chrome/121");
    drifted["fonts"] = json!(["Arial", "Helvetica", "Courier", "Times", "Segoe"]);
    let second = store.identify(&drifted, 2_000);

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
    let a = privacy.identify(
        &json!({ "webgl": "GPU-A", "platform": "Linux", "timezone": "UTC", "canvas": null }),
        1_000,
    );
    let b = privacy.identify(
        &json!({ "webgl": "GPU-B", "platform": "Windows", "timezone": "GMT", "canvas": null }),
        2_000,
    );
    assert!(a.is_new_device && b.is_new_device);
    assert_ne!(a.visitor_id, b.visitor_id);

    // Completeness: a full match is more confident than a match resting on
    // only a few components.
    let store = FuzzyStore::new();
    store.identify(&full_probe(), 1_000);
    let full = store.identify(&full_probe(), 2_000);
    assert_eq!(full.decision, Decision::Match);

    // A sparse probe carrying only three of the stable components.
    let sparse = json!({
        "webgl": "ANGLE (Intel)",
        "platform": "Linux x86_64",
        "timezone": "Asia/Shanghai",
    });
    let partial = store.identify(&sparse, 3_000);
    assert!(partial.compared_components < full.compared_components);
    assert!(
        partial.confidence < full.confidence,
        "partial {} should be below full {}",
        partial.confidence,
        full.confidence,
    );
}

/// (RT-001) Fresh-seed-per-launch farming footprint — pinned regression
/// baseline. The `CloakBrowser` adversary re-seeds its fingerprint on every
/// launch, so successive sessions present fully distinct high-stability
/// components (webgl/platform/timezone/…). Each one lands in its own blocking
/// keys, recalls no prior device, and is minted as a brand-new device. That is
/// exactly the footprint of an account farm — many "new devices" in quick
/// succession — and it is invisible to this per-session engine by design. The
/// cross-session velocity signal (RT-003) is what catches this pattern; this
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
        json!({
            "webgl": "ANGLE (NVIDIA GeForce RTX 3060)",
            "platform": "Win32",
            "timezone": "America/Chicago",
            "audio": "124.11",
            "cpu_cores": 12,
            "device_memory": 16,
            "fonts": ["Arial", "Calibri", "Segoe UI", "Tahoma"],
            "user_agent": "Chrome/126",
        }),
        json!({
            "webgl": "ANGLE (AMD Radeon RX 6800)",
            "platform": "MacIntel",
            "timezone": "Europe/Berlin",
            "audio": "121.37",
            "cpu_cores": 8,
            "device_memory": 8,
            "fonts": ["Helvetica", "SF Pro", "Menlo", "Geneva"],
            "user_agent": "Chrome/126",
        }),
        json!({
            "webgl": "ANGLE (Intel Iris Xe)",
            "platform": "Linux x86_64",
            "timezone": "Asia/Tokyo",
            "audio": "119.82",
            "cpu_cores": 4,
            "device_memory": 4,
            "fonts": ["Roboto", "Noto Sans", "Ubuntu", "DejaVu Sans"],
            "user_agent": "Chrome/126",
        }),
    ];

    let mut ids = HashSet::new();
    for (i, probe) in launches.iter().enumerate() {
        let out = store.identify(probe, 1_000 + i as u64 * 1_000);
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
/// [`VelocityBand::Low`], and the outcome equals the plain `identify` path.
#[test]
fn no_client_ip_stays_low_and_neutral() {
    let store = FuzzyStore::new();
    let probe = distinct_probe(1);
    let out = store.identify_with_ip(&probe, 1_000_000, None);
    assert_eq!(out.new_device_velocity, VelocityBand::Low);
    assert!((out.confidence - 0.5).abs() < 1e-9);

    // A brand-new IP that later mints a single device is Low (below MEDIUM).
    let other = distinct_probe(2);
    let banded = store.identify_with_ip(&other, 1_000_100, Some("198.51.100.7"));
    assert_eq!(banded.new_device_velocity, VelocityBand::Low);
}

/// Cold-start invariance: on a fresh store, the first `identify` is unchanged
/// for every field that existed before RT-003 (decision / visitorId /
/// `is_new_device`), and the new band defaults to [`VelocityBand::Low`] — so an
/// empty velocity store is bit-identical to today and the delegating `identify`
/// matches an explicit no-IP `identify_with_ip`.
#[test]
fn cold_start_is_neutral_and_identify_delegates_to_no_ip() {
    let probe = full_probe();

    let via_identify = FuzzyStore::new().identify(&probe, 1_000);
    let via_no_ip = FuzzyStore::new().identify_with_ip(&probe, 1_000, None);

    assert_eq!(via_identify.decision, Decision::NewDevice);
    assert_eq!(via_identify.new_device_velocity, VelocityBand::Low);
    // The two paths agree on the pre-existing identity fields and confidence.
    assert_eq!(via_identify.decision, via_no_ip.decision);
    assert_eq!(via_identify.visitor_id, via_no_ip.visitor_id);
    assert_eq!(via_identify.is_new_device, via_no_ip.is_new_device);
    assert!((via_identify.confidence - via_no_ip.confidence).abs() < f64::EPSILON);
}

/// A realistic SDK-shaped phone payload (real Android Chrome value shapes):
/// `n` varies every device-distinctive component (GPU, canvas, audio, the
/// hashed `FingerprintJS` objects, screen), while the low-entropy values every
/// phone in one city shares stay identical — booleans, colour depth, locale,
/// timezone, cores, memory, the constant Android font probe, no plugins.
fn phone(n: u64) -> Value {
    let h = |tag: &str| format!("{tag}{n:0>31}");
    json!({
        "userAgentData": h("u"), "fontPreferences": h("f"), "screenFrame": h("s"),
        "math": h("m"), "canvas": h("c"), "webgl_extensions": h("x"),
        "touchSupport": h("t"), "domBlockers": h("d"),
        "webgl": format!("Google Inc. (Vendor {})|ANGLE (GPU {n})", n % 7),
        "audio": format!("124.{n}"),
        "screen": format!("{}x{}", 800 + n % 50, 380 + n % 20),
        "colorDepth": 24, "sessionStorage": true, "localStorage": true,
        "indexedDB": true, "openDatabase": false, "vendor": "Google Inc.",
        "vendorFlavors": "chrome", "cookiesEnabled": true, "colorGamut": "srgb",
        "forcedColors": false, "monochrome": 0, "contrast": 0,
        "reducedMotion": false, "reducedTransparency": false, "hdr": false,
        "pdfViewerEnabled": false, "architecture": 127, "applePay": -1,
        "audioBaseLatency": 0.003, "dateTimeLocale": "zh-CN",
        "languages": "zh-CN", "timezone": "Asia/Shanghai",
        "platform": "Linux armv81", "cpu_cores": 8, "device_memory": 8,
        "fonts": ["sans-serif-thin"], "plugins": [],
    })
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
        let out = store.identify(&phone(1_000_000), 2_000);
        assert_eq!(
            out.decision,
            Decision::NewDevice,
            "library of {size}: stranger scored {:?} against {}",
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
        let first = store.identify(&phone(1_000_000), 2_000);
        let again = store.identify(&phone(1_000_000), 3_000);
        assert_eq!(
            again.decision,
            Decision::Match,
            "library of {size}: {:?}",
            again.score
        );
        assert_eq!(again.visitor_id, first.visitor_id);
    }
}
