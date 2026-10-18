//! Fixture-driven behaviour tests against REAL `CloakBrowser` captures.
//!
//! The JSON files under `tests/fixtures/cloakbrowser/` were produced by the
//! adversarial capture harness (`scripts/redteam/cloak/run.sh`): the actual client SDK
//! collector (`FingerprintJS` + `BotD`) run inside the `CloakBrowser` free binary
//! (Chromium 146, Windows persona, several `--fingerprint` seeds) and inside
//! stock Chromium 149 as the negative control. These tests pin what the engine
//! does with that material — they document behaviour, they do not assert a
//! desired end state.
//!
//! Each capture's `components` is the raw collector output reduced to the closed
//! schema with the SDK adapter's mapping (`hardwareConcurrency` → `cpu_cores`,
//! `webGlBasics` → `webgl`, `screenResolution` → `screen`, …): only schema keys
//! are kept, every other `FingerprintJS` key is dropped, `plugins` keeps the
//! plugin names, and an object/array value for a category key would become its
//! compact JSON with sorted object keys (no capture carries one). What survives
//! here is `platform`, `timezone`, `audio`, `cpu_cores`, `device_memory`,
//! `fonts`, and `plugins`. The claimed UA is the capture's top-level
//! `user_agent`.

// Test-only fixture loading: a missing or malformed capture must abort loudly.
#![allow(clippy::expect_used, clippy::panic)]

use std::{fs, path::PathBuf};

use fingerprintd::{
    fuzzy::{Components, Decision, FuzzyStore, IdentifyContext, MatchOutcome},
    signals::{PersonaCoherence, persona_coherence},
};
use serde::Deserialize;

fn identify(store: &FuzzyStore, components: &Components, now_ms: u64) -> MatchOutcome {
    store.identify(&IdentifyContext {
        components,
        now_ms,
        client_ip: None,
    })
}

#[derive(Deserialize)]
struct Capture {
    meta: Meta,
    user_agent: String,
    components: Components,
}

#[derive(Deserialize)]
struct Meta {
    label: String,
    mode: String,
    seed: Option<String>,
}

fn fixtures() -> Vec<Capture> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cloakbrowser");
    let mut out: Vec<Capture> = fs::read_dir(&dir)
        .expect("fixtures dir")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| {
            serde_json::from_slice(&fs::read(&p).expect("read fixture")).expect("parse fixture")
        })
        .collect();
    out.sort_by(|a, b| a.meta.label.cmp(&b.meta.label));
    assert!(
        out.len() >= 7,
        "expected the curated capture set, found {}",
        out.len()
    );
    out
}

fn by_label<'a>(all: &'a [Capture], label: &str) -> &'a Capture {
    all.iter()
        .find(|c| c.meta.label == label)
        .unwrap_or_else(|| panic!("missing fixture {label}"))
}

/// The binary's fingerprint is a deterministic function of the seed.
/// Two independent launches with `--fingerprint=12345` hand the SDK identical
/// `components`, and the engine recalls the same device at full match.
#[test]
fn same_seed_captures_are_identical_and_match_the_same_device() {
    let all = fixtures();
    let a = by_label(&all, "cloak-windows-seed-12345-a");
    let b = by_label(&all, "cloak-windows-seed-12345-b");
    assert_eq!(a.components, b.components);

    let store = FuzzyStore::new();
    let first = identify(&store, &a.components, 1_000);
    let second = identify(&store, &b.components, 2_000);
    assert!(first.is_new_device);
    assert_eq!(second.decision, Decision::Match);
    assert!(!second.is_new_device);
    assert_eq!(second.visitor_id, first.visitor_id);
}

/// These captures carry no `canvas` / `webgl` / `screen` (the collector that
/// produced them did not emit them), and the Linux container exposes none of
/// the fonts `FingerprintJS` probes. What reaches the engine from a re-seeded
/// `CloakBrowser` launch therefore differs from the previous seed in `audio`
/// ONLY. This test pins how the engine treats that worst case: `audio` is a
/// high-stability blocking key, so each re-seeded launch misses recall and is
/// minted as a brand-new device — the fresh-seed farm footprint the velocity
/// signal counts.
#[test]
fn distinct_seeds_differ_only_in_audio_and_each_mint_a_new_device() {
    let all = fixtures();
    let seeds: Vec<&Capture> = all
        .iter()
        .filter(|c| c.meta.mode == "cloak" && c.meta.seed.as_deref() != Some("off"))
        .filter(|c| !c.meta.label.ends_with("-b"))
        .collect();
    assert!(seeds.len() >= 3, "need several distinct seeds");

    let base = serde_json::to_value(&seeds[0].components).expect("serialize");
    let base = base.as_object().expect("object");
    for other in &seeds[1..] {
        let obj = serde_json::to_value(&other.components).expect("serialize");
        let obj = obj.as_object().expect("object");
        assert_eq!(base.len(), obj.len(), "{}", other.meta.label);
        let differing: Vec<&String> = base
            .iter()
            .filter(|(k, v)| obj.get(*k) != Some(v))
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            differing,
            vec!["audio"],
            "{} vs {}",
            seeds[0].meta.label,
            other.meta.label
        );
    }

    let store = FuzzyStore::new();
    let mut ids = Vec::new();
    for (i, capture) in seeds.iter().enumerate() {
        let outcome = identify(&store, &capture.components, 1_000 + i as u64);
        assert_eq!(
            outcome.decision,
            Decision::NewDevice,
            "{}",
            capture.meta.label
        );
        assert!(outcome.is_new_device, "{}", capture.meta.label);
        assert!(!ids.contains(&outcome.visitor_id), "{}", capture.meta.label);
        ids.push(outcome.visitor_id);
    }
}

/// Negative control: stock Chromium on the same host is a different device from
/// every `CloakBrowser` capture (platform, device memory and audio all differ), so
/// the cloak material does not over-link onto a genuine browser.
#[test]
fn stock_controls_never_link_to_a_cloak_capture() {
    let all = fixtures();
    let store = FuzzyStore::new();
    let mut cloak_ids = Vec::new();
    for c in all.iter().filter(|c| c.meta.mode == "cloak") {
        cloak_ids.push(identify(&store, &c.components, 1_000).visitor_id);
    }
    for c in all.iter().filter(|c| c.meta.mode == "stock") {
        let outcome = identify(&store, &c.components, 5_000);
        assert!(
            !cloak_ids.contains(&outcome.visitor_id),
            "{} linked to a cloak device",
            c.meta.label
        );
    }
}

/// The Windows persona exposes none of the fonts every real Windows
/// has (the container hides the host's Linux fonts but adds no Windows ones), so
/// the UA↔fonts cross-check reads `mismatch` on every Windows-persona capture.
/// Stock Linux Chromium is outside the curated OS set → `unknown`, never a
/// false mismatch.
#[test]
fn windows_persona_captures_are_persona_mismatches_and_stock_linux_is_unknown() {
    let all = fixtures();
    for c in all.iter().filter(|c| c.meta.mode == "cloak") {
        let fonts = c.components.fonts.as_deref();
        let expected = if c.user_agent.contains("Windows NT") {
            PersonaCoherence::Mismatch
        } else {
            // `--fingerprint=off` keeps the host's Linux UA.
            PersonaCoherence::Unknown
        };
        assert_eq!(
            persona_coherence(Some(&c.user_agent), fonts),
            expected,
            "{}",
            c.meta.label
        );
    }
    for c in all.iter().filter(|c| c.meta.mode == "stock") {
        assert_eq!(
            persona_coherence(Some(&c.user_agent), c.components.fonts.as_deref()),
            PersonaCoherence::Unknown,
            "{}",
            c.meta.label
        );
    }
}
