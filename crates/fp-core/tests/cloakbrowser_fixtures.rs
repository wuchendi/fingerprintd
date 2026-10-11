//! Fixture-driven behaviour tests against REAL `CloakBrowser` captures.
//!
//! The JSON files under `tests/fixtures/cloakbrowser/` were produced by the
//! red-team harness (`scripts/redteam/cloak/run.sh`): the actual client SDK
//! collector (`FingerprintJS` + `BotD`, adapted to the server schema) run inside
//! the `CloakBrowser` free binary (Chromium 146, Windows persona, several
//! `--fingerprint` seeds) and inside stock Chromium 149 as the negative
//! control. `stable_components` in each file is byte-for-byte what `/identify`
//! would receive. These tests pin what the engine does with that material
//! today — they document behaviour, they do not assert a desired end state.

// Test-only fixture loading: a missing or malformed capture must abort loudly.
#![allow(clippy::expect_used, clippy::panic)]

use std::{fs, path::PathBuf};

use fingerprintd::{
    fuzzy::{Decision, FuzzyStore},
    signals::{PersonaCoherence, persona_coherence},
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Capture {
    meta: Meta,
    user_agent: String,
    stable_components: Value,
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
/// `stable_components`, and the engine recalls the same device at full match.
#[test]
fn same_seed_captures_are_identical_and_match_the_same_device() {
    let all = fixtures();
    let a = by_label(&all, "cloak-windows-seed-12345-a");
    let b = by_label(&all, "cloak-windows-seed-12345-b");
    assert_eq!(a.stable_components, b.stable_components);

    let store = FuzzyStore::new();
    let first = store.identify(&a.stable_components, 1_000);
    let second = store.identify(&b.stable_components, 2_000);
    assert!(first.is_new_device);
    assert_eq!(second.decision, Decision::Match);
    assert!(!second.is_new_device);
    assert_eq!(second.visitor_id, first.visitor_id);
}

/// The adapter drops `FingerprintJS's` object-valued `canvas` / `webGlBasics` and
/// the array-valued `screenResolution` (documented follow-up in
/// `packages/client/src/adapter.ts`), and the Linux container exposes none of
/// the fonts `FingerprintJS` probes. What reaches the engine from a re-seeded
/// `CloakBrowser` launch therefore differs from the previous seed in `audio`
/// ONLY — every other stored component is identical. This test pins how the
/// engine treats that: `audio` is a high-stability blocking key, so each
/// re-seeded launch misses recall and is minted as a brand-new device — the
/// fresh-seed farm footprint the velocity signal counts. Load-bearing caveat:
/// the whole per-seed distinction rides on ONE component today; canvas/webgl
/// entropy only enters matching once the adapter canonicalizes those objects.
#[test]
fn distinct_seeds_differ_only_in_audio_and_each_mint_a_new_device() {
    let all = fixtures();
    let seeds: Vec<&Capture> = all
        .iter()
        .filter(|c| c.meta.mode == "cloak" && c.meta.seed.as_deref() != Some("off"))
        .filter(|c| !c.meta.label.ends_with("-b"))
        .collect();
    assert!(seeds.len() >= 3, "need several distinct seeds");

    let base = seeds[0].stable_components.as_object().expect("object");
    for other in &seeds[1..] {
        let obj = other.stable_components.as_object().expect("object");
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
        let outcome = store.identify(&capture.stable_components, 1_000 + i as u64);
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
        cloak_ids.push(store.identify(&c.stable_components, 1_000).visitor_id);
    }
    for c in all.iter().filter(|c| c.meta.mode == "stock") {
        let outcome = store.identify(&c.stable_components, 5_000);
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
        let fonts = c.stable_components.get("fonts");
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
            persona_coherence(Some(&c.user_agent), c.stable_components.get("fonts")),
            PersonaCoherence::Unknown,
            "{}",
            c.meta.label
        );
    }
}
