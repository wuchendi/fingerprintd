//! Native parity vectors for the matching engine.
//!
//! The native server and the edge Worker (`crates/fp-wasm` scoring over salted
//! stored templates the host persists) are two deployments of ONE engine. This
//! test drives the vectors in `tests/fixtures/parity.json` (closed component
//! schema) through the native [`FuzzyStore::identify`] path and asserts the
//! committed `expect` block; `crates/fp-wasm` drives the same fixture through
//! the stored-form edge path. A changed threshold, a different salt derivation,
//! or a broken serialization boundary fails against the pinned reference.
//! Minted ids are random, so visitors are asserted by symbolic label.
//!
//! The store is seeded from the fixture's `salt_secret`, because blocking-key
//! derivation and stored hashing are only reproducible across isolates when the
//! salt is deterministic (native production uses a per-process random salt; the
//! parity claim is "same secret ⇒ same identity/decision/confidence").
//!
//! Run with `-- --nocapture` to print the outcomes the engine computed, which is
//! how the fixture's `expect` values are regenerated when the engine changes.

use std::collections::HashMap;

use fingerprintd::fuzzy::{Components, FuzzyStore, IdentifyContext};
use serde::Deserialize;

/// The whole fixture: shared salt, tolerance, named component objects, scenarios.
#[derive(Debug, Deserialize)]
struct Fixture {
    salt_secret: String,
    confidence_tolerance: f64,
    components: HashMap<String, Components>,
    scenarios: Vec<Scenario>,
}

/// One independent scenario, run against a fresh store.
#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    steps: Vec<Step>,
}

/// One `/identify` step: which named component object to send, and what to expect.
#[derive(Debug, Deserialize)]
struct Step {
    input: String,
    expect: Expect,
}

/// The parity assertion for a step.
#[derive(Debug, Deserialize)]
struct Expect {
    decision: String,
    is_new_device: bool,
    /// Symbolic visitor label: steps sharing a label resolve to one id, and
    /// distinct labels to distinct ids.
    visitor: String,
    collision_risk: bool,
    confidence: f64,
    template_jump: bool,
}

/// The native parity fixture.
const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/parity.json");

#[test]
fn native_engine_matches_shared_parity_vectors() {
    let raw = std::fs::read_to_string(FIXTURE_PATH).expect("read parity fixture");
    let fixture: Fixture = serde_json::from_str(&raw).expect("parse parity fixture");
    let secret = fixture.salt_secret.as_bytes();
    let tol = fixture.confidence_tolerance;

    for scenario in &fixture.scenarios {
        println!("=== {} ===", scenario.name);
        // A fresh deterministic store per scenario.
        let store = FuzzyStore::deterministic(secret);
        // label -> resolved id, so a `match`/`review` step must reuse the id the
        // earlier `new_device` step minted.
        let mut visitors: HashMap<String, String> = HashMap::new();

        for (i, step) in scenario.steps.iter().enumerate() {
            let components = fixture
                .components
                .get(&step.input)
                .expect("fixture step references a known component input");
            // Timestamps only stamp record freshness; they do not affect identity,
            // decision, or confidence. Use the step index so runs are reproducible.
            let now = (i as u64 + 1) * 1000;
            let outcome = store.identify(&IdentifyContext {
                components,
                now_ms: now,
                client_ip: None,
            });
            let visitor_id = outcome.visitor_id.clone().expect("identify resolves an id");

            println!(
                "{}.{i} decision={} new={} vid={} conf={:.17} collision={} jump={}",
                scenario.name,
                outcome.decision.as_str(),
                outcome.is_new_device,
                visitor_id,
                outcome.confidence,
                outcome.collision_risk,
                outcome.template_jump,
            );

            let e = &step.expect;
            assert_eq!(outcome.decision.as_str(), e.decision, "decision @ step {i}");
            assert_eq!(
                outcome.is_new_device, e.is_new_device,
                "is_new_device @ step {i}"
            );
            assert_eq!(
                outcome.collision_risk, e.collision_risk,
                "collision_risk @ step {i}"
            );
            assert_eq!(
                outcome.template_jump, e.template_jump,
                "template_jump @ step {i}"
            );
            assert!(
                (outcome.confidence - e.confidence).abs() <= tol,
                "confidence @ step {i}: got {}, expected {} (tol {tol})",
                outcome.confidence,
                e.confidence,
            );

            // Symbolic-label stability: every step tagged with the same visitor
            // resolves to one id, and a new label to an id no other label holds.
            if let Some(id) = visitors.get(&e.visitor) {
                assert_eq!(
                    &visitor_id, id,
                    "visitor '{}' must be stable @ step {i}",
                    e.visitor
                );
            } else {
                assert!(
                    !visitors.values().any(|id| *id == visitor_id),
                    "visitor '{}' must be distinct @ step {i}",
                    e.visitor
                );
                assert_eq!(visitor_id.len(), 32, "minted id @ step {i}");
                visitors.insert(e.visitor.clone(), visitor_id);
            }
        }
    }
}
