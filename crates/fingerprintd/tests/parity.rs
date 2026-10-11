//! Native half of the cross-stack parity proof.
//!
//! The native `fp-core` engine and the edge Worker (`apps/edge`: Rust→WASM
//! compute over a Durable Object nonce + D1 candidate index) are two deployments
//! of ONE engine. This test drives the shared vectors in
//! `apps/edge/tests/fixtures/parity.json` through the native
//! [`FuzzyStore::identify`] path; the edge half
//! (`apps/edge/tests/parity.workers.test.ts`) drives the SAME fixture through
//! the Worker. Both assert the SAME committed `expect` block, so a divergence in
//! either stack — a changed threshold, a different salt derivation, a broken
//! serialization boundary — fails one side against the shared reference.
//!
//! Both stacks are seeded from the fixture's `salt_secret`, because blocking-key
//! derivation and stored hashing are only reproducible across isolates when the
//! salt is deterministic (native production uses a per-process random salt; the
//! parity claim is "same secret ⇒ same identity/decision/confidence").
//!
//! Run with `-- --nocapture` to print the outcomes the engine computed, which is
//! how the fixture's `expect` values are regenerated when the engine changes.

use std::collections::HashMap;

use fingerprintd_server::fuzzy::FuzzyStore;
use serde::Deserialize;
use serde_json::{Map, Value};

/// The whole fixture: shared salt, tolerance, named component objects, scenarios.
#[derive(Debug, Deserialize)]
struct Fixture {
    salt_secret: String,
    confidence_tolerance: f64,
    components: Map<String, Value>,
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

/// The parity assertion for a step — identical to the edge test's `expect`.
#[derive(Debug, Deserialize)]
struct Expect {
    decision: String,
    is_new_device: bool,
    /// Symbolic visitor label, asserted stable across the steps that share it.
    visitor: String,
    /// Absolute derived id, pinned on the step that first mints the visitor.
    #[serde(default)]
    visitor_id: Option<String>,
    collision_risk: bool,
    confidence: f64,
}

/// The shared fixture, in the `apps/edge` tree so one file drives both stacks.
const FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../apps/edge/tests/fixtures/parity.json"
);

#[test]
fn native_engine_matches_shared_parity_vectors() {
    let raw = std::fs::read_to_string(FIXTURE_PATH).expect("read parity fixture");
    let fixture: Fixture = serde_json::from_str(&raw).expect("parse parity fixture");
    let secret = fixture.salt_secret.as_bytes();
    let tol = fixture.confidence_tolerance;

    for scenario in &fixture.scenarios {
        println!("=== {} ===", scenario.name);
        // A fresh deterministic store per scenario: the edge test resets its D1 +
        // Durable Object between scenarios the same way.
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
            let outcome = store.identify(components, now);

            println!(
                "{}.{i} decision={} new={} vid={} conf={:.17} collision={}",
                scenario.name,
                outcome.decision.as_str(),
                outcome.is_new_device,
                outcome.visitor_id,
                outcome.confidence,
                outcome.collision_risk,
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
            assert!(
                (outcome.confidence - e.confidence).abs() <= tol,
                "confidence @ step {i}: got {}, expected {} (tol {tol})",
                outcome.confidence,
                e.confidence,
            );

            // Absolute id pin (present on the minting step).
            if let Some(expected_id) = &e.visitor_id {
                assert_eq!(&outcome.visitor_id, expected_id, "visitor_id @ step {i}");
            }
            // Symbolic-label stability: every step tagged with the same visitor
            // must resolve to one id.
            match visitors.get(&e.visitor) {
                Some(id) => assert_eq!(
                    &outcome.visitor_id, id,
                    "visitor '{}' must be stable @ step {i}",
                    e.visitor
                ),
                None => {
                    visitors.insert(e.visitor.clone(), outcome.visitor_id.clone());
                }
            }
        }
    }
}
