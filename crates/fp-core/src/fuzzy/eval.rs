//! Offline evaluation harness for the matching engine (fuzzy-matching §10).
//!
//! The design gates the architecture §3 targets (stability ≥ 95 %, collision ≤ 1 %)
//! behind an offline evaluation against a **labelled** set: observations tagged
//! with a ground-truth `deviceId` (login state / long-lived cookie). This module
//! defines that fixture format, replays it through [`FuzzyStore::identify`], and
//! reports the two headline metrics:
//!
//! - **stability rate** — of all same-device revisits, the fraction re-resolved
//!   to that device's own `visitor_id` (fuzzy-matching §10).
//! - **collision rate** — of all observations, the fraction merged onto a
//!   `visitor_id` first minted by a *different* ground-truth device (fuzzy-matching §10).
//!
//! The bundled [`Fixture::synthetic`] fixture is hand-authored to exercise the engine
//! **directionally** — same-device visits drift only slightly (a browser
//! upgrade, one font swap) while distinct devices disagree on every
//! high-stability discriminant. It is a smoke test for the scoring wiring, not
//! evidence for the numeric targets.
//!
//! TODO(real-data): replace [`Fixture::synthetic`] with a real labelled corpus (design
//! §10 ground truth) and grid-search `T_lo / T_hi / τ` and the component priors
//! before claiming the architecture §3 95 %/1 % numbers. The rates this harness prints on
//! synthetic input MUST NOT be reported as the production stability/collision
//! figures.

use std::collections::{HashMap, HashSet};

use super::{Components, FuzzyStore, IdentifyContext};
use serde::Deserialize;

/// A labelled evaluation fixture: observations grouped by ground-truth device
/// (fuzzy-matching §10). Every observation under one [`DeviceGroup`] is the *same*
/// physical device across visits; distinct groups are distinct devices.
#[derive(Debug, Clone, Deserialize)]
pub struct Fixture {
    /// Ground-truth device groups.
    pub devices: Vec<DeviceGroup>,
}

/// All observations captured for one ground-truth device.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceGroup {
    /// Stable ground-truth identifier for the physical device.
    #[serde(rename = "deviceId")]
    pub device_id: String,
    /// The components observed across this device's visits, oldest first.
    /// Each is fed to [`FuzzyStore::identify`] verbatim.
    pub observations: Vec<Components>,
}

/// Headline evaluation metrics over one fixture replay (fuzzy-matching §10).
#[derive(Debug, Clone, PartialEq)]
pub struct EvalReport {
    /// Observations replayed through the engine.
    pub total_observations: usize,
    /// Distinct ground-truth devices in the fixture.
    pub total_devices: usize,
    /// Observations that were a device's *second or later* visit (the population
    /// the stability rate is measured over).
    pub revisits: usize,
    /// Revisits correctly re-resolved to their device's own `visitor_id`.
    pub stable_links: usize,
    /// Observations merged onto a `visitor_id` first minted by another device.
    pub collisions: usize,
    /// `visitor_id`s minted across the replay (one per new device seen; more than
    /// [`total_devices`] indicates fragmentation).
    ///
    /// [`total_devices`]: EvalReport::total_devices
    pub minted_ids: usize,
}

impl EvalReport {
    /// Stability rate = stable revisits / revisits (fuzzy-matching §10).
    ///
    /// Returns `1.0` when there are no revisits (nothing to re-link).
    #[allow(clippy::cast_precision_loss)] // fixture-sized counts; precision loss immaterial
    pub fn stability_rate(&self) -> f64 {
        if self.revisits == 0 {
            return 1.0;
        }
        self.stable_links as f64 / self.revisits as f64
    }

    /// Collision rate = cross-device merges / observations (fuzzy-matching §10).
    #[allow(clippy::cast_precision_loss)] // fixture-sized counts; precision loss immaterial
    pub fn collision_rate(&self) -> f64 {
        if self.total_observations == 0 {
            return 0.0;
        }
        self.collisions as f64 / self.total_observations as f64
    }
}

impl Fixture {
    /// Parse a fixture from its JSON representation (see `fixtures/eval/`).
    ///
    /// # Errors
    /// Returns the underlying `serde_json` error if `json` is not a valid
    /// fixture document.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }

    /// The bundled synthetic fixture (fuzzy-matching §10 smoke test — see the module
    /// docs and the TODO on real data).
    ///
    /// # Errors
    /// Returns a `serde_json` error only if the compiled-in fixture is
    /// malformed — a build regression the module tests guard against.
    pub fn synthetic() -> serde_json::Result<Self> {
        Self::from_json(SYNTHETIC_FIXTURE)
    }
}

/// The compiled-in synthetic fixture (fuzzy-matching §10). Real labelled data is a
/// runtime input; this constant only backs the smoke test and example.
const SYNTHETIC_FIXTURE: &str = include_str!("../../fixtures/eval/synthetic.json");

/// Replay `fixture` through a fresh [`FuzzyStore`] and score it (fuzzy-matching §10).
///
/// Observations are interleaved round-robin across devices and stamped with a
/// monotonically increasing `now_ms`, so a device's revisit always arrives
/// *after* the other devices have been recorded — the ordering that actually
/// stresses cross-device collisions rather than replaying one device to
/// exhaustion in isolation.
///
/// A `visitor_id` is attributed to the ground-truth device of the observation
/// that first minted it. Thereafter each observation is judged:
/// - re-resolved to its own device's id → a correct link (stable if a revisit);
/// - resolved to another device's id → a collision;
/// - minted a fresh id on a revisit → a stability miss (device fragmented).
pub fn evaluate(fixture: &Fixture) -> EvalReport {
    let store = FuzzyStore::new();
    // `visitor_id → the ground-truth device that first minted it`.
    let mut owner: HashMap<String, String> = HashMap::new();
    // Ground-truth devices whose first observation has already been replayed.
    let mut seen_devices: HashSet<String> = HashSet::new();

    let mut report = EvalReport {
        total_observations: 0,
        total_devices: fixture.devices.len(),
        revisits: 0,
        stable_links: 0,
        collisions: 0,
        minted_ids: 0,
    };

    let mut now_ms = 1_000u64;
    for (device_id, components) in interleave(fixture) {
        let outcome = store.identify(&IdentifyContext {
            components,
            now_ms,
            client_ip: None,
        });
        now_ms += 1_000;
        // `identify` always resolves an id; an unset one cannot be attributed.
        let Some(visitor_id) = outcome.visitor_id else {
            continue;
        };
        report.total_observations += 1;

        let is_revisit = !seen_devices.insert(device_id.clone());
        if is_revisit {
            report.revisits += 1;
        }

        match owner.get(&visitor_id) {
            // A `visitor_id` we have not attributed yet ⇒ freshly minted here.
            None => {
                owner.insert(visitor_id, device_id.clone());
                report.minted_ids += 1;
                // Minting a new id on a revisit means the device fragmented: it
                // is a revisit that failed to re-link, so not counted stable.
            }
            Some(owning_device) if owning_device == device_id => {
                if is_revisit {
                    report.stable_links += 1;
                }
            }
            // Resolved to an id owned by a different ground-truth device.
            Some(_) => {
                report.collisions += 1;
            }
        }
    }

    report
}

/// Interleave a fixture's observations round-robin across devices, oldest visit
/// first: round 0 yields every device's first observation, round 1 their second,
/// and so on. Returns `(deviceId, observation)` pairs.
fn interleave(fixture: &Fixture) -> Vec<(&String, &Components)> {
    let max_visits = fixture
        .devices
        .iter()
        .map(|d| d.observations.len())
        .max()
        .unwrap_or(0);

    let mut order = Vec::new();
    for round in 0..max_visits {
        for device in &fixture.devices {
            if let Some(obs) = device.observations.get(round) {
                order.push((&device.device_id, obs));
            }
        }
    }
    order
}

#[cfg(test)]
mod tests {
    use super::{Fixture, evaluate};

    /// The bundled fixture parses and is internally consistent.
    #[test]
    fn synthetic_fixture_parses() {
        let fixture = Fixture::synthetic().unwrap();
        assert!(
            fixture.devices.len() >= 3,
            "need several distinct devices to measure collisions"
        );
        assert!(
            fixture.devices.iter().any(|d| d.observations.len() >= 2),
            "need at least one multi-visit device to measure stability"
        );
    }

    /// Directional acceptance (fuzzy-matching §10): on a synthetic set where same-device
    /// visits drift only slightly and distinct devices disagree on every
    /// high-stability discriminant, the engine should re-link revisits and keep
    /// devices apart. These are DIRECTIONAL bounds on hand-authored data — they
    /// assert the scoring is wired the right way round, NOT the architecture §3 95 %/1 %
    /// targets, which require the real labelled corpus (see module TODO).
    #[test]
    fn synthetic_eval_is_directionally_correct() {
        let report = evaluate(&Fixture::synthetic().unwrap());

        assert!(report.revisits > 0, "fixture must exercise revisits");
        assert!(
            report.stability_rate() >= 0.9,
            "same-device revisits should re-link: {report:?}",
        );
        assert!(
            report.collision_rate() <= 0.1,
            "distinct devices should not merge: {report:?}",
        );
        // No fragmentation and no cross-device merges: one id per ground-truth
        // device on this cleanly-separable synthetic set.
        assert_eq!(
            report.minted_ids, report.total_devices,
            "each device should own exactly one visitor_id: {report:?}",
        );
    }

    /// A degenerate all-distinct fixture (one visit each) has no revisits, so
    /// the stability rate defaults to 1.0 and nothing collides.
    #[test]
    fn no_revisits_yields_neutral_stability() {
        let json = r#"{
            "devices": [
                { "deviceId": "d1", "observations": [ { "webgl": "A", "platform": "Linux" } ] },
                { "deviceId": "d2", "observations": [ { "webgl": "B", "platform": "Windows" } ] }
            ]
        }"#;
        let report = evaluate(&Fixture::from_json(json).unwrap());
        assert_eq!(report.revisits, 0);
        assert!((report.stability_rate() - 1.0).abs() < f64::EPSILON);
        assert_eq!(report.collisions, 0);
    }
}
