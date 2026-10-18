//! Stage-two probabilistic scoring, decision, and drift (fuzzy-matching §5/§6/§7/§8).
//!
//! Given a probe, [`FuzzyStore::identify`] performs the full two-stage match:
//! stage one recalls candidates from the blocking indexes (fuzzy-matching §4, in
//! [`super`]), stage two scores each candidate with the Fellegi–Sunter model
//! (§5) and applies the double-threshold decision (§5.4), the template-jump
//! guard, drift update (§7), and confidence fusion (§6).
//!
//! The Fellegi–Sunter weights use two per-component parameters:
//! - `m_i = P(agree | same device)` — the cold-start stability prior (§2/§9),
//!   read from [`Component::stability`].
//! - `u_i = P(agree | different device)` — the value's rarity, estimated from
//!   the frequency table (§9). Rare values that agree are strong evidence;
//!   common ones (Chrome-on-Windows) carry almost none.
//!
//! Thresholds and priors here are **cold-start defaults**; the fuzzy-matching spec's offline
//! evaluation (§10) tunes them against a labelled set. They are deliberately
//! separated so the eval harness can grid-search without touching scoring.

use std::collections::BTreeMap;

use super::{
    FuzzyStore, State,
    component::{Component, Hash32, Stability, Stored, jaccard, set_digest},
    components::Components,
    record::FingerprintRecord,
    velocity::VelocityBand,
};

/// Score at or above which the best candidate is accepted as the same device
/// (fuzzy-matching §5.4 `T_hi`). Units are bits of summed log-likelihood ratio.
const T_HI: f64 = 12.0;
/// Score below which the best candidate is rejected as a different device; the
/// `[T_LO, T_HI)` band is the "suspected" review zone (fuzzy-matching §5.4 `T_lo`).
const T_LO: f64 = 8.0;
/// Jaccard threshold above which a set component counts as a full agreement
/// (fuzzy-matching §5.1 `τ`); below it the score interpolates by Jaccard (§5.3).
const TAU: f64 = 0.5;
/// Two candidates both `≥ T_hi` within this many bits are flagged as a
/// collision risk (fuzzy-matching §5.4).
const COLLISION_GAP: f64 = 2.0;
/// Pseudo-count weighting each component's `u_i` prior ([`Component::u_prior`]) against
/// its observed value frequency (fuzzy-matching §9). Holds the estimate near the
/// prior on a cold or tiny library (a single recalled candidate), letting the
/// observed frequency take over as sightings accumulate.
const U_PSEUDO: f64 = 10.0;
/// Lower/upper clamps keeping `u_i` in `(0, 1)` so the log-ratios stay finite.
const U_FLOOR: f64 = 1e-4;
const U_CEIL: f64 = 0.9999;
/// Pseudo-count weighting the `m_i` prior against the observed agreement rate
/// (fuzzy-matching §9). A larger `α` holds the estimate near the prior until
/// enough confirmed same-device revisits accumulate; `est → agree/total` only as
/// `total` grows past it.
const ALPHA: f64 = 20.0;
/// Lower/upper clamps keeping the estimated `m_i` in `(0, 1)`. `M_CEIL < 1` keeps
/// `(1 - m)` strictly positive so the disagreement log-ratio `log2((1-m)/(1-u))`
/// stays finite; `M_FLOOR > 0` keeps the agreement log-ratio `log2(m/u)` finite.
const M_FLOOR: f64 = 1e-4;
const M_CEIL: f64 = 0.9999;
/// Score scale (bits) over which confidence margins saturate (fuzzy-matching §6).
const CONF_SCALE: f64 = 4.0;
/// Component count of a full rich fingerprint. Confidence scales the number of
/// components that actually took part in scoring against this, so a sparse probe
/// (many missing) is less certain (fuzzy-matching §6/§8).
const FULL_COMPONENTS: f64 = 8.0;
/// Most High-stability components a probe may change against a matched
/// template and still be accepted as a [`Decision::Match`]. A probe changing
/// more is the shape of a template being walked onto another device, so the
/// match is downgraded to [`Decision::Review`] (see [`is_template_jump`]).
pub const TEMPLATE_JUMP_MAX_HIGH_CHANGES: usize = 2;

/// The double-threshold verdict for a probe (fuzzy-matching §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Best candidate scored `≥ T_hi` — accepted as the same device.
    Match,
    /// Best candidate scored in `[T_lo, T_hi)`, or scored a match but jumped
    /// its template — suspected; returned but the template is **not** updated
    /// (anti-poisoning, fuzzy-matching §7).
    Review,
    /// No candidate cleared `T_lo` — a fresh `visitor_id` is minted.
    NewDevice,
}

impl Decision {
    /// Stable wire label for the response body.
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Match => "match",
            Decision::Review => "review",
            Decision::NewDevice => "new_device",
        }
    }
}

/// One identify request: the probe plus the request facts the engine needs.
#[derive(Debug, Clone, Copy)]
pub struct IdentifyContext<'a> {
    /// The probe components.
    pub components: &'a Components,
    /// Unix milliseconds, stamped onto stored observations; the velocity
    /// window keys on `now_ms / 1000`.
    pub now_ms: u64,
    /// The trusted client IP keying the cross-session velocity signal; `None`
    /// leaves the band [`VelocityBand::Low`].
    pub client_ip: Option<&'a str>,
}

/// Outcome of [`FuzzyStore::identify`] or [`FuzzyStore::score`].
#[derive(Debug, Clone)]
pub struct MatchOutcome {
    /// Resolved device identifier: the existing id on match/review. On a new
    /// device, [`FuzzyStore::identify`] mints a random id (always `Some`);
    /// the pure [`FuzzyStore::score`] mints nothing and returns `None`, leaving
    /// id minting to the host that persists the device.
    pub visitor_id: Option<String>,
    /// `true` only when the verdict is [`Decision::NewDevice`].
    pub is_new_device: bool,
    /// Fused confidence in `[0, 1]` (fuzzy-matching §6).
    pub confidence: f64,
    /// The verdict that produced this outcome (fuzzy-matching §5.4).
    pub decision: Decision,
    /// Best candidate's score in bits, if any candidate was scored.
    pub score: Option<f64>,
    /// Number of components that actually participated in scoring (fuzzy-matching §8).
    pub compared_components: usize,
    /// Whether a runner-up also cleared `T_hi` within `COLLISION_GAP`.
    pub collision_risk: bool,
    /// Whether a match was downgraded to [`Decision::Review`] because the probe
    /// changed more than [`TEMPLATE_JUMP_MAX_HIGH_CHANGES`] High-stability
    /// components of the matched template.
    pub template_jump: bool,
    /// Cross-session distinct new-device band for the client IP, a risk signal
    /// surfaced alongside `ip_risk` (never folded into identity). Computed only
    /// by [`FuzzyStore::identify`] when a client IP is supplied and a new device
    /// is minted; [`VelocityBand::Low`] otherwise.
    pub new_device_velocity: VelocityBand,
}

/// A read-phase verdict, pinned to the state generation it was decided at.
#[cfg(feature = "rng")]
struct Pending {
    generation: u64,
    outcome: MatchOutcome,
}

/// Per-candidate stage-two score and its comparison count.
struct Scored {
    score: f64,
    compared: usize,
}

impl FuzzyStore {
    /// Identify a probe, folding the observation in per the verdict.
    ///
    /// Two-stage (fuzzy-matching §4/§5): recall candidates, score each with
    /// Fellegi–Sunter, then apply the double-threshold decision (§5.4) and the
    /// template-jump guard. A match drifts the winning template (§7); a review
    /// returns the suspected visitor without updating it (anti-poisoning, §7);
    /// a new device is stored under a freshly minted random 128-bit id
    /// (32 lowercase hex chars) that is neither live nor erased.
    ///
    /// Only when the verdict is [`Decision::NewDevice`] and `client_ip` is
    /// present, the new id is recorded against that IP and the trailing-window
    /// distinct-id count is banded into [`MatchOutcome::new_device_velocity`]; a
    /// [`VelocityBand::High`] band subtracts [`super::velocity_penalty`] from
    /// confidence without touching the id or decision.
    ///
    /// **Concurrency:** recall and scoring run under the store's shared read
    /// guard, so concurrent identifies score in parallel; the write-back then
    /// takes the exclusive guard. Every write bumps a state generation: if the
    /// state changed since the read phase, the verdict is re-decided against
    /// the write-guarded state before anything is persisted, and a new id is
    /// minted only after that final decision. So every write-back is decided
    /// against the exact state it lands in:
    /// - concurrent first sightings of one device yield one visitor — the
    ///   later write re-decides and folds in as a match of the first;
    /// - an identify racing an erase never resurrects the erased id — it
    ///   re-decides (typically as a new device under a different id), and an
    ///   erased id is tombstoned so it is never minted or recorded again.
    #[cfg(feature = "rng")]
    pub fn identify(&self, ctx: &IdentifyContext<'_>) -> MatchOutcome {
        let pending = self.identify_read(ctx.components);
        self.identify_write(ctx, pending)
    }

    /// The read phase of [`identify`](Self::identify): the verdict and the
    /// generation it was decided at.
    #[cfg(feature = "rng")]
    fn identify_read(&self, components: &Components) -> Pending {
        let state = self.read();
        Pending {
            generation: state.generation,
            outcome: self.evaluate(&state, components),
        }
    }

    /// The write phase of [`identify`](Self::identify): re-decide if the state
    /// moved since `pending`, then persist per the final verdict.
    #[cfg(feature = "rng")]
    fn identify_write(&self, ctx: &IdentifyContext<'_>, pending: Pending) -> MatchOutcome {
        let stored = self.stored_map(ctx.components);
        let mut state = self.write();
        let mut outcome = if state.generation == pending.generation {
            pending.outcome
        } else {
            self.evaluate(&state, ctx.components)
        };
        // Persist per the verdict (fuzzy-matching §7): a confirmed match drifts the
        // winning template toward this observation and a new device is stored
        // under a freshly minted id; a review leaves the template untouched
        // (anti-poisoning).
        match outcome.decision {
            Decision::Match => {
                if let Some(id) = outcome.visitor_id.clone() {
                    // Learn `m_i` material from this confirmed same-device pair
                    // (fuzzy-matching §9) BEFORE `observe` drifts the template, so the
                    // probe is compared against the template as it stood at the match.
                    self.record_agreement(&mut state, &id, ctx.components);
                    self.observe_locked(&mut state, &id, stored, ctx.now_ms);
                }
            }
            Decision::NewDevice => {
                let id = mint_visitor_id(&state);
                self.observe_locked(&mut state, &id, stored, ctx.now_ms);
                // Cross-session velocity: a fresh device from a client IP that is
                // churning out new devices is the farm footprint.
                if let Some(ip) = ctx.client_ip {
                    let now_secs = ctx.now_ms / 1000;
                    state.velocity.record(ip, &id, now_secs);
                    let n = state.velocity.count(ip, now_secs, super::velocity::WINDOW);
                    let band = VelocityBand::classify(n);
                    outcome.new_device_velocity = band;
                    outcome.confidence =
                        (outcome.confidence - super::velocity_penalty(band)).clamp(0.0, 1.0);
                }
                outcome.visitor_id = Some(id);
            }
            Decision::Review => {}
        }
        outcome
    }

    /// Score `components` and decide, **without mutating** the store (fuzzy-matching §5).
    ///
    /// The pure half of [`identify`](Self::identify): stage-one recall, Fellegi–Sunter scoring,
    /// the double-threshold decision, and the template-jump guard. It returns
    /// the verdict `identify` would reach but leaves every table untouched and
    /// mints no id (`visitor_id` is `None` on a new device) — the entry point a
    /// stateless edge host calls before performing its own persistence per the
    /// returned [`Decision`].
    pub fn score(&self, components: &Components) -> MatchOutcome {
        self.evaluate(&self.read(), components)
    }

    /// Stage-one recall + stage-two scoring + decision for `components`, with no
    /// side effects. Shared by [`identify`] (which then persists) and [`score`]
    /// (which does not), so both apply the same template-jump guard.
    ///
    /// [`identify`]: FuzzyStore::identify
    /// [`score`]: FuzzyStore::score
    fn evaluate(&self, state: &State, components: &Components) -> MatchOutcome {
        let probe = self.stored_entries(components);
        let probe_map = self.stored_map(components);
        let keys = self.blocking_keys(&probe_map);

        // Stage one: recall, then score every candidate template in place.
        let mut scored: Vec<(&str, Scored)> = state
            .blocking
            .candidates(&keys)
            .into_iter()
            .filter_map(|id| {
                let record = state.records.get(id)?;
                Some((id, self.score_candidate(state, &probe, record)))
            })
            .collect();
        // Highest score first; a runner-up (if any) drives collision detection.
        scored.sort_by(|a, b| b.1.score.total_cmp(&a.1.score));

        let best = scored.first();
        let second_score = scored.get(1).map(|(_, s)| s.score);
        let best_score = best.map(|(_, s)| s.score);
        let compared = best.map_or(0, |(_, s)| s.compared);

        let mut decision = match best_score {
            Some(s) if s >= T_HI => Decision::Match,
            Some(s) if s >= T_LO => Decision::Review,
            _ => Decision::NewDevice,
        };
        // Template-jump guard: a match that changes too many High-stability
        // components of its template is suspected, not confirmed.
        let template_jump = decision == Decision::Match
            && best
                .and_then(|(id, _)| state.records.get(id))
                .is_some_and(|record| is_template_jump(&probe_map, &record.components));
        if template_jump {
            decision = Decision::Review;
        }

        let confidence = confidence(decision, best_score, second_score, compared);
        let collision_risk = decision == Decision::Match
            && best.is_some_and(|(_, top)| {
                second_score.is_some_and(|s2| s2 >= T_HI && (top.score - s2) < COLLISION_GAP)
            });
        let visitor_id = match decision {
            Decision::Match | Decision::Review => best.map(|(id, _)| (*id).to_owned()),
            Decision::NewDevice => None,
        };

        MatchOutcome {
            visitor_id,
            is_new_device: decision == Decision::NewDevice,
            confidence,
            decision,
            score: best_score,
            compared_components: compared,
            collision_risk,
            template_jump,
            new_device_velocity: VelocityBand::Low,
        }
    }

    /// Record per-component agreement of `components` against the matched
    /// template's stored values, accumulating the material behind `m_i`
    /// (fuzzy-matching §9).
    ///
    /// Called only from the `Decision::Match` arm of [`identify`], under the
    /// write guard and **before** [`observe`] drifts the template, so it
    /// compares the probe against the template as it stood when the match was
    /// confirmed. Each
    /// component present (and kind-compatible) on both sides contributes one
    /// same-device observation: agreement iff its similarity clears `τ` — the
    /// same threshold [`score_candidate`] uses. Names missing on either side, or
    /// of mismatched kind (`compare` → `None`), are skipped.
    ///
    /// [`identify`]: FuzzyStore::identify
    /// [`observe`]: FuzzyStore::observe
    /// [`score_candidate`]: FuzzyStore::score_candidate
    #[cfg(feature = "rng")]
    fn record_agreement(&self, state: &mut State, visitor_id: &str, components: &Components) {
        let Some(template) = state.records.get(visitor_id) else {
            return;
        };
        let agreements: Vec<(Component, bool)> = self
            .stored_entries(components)
            .iter()
            .filter_map(|(component, probe_value)| {
                // Missing on the template side → not compared (§8).
                let template_value = template.components.get(component.name())?;
                // Kind mismatch → not comparable.
                let (sim, _u) = self.compare(state, *component, probe_value, template_value)?;
                Some((*component, sim >= TAU))
            })
            .collect();
        for (component, agreed) in agreements {
            state.agreement.record(component.name(), agreed);
        }
        state.bump();
    }

    /// Fellegi–Sunter score of a candidate template against the probe (fuzzy-matching §5).
    ///
    /// Sums the per-component log-likelihood weight over components present on
    /// both sides; components missing on either side are skipped, contributing
    /// zero (fuzzy-matching §5.3/§8).
    fn score_candidate(
        &self,
        state: &State,
        probe: &[(Component, Stored)],
        template: &FingerprintRecord,
    ) -> Scored {
        let mut score = 0.0;
        let mut compared = 0;
        for (component, probe_value) in probe {
            let Some(template_value) = template.components.get(component.name()) else {
                continue; // missing on the template side → not compared (§8)
            };
            let Some((sim, u)) = self.compare(state, *component, probe_value, template_value)
            else {
                continue; // kind mismatch → not comparable
            };
            let m = m_estimate(state, component.name(), component.stability().m_prior());
            score += agreement_weight(m, u, sim);
            compared += 1;
        }
        Scored { score, compared }
    }

    /// Compare one component, returning its agreement fraction `sim ∈ [0, 1]`
    /// and the rarity `u_i` of the probe's value for that component
    /// (fuzzy-matching §5.1/§5.3). `None` if the two stored forms are of
    /// different kinds and cannot be compared.
    fn compare(
        &self,
        state: &State,
        component: Component,
        probe: &Stored,
        template: &Stored,
    ) -> Option<(f64, f64)> {
        match (probe, template) {
            (Stored::Category(a), Stored::Category(b)) => {
                let sim = f64::from(u8::from(a == b));
                Some((sim, u_estimate(state, component, *a)))
            }
            (Stored::Numeric(a), Stored::Numeric(b)) => {
                let sim = f64::from(u8::from(a == b));
                Some((
                    sim,
                    u_estimate(state, component, self.salt.hash(&a.to_string())),
                ))
            }
            (Stored::Set(a), Stored::Set(b)) => {
                let j = jaccard(a, b);
                // `J ≥ τ` counts as full agreement; below it, interpolate by J (§5.3).
                let sim = if j >= TAU { 1.0 } else { j };
                Some((sim, u_estimate(state, component, set_digest(a))))
            }
            _ => None,
        }
    }
}

/// Estimate `u_i` for `value` of `component`: its relative frequency
/// among that component's sightings (fuzzy-matching §5/§9), shrunk toward
/// the component's [`Component::u_prior`] by [`U_PSEUDO`] pseudo-sightings and clamped
/// to keep the log-ratios finite.
///
/// The denominator is the component's own sighting count: a value every
/// device shares reads as common (`u → 1`) instead of being diluted by the
/// number of components, and the prior keeps a cold or tiny library from
/// reading every value as either unique or universal.
#[allow(clippy::cast_precision_loss)] // frequency ratio; precision loss immaterial
fn u_estimate(state: &State, component: Component, value: Hash32) -> f64 {
    let hits = state.frequency.count(component.name(), value) as f64;
    let total = state.frequency.total(component.name()) as f64;
    ((hits + U_PSEUDO * component.u_prior()) / (total + U_PSEUDO)).clamp(U_FLOOR, U_CEIL)
}

/// Estimate `m_i` for the component `name`: its observed same-device
/// agreement rate, shrunk toward the cold-start stability `prior` by an
/// `ALPHA`-weighted pseudo-count (fuzzy-matching §9).
///
/// **Cold start is exact:** with no recorded agreements (`total == 0`) this
/// returns the `prior` *exactly*, before any arithmetic, so an empty store
/// scores on the fixed stability priors. Once
/// confirmed same-device revisits accumulate, the estimate moves from the
/// prior toward the empirical rate; the clamp keeps it in `(0, 1)` so the
/// log-ratios stay finite.
#[allow(clippy::cast_precision_loss)] // agreement counts; precision loss immaterial
fn m_estimate(state: &State, name: &str, prior: f64) -> f64 {
    let (agree, total) = state.agreement.stats(name);
    if total == 0 {
        return prior; // cold start: the exact prior
    }
    let est = (agree as f64 + ALPHA * prior) / (total as f64 + ALPHA);
    est.clamp(M_FLOOR, M_CEIL)
}

/// Per-component Fellegi–Sunter weight in bits (fuzzy-matching §5.3).
///
/// `sim` blends the agree and disagree log-ratios: `1.0` is a full agreement
/// (`log2(m/u)`), `0.0` a full disagreement (`log2((1-m)/(1-u))`), and a set's
/// partial Jaccard interpolates between them.
fn agreement_weight(m: f64, u: f64, sim: f64) -> f64 {
    // A value more common among different devices than it is stable on one
    // (`u > m`) is no evidence either way; capping `u` at `m` zeroes both
    // weights instead of letting a disagreement count as evidence of a match.
    let u = u.min(m);
    let agree = (m / u).log2();
    let disagree = ((1.0 - m) / (1.0 - u)).log2();
    sim * agree + (1.0 - sim) * disagree
}

/// Fuse the confidence in `[0, 1]` from the decision, score margins, and probe
/// completeness (fuzzy-matching §6).
///
/// Three factors combine: how far the best score sits past its decision
/// boundary, its separation from the runner-up, and the fraction of the probe's
/// components that took part in scoring (a sparse probe is less certain, §8).
/// The passive JA4/UA consistency input (fuzzy-matching §6) is fused by the
/// host on top of this value, not here.
///
/// This is **decision confidence, not identity trust**. A first-ever
/// device with no candidate is a confident `NewDevice` and can return a *high*
/// confidence — it is confidently *new* — yet its identity is entirely
/// unestablished. A downstream consumer must therefore key trust off
/// `is_new_device` / `decision`, not `confidence` alone: a high confidence on a
/// `NewDevice` verdict means "confidently unrecognized", not "trusted identity".
#[allow(clippy::cast_precision_loss)] // small component counts; precision loss immaterial
fn confidence(
    decision: Decision,
    best_score: Option<f64>,
    second_score: Option<f64>,
    compared: usize,
) -> f64 {
    // Completeness pulls a sparse decision (few components scored) toward
    // uncertainty (§6/§8): fewer participating components → lower confidence.
    let completeness = (compared as f64 / FULL_COMPONENTS).min(1.0);
    let completeness_scale = 0.5 + 0.5 * completeness;

    let base = match decision {
        Decision::Match => {
            let s = best_score.unwrap_or(T_HI);
            let margin = logistic((s - T_HI) / CONF_SCALE);
            let gap = second_score.map_or(1.0, |s2| logistic((s - s2) / CONF_SCALE));
            0.5 + 0.5 * margin.min(gap)
        }
        Decision::Review => {
            let s = best_score.unwrap_or(T_LO);
            let position = ((s - T_LO) / (T_HI - T_LO)).clamp(0.0, 1.0);
            0.25 + 0.25 * position
        }
        Decision::NewDevice => {
            // Confident it is new when the best score sits well below `T_lo`;
            // a competitor near the band makes "new" less certain.
            let closeness = best_score.map_or(0.0, |s| logistic((s - T_LO) / CONF_SCALE));
            0.5 + 0.5 * (1.0 - closeness)
        }
    };

    (base * completeness_scale).clamp(0.0, 1.0)
}

/// Standard logistic `1 / (1 + e^-x)`, mapping a score margin to `(0, 1)`.
fn logistic(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

/// Mint a random 128-bit `visitor_id` (32 lowercase hex chars) from the OS RNG,
/// re-drawing while it names a live record or a tombstoned (erased) visitor.
#[cfg(feature = "rng")]
fn mint_visitor_id(state: &State) -> String {
    use rand::{Rng, rng};
    loop {
        let mut bytes = [0u8; 16];
        rng().fill_bytes(&mut bytes);
        let id = hex::encode(bytes);
        if state.records.get(&id).is_none() && !state.tombstones.contains(&id) {
            return id;
        }
    }
}

/// Whether `probe` changes more than [`TEMPLATE_JUMP_MAX_HIGH_CHANGES`]
/// High-stability components of `template`, over the stored forms keyed by
/// component name. Only components present on both sides count; a set
/// component disagrees when its Jaccard falls below `τ`.
pub fn is_template_jump(
    probe: &BTreeMap<String, Stored>,
    template: &BTreeMap<String, Stored>,
) -> bool {
    let changes = Component::ALL
        .into_iter()
        .filter(|component| component.stability() == Stability::High)
        .filter_map(|component| {
            Some((
                probe.get(component.name())?,
                template.get(component.name())?,
            ))
        })
        .filter(|(a, b)| match (a, b) {
            (Stored::Set(a), Stored::Set(b)) => jaccard(a, b) < TAU,
            _ => a != b,
        })
        .count();
    changes > TEMPLATE_JUMP_MAX_HIGH_CHANGES
}

#[cfg(test)]
mod tests {
    use super::{Decision, IdentifyContext, MatchOutcome, T_HI, T_LO};
    use crate::fuzzy::{Component, Components, FuzzyStore};
    use serde_json::json;

    fn components(value: serde_json::Value) -> Components {
        serde_json::from_value(value).unwrap()
    }

    fn identify(store: &FuzzyStore, components: &Components, now_ms: u64) -> MatchOutcome {
        store.identify(&IdentifyContext {
            components,
            now_ms,
            client_ip: None,
        })
    }

    fn identify_from(
        store: &FuzzyStore,
        components: &Components,
        now_ms: u64,
        ip: &str,
    ) -> MatchOutcome {
        store.identify(&IdentifyContext {
            components,
            now_ms,
            client_ip: Some(ip),
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

    /// (b) Anti-collision: two different devices that collide on a blocking key
    /// (shared audio+cpu+memory) but disagree on the high-stability discriminants
    /// (webgl/platform/timezone/fonts) must be scored apart, not merged (§5).
    #[test]
    fn b_shared_block_but_distinct_device_is_not_merged() {
        let store = FuzzyStore::new();
        let first = identify(&store, &full_probe(), 1_000);

        // Same K2 subset (audio + cpu_cores + device_memory) so `first` is
        // recalled, but every high-stability discriminant disagrees.
        let other = components(json!({
            "webgl": "Mali-G78",
            "platform": "Linux armv8",
            "timezone": "America/New_York",
            "audio": "124.04",
            "cpu_cores": 8,
            "device_memory": 8,
            "fonts": ["Roboto", "Noto", "Droid", "Ubuntu"],
            "canvas": "f00d",
        }));
        // The collision is real at stage one: `first` is in the candidate set.
        assert!(
            store
                .candidates(&other)
                .contains(first.visitor_id.as_deref().unwrap())
        );

        let second = identify(&store, &other, 2_000);
        assert_eq!(second.decision, Decision::NewDevice);
        assert!(second.is_new_device);
        assert_ne!(second.visitor_id, first.visitor_id);
    }

    /// (c) Low-entropy fade: agreeing only on components that are common across
    /// the library (timezone/platform/languages, high `u_i`) carries almost no
    /// evidence, so a bare low-entropy overlap does not merge (fuzzy-matching §5.3).
    #[test]
    fn c_low_entropy_only_overlap_does_not_merge() {
        let store = FuzzyStore::new();
        let low = components(json!({
            "platform": "Linux x86_64",
            "timezone": "Asia/Shanghai",
            "languages": "en-US",
        }));
        // A crowd shares these exact low-entropy values, inflating their `u_i`.
        for i in 0..30 {
            store.observe(&format!("bg{i}"), &low, 1_000);
        }

        // The victim is recalled against the crowd (they share the K0 key)...
        assert!(!store.candidates(&low).is_empty());
        // ...but the common agreements never clear T_lo, so it is judged new.
        let out = identify(&store, &low, 2_000);
        assert_eq!(out.decision, Decision::NewDevice);
        assert!(out.is_new_device);
        assert!(out.score.unwrap() < T_LO, "score was {:?}", out.score);
    }

    /// (d, anti-poisoning) Drift updates the template ONLY on a `≥ T_hi` match
    /// (fuzzy-matching §7). An ambiguous `[T_lo, T_hi)` review-band hit must NOT mutate
    /// the stored template, so an attacker cannot walk one device's fingerprint
    /// toward another through a run of low-confidence near-misses.
    #[test]
    fn review_band_hit_does_not_drift_the_template() {
        let store = FuzzyStore::new();
        let seed = identify(&store, &full_probe(), 1_000);
        let id = seed.visitor_id.clone().unwrap();

        let before = store.record(&id).unwrap();
        assert_eq!(before.last_seen, 1_000);

        // A probe agreeing on only the stable K1 subset plus audio and
        // cpu_cores scores in the review band: enough evidence to suspect `id`,
        // not enough to confirm and drift it.
        let review_probe = components(json!({
            "webgl": "ANGLE (Intel)",
            "platform": "Linux x86_64",
            "timezone": "Asia/Shanghai",
            "audio": "124.04",
            "cpu_cores": 8,
        }));
        let review = identify(&store, &review_probe, 5_000);
        assert_eq!(review.decision, Decision::Review);
        assert_eq!(review.visitor_id.as_deref(), Some(id.as_str()));

        // The template is untouched: same last_seen, components, and count.
        let after = store.record(&id).unwrap();
        assert_eq!(
            after.last_seen, before.last_seen,
            "review must not drift last_seen"
        );
        assert_eq!(after.observation_count, before.observation_count);
        assert_eq!(after.components, before.components);

        // Bracket the gate: a genuine `≥ T_hi` match DOES advance the template.
        let confirm = identify(&store, &full_probe(), 9_000);
        assert_eq!(confirm.decision, Decision::Match);
        assert_eq!(store.record(&id).unwrap().last_seen, 9_000);
    }

    /// (concurrency) Many threads hammer `identify` against one shared store
    /// with a mix of the same and distinct devices. Scoring runs under the shared
    /// guard and each write-back under the exclusive one, so no write is torn or
    /// lost. The store must end in a consistent state: no panic, one
    /// stable record per distinct device, every observation folded in exactly
    /// once, and a re-identify of an already-seen full probe still Matches its id.
    #[test]
    fn concurrent_identify_stays_consistent() {
        use std::{
            collections::HashSet,
            sync::{Arc, Mutex},
            thread,
        };

        const THREADS: usize = 8;
        const ITERS: u64 = 40;

        // Distinct full devices. Each recalls only itself (disjoint blocking
        // keys), so every identify is a Match — or the one-time NewDevice — that
        // folds an observation in, never a Review, and no two ever cross-match.
        let devices: Arc<Vec<Components>> = Arc::new(
            (0..8)
                .map(|i| {
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
                })
                .collect(),
        );

        let store = Arc::new(FuzzyStore::new());
        let seen: Arc<Mutex<HashSet<(usize, String)>>> = Arc::new(Mutex::new(HashSet::new()));

        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let store = Arc::clone(&store);
                let devices = Arc::clone(&devices);
                let seen = Arc::clone(&seen);
                thread::spawn(move || {
                    let mut local = HashSet::new();
                    for i in 0..ITERS {
                        // Every thread hammers every device, interleaving the
                        // same-device evaluate/observe across threads.
                        for (d, probe) in devices.iter().enumerate() {
                            let now = 1_000 + (t as u64) * 1_000_000 + i * 1_000 + d as u64;
                            let out = identify(&store, probe, now);
                            assert!(
                                matches!(out.decision, Decision::Match | Decision::NewDevice),
                                "unexpected {:?} for device {d}",
                                out.decision,
                            );
                            local.insert((d, out.visitor_id.unwrap()));
                        }
                    }
                    seen.lock().unwrap().extend(local);
                })
            })
            .collect();
        for h in handles {
            h.join().expect("identify thread panicked");
        }

        // One stable id per distinct device: the count of (device, id) pairs
        // equals the device count, so the concurrent RMW never fractured a device
        // into two records.
        let seen = Arc::into_inner(seen).unwrap().into_inner().unwrap();
        assert_eq!(seen.len(), devices.len());

        // Every observation was folded in exactly once — no lost or double
        // counted writes under contention.
        for (d, id) in &seen {
            let record = store.record(id).expect("device record present");
            assert_eq!(
                record.observation_count,
                THREADS as u64 * ITERS,
                "device {d} observation_count",
            );
        }

        // Reproducibility: after all the churn, re-identifying any full device
        // still Matches its established id.
        for (d, probe) in devices.iter().enumerate() {
            let out = identify(&store, probe, 9_000_000);
            assert_eq!(out.decision, Decision::Match, "re-identify device {d}");
            assert!(seen.contains(&(d, out.visitor_id.unwrap())));
        }
    }

    /// Single-threaded identify is deterministic: two stores with the same
    /// secret, fed the same sequence (matches, a review, new devices, drift),
    /// produce identical outcomes step by step. Minted ids are random, so ids
    /// are compared as labels in order of first appearance.
    #[test]
    fn single_threaded_identify_is_deterministic() {
        let sequence: Vec<Components> = (0..30u64)
            .map(|i| {
                let mut p = full_probe();
                match i % 5 {
                    0 => {}
                    1 => p.canvas = Some(format!("noise-{i}")),
                    2 => p.webgl = Some(format!("GPU {}", i % 3)),
                    3 => {
                        p.fonts = None;
                        p.device_memory = None;
                        p.canvas = None;
                    }
                    _ => p.timezone = Some(format!("Zone/{i}")),
                }
                p
            })
            .collect();
        let run = || {
            let store = FuzzyStore::deterministic(b"determinism");
            let mut labels: Vec<String> = Vec::new();
            sequence
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    let o = identify(&store, p, 1_000 + i as u64);
                    let id = o.visitor_id.unwrap();
                    let label = labels.iter().position(|l| *l == id).unwrap_or_else(|| {
                        labels.push(id);
                        labels.len() - 1
                    });
                    (
                        label,
                        o.decision,
                        o.score.map(f64::to_bits),
                        o.confidence.to_bits(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let first = run();
        assert_eq!(first, run());
        // The sequence exercises more than one verdict.
        assert!(first.iter().any(|o| o.1 == Decision::Match));
        assert!(first.iter().any(|o| o.1 == Decision::NewDevice));
    }

    /// Cold start is prior-driven: on a fresh store the agreement table is empty
    /// during the matching `evaluate`, so `m_estimate` returns the prior exactly.
    /// The first identify mints a
    /// device; the second still Matches it, and only then does the Match-hook
    /// populate the agreement material.
    #[test]
    fn cold_start_matches_on_priors_then_records_agreement() {
        let store = FuzzyStore::new();
        // Nothing learned yet: the estimate is the untouched prior.
        assert_eq!(store.read().agreement.stats("webgl"), (0, 0));

        let first = identify(&store, &full_probe(), 1_000);
        assert!(first.is_new_device); // NewDevice does not record agreement
        assert_eq!(store.read().agreement.stats("webgl"), (0, 0));

        let second = identify(&store, &full_probe(), 2_000);
        assert_eq!(second.decision, Decision::Match);
        assert_eq!(second.visitor_id, first.visitor_id);
        // The Match-hook fired: webgl agreed on this same-device revisit.
        assert_eq!(store.read().agreement.stats("webgl"), (1, 1));
    }

    /// A high-stability component that agrees on every confirmed same-device
    /// revisit accumulates agreement counts, and `m_estimate` moves from the cold
    /// prior up toward `M_CEIL` as the empirical rate reinforces it (fuzzy-matching §9).
    #[test]
    fn repeated_same_device_matches_lift_m_estimate() {
        let store = FuzzyStore::new();
        let prior = Component::Webgl.stability().m_prior();

        // Seed the device, then revisit it repeatedly with the identical probe —
        // every revisit is a Match that records webgl as agreeing.
        identify(&store, &full_probe(), 1_000);
        for i in 0..10 {
            let out = identify(&store, &full_probe(), 2_000 + i);
            assert_eq!(out.decision, Decision::Match);
        }

        // Ten confirmed same-device agreements accumulated.
        assert_eq!(store.read().agreement.stats("webgl"), (10, 10));
        // The estimate has climbed above the cold prior toward the ceiling.
        let est = super::m_estimate(&store.read(), "webgl", prior);
        assert!(est > prior, "m_estimate {est} should exceed prior {prior}");
        assert!(est < super::M_CEIL);
        // An unlearned component still returns its untouched prior exactly.
        assert!((super::m_estimate(&store.read(), "plugins", 0.8) - 0.8).abs() < f64::EPSILON);
    }

    /// Learning is monotone: each confirmed same-device revisit of an
    /// always-agreeing component moves its `m_estimate` strictly upward, starting
    /// from the exact cold prior and rising toward — but never past — `M_CEIL`
    /// (fuzzy-matching §9).
    #[test]
    fn m_estimate_climbs_monotonically_across_same_device_revisits() {
        let store = FuzzyStore::new();
        let prior = Component::Webgl.stability().m_prior();

        // Mint the device: NewDevice records no agreement, so the estimate is
        // still the untouched cold prior, bit-for-bit.
        identify(&store, &full_probe(), 1_000);
        let mut prev = super::m_estimate(&store.read(), "webgl", prior);
        assert!(
            (prev - prior).abs() < f64::EPSILON,
            "cold start returns the prior exactly"
        );

        // Every identical revisit is a Match that records webgl agreeing, lifting
        // the estimate a little further each time.
        for i in 0..12 {
            let out = identify(&store, &full_probe(), 2_000 + i);
            assert_eq!(out.decision, Decision::Match);
            let est = super::m_estimate(&store.read(), "webgl", prior);
            assert!(
                est > prev,
                "estimate must rise each revisit: {prev} -> {est}"
            );
            assert!(
                est <= super::M_CEIL,
                "estimate stays within the ceiling clamp"
            );
            assert!(est < 1.0);
            prev = est;
        }
        assert!(
            prev > prior,
            "after revisits the estimate sits above the cold prior {prior}"
        );
    }

    /// The `m_i` clamp keeps the log-ratio weights finite even at the limit
    /// (`m → 1`): saturating a component's agreement pins `m_estimate` at `M_CEIL`
    /// (never `1.0`), so the agree/disagree weights and the resulting identify
    /// score stay finite — no `inf`/`NaN` leaks into scoring (fuzzy-matching §5/§9).
    #[test]
    fn score_stays_finite_when_m_is_driven_to_the_clamp() {
        let store = FuzzyStore::new();
        identify(&store, &full_probe(), 1_000);

        // Drive every component's agreement well past the point where the smoothed
        // estimate would exceed the ceiling, so each `m_estimate` clamps at M_CEIL.
        for name in [
            "webgl",
            "platform",
            "timezone",
            "audio",
            "cpu_cores",
            "device_memory",
            "fonts",
            "canvas",
        ] {
            for _ in 0..20_000 {
                store.write().agreement.record(name, true);
            }
            assert!(
                (super::m_estimate(&store.read(), name, 0.95) - super::M_CEIL).abs() < 1e-9,
                "{name} m_estimate should clamp to M_CEIL"
            );
        }

        // The per-component weight is finite at the extreme for a full agreement
        // (`log2(m/u)`) and a full disagreement (`log2((1-m)/(1-u))`) alike — the
        // clamp keeps `m` off `0`/`1`, so neither log-ratio blows up.
        assert!(super::agreement_weight(super::M_CEIL, super::U_FLOOR, 1.0).is_finite());
        assert!(super::agreement_weight(super::M_CEIL, super::U_CEIL, 0.0).is_finite());

        // A real identify with every `m` at the clamp still produces a finite score.
        let out = identify(&store, &full_probe(), 2_000);
        assert_eq!(out.decision, Decision::Match);
        let matched_score = out.score.expect("a matched candidate has a score");
        assert!(matched_score.is_finite(), "score was {matched_score}");
    }

    /// A churning component that never agrees earns *less* trust than its cold
    /// prior: the stable components carry each match, but the re-noised `canvas`
    /// disagrees on every confirmed revisit, so its `m_estimate` is pulled below
    /// the prior (fuzzy-matching §9).
    #[test]
    fn churning_component_m_estimate_falls_below_its_prior() {
        let store = FuzzyStore::new();
        let canvas_prior = Component::Canvas.stability().m_prior();

        // Seed the device, then revisit with the stable components unchanged (they
        // carry the match) but a fresh canvas each time, so it never agrees.
        identify(&store, &full_probe(), 1_000);
        for i in 0..12 {
            let mut probe = full_probe();
            probe.canvas = Some(format!("noise-{i}"));
            let out = identify(&store, &probe, 2_000 + i);
            assert_eq!(
                out.decision,
                Decision::Match,
                "stable components must carry the match while canvas churns"
            );
        }

        let (agree, total) = store.read().agreement.stats("canvas");
        assert_eq!(agree, 0, "canvas never agreed");
        assert!(
            total >= 12,
            "every revisit recorded a same-device comparison"
        );
        let est = super::m_estimate(&store.read(), "canvas", canvas_prior);
        assert!(
            est < canvas_prior,
            "churning estimate {est} should fall below prior {canvas_prior}"
        );
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

    /// The cross-session catch: one client IP minting a burst of fresh devices
    /// inside the window crosses to [`VelocityBand::High`] and takes the
    /// documented confidence downgrade — while its decision and `visitor_id` are
    /// untouched. A per-session view (each launch a new device) cannot see this.
    #[test]
    fn burst_of_new_devices_from_one_ip_crosses_to_high_and_downgrades() {
        use crate::fuzzy::velocity::HIGH;

        let store = FuzzyStore::new();
        let ip = "203.0.113.9";

        // `HIGH` distinct fresh devices from one IP, all within the window
        // (seconds apart). Each is a NewDevice; the last crosses the High band.
        let mut last = None;
        for i in 0..HIGH {
            let probe = distinct_probe(i);
            let out = identify_from(&store, &probe, 1_000_000 + i * 1_000, ip);
            assert_eq!(out.decision, Decision::NewDevice, "device {i}");
            assert!(out.is_new_device);
            last = Some(out);
        }
        let last = last.unwrap();
        assert_eq!(last.new_device_velocity, super::VelocityBand::High);
        // A no-candidate NewDevice's neutral confidence is 0.5; the High band
        // subtracts the documented penalty, fused like the passive adjustment.
        assert!(
            (last.confidence - (0.5 - super::super::VELOCITY_PENALTY)).abs() < 1e-9,
            "confidence was {}",
            last.confidence,
        );
    }

    /// The same burst spread *beyond* the window never accumulates: each event
    /// ages out before the next, so the band stays [`VelocityBand::Low`] and no
    /// downgrade is applied.
    #[test]
    fn new_devices_spread_beyond_the_window_stay_low() {
        use crate::fuzzy::velocity::{HIGH, WINDOW};

        let store = FuzzyStore::new();
        let ip = "203.0.113.10";

        // Space events more than a window apart (in ms), so at each access the
        // prior events have all aged out and the count is 1.
        let step_ms = (WINDOW + 10) * 1_000;
        let mut last = None;
        for i in 0..HIGH {
            let probe = distinct_probe(i);
            let out = identify_from(&store, &probe, 1_000_000 + i * step_ms, ip);
            assert_eq!(out.decision, Decision::NewDevice, "device {i}");
            last = Some(out);
        }
        let last = last.unwrap();
        assert_eq!(last.new_device_velocity, super::VelocityBand::Low);
        assert!(
            (last.confidence - 0.5).abs() < 1e-9,
            "no downgrade expected"
        );
    }

    fn ctx(components: &Components, now_ms: u64) -> IdentifyContext<'_> {
        IdentifyContext {
            components,
            now_ms,
            client_ip: None,
        }
    }

    fn is_lower_hex_128(id: &str) -> bool {
        id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    /// Identical first sightings in separate stores get unrelated random ids.
    #[test]
    fn minted_ids_are_random_128_bit_lower_hex() {
        let a = identify(&FuzzyStore::new(), &full_probe(), 1_000);
        let b = identify(&FuzzyStore::new(), &full_probe(), 1_000);
        let (a, b) = (a.visitor_id.unwrap(), b.visitor_id.unwrap());
        assert!(is_lower_hex_128(&a), "{a}");
        assert!(is_lower_hex_128(&b), "{b}");
        assert_ne!(a, b);
    }

    /// An erased id never recurs: the same device afterwards is a new device
    /// under a different id.
    #[test]
    fn identify_after_erase_mints_a_different_id() {
        let store = FuzzyStore::new();
        let first = identify(&store, &full_probe(), 1_000).visitor_id.unwrap();
        assert!(store.erase(&first));
        let again = identify(&store, &full_probe(), 2_000);
        assert!(again.is_new_device);
        assert_ne!(again.visitor_id.unwrap(), first);
        assert!(store.record(&first).is_none());
    }

    /// The pure scoring path never mints an id.
    #[test]
    fn score_on_an_empty_store_returns_no_id() {
        let out = FuzzyStore::new().score(&full_probe());
        assert_eq!(out.decision, Decision::NewDevice);
        assert!(out.is_new_device);
        assert!(out.visitor_id.is_none());
    }

    /// One device revisiting from one IP is never a new device again, so it
    /// never feeds the velocity band.
    #[test]
    fn one_device_revisiting_from_one_ip_never_raises_the_band() {
        let store = FuzzyStore::new();
        let ip = "203.0.113.20";
        for i in 0..50 {
            let out = identify_from(&store, &full_probe(), 1_000_000 + i * 1_000, ip);
            assert_eq!(
                out.new_device_velocity,
                super::VelocityBand::Low,
                "visit {i}"
            );
            if i > 0 {
                assert_eq!(out.decision, Decision::Match, "visit {i}");
            }
        }
    }

    /// Distinct new devices from one IP reach High, and the High band costs
    /// exactly the documented penalty against the same probe with no IP.
    #[test]
    fn distinct_new_devices_from_one_ip_reach_high_and_cost_the_penalty() {
        let store = FuzzyStore::new();
        let ip = "203.0.113.21";
        let mut last = None;
        for i in 0..25 {
            last = Some(identify_from(
                &store,
                &distinct_probe(i),
                1_000_000 + i * 1_000,
                ip,
            ));
        }
        let last = last.unwrap();
        assert_eq!(last.new_device_velocity, super::VelocityBand::High);
        let baseline = identify(&FuzzyStore::new(), &distinct_probe(24), 1_024_000);
        assert!(
            (baseline.confidence - last.confidence - super::super::VELOCITY_PENALTY).abs() < 1e-9,
            "baseline {} vs banded {}",
            baseline.confidence,
            last.confidence,
        );
    }

    /// A rich probe (18 components): many agreeing components keep the score
    /// past `T_hi` even when several High-stability components change.
    fn rich_probe() -> Components {
        components(json!({
            "webgl": "ANGLE (Intel)",
            "platform": "Linux x86_64",
            "timezone": "Asia/Shanghai",
            "languages": "en-US",
            "audio": "124.04",
            "cpu_cores": 8,
            "device_memory": 8,
            "fonts": ["Arial", "Helvetica", "Courier", "Times", "Verdana"],
            "canvas": "c0ffee",
            "screen": "1920x1080",
            "webgl_extensions": "ext-hash-1",
            "user_agent_data": "uad-hash-1",
            "font_preferences": "fp-hash-1",
            "screen_frame": "sf-hash-1",
            "math": "math-hash-1",
            "touch_support": "ts-hash-1",
            "dom_blockers": "db-hash-1",
            "plugins": ["PDF Viewer", "Chrome PDF Viewer"],
        }))
    }

    /// Changing three High-stability components of a matched template is a
    /// template jump: the strong match is downgraded to Review, flagged, and
    /// the template is left untouched — in `score` and `identify` alike.
    #[test]
    fn three_high_component_changes_are_a_template_jump() {
        let store = FuzzyStore::new();
        let id = identify(&store, &rich_probe(), 1_000).visitor_id.unwrap();
        let before = store.record(&id).unwrap();

        let mut jump = rich_probe();
        jump.webgl = Some("Mali-G78".into());
        jump.platform = Some("Linux armv8".into());
        jump.languages = Some("de-DE".into());

        let scored = store.score(&jump);
        assert!(scored.score.unwrap() >= T_HI, "score {:?}", scored.score);
        assert_eq!(scored.decision, Decision::Review);
        assert!(scored.template_jump);

        let out = identify(&store, &jump, 2_000);
        assert_eq!(out.decision, Decision::Review);
        assert!(out.template_jump);
        assert!(!out.is_new_device);
        assert_eq!(out.visitor_id.as_deref(), Some(id.as_str()));
        assert_eq!(store.record(&id).unwrap(), before);
        assert_eq!(store.read().agreement.stats("webgl"), (0, 0));
    }

    /// Two High-stability changes stay within the guard and still match.
    #[test]
    fn two_high_component_changes_still_match() {
        let store = FuzzyStore::new();
        let id = identify(&store, &rich_probe(), 1_000).visitor_id.unwrap();
        let mut probe = rich_probe();
        probe.webgl = Some("Mali-G78".into());
        probe.platform = Some("Linux armv8".into());
        let out = identify(&store, &probe, 2_000);
        assert_eq!(out.decision, Decision::Match);
        assert!(!out.template_jump);
        assert_eq!(out.visitor_id.as_deref(), Some(id.as_str()));
    }

    /// Drift moves the template but never the first-observation snapshot.
    #[test]
    fn drift_leaves_the_first_observation_snapshot_unchanged() {
        let store = FuzzyStore::new();
        let id = identify(&store, &rich_probe(), 1_000).visitor_id.unwrap();
        let snapshot = store.record(&id).unwrap().first_observation;
        assert_eq!(snapshot, store.record(&id).unwrap().components);

        let mut drifted = rich_probe();
        drifted.canvas = Some("beef".into());
        assert_eq!(identify(&store, &drifted, 2_000).decision, Decision::Match);
        let after = store.record(&id).unwrap();
        assert_ne!(after.components, snapshot);
        assert_eq!(after.first_observation, snapshot);
    }

    /// Two first sightings of one device whose read phases both run before
    /// either write phase resolve to ONE visitor: the second write sees the
    /// state moved, re-decides, and folds in as a match.
    #[test]
    fn interleaved_identical_first_sightings_yield_one_visitor() {
        let store = FuzzyStore::new();
        let probe = full_probe();
        let first_read = store.identify_read(&probe);
        let second_read = store.identify_read(&probe);
        assert_eq!(first_read.outcome.decision, Decision::NewDevice);
        assert_eq!(second_read.outcome.decision, Decision::NewDevice);

        let first = store.identify_write(&ctx(&probe, 1_000), first_read);
        let second = store.identify_write(&ctx(&probe, 1_001), second_read);
        assert_eq!(first.decision, Decision::NewDevice);
        assert_eq!(second.decision, Decision::Match);
        assert!(!second.is_new_device);
        assert_eq!(second.visitor_id, first.visitor_id);
        assert_eq!(store.read().records.len(), 1);
    }

    /// An erase landing between an identify's read and write phases never
    /// resurrects the erased id: the write re-decides, the probe becomes a new
    /// device under a different id, and the erased id is in no record or block.
    #[test]
    fn erase_between_phases_never_recreates_the_erased_id() {
        let store = FuzzyStore::new();
        let probe = full_probe();
        let erased = identify(&store, &probe, 1_000).visitor_id.unwrap();

        let pending = store.identify_read(&probe);
        assert_eq!(pending.outcome.decision, Decision::Match);
        assert!(store.erase(&erased));
        let out = store.identify_write(&ctx(&probe, 2_000), pending);

        assert_eq!(out.decision, Decision::NewDevice);
        let minted = out.visitor_id.unwrap();
        assert_ne!(minted, erased);
        assert!(store.record(&erased).is_none());
        assert!(!store.read().blocking.indexes(&erased));
        assert!(store.read().tombstones.contains(&erased));
    }
}
