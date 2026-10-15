//! Stage-two probabilistic scoring, decision, and drift (fuzzy-matching §5/§6/§7/§8).
//!
//! Given a probe, [`FuzzyStore::identify`] performs the full two-stage match:
//! stage one recalls candidates from the blocking indexes (fuzzy-matching §4, in
//! [`super`]), stage two scores each candidate with the Fellegi–Sunter model
//! (§5) and applies the double-threshold decision (§5.4), drift update (§7), and
//! confidence fusion (§6).
//!
//! The Fellegi–Sunter weights use two per-component parameters:
//! - `m_i = P(agree | same device)` — the cold-start stability prior (§2/§9),
//!   read from [`super::classify`].
//! - `u_i = P(agree | different device)` — the value's rarity, estimated from
//!   the frequency table (§9). Rare values that agree are strong evidence;
//!   common ones (Chrome-on-Windows) carry almost none.
//!
//! Thresholds and priors here are **cold-start defaults**; the fuzzy-matching spec's offline
//! evaluation (§10) tunes them against a labelled set. They are deliberately
//! separated so the eval harness can grid-search without touching scoring.

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{
    FuzzyStore, classify,
    component::{Hash32, Stored, jaccard, set_digest, u_prior},
    record::FingerprintRecord,
    velocity::{self, VelocityBand},
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
/// Pseudo-count weighting each component's `u_i` prior ([`u_prior`]) against
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
/// Confidence downgrade applied when a client IP's cross-session new-device rate
/// reaches [`VelocityBand::High`] — the fresh-seed-per-launch farm's footprint.
///
/// TUNING PLACEHOLDER (a policy guess, not a measured claim): fused the same way
/// as the passive-signal adjustment (`signals.rs` `confidence_adjustment`), it
/// lowers decision confidence for a `NewDevice` verdict without touching the
/// `visitorId` or the decision itself.
const VELOCITY_PENALTY: f64 = 0.3;
/// Component count of a full rich fingerprint. Confidence scales the number of
/// components that actually took part in scoring against this, so a sparse probe
/// (many missing) is less certain (fuzzy-matching §6/§8).
const FULL_COMPONENTS: f64 = 8.0;

/// The double-threshold verdict for a probe (fuzzy-matching §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Best candidate scored `≥ T_hi` — accepted as the same device.
    Match,
    /// Best candidate scored in `[T_lo, T_hi)` — suspected; returned but the
    /// template is **not** updated (anti-poisoning, fuzzy-matching §7).
    Review,
    /// No candidate cleared `T_lo` — a fresh `visitorId` is minted.
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

/// Outcome of [`FuzzyStore::identify`].
#[derive(Debug, Clone)]
pub struct MatchOutcome {
    /// Resolved device identifier (existing on match/review, freshly minted new).
    pub visitor_id: String,
    /// `true` only when a new `visitorId` was minted.
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
    /// Cross-session new-device production-rate band for the client IP, a risk
    /// signal surfaced alongside `ip_risk` (never folded into identity). Always
    /// [`VelocityBand::Low`] from [`FuzzyStore::score`] and the no-IP identify
    /// path — the band is computed only by [`FuzzyStore::identify_with_ip`] when a
    /// client IP is supplied and a new device is minted.
    pub new_device_velocity: VelocityBand,
    /// Cross-session new-device production-rate band for the client's coarse JA4
    /// **class** (proxy-pool farm footprint, PLAN-006 HARDEN-002), surfaced
    /// alongside [`new_device_velocity`](MatchOutcome::new_device_velocity) —
    /// never folded into identity, and (under the default fusion) never into
    /// confidence either. Always [`VelocityBand::Low`] unless a JA4 is supplied to
    /// [`FuzzyStore::identify_with_signals`] and a new device is minted.
    pub new_device_velocity_ja4: VelocityBand,
}

/// Per-candidate stage-two score and its comparison count.
struct Scored {
    score: f64,
    compared: usize,
}

impl FuzzyStore {
    /// Identify `components`, folding the observation in per the verdict.
    ///
    /// Two-stage (fuzzy-matching §4/§5): recall candidates, score each with
    /// Fellegi–Sunter, then apply the double-threshold decision (§5.4). A match
    /// drifts the winning template (§7); a review returns the suspected visitor
    /// without updating it (anti-poisoning, §7); a new device is minted and
    /// stored. `now_ms` is Unix milliseconds for the stored timestamps.
    ///
    /// **Atomicity:** the evaluate-then-observe read-modify-write
    /// runs under one per-store guard, so concurrent `identify` calls cannot
    /// interleave their `observe` between another call's `evaluate` and
    /// `observe`. Each backend guards only its own state, so without this seam
    /// the read (`evaluate`) and the write-back (`observe`) are two separate
    /// atomic steps; a racing `observe` between them could change the frequency
    /// material and thus perturb scores non-deterministically. The guard makes
    /// the whole RMW a single critical section — the single-threaded outcome is
    /// byte-for-byte unchanged, at the cost of serializing `identify`. The
    /// deliberate trade-off: the read-only [`FuzzyStore::score`] path does **no**
    /// `observe` and never takes this guard, so the stateless edge remains
    /// lock-light and its parity/perf are unaffected.
    pub fn identify(&self, components: &Value, now_ms: u64) -> MatchOutcome {
        self.identify_with_signals(components, now_ms, None, None)
    }

    /// Identify `components`, additionally computing the per-IP cross-session
    /// new-device velocity band for the supplied `client_ip` (PLAN-004 red-team
    /// hardening). Thin wrapper over [`FuzzyStore::identify_with_signals`] with no
    /// JA4 supplied — behaviourally unchanged from before HARDEN-002.
    pub fn identify_with_ip(
        &self,
        components: &Value,
        now_ms: u64,
        client_ip: Option<&str>,
    ) -> MatchOutcome {
        self.identify_with_signals(components, now_ms, client_ip, None)
    }

    /// Identify `components`, additionally computing the cross-session new-device
    /// velocity bands for the supplied `client_ip` and raw `ja4` fingerprint.
    ///
    /// Behaves exactly like [`FuzzyStore::identify`] — same evaluate-then-observe
    /// under the `identify_lock`, same persistence per verdict — and adds two
    /// independent cross-session signals, both computed **only** when the verdict
    /// is [`Decision::NewDevice`]:
    ///
    /// - **per-IP** (PLAN-004): when `client_ip` is present, records a new-device
    ///   event for that IP and bands the trailing-window count into
    ///   [`MatchOutcome::new_device_velocity`] via [`VelocityBand::classify`]. A
    ///   [`VelocityBand::High`] rate — the fresh-seed-per-launch farm's footprint
    ///   — applies the documented `VELOCITY_PENALTY` confidence downgrade, fused
    ///   like `PassiveSignals::confidence_adjustment` (`signals.rs`).
    /// - **per-JA4-class** (PLAN-006 HARDEN-002): when `ja4` parses to a coarse
    ///   class ([`crate::signals::ja4_class`]), records a new-device event for
    ///   that class *alongside* the IP key (namespaced so the two never collide in
    ///   the shared store) and bands the count into
    ///   [`MatchOutcome::new_device_velocity_ja4`] via
    ///   [`VelocityBand::classify_ja4`] — deliberately far-higher thresholds,
    ///   since a JA4 class is shared by every real client of a browser family.
    ///   This catches a farm that rotates a residential proxy pool (defeating the
    ///   per-IP key) but shares one Chrome JA4 class.
    ///
    /// **Fusion — option (a), surface-only (DELIBERATE, load-bearing):** the
    /// JA4-class band is surfaced but applies **no** confidence change of its own,
    /// even at [`VelocityBand::High`]. A JA4 class is low-entropy and shared by
    /// *every* real Chrome user, so a lone High JA4-class band is the *expected*
    /// steady state for any popular class — penalising it would downgrade all
    /// normal Chrome traffic (a mass false positive). A safe confidence fusion
    /// would require corroboration by an *independent* adverse signal (per-IP band
    /// High, or a datacenter IP-risk verdict), but the per-IP `IpRisk` classifier
    /// lives in the HTTP/edge adapter, not this core engine, and the target
    /// adversary rides *residential* proxies (IP-risk Low) — so no safe composite
    /// is defensible from here. Confidence fusion for the JA4-class band is
    /// therefore deferred to a follow-up (L1/user decision); only the per-IP band
    /// moves confidence.
    ///
    /// With both signals absent (or any non-`NewDevice` verdict) the outcome is
    /// byte-identical to before: both bands stay [`VelocityBand::Low`] and no
    /// confidence adjustment is applied, so an empty velocity store is cold-start
    /// neutral. `now_ms` is Unix milliseconds; the velocity store keys on Unix
    /// seconds (`now_ms / 1000`), keeping the core clock-free and deterministic.
    pub fn identify_with_signals(
        &self,
        components: &Value,
        now_ms: u64,
        client_ip: Option<&str>,
        ja4: Option<&str>,
    ) -> MatchOutcome {
        // Hold the guard across evaluate + observe so the RMW is atomic; recover
        // from poisoning like the backend locks (a prior panic left no logical
        // corruption — the `()` guard carries no state).
        let _guard = self
            .identify_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut outcome = self.evaluate(components);
        // Persist per the verdict (fuzzy-matching §7): a confirmed match drifts the
        // winning template toward this observation and a new device is stored
        // under its freshly minted id; a review-band hit leaves the template
        // untouched (anti-poisoning).
        match outcome.decision {
            Decision::Match => {
                // Learn `m_i` material from this confirmed same-device pair
                // (fuzzy-matching §9) BEFORE `observe` drifts the template, so the
                // probe is compared against the template as it stood at the match.
                self.record_agreement(&outcome.visitor_id, components);
                self.observe(&outcome.visitor_id, components, now_ms);
            }
            Decision::NewDevice => {
                self.observe(&outcome.visitor_id, components, now_ms);
                // Cross-session velocity: a fresh device from a client IP that is
                // churning out new devices is the farm footprint (RT-003). Record
                // the event and band the trailing-window rate; a High rate
                // downgrades confidence without touching identity.
                if let Some(ip) = client_ip {
                    let now_secs = now_ms / 1000;
                    self.velocity.record(ip, now_secs);
                    let n = self.velocity.count(ip, now_secs, velocity::WINDOW);
                    outcome.new_device_velocity = VelocityBand::classify(n);
                    if outcome.new_device_velocity == VelocityBand::High {
                        outcome.confidence =
                            (outcome.confidence - VELOCITY_PENALTY).clamp(0.0, 1.0);
                    }
                }
                // Secondary JA4-class velocity (HARDEN-002): record ALONGSIDE the
                // IP key, under the coarse JA4 shape class, to catch a farm that
                // rotates a proxy pool but shares one Chrome JA4 class. The key is
                // namespaced ("ja4:") so a class string can never collide with an
                // IP key in the shared store.
                //
                // Fusion is option (a) — surface only: the band is set but NO
                // confidence downgrade is applied on its own (not even at High).
                // JA4 is low-entropy and shared by every real Chrome user, so a
                // lone High JA4-class band is the expected steady state and must
                // not penalise all Chrome traffic. Confidence fusion is deferred
                // (see the method doc); only the per-IP band above moves confidence.
                if let Some(class) = ja4.and_then(crate::signals::ja4_class) {
                    let now_secs = now_ms / 1000;
                    let key = format!("ja4:{class}");
                    self.velocity.record(&key, now_secs);
                    let n = self.velocity.count(&key, now_secs, velocity::WINDOW);
                    outcome.new_device_velocity_ja4 = VelocityBand::classify_ja4(n);
                }
            }
            Decision::Review => {}
        }
        outcome
    }

    /// Score `components` and decide, **without mutating** the store (fuzzy-matching §5).
    ///
    /// The pure half of [`identify`](Self::identify): stage-one recall, Fellegi–Sunter scoring,
    /// and the double-threshold decision. It returns the same [`MatchOutcome`]
    /// `identify` would but leaves the record library, blocking index, and
    /// frequency table untouched — the entry point a stateless edge host calls
    /// to obtain a verdict before performing its own persistence (D1/DO
    /// write-back) per the returned [`Decision`].
    pub fn score(&self, components: &Value) -> MatchOutcome {
        self.evaluate(components)
    }

    /// Stage-one recall + stage-two scoring + decision for `components`, with no
    /// side effects. Shared by [`identify`] (which then persists) and [`score`]
    /// (which does not).
    ///
    /// [`identify`]: FuzzyStore::identify
    /// [`score`]: FuzzyStore::score
    fn evaluate(&self, components: &Value) -> MatchOutcome {
        let probe = self.stored_map(components);

        // Stage one: recall, then score every candidate against the probe.
        let mut scored: Vec<(String, Scored)> = self
            .candidates(components)
            .into_iter()
            .map(|id| {
                let record = self.record(&id);
                let s = record.map_or(
                    Scored {
                        score: f64::NEG_INFINITY,
                        compared: 0,
                    },
                    |r| self.score_candidate(&probe, &r),
                );
                (id, s)
            })
            .collect();
        // Highest score first; a runner-up (if any) drives collision detection.
        scored.sort_by(|a, b| b.1.score.total_cmp(&a.1.score));

        let best = scored.first();
        let second_score = scored.get(1).map(|(_, s)| s.score);
        let best_score = best.map(|(_, s)| s.score);
        let compared = best.map_or(0, |(_, s)| s.compared);

        let decision = match best_score {
            Some(s) if s >= T_HI => Decision::Match,
            Some(s) if s >= T_LO => Decision::Review,
            _ => Decision::NewDevice,
        };

        let confidence = confidence(decision, best_score, second_score, compared);

        // `decision` is `Match`/`Review` only when `best` is `Some`, so the
        // matched arms always bind the winning candidate; the fallthrough covers
        // `NewDevice` (and the unreachable no-candidate case).
        match (decision, best) {
            (Decision::Match, Some((id, top))) => {
                let collision_risk =
                    second_score.is_some_and(|s2| s2 >= T_HI && (top.score - s2) < COLLISION_GAP);
                MatchOutcome {
                    visitor_id: id.clone(),
                    is_new_device: false,
                    confidence,
                    decision,
                    score: best_score,
                    compared_components: compared,
                    collision_risk,
                    new_device_velocity: VelocityBand::Low,
                    new_device_velocity_ja4: VelocityBand::Low,
                }
            }
            (Decision::Review, Some((id, _))) => MatchOutcome {
                visitor_id: id.clone(),
                is_new_device: false,
                confidence,
                decision,
                score: best_score,
                compared_components: compared,
                collision_risk: false,
                new_device_velocity: VelocityBand::Low,
                new_device_velocity_ja4: VelocityBand::Low,
            },
            _ => {
                let id = derive_visitor_id(components);
                MatchOutcome {
                    visitor_id: id,
                    is_new_device: true,
                    confidence,
                    decision: Decision::NewDevice,
                    score: best_score,
                    compared_components: compared,
                    collision_risk: false,
                    new_device_velocity: VelocityBand::Low,
                    new_device_velocity_ja4: VelocityBand::Low,
                }
            }
        }
    }

    /// Record per-component agreement of `components` against the matched
    /// template's stored values, accumulating the material behind `m_i`
    /// (fuzzy-matching §9).
    ///
    /// Called only from the `Decision::Match` arm of [`identify`], under its lock
    /// and **before** [`observe`] drifts the template, so it compares the probe
    /// against the template as it stood when the match was confirmed. Each
    /// component present (and kind-compatible) on both sides contributes one
    /// same-device observation: agreement iff its similarity clears `τ` — the
    /// same threshold [`score_candidate`] uses. Names missing on either side, or
    /// of mismatched kind (`compare` → `None`), are skipped.
    ///
    /// [`identify`]: FuzzyStore::identify
    /// [`observe`]: FuzzyStore::observe
    /// [`score_candidate`]: FuzzyStore::score_candidate
    fn record_agreement(&self, visitor_id: &str, components: &Value) {
        let Some(template) = self.record(visitor_id) else {
            return;
        };
        let probe = self.stored_map(components);
        for (name, probe_value) in &probe {
            let Some(template_value) = template.components.get(name) else {
                continue; // missing on the template side → not compared (§8)
            };
            let Some((sim, _u)) = self.compare(name, probe_value, template_value) else {
                continue; // kind mismatch → not comparable
            };
            self.agreement.record(name, sim >= TAU);
        }
    }

    /// Fellegi–Sunter score of a candidate template against the probe (fuzzy-matching §5).
    ///
    /// Sums the per-component log-likelihood weight over components present on
    /// both sides; components missing on either side are skipped, contributing
    /// zero (fuzzy-matching §5.3/§8).
    fn score_candidate(&self, probe: &ProbeMap, template: &FingerprintRecord) -> Scored {
        let mut score = 0.0;
        let mut compared = 0;
        for (name, probe_value) in probe {
            let Some(template_value) = template.components.get(name) else {
                continue; // missing on the template side → not compared (§8)
            };
            let Some((sim, u)) = self.compare(name, probe_value, template_value) else {
                continue; // kind mismatch → not comparable
            };
            let m = self.m_estimate(name, classify(name).stability.m_prior());
            score += agreement_weight(m, u, sim);
            compared += 1;
        }
        Scored { score, compared }
    }

    /// Compare one component, returning its agreement fraction `sim ∈ [0, 1]`
    /// and the rarity `u_i` of the probe's value for that component
    /// (fuzzy-matching §5.1/§5.3). `None` if the two stored forms are of
    /// different kinds and cannot be compared.
    fn compare(&self, name: &str, probe: &Stored, template: &Stored) -> Option<(f64, f64)> {
        match (probe, template) {
            (Stored::Category(a), Stored::Category(b)) => {
                let sim = f64::from(u8::from(a == b));
                Some((sim, self.u_estimate(name, *a)))
            }
            (Stored::Numeric(a), Stored::Numeric(b)) => {
                let sim = f64::from(u8::from(a == b));
                Some((sim, self.u_estimate(name, self.salt.hash(&a.to_string()))))
            }
            (Stored::Set(a), Stored::Set(b)) => {
                let j = jaccard(a, b);
                // `J ≥ τ` counts as full agreement; below it, interpolate by J (§5.3).
                let sim = if j >= TAU { 1.0 } else { j };
                Some((sim, self.u_estimate(name, set_digest(a))))
            }
            _ => None,
        }
    }

    /// Estimate `u_i` for `value` of component `name`: its relative frequency
    /// among that component's sightings (fuzzy-matching §5/§9), shrunk toward
    /// the component's [`u_prior`] by [`U_PSEUDO`] pseudo-sightings and clamped
    /// to keep the log-ratios finite.
    ///
    /// The denominator is the component's own sighting count: a value every
    /// device shares reads as common (`u → 1`) instead of being diluted by the
    /// number of components, and the prior keeps a cold or tiny library from
    /// reading every value as either unique or universal.
    #[allow(clippy::cast_precision_loss)] // frequency ratio; precision loss immaterial
    fn u_estimate(&self, name: &str, value: Hash32) -> f64 {
        let hits = self.frequency.count(name, value) as f64;
        let total = self.frequency.total(name) as f64;
        ((hits + U_PSEUDO * u_prior(name)) / (total + U_PSEUDO)).clamp(U_FLOOR, U_CEIL)
    }

    /// Estimate `m_i` for the component `name`: its observed same-device
    /// agreement rate, shrunk toward the cold-start stability `prior` by an
    /// `ALPHA`-weighted pseudo-count (fuzzy-matching §9).
    ///
    /// **Cold start is bit-identical:** with no recorded agreements
    /// (`total == 0`) this returns the `prior` *exactly*, before any arithmetic,
    /// so an empty store scores byte-for-byte as the fixed-prior path did. Once
    /// confirmed same-device revisits accumulate, the estimate moves from the
    /// prior toward the empirical rate; the clamp keeps it in `(0, 1)` so the
    /// log-ratios stay finite.
    #[allow(clippy::cast_precision_loss)] // agreement counts; precision loss immaterial
    fn m_estimate(&self, name: &str, prior: f64) -> f64 {
        let (agree, total) = self.agreement.stats(name);
        if total == 0 {
            return prior; // cold-start bit-identical
        }
        let est = (agree as f64 + ALPHA * prior) / (total as f64 + ALPHA);
        est.clamp(M_FLOOR, M_CEIL)
    }
}

/// Alias to name the probe map inside method signatures without leaking the
/// `BTreeMap` spelling everywhere.
type ProbeMap = std::collections::BTreeMap<String, Stored>;

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
/// The passive JA4/UA consistency input (fuzzy-matching §6) is a P2 signal, left
/// neutral here.
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

/// Derive a fresh deterministic `visitorId` for a new device: the SHA-256 of the
/// canonical component bytes, hex-encoded. Deterministic so an identical probe
/// that somehow escaped recall still resolves to one id.
fn derive_visitor_id(components: &Value) -> String {
    let canonical = serde_json::to_vec(components).unwrap_or_default();
    hex::encode(Sha256::digest(&canonical))
}

#[cfg(test)]
mod tests {
    use super::{Decision, T_LO};
    use crate::fuzzy::FuzzyStore;
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

    /// (b) Anti-collision: two different devices that collide on a blocking key
    /// (shared audio+cpu+memory) but disagree on the high-stability discriminants
    /// (webgl/platform/timezone/fonts) must be scored apart, not merged (§5).
    #[test]
    fn b_shared_block_but_distinct_device_is_not_merged() {
        let store = FuzzyStore::new();
        let first = store.identify(&full_probe(), 1_000);

        // Same K2 subset (audio + cpu_cores + device_memory) so `first` is
        // recalled, but every high-stability discriminant disagrees.
        let other = json!({
            "webgl": "Mali-G78",
            "platform": "Linux armv8",
            "timezone": "America/New_York",
            "audio": "124.04",
            "cpu_cores": 8,
            "device_memory": 8,
            "fonts": ["Roboto", "Noto", "Droid", "Ubuntu"],
            "user_agent": "Firefox/119",
        });
        // The collision is real at stage one: `first` is in the candidate set.
        assert!(store.candidates(&other).contains(&first.visitor_id));

        let second = store.identify(&other, 2_000);
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
        let low = json!({
            "platform": "Linux x86_64",
            "timezone": "Asia/Shanghai",
            "languages": "en-US",
        });
        // A crowd shares these exact low-entropy values, inflating their `u_i`.
        for i in 0..30 {
            store.observe(&format!("bg{i}"), &low, 1_000);
        }

        // The victim is recalled against the crowd (they share the K0 key)...
        assert!(!store.candidates(&low).is_empty());
        // ...but the common agreements never clear T_lo, so it is judged new.
        let out = store.identify(&low, 2_000);
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
        let seed = store.identify(&full_probe(), 1_000);
        let id = seed.visitor_id.clone();

        let before = store.record(&id).unwrap();
        assert_eq!(before.last_seen, 1_000);

        // A probe agreeing on only the stable K1 subset plus audio and
        // cpu_cores scores in the review band: enough evidence to suspect `id`,
        // not enough to confirm and drift it.
        let review_probe = json!({
            "webgl": "ANGLE (Intel)",
            "platform": "Linux x86_64",
            "timezone": "Asia/Shanghai",
            "audio": "124.04",
            "cpu_cores": 8,
        });
        let review = store.identify(&review_probe, 5_000);
        assert_eq!(review.decision, Decision::Review);
        assert_eq!(review.visitor_id, id);

        // The template is untouched: same last_seen, components, and count.
        let after = store.record(&id).unwrap();
        assert_eq!(
            after.last_seen, before.last_seen,
            "review must not drift last_seen"
        );
        assert_eq!(after.observation_count, before.observation_count);
        assert_eq!(after.components, before.components);

        // Bracket the gate: a genuine `≥ T_hi` match DOES advance the template.
        let confirm = store.identify(&full_probe(), 9_000);
        assert_eq!(confirm.decision, Decision::Match);
        assert_eq!(store.record(&id).unwrap().last_seen, 9_000);
    }

    /// (concurrency) Many threads hammer `identify` against one shared store
    /// with a mix of the same and distinct devices. `identify`'s evaluate +
    /// observe run under the per-store guard, so the concurrent read-modify-write
    /// stays atomic. The store must end in a consistent state: no panic, one
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
        let devices: Arc<Vec<Value>> = Arc::new(
            (0..8)
                .map(|i| {
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
                        // same-device evaluate/observe across threads — the raced
                        // RMW the guard serializes.
                        for (d, probe) in devices.iter().enumerate() {
                            let now = 1_000 + (t as u64) * 1_000_000 + i * 1_000 + d as u64;
                            let out = store.identify(probe, now);
                            assert!(
                                matches!(out.decision, Decision::Match | Decision::NewDevice),
                                "unexpected {:?} for device {d}",
                                out.decision,
                            );
                            local.insert((d, out.visitor_id));
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
            let out = store.identify(probe, 9_000_000);
            assert_eq!(out.decision, Decision::Match, "re-identify device {d}");
            assert!(seen.contains(&(d, out.visitor_id)));
        }
    }

    /// Cold start is prior-driven: on a fresh store the agreement table is empty
    /// during the matching `evaluate`, so `m_estimate` returns the prior exactly
    /// (bit-identity is proven cross-stack in MI-003). The first identify mints a
    /// device; the second still Matches it, and only then does the Match-hook
    /// populate the agreement material.
    #[test]
    fn cold_start_matches_on_priors_then_records_agreement() {
        let store = FuzzyStore::new();
        // Nothing learned yet: the estimate is the untouched prior.
        assert_eq!(store.agreement.stats("webgl"), (0, 0));

        let first = store.identify(&full_probe(), 1_000);
        assert!(first.is_new_device); // NewDevice does not record agreement
        assert_eq!(store.agreement.stats("webgl"), (0, 0));

        let second = store.identify(&full_probe(), 2_000);
        assert_eq!(second.decision, Decision::Match);
        assert_eq!(second.visitor_id, first.visitor_id);
        // The Match-hook fired: webgl agreed on this same-device revisit.
        assert_eq!(store.agreement.stats("webgl"), (1, 1));
    }

    /// A high-stability component that agrees on every confirmed same-device
    /// revisit accumulates agreement counts, and `m_estimate` moves from the cold
    /// prior up toward `M_CEIL` as the empirical rate reinforces it (fuzzy-matching §9).
    #[test]
    fn repeated_same_device_matches_lift_m_estimate() {
        use crate::fuzzy::classify;

        let store = FuzzyStore::new();
        let prior = classify("webgl").stability.m_prior();

        // Seed the device, then revisit it repeatedly with the identical probe —
        // every revisit is a Match that records webgl as agreeing.
        store.identify(&full_probe(), 1_000);
        for i in 0..10 {
            let out = store.identify(&full_probe(), 2_000 + i);
            assert_eq!(out.decision, Decision::Match);
        }

        // Ten confirmed same-device agreements accumulated.
        assert_eq!(store.agreement.stats("webgl"), (10, 10));
        // The estimate has climbed above the cold prior toward the ceiling.
        let est = store.m_estimate("webgl", prior);
        assert!(est > prior, "m_estimate {est} should exceed prior {prior}");
        assert!(est < super::M_CEIL);
        // An unlearned component still returns its untouched prior exactly.
        assert!((store.m_estimate("plugins", 0.8) - 0.8).abs() < f64::EPSILON);
    }

    /// Learning is monotone: each confirmed same-device revisit of an
    /// always-agreeing component moves its `m_estimate` strictly upward, starting
    /// from the exact cold prior and rising toward — but never past — `M_CEIL`
    /// (fuzzy-matching §9).
    #[test]
    fn m_estimate_climbs_monotonically_across_same_device_revisits() {
        use crate::fuzzy::classify;

        let store = FuzzyStore::new();
        let prior = classify("webgl").stability.m_prior();

        // Mint the device: NewDevice records no agreement, so the estimate is
        // still the untouched cold prior, bit-for-bit.
        store.identify(&full_probe(), 1_000);
        let mut prev = store.m_estimate("webgl", prior);
        assert!(
            (prev - prior).abs() < f64::EPSILON,
            "cold start returns the prior exactly"
        );

        // Every identical revisit is a Match that records webgl agreeing, lifting
        // the estimate a little further each time.
        for i in 0..12 {
            let out = store.identify(&full_probe(), 2_000 + i);
            assert_eq!(out.decision, Decision::Match);
            let est = store.m_estimate("webgl", prior);
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
        store.identify(&full_probe(), 1_000);

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
            "user_agent",
        ] {
            for _ in 0..20_000 {
                store.agreement.record(name, true);
            }
            assert!(
                (store.m_estimate(name, 0.95) - super::M_CEIL).abs() < 1e-9,
                "{name} m_estimate should clamp to M_CEIL"
            );
        }

        // The per-component weight is finite at the extreme for a full agreement
        // (`log2(m/u)`) and a full disagreement (`log2((1-m)/(1-u))`) alike — the
        // clamp keeps `m` off `0`/`1`, so neither log-ratio blows up.
        assert!(super::agreement_weight(super::M_CEIL, super::U_FLOOR, 1.0).is_finite());
        assert!(super::agreement_weight(super::M_CEIL, super::U_CEIL, 0.0).is_finite());

        // A real identify with every `m` at the clamp still produces a finite score.
        let out = store.identify(&full_probe(), 2_000);
        assert_eq!(out.decision, Decision::Match);
        let matched_score = out.score.expect("a matched candidate has a score");
        assert!(matched_score.is_finite(), "score was {matched_score}");
    }

    /// A churning component that never agrees earns *less* trust than its cold
    /// prior: the stable components carry each match, but the flaky `user_agent`
    /// disagrees on every confirmed revisit, so its `m_estimate` is pulled below
    /// the prior (fuzzy-matching §9).
    #[test]
    fn churning_component_m_estimate_falls_below_its_prior() {
        use crate::fuzzy::classify;

        let store = FuzzyStore::new();
        let ua_prior = classify("user_agent").stability.m_prior();

        // Seed the device, then revisit with the stable components unchanged (they
        // carry the match) but a fresh user_agent each time, so it never agrees.
        store.identify(&full_probe(), 1_000);
        for i in 0..12 {
            let mut probe = full_probe();
            probe["user_agent"] = json!(format!("Chrome/{}", 200 + i));
            let out = store.identify(&probe, 2_000 + i);
            assert_eq!(
                out.decision,
                Decision::Match,
                "stable components must carry the match while UA churns"
            );
        }

        let (agree, total) = store.agreement.stats("user_agent");
        assert_eq!(agree, 0, "user_agent never agreed");
        assert!(
            total >= 12,
            "every revisit recorded a same-device comparison"
        );
        let est = store.m_estimate("user_agent", ua_prior);
        assert!(
            est < ua_prior,
            "churning estimate {est} should fall below prior {ua_prior}"
        );
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

    /// (RT-003) The cross-session catch: one client IP minting a burst of fresh
    /// devices inside the window crosses to [`VelocityBand::High`] and takes the
    /// documented confidence downgrade — while its decision/visitorId are
    /// untouched. This is what RT-001's per-session
    /// `fresh_seed_per_launch_each_mints_a_new_device` baseline cannot see.
    #[test]
    fn burst_of_new_devices_from_one_ip_crosses_to_high_and_downgrades() {
        use super::velocity::HIGH;

        let store = FuzzyStore::new();
        let ip = "203.0.113.9";

        // `HIGH` distinct fresh devices from one IP, all within the window
        // (seconds apart). Each is a NewDevice; the last crosses the High band.
        let mut last = None;
        for i in 0..HIGH {
            let probe = distinct_probe(i);
            let out = store.identify_with_ip(&probe, 1_000_000 + i * 1_000, Some(ip));
            assert_eq!(out.decision, Decision::NewDevice, "device {i}");
            assert!(out.is_new_device);
            last = Some(out);
        }
        let last = last.unwrap();
        assert_eq!(last.new_device_velocity, super::VelocityBand::High);
        // A no-candidate NewDevice's neutral confidence is 0.5; the High band
        // subtracts the documented penalty, fused like the passive adjustment.
        assert!(
            (last.confidence - (0.5 - super::VELOCITY_PENALTY)).abs() < 1e-9,
            "confidence was {}",
            last.confidence,
        );
    }

    /// The same burst spread *beyond* the window never accumulates: each event
    /// ages out before the next, so the band stays [`VelocityBand::Low`] and no
    /// downgrade is applied.
    #[test]
    fn new_devices_spread_beyond_the_window_stay_low() {
        use super::velocity::{HIGH, WINDOW};

        let store = FuzzyStore::new();
        let ip = "203.0.113.10";

        // Space events more than a window apart (in ms), so at each access the
        // prior events have all aged out and the count is 1.
        let step_ms = (WINDOW + 10) * 1_000;
        let mut last = None;
        for i in 0..HIGH {
            let probe = distinct_probe(i);
            let out = store.identify_with_ip(&probe, 1_000_000 + i * step_ms, Some(ip));
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

    /// A real-browser JA4 (Chrome-over-HTTP/2 shape); its coarse class
    /// (`t13dh2`) is shared by every real client of that family.
    const BROWSER_JA4: &str = "t13d1516h2_8daaf6152771_02713d6af862";

    /// (HARDEN-002) The proxy-pool farm catch: many fresh devices that share ONE
    /// coarse JA4 class — each from a different (here absent) IP — drive the
    /// per-class velocity band up through its far-higher thresholds. This is the
    /// footprint the per-IP key (RT-003) misses when a farm rotates a residential
    /// proxy pool but keeps one Chrome JA4 class. The band rises (crossing MEDIUM,
    /// then HIGH) while the per-IP band and — under fusion (a) — confidence stay
    /// untouched.
    #[test]
    fn burst_sharing_one_ja4_class_rises_but_band_only_never_downgrades() {
        use super::velocity::{JA4_HIGH, JA4_MEDIUM};

        let store = FuzzyStore::new();

        let mut at_medium = None;
        let mut last = None;
        for i in 0..JA4_HIGH {
            let probe = distinct_probe(i);
            // No client IP: the JA4-class band must rise on its own, with NO
            // per-IP corroboration — the load-bearing lone-High case.
            let out =
                store.identify_with_signals(&probe, 1_000_000 + i * 1_000, None, Some(BROWSER_JA4));
            assert_eq!(out.decision, Decision::NewDevice, "device {i}");
            // The per-IP band never moves (no IP supplied).
            assert_eq!(out.new_device_velocity, super::VelocityBand::Low);
            if i + 1 == JA4_MEDIUM {
                at_medium = Some(out.clone());
            }
            last = Some(out);
        }

        // Crossing MEDIUM: the per-class band is Medium at the documented threshold.
        assert_eq!(
            at_medium.unwrap().new_device_velocity_ja4,
            super::VelocityBand::Medium
        );

        // Crossing HIGH: the per-class band reaches High...
        let last = last.unwrap();
        assert_eq!(last.new_device_velocity_ja4, super::VelocityBand::High);
        // ...yet confidence is UNTOUCHED. Fusion (a): a lone High JA4-class band,
        // with no IP-High and no datacenter IP risk, must NOT downgrade confidence
        // — else every popular real Chrome class would be penalised. A
        // no-candidate NewDevice's neutral confidence is 0.5, unchanged here.
        assert!(
            (last.confidence - 0.5).abs() < 1e-9,
            "lone High JA4 band must not downgrade confidence; was {}",
            last.confidence,
        );
    }

    /// No (or unparseable) JA4 is neutral for the per-class band: no event is
    /// recorded, the band stays [`VelocityBand::Low`], and confidence is
    /// untouched — an empty JA4 velocity store is cold-start neutral, so the
    /// parity vectors stay byte-identical.
    #[test]
    fn absent_or_malformed_ja4_keeps_the_class_band_low_and_neutral() {
        let store = FuzzyStore::new();

        // No JA4 at all (an IP is present, exercising the IP path independently).
        let out =
            store.identify_with_signals(&distinct_probe(1), 1_000_000, Some("198.51.100.7"), None);
        assert_eq!(out.new_device_velocity_ja4, super::VelocityBand::Low);

        // A malformed JA4 parses to no class → no event recorded → band stays Low.
        let out2 =
            store.identify_with_signals(&distinct_probe(2), 1_000_100, None, Some("garbage"));
        assert_eq!(out2.new_device_velocity_ja4, super::VelocityBand::Low);
        assert!((out2.confidence - 0.5).abs() < 1e-9);
    }
}
