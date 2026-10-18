//! `fp-wasm` — the fingerprinting compute compiled to WebAssembly.
//!
//! The stateless compute a Cloudflare Worker host (`apps/edge`) runs for an
//! `/identify` request, backed by [`fingerprintd`] so the Worker and the native
//! Axum server share one implementation. The host owns all I/O and state: it
//! persists only the **salted stored form** of a device (never raw component
//! values), recalls candidates from its own index, and mints visitor ids itself.
//!
//! # Wire shapes
//!
//! - **components** — the closed component schema
//!   (`fingerprintd::fuzzy::Components`, keys = [`component_keys`]). An unknown
//!   key or a wrongly-typed value is an error (a thrown JS exception).
//! - **stored** — the salted stored form
//!   (`fingerprintd::fuzzy::StoredComponents`): an object keyed by component
//!   name, each value one of `{"category": "<64 hex>"}`, `{"numeric": <i64>}`,
//!   `{"set": ["<64 hex>", ..]}` matching the component's kind. Absent
//!   components are omitted. An unknown name, wrong kind, or malformed hash is
//!   an error.
//! - **keys** — a JSON array of 64-hex-char blocking keys.
//!
//! # Exports
//!
//! - [`component_keys`]`()` → JSON array of the closed schema's keys.
//! - [`FpEngine`] — configured with the deployment's salt secret (a Worker
//!   Secret, never embedded in the module):
//!   - `new(salt_secret)` — constructor.
//!   - [`FpEngine::stored_form`]`(components_json)` → **stored**.
//!   - [`FpEngine::blocking_keys`]`(components_json)` → **keys**.
//!   - [`FpEngine::blocking_keys_stored`]`(stored_json)` → **keys** of a
//!     persisted template (identical to the keys of its source components).
//!   - [`FpEngine::score`]`(request_json)` → the verdict plus what to persist:
//!     request `{"components": {..}, "candidates": [{"visitor_id": "..",
//!     "stored": {..}}, ..]}`, reply `{"decision": "match"|"review"|"new_device",
//!     "visitor_id": string|null, "is_new_device": bool, "confidence": f64,
//!     "score": f64|null, "compared_components": int, "collision_risk": bool,
//!     "template_jump": bool, "probe_stored": {..}, "template": {..}|null,
//!     "template_blocking_keys": [..]|null}`.
//! - [`passive_signals`]`(ja4?, client_ip?, claimed_ua?)` →
//!   `{"ua_tls_consistent": bool, "ip_risk": "low"|"medium"|"high",
//!   "confidence_adjustment": f64}`.
//! - [`client_integrity`]`(integrity_json?, penalty_enabled)` →
//!   `{"client_integrity": "ok"|"noise"|"unavailable",
//!   "confidence_adjustment": f64}`; `integrity_json` is the request's
//!   top-level `{"canvas"?, "webgl"?, "audio"?, "rect"?}` object, each value
//!   `"ok"|"noise"|"unavailable"` (closed; malformed input throws).
//! - [`persona_coherence_label`]`(claimed_ua?, fonts_json?)` →
//!   `"consistent"|"mismatch"|"unknown"`; `fonts_json` is the `fonts`
//!   component (a JSON array of strings).
//! - [`automation`]`(botd_json?)` → `"detected"|"not_detected"|"unknown"`;
//!   `botd_json` is `{"bot": bool, "kind"?: string|null}` (closed; malformed
//!   input throws).
//! - [`velocity_band`]`(distinct_count)` → `"low"|"medium"|"high"` for the
//!   number of distinct new devices the host counted for one client IP in its
//!   trailing window.
//! - [`velocity_penalty`]`(band)` → the confidence penalty the host subtracts
//!   for that band (unknown label throws).

use fingerprintd::fuzzy::{
    COMPONENT_KEYS, Components, Decision, FuzzyStore, StoredComponents, VelocityBand,
};
use fingerprintd::signals::{
    Automation, Botd, ClientIntegrity, Integrity, StaticIpIntel, compute, persona_coherence,
};
use serde::Deserialize;
use serde_json::{Value, json};
use wasm_bindgen::prelude::{JsError, wasm_bindgen};

/// Passive-signals verdict for one request, computed exactly as the native
/// server ([`fingerprintd::signals::compute`]) does, so the edge Worker reaches
/// the same UA↔TLS / IP-risk verdict.
///
/// Uses the dependency-free [`StaticIpIntel`] classifier and cross-checks the
/// trusted JA4 stack against the claimed UA. A missing/unparseable JA4
/// auto-degrades (neutral); a missing/unparseable IP defaults to `"low"` (§4.2).
///
/// The owned `Option<String>` parameters are the wasm-bindgen boundary shape (JS
/// strings arrive owned); the body only borrows them, hence the local allow.
#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)]
pub fn passive_signals(
    ja4: Option<String>,
    client_ip: Option<String>,
    claimed_ua: Option<String>,
) -> String {
    passive_signals_impl(ja4.as_deref(), client_ip.as_deref(), claimed_ua.as_deref())
}

/// Native-testable core of [`passive_signals`].
fn passive_signals_impl(
    ja4: Option<&str>,
    client_ip: Option<&str>,
    claimed_ua: Option<&str>,
) -> String {
    let intel = StaticIpIntel::new();
    let signals = compute(ja4, client_ip, claimed_ua, &intel);
    let reply = json!({
        "ua_tls_consistent": signals.tls_consistency.ua_tls_consistent(),
        "ip_risk": signals.ip_risk.as_str(),
        "confidence_adjustment": signals.confidence_adjustment(),
    });
    reply.to_string()
}

/// Fuse the client's known-answer integrity verdicts (the request's top-level
/// `integrity` object, JSON-encoded) into one verdict plus its confidence
/// adjustment ([`ClientIntegrity`]), as the native server does. `None` reads
/// `unavailable` with a neutral `0` adjustment; the penalty applies only when
/// the deployment enabled it. A non-object, an unknown key, or a verdict other
/// than `ok` | `noise` | `unavailable` throws ([`Integrity`]).
#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)]
pub fn client_integrity(
    integrity_json: Option<String>,
    penalty_enabled: bool,
) -> Result<String, JsError> {
    client_integrity_impl(integrity_json.as_deref(), penalty_enabled).map_err(|e| JsError::new(&e))
}

/// Native-testable core of [`client_integrity`].
fn client_integrity_impl(
    integrity_json: Option<&str>,
    penalty_enabled: bool,
) -> Result<String, String> {
    let integrity: Option<Integrity> = integrity_json
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| format!("invalid integrity JSON: {e}"))?;
    let verdict = ClientIntegrity::from_integrity(integrity.as_ref());
    let reply = json!({
        "client_integrity": verdict.as_str(),
        "confidence_adjustment": verdict.confidence_adjustment(penalty_enabled),
    });
    Ok(reply.to_string())
}

/// Cross-check the UA-claimed OS family against the `fonts` component (a JSON
/// array of strings) — [`persona_coherence`]. Returns `consistent` |
/// `mismatch` | `unknown`; `None` or unparseable `fonts_json` reads `unknown`
/// (neutral). Surfaced-only.
#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)]
pub fn persona_coherence_label(claimed_ua: Option<String>, fonts_json: Option<String>) -> String {
    persona_coherence_impl(claimed_ua.as_deref(), fonts_json.as_deref())
}

/// Native-testable core of [`persona_coherence_label`].
fn persona_coherence_impl(claimed_ua: Option<&str>, fonts_json: Option<&str>) -> String {
    let fonts: Option<Vec<String>> = fonts_json.and_then(|raw| serde_json::from_str(raw).ok());
    persona_coherence(claimed_ua, fonts.as_deref())
        .as_str()
        .to_owned()
}

/// The automation verdict for the request's client-side bot-detection result
/// (`{"bot": bool, "kind"?: string|null}`, JSON-encoded), as
/// [`Automation::from_botd`] maps it: `detected` | `not_detected`, or `unknown`
/// when absent. Surfaced-only. An unknown field or wrong type throws.
#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)]
pub fn automation(botd_json: Option<String>) -> Result<String, JsError> {
    automation_impl(botd_json.as_deref()).map_err(|e| JsError::new(&e))
}

/// Native-testable core of [`automation`].
fn automation_impl(botd_json: Option<&str>) -> Result<String, String> {
    let botd: Option<Botd> = botd_json
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| format!("invalid botd JSON: {e}"))?;
    Ok(Automation::from_botd(botd.as_ref()).as_str().to_owned())
}

/// The cross-session velocity band (`low` | `medium` | `high`) for the number
/// of distinct new devices the host counted for one client IP within its
/// trailing window — [`VelocityBand::classify`], identical to the native store.
#[wasm_bindgen]
pub fn velocity_band(distinct_count: u32) -> String {
    VelocityBand::classify(u64::from(distinct_count))
        .as_str()
        .to_owned()
}

/// The confidence penalty the host subtracts for a velocity `band` label —
/// [`fingerprintd::fuzzy::velocity_penalty`]. An unknown label throws.
#[wasm_bindgen]
pub fn velocity_penalty(band: &str) -> Result<f64, JsError> {
    velocity_penalty_impl(band).map_err(|e| JsError::new(&e))
}

/// Native-testable core of [`velocity_penalty`].
fn velocity_penalty_impl(band: &str) -> Result<f64, String> {
    VelocityBand::from_label(band)
        .map(fingerprintd::fuzzy::velocity_penalty)
        .ok_or_else(|| format!("unknown velocity band {band:?}"))
}

/// The closed component schema's keys as a JSON array, in schema order — the
/// only keys a `components` object may carry.
#[wasm_bindgen]
pub fn component_keys() -> String {
    Value::from(COMPONENT_KEYS.to_vec()).to_string()
}

/// Server-side edge compute, configured with a deployment's salt secret.
///
/// A Cloudflare Worker host constructs one `FpEngine` per isolate from its
/// Worker Secret. It holds no request state: [`FpEngine::score`] loads the
/// recalled candidate block into a transient store per call and discards it.
#[wasm_bindgen]
pub struct FpEngine {
    /// Secret seeding the deterministic salt + `MinHash` family, so blocking keys
    /// and stored hashes are stable across isolates.
    salt_secret: Vec<u8>,
}

#[wasm_bindgen]
impl FpEngine {
    /// Construct an engine from the deployment's salt secret.
    ///
    /// `salt_secret` seeds the deterministic salt and `MinHash` family so
    /// blocking keys and stored hashes are reproducible across isolates. In a
    /// real deployment it is a Worker Secret.
    #[wasm_bindgen(constructor)]
    pub fn new(salt_secret: &str) -> FpEngine {
        FpEngine {
            salt_secret: salt_secret.as_bytes().to_vec(),
        }
    }

    /// The salted stored form of `components_json` (see the module docs for the
    /// shape) — the only representation the host may persist.
    pub fn stored_form(&self, components_json: &str) -> Result<String, JsError> {
        self.stored_form_impl(components_json)
            .map_err(|e| JsError::new(&e))
    }

    /// Blocking keys for a `components` object, as a JSON array of hex strings
    /// the host queries its candidate index with.
    pub fn blocking_keys(&self, components_json: &str) -> Result<String, JsError> {
        self.blocking_keys_impl(components_json)
            .map_err(|e| JsError::new(&e))
    }

    /// Blocking keys of a stored form (e.g. a persisted template), as a JSON
    /// array of hex strings — the keys the host indexes the template under.
    pub fn blocking_keys_stored(&self, stored_json: &str) -> Result<String, JsError> {
        self.blocking_keys_stored_impl(stored_json)
            .map_err(|e| JsError::new(&e))
    }

    /// Score a `components` object against host-recalled stored candidates and
    /// return the verdict plus the template the host must persist (shapes in
    /// the module docs), **without** keeping any state or minting an id.
    ///
    /// - `match` — `visitor_id` is the matched candidate; `template` is its
    ///   stored template drifted toward this observation, exactly as the native
    ///   store drifts a match (fuzzy-matching §7).
    /// - `new_device` — `visitor_id` is `null`: the host mints a random id and
    ///   persists `template` (= `probe_stored`) under it.
    /// - `review` — `visitor_id` is the suspected candidate; `template` is
    ///   `null` and nothing is persisted (anti-poisoning). `template_jump`
    ///   marks a match downgraded to review for changing too many
    ///   high-stability components.
    ///
    /// `template_blocking_keys` are the keys to index `template` under (`null`
    /// with it). `u_i` rarity is estimated over the supplied candidate block
    /// only — each candidate counts once — a local approximation of the native
    /// server's global frequency table; `m_i` uses the cold-start stability
    /// priors.
    pub fn score(&self, request_json: &str) -> Result<String, JsError> {
        self.score_impl(request_json).map_err(|e| JsError::new(&e))
    }
}

impl FpEngine {
    /// A fresh transient store seeded from the configured salt secret, so the
    /// observation and every candidate template are salted identically.
    fn store(&self) -> FuzzyStore {
        FuzzyStore::deterministic(&self.salt_secret)
    }

    /// Native-testable core of [`FpEngine::stored_form`].
    fn stored_form_impl(&self, components_json: &str) -> Result<String, String> {
        let components = parse_components(components_json)?;
        to_json(&self.store().stored_form(&components))
    }

    /// Native-testable core of [`FpEngine::blocking_keys`].
    fn blocking_keys_impl(&self, components_json: &str) -> Result<String, String> {
        let components = parse_components(components_json)?;
        to_json(&self.store().blocking_key_hexes(&components))
    }

    /// Native-testable core of [`FpEngine::blocking_keys_stored`].
    fn blocking_keys_stored_impl(&self, stored_json: &str) -> Result<String, String> {
        let stored: StoredComponents =
            serde_json::from_str(stored_json).map_err(|e| format!("invalid stored JSON: {e}"))?;
        to_json(&self.store().blocking_key_hexes_stored(&stored))
    }

    /// Native-testable core of [`FpEngine::score`].
    fn score_impl(&self, request_json: &str) -> Result<String, String> {
        let request: ScoreRequest = serde_json::from_str(request_json)
            .map_err(|e| format!("invalid score request JSON: {e}"))?;
        let store = self.store();
        // The timestamp only stamps record freshness, which scoring ignores.
        for candidate in request.candidates {
            store.observe_stored(&candidate.visitor_id, candidate.stored, 0);
        }
        let outcome = store.score(&request.components);
        let observed = store.stored_form(&request.components);
        let template = match outcome.decision {
            Decision::Match => outcome
                .visitor_id
                .as_deref()
                .and_then(|id| store.record(id))
                .map(|record| StoredComponents::from(record.components).merged(&observed)),
            Decision::NewDevice => Some(observed.clone()),
            Decision::Review => None,
        };
        let template_keys = template
            .as_ref()
            .map(|template| store.blocking_key_hexes_stored(template));
        let reply = json!({
            "decision": outcome.decision.as_str(),
            "visitor_id": outcome.visitor_id,
            "is_new_device": outcome.is_new_device,
            "confidence": outcome.confidence,
            "score": outcome.score,
            "compared_components": outcome.compared_components,
            "collision_risk": outcome.collision_risk,
            "template_jump": outcome.template_jump,
            "probe_stored": observed,
            "template": template,
            "template_blocking_keys": template_keys,
        });
        Ok(reply.to_string())
    }
}

/// Parse a `components` object into the closed schema.
fn parse_components(components_json: &str) -> Result<Components, String> {
    serde_json::from_str(components_json).map_err(|e| format!("invalid components JSON: {e}"))
}

/// Serialize a reply value.
fn to_json<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|e| e.to_string())
}

impl core::fmt::Debug for FpEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never leak the salt secret.
        f.debug_struct("FpEngine").finish_non_exhaustive()
    }
}

/// The `score` request body: the observation plus the host-recalled candidates.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScoreRequest {
    /// The request's components (closed schema).
    components: Components,
    /// Candidate templates the host recalled from its index; empty ⇒ new device.
    #[serde(default)]
    candidates: Vec<Candidate>,
}

/// One recalled candidate: its id and its persisted stored template.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    /// The candidate's visitor id.
    visitor_id: String,
    /// The candidate's salted stored template.
    stored: StoredComponents,
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use super::{
        FpEngine, automation_impl, client_integrity_impl, component_keys, passive_signals_impl,
        persona_coherence_impl, velocity_band, velocity_penalty_impl,
    };
    use serde::Deserialize;
    use serde_json::{Value, json};

    /// A JA4 whose structural counts read as a real browser (15 ciphers, 16 ext)
    /// — the same fixture shape fp-core's `signals` tests use.
    const BROWSER_JA4: &str = "t13d1516h2_8daaf6152771_02713d6af862";
    /// A JA4 whose structural counts read as a minimal automation stack (3/4).
    const AUTOMATION_JA4: &str = "t13d0304h1_aaaaaaaaaaaa_bbbbbbbbbbbb";
    /// A spoofed browser UA (headless automation self-reporting Chrome).
    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0";

    /// A full, high-signal component object (8 components across all kinds).
    fn full_components() -> Value {
        json!({
            "webgl": "ANGLE (Intel)",
            "platform": "Linux x86_64",
            "timezone": "Asia/Shanghai",
            "audio": "124.04",
            "cpu_cores": 8,
            "device_memory": 8,
            "fonts": ["Arial", "Helvetica", "Courier", "Times", "Verdana"],
            "canvas": "c0ffee",
        })
    }

    fn parse(raw: &str) -> Value {
        serde_json::from_str(raw).unwrap()
    }

    /// The stored form of `components` under `engine`'s salt.
    fn stored(engine: &FpEngine, components: &Value) -> Value {
        parse(&engine.stored_form_impl(&components.to_string()).unwrap())
    }

    fn score(engine: &FpEngine, components: &Value, candidates: &[(&str, Value)]) -> Value {
        let candidates: Vec<Value> = candidates
            .iter()
            .map(|(id, stored)| json!({ "visitor_id": id, "stored": stored }))
            .collect();
        let request = json!({ "components": components, "candidates": candidates });
        parse(&engine.score_impl(&request.to_string()).unwrap())
    }

    /// Blocking keys are non-empty for a rich object and **deterministic**
    /// across separate engines sharing a salt secret — the stability an
    /// externalized index relies on. A different secret yields different keys.
    #[test]
    fn blocking_keys_are_stable_across_engines() {
        let a = FpEngine::new("salt-secret");
        let b = FpEngine::new("salt-secret");
        let raw = full_components().to_string();

        let ka = a.blocking_keys_impl(&raw).unwrap();
        let kb = b.blocking_keys_impl(&raw).unwrap();
        assert_eq!(ka, kb, "same secret must yield identical keys");

        let parsed: Vec<String> = serde_json::from_str(&ka).unwrap();
        assert_ne!(parsed.len(), 0);
        assert!(parsed.iter().all(|k| k.len() == 64)); // hex of a 32-byte digest

        let other = FpEngine::new("other-secret");
        assert_ne!(
            other.blocking_keys_impl(&raw).unwrap(),
            ka,
            "a different salt secret must diverge"
        );
    }

    /// The stored form carries no raw value, only the documented shapes, and
    /// is stable for a salt secret.
    #[test]
    fn stored_form_rejects_a_non_object() {
        let engine = FpEngine::new("s");
        for raw in ["[]", "[\"x\"]", "null", "\"webgl\""] {
            assert!(engine.stored_form_impl(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn stored_form_is_salted_and_closed() {
        let engine = FpEngine::new("s");
        let raw = engine
            .stored_form_impl(&full_components().to_string())
            .unwrap();
        for value in [
            "ANGLE (Intel)",
            "Linux x86_64",
            "Asia/Shanghai",
            "Arial",
            "c0ffee",
        ] {
            assert!(!raw.contains(value), "{value} leaked into {raw}");
        }
        let form = parse(&raw);
        assert_eq!(form["webgl"]["category"].as_str().unwrap().len(), 64);
        assert_eq!(form["cpu_cores"], json!({ "numeric": 8 }));
        assert_eq!(form["fonts"]["set"].as_array().unwrap().len(), 5);
        assert_eq!(form, stored(&FpEngine::new("s"), &full_components()));
        assert_ne!(form, stored(&FpEngine::new("t"), &full_components()));
        // Absent components are omitted.
        let sparse = stored(&engine, &json!({ "webgl": "x", "canvas": null }));
        assert_eq!(sparse.as_object().unwrap().len(), 1);
    }

    #[test]
    fn blocking_keys_stored_match_the_source_components() {
        let engine = FpEngine::new("s");
        let form = stored(&engine, &full_components()).to_string();
        assert_eq!(
            engine.blocking_keys_stored_impl(&form).unwrap(),
            engine
                .blocking_keys_impl(&full_components().to_string())
                .unwrap()
        );
        for bad in [
            json!({ "user_agent": { "category": "ab".repeat(32) } }),
            json!({ "webgl": { "numeric": 1 } }),
            json!({ "webgl": "ANGLE (Intel)" }),
        ] {
            assert!(
                engine.blocking_keys_stored_impl(&bad.to_string()).is_err(),
                "{bad}"
            );
        }
    }

    /// Every entry point rejects a component outside the closed schema, a
    /// wrongly-typed value, or a raw-component candidate.
    #[test]
    fn unknown_or_mistyped_input_is_rejected() {
        let engine = FpEngine::new("s");
        for bad in [
            json!({ "webgl": "x", "user_agent": "Chrome/120" }),
            json!({ "math": { "sin": 1 } }),
        ] {
            let raw = bad.to_string();
            assert!(engine.stored_form_impl(&raw).is_err(), "{raw}");
            assert!(engine.blocking_keys_impl(&raw).is_err(), "{raw}");
            let request = json!({ "components": bad, "candidates": [] }).to_string();
            assert!(engine.score_impl(&request).is_err(), "{request}");
        }
        for request in [
            json!({
                "components": { "webgl": "x" },
                "candidates": [{ "visitor_id": "v1", "components": { "webgl": "x" } }],
            }),
            json!({
                "components": { "webgl": "x" },
                "candidates": [{ "visitor_id": "v1", "stored": { "webgl": "x" } }],
            }),
            json!({ "components": { "webgl": "x" }, "extra": 1 }),
        ] {
            assert!(
                engine.score_impl(&request.to_string()).is_err(),
                "{request}"
            );
        }
        for raw in ["not json", "42"] {
            assert!(engine.stored_form_impl(raw).is_err());
            assert!(engine.blocking_keys_impl(raw).is_err());
            assert!(engine.blocking_keys_stored_impl(raw).is_err());
            assert!(engine.score_impl(raw).is_err());
        }
    }

    #[test]
    fn component_keys_lists_the_schema() {
        let keys: Vec<String> = serde_json::from_str(&component_keys()).unwrap();
        assert_eq!(keys, fingerprintd::fuzzy::COMPONENT_KEYS);
    }

    /// An SDK-shaped phone: `n` varies every device-distinctive component, the
    /// city-wide low-entropy values (locale, platform, cores, memory, the
    /// constant Android font list, no plugins) are shared by every phone.
    fn phone(n: u64) -> Value {
        let h = |tag: &str| format!("{tag}{n:0>31}");
        json!({
            "user_agent_data": h("u"), "font_preferences": h("f"), "math": h("m"),
            "canvas": h("c"), "webgl_extensions": h("x"), "screen_frame": h("s"),
            "webgl": format!("ANGLE (GPU {n})"), "audio": format!("124.{n}"),
            "screen": format!("{}x{}", 800 + n % 50, 380 + n % 20),
            "languages": "zh-CN", "timezone": "Asia/Shanghai",
            "platform": "Linux armv81", "cpu_cores": 8, "device_memory": 8,
            "fonts": ["sans-serif-thin"], "plugins": [],
        })
    }

    /// The edge estimates `u_i` over the recalled block only. A stranger that
    /// shares nothing but the common values must stay a new device whatever the
    /// block size, while the same phone in the block is still matched.
    #[test]
    fn block_local_scoring_rejects_strangers_and_keeps_the_same_phone() {
        let engine = FpEngine::new("s");
        for size in [1_u64, 10, 100, 500] {
            let ids: Vec<String> = (0..size).map(|n| format!("p{n}")).collect();
            let candidates: Vec<(&str, Value)> = (0..size)
                .map(|n| {
                    (
                        ids[usize::try_from(n).unwrap()].as_str(),
                        stored(&engine, &phone(n)),
                    )
                })
                .collect();

            let stranger = score(&engine, &phone(1_000_000), &candidates);
            assert_eq!(
                stranger["decision"], "new_device",
                "block {size}: {stranger}"
            );

            let same = score(&engine, &phone(0), &candidates);
            assert_eq!(same["decision"], "match", "block {size}: {same}");
            assert_eq!(same["visitor_id"], "p0");
        }
    }

    /// An empty candidate set is a new device: no id is minted and the template
    /// to persist is the observation's own stored form.
    #[test]
    fn new_device_returns_its_stored_form_as_template() {
        let engine = FpEngine::new("salt-secret");
        let reply = score(&engine, &full_components(), &[]);
        assert_eq!(reply["decision"], "new_device");
        assert_eq!(reply["is_new_device"], true);
        assert!(reply["visitor_id"].is_null());
        assert_eq!(reply["template_jump"], false);
        assert_eq!(reply["probe_stored"], stored(&engine, &full_components()));
        assert_eq!(reply["template"], reply["probe_stored"]);
        let keys = engine
            .blocking_keys_impl(&full_components().to_string())
            .unwrap();
        assert_eq!(reply["template_blocking_keys"], parse(&keys));
        assert!(!reply.to_string().contains("ANGLE (Intel)"));
    }

    /// A match returns the candidate's id and its template drifted toward the
    /// observation: observed components overwrite or extend it, absent ones are
    /// kept.
    #[test]
    fn match_returns_the_drifted_template() {
        let engine = FpEngine::new("salt-secret");
        let template = stored(&engine, &full_components());
        let mut drifted = full_components();
        drifted.as_object_mut().unwrap().remove("canvas");
        drifted["screen"] = json!("1920x1080");

        let reply = score(&engine, &drifted, &[("v1", template.clone())]);
        assert_eq!(reply["decision"], "match", "{reply}");
        assert_eq!(reply["is_new_device"], false);
        assert_eq!(reply["visitor_id"], "v1");

        let observed = stored(&engine, &drifted);
        let mut expected = template.clone();
        expected["screen"] = observed["screen"].clone();
        assert_eq!(reply["probe_stored"], observed);
        assert_eq!(reply["template"], expected);
        assert_eq!(reply["template"]["canvas"], template["canvas"]);
        let keys = engine
            .blocking_keys_stored_impl(&expected.to_string())
            .unwrap();
        assert_eq!(reply["template_blocking_keys"], parse(&keys));
    }

    /// A review persists nothing: no template, no keys.
    #[test]
    fn review_returns_no_template() {
        let engine = FpEngine::new("salt-secret");
        let template = stored(&engine, &full_components());
        let partial = json!({
            "webgl": "ANGLE (Intel)",
            "platform": "Linux x86_64",
            "timezone": "Asia/Shanghai",
            "audio": "124.04",
            "cpu_cores": 8,
        });
        let reply = score(&engine, &partial, &[("v1", template)]);
        assert_eq!(reply["decision"], "review", "{reply}");
        assert_eq!(reply["visitor_id"], "v1");
        assert!(reply["template"].is_null());
        assert!(reply["template_blocking_keys"].is_null());
        assert_eq!(reply["probe_stored"], stored(&engine, &partial));
    }

    #[test]
    fn automation_maps_the_botd_result() {
        assert_eq!(
            automation_impl(Some(r#"{"bot":true,"kind":"headless_chrome"}"#)).unwrap(),
            "detected"
        );
        assert_eq!(
            automation_impl(Some(r#"{"bot":false}"#)).unwrap(),
            "not_detected"
        );
        assert_eq!(
            automation_impl(Some(r#"{"bot":false,"kind":null}"#)).unwrap(),
            "not_detected"
        );
        assert_eq!(automation_impl(None).unwrap(), "unknown");
        for bad in [r#"{"bot":true,"score":1}"#, r#"{"kind":"x"}"#, "not json"] {
            assert!(automation_impl(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn velocity_band_and_penalty_mirror_fingerprintd() {
        use fingerprintd::fuzzy::{VELOCITY_PENALTY, velocity::HIGH, velocity::MEDIUM};
        let medium = u32::try_from(MEDIUM).unwrap();
        let high = u32::try_from(HIGH).unwrap();
        assert_eq!(velocity_band(0), "low");
        assert_eq!(velocity_band(medium - 1), "low");
        assert_eq!(velocity_band(medium), "medium");
        assert_eq!(velocity_band(high - 1), "medium");
        assert_eq!(velocity_band(high), "high");
        assert_eq!(velocity_band(u32::MAX), "high");
        assert!(velocity_penalty_impl("low").unwrap().abs() < f64::EPSILON);
        assert!(velocity_penalty_impl("medium").unwrap().abs() < f64::EPSILON);
        assert!((velocity_penalty_impl("high").unwrap() - VELOCITY_PENALTY).abs() < f64::EPSILON);
        assert!(velocity_penalty_impl("HIGH").is_err());
    }

    /// The native parity fixture shared with `crates/fingerprintd/tests/parity.rs`.
    const FIXTURE_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fingerprintd/tests/fixtures/parity.json"
    );

    #[derive(Deserialize)]
    struct Fixture {
        salt_secret: String,
        confidence_tolerance: f64,
        components: HashMap<String, Value>,
        scenarios: Vec<Scenario>,
    }

    #[derive(Deserialize)]
    struct Scenario {
        name: String,
        steps: Vec<Step>,
    }

    #[derive(Deserialize)]
    struct Step {
        input: String,
        expect: Expect,
    }

    #[derive(Deserialize)]
    struct Expect {
        decision: String,
        is_new_device: bool,
        visitor: String,
        collision_risk: bool,
        confidence: f64,
        template_jump: bool,
    }

    /// One persisted device in the simulated host database.
    struct Row {
        template: Value,
        keys: BTreeSet<String>,
    }

    /// Drives the native parity fixture through the stored-form path the edge
    /// host runs: recall by blocking key from a database of stored templates,
    /// `score`, then persist `template` under the returned id (or a host-minted
    /// id on `new_device`, nothing on `review`). Every step must reach the
    /// verdict the native `identify` path pins in the fixture.
    #[test]
    fn host_simulation_matches_native_parity_vectors() {
        let raw = std::fs::read_to_string(FIXTURE_PATH).unwrap();
        let fixture: Fixture = serde_json::from_str(&raw).unwrap();
        let engine = FpEngine::new(&fixture.salt_secret);
        let tol = fixture.confidence_tolerance;

        for scenario in &fixture.scenarios {
            let mut db: HashMap<String, Row> = HashMap::new();
            let mut labels: HashMap<String, String> = HashMap::new();
            let mut minted = 0_u32;

            for (i, step) in scenario.steps.iter().enumerate() {
                let at = format!("{} @ step {i}", scenario.name);
                let components = &fixture.components[&step.input];
                let keys: BTreeSet<String> = serde_json::from_str(
                    &engine.blocking_keys_impl(&components.to_string()).unwrap(),
                )
                .unwrap();
                let mut recalled: Vec<(&str, Value)> = db
                    .iter()
                    .filter(|(_, row)| !row.keys.is_disjoint(&keys))
                    .map(|(id, row)| (id.as_str(), row.template.clone()))
                    .collect();
                recalled.sort_by(|a, b| a.0.cmp(b.0));
                let reply = score(&engine, components, &recalled);

                let e = &step.expect;
                assert_eq!(reply["decision"], e.decision.as_str(), "{at}");
                assert_eq!(reply["is_new_device"], e.is_new_device, "{at}");
                assert_eq!(reply["collision_risk"], e.collision_risk, "{at}");
                assert_eq!(reply["template_jump"], e.template_jump, "{at}");
                let confidence = reply["confidence"].as_f64().unwrap();
                assert!(
                    (confidence - e.confidence).abs() <= tol,
                    "{at}: confidence {confidence} vs {}",
                    e.confidence
                );

                let id = if let Some(id) = reply["visitor_id"].as_str() {
                    id.to_owned()
                } else {
                    minted += 1;
                    format!("host-{minted}")
                };
                if !reply["template"].is_null() {
                    let keys =
                        serde_json::from_value(reply["template_blocking_keys"].clone()).unwrap();
                    let template = reply["template"].clone();
                    db.insert(id.clone(), Row { template, keys });
                }

                if let Some(known) = labels.get(&e.visitor) {
                    assert_eq!(known, &id, "{at}: label {}", e.visitor);
                } else {
                    assert!(!labels.values().any(|v| *v == id), "{at}");
                    labels.insert(e.visitor.clone(), id);
                }
            }
        }
    }

    /// A browser JA4 over a Chrome UA agrees → consistent + positive boost.
    #[test]
    fn passive_signals_consistent_boosts() {
        let reply: Value = serde_json::from_str(&passive_signals_impl(
            Some(BROWSER_JA4),
            Some("198.51.100.7"),
            Some(CHROME_UA),
        ))
        .unwrap();
        assert_eq!(reply["ua_tls_consistent"], true);
        assert!(reply["confidence_adjustment"].as_f64().unwrap() > 0.0);
    }

    /// A Chrome UA over an automation TLS stack is the anti-forgery mismatch →
    /// inconsistent + strong negative downgrade.
    #[test]
    fn passive_signals_mismatch_penalises() {
        let reply: Value = serde_json::from_str(&passive_signals_impl(
            Some(AUTOMATION_JA4),
            Some("34.120.5.6"),
            Some(CHROME_UA),
        ))
        .unwrap();
        assert_eq!(reply["ua_tls_consistent"], false);
        assert!(reply["confidence_adjustment"].as_f64().unwrap() < 0.0);
    }

    /// A missing JA4 auto-degrades: consistent-by-default, neutral adjustment.
    #[test]
    fn passive_signals_absent_ja4_degrades_neutral() {
        let reply: Value =
            serde_json::from_str(&passive_signals_impl(None, None, Some(CHROME_UA))).unwrap();
        assert_eq!(reply["ua_tls_consistent"], true);
        assert!(reply["confidence_adjustment"].as_f64().unwrap().abs() < f64::EPSILON);
    }

    /// The IP band mirrors fp-core: a datacenter IP is "high", a residential /
    /// absent IP is "low".
    #[test]
    fn passive_signals_ip_risk_band() {
        let datacenter: Value = serde_json::from_str(&passive_signals_impl(
            Some(BROWSER_JA4),
            Some("34.120.5.6"),
            Some(CHROME_UA),
        ))
        .unwrap();
        assert_eq!(datacenter["ip_risk"], "high");

        let residential: Value = serde_json::from_str(&passive_signals_impl(
            Some(BROWSER_JA4),
            Some("198.51.100.7"),
            Some(CHROME_UA),
        ))
        .unwrap();
        assert_eq!(residential["ip_risk"], "low");

        let absent: Value = serde_json::from_str(&passive_signals_impl(
            Some(BROWSER_JA4),
            None,
            Some(CHROME_UA),
        ))
        .unwrap();
        assert_eq!(absent["ip_risk"], "low");
    }

    #[test]
    fn client_integrity_noise_is_surfaced_and_penalised_only_when_enabled() {
        let noisy = r#"{"canvas":"noise","webgl":"noise","audio":"noise","rect":"noise"}"#;
        let surfaced: Value =
            serde_json::from_str(&client_integrity_impl(Some(noisy), false).unwrap()).unwrap();
        assert_eq!(surfaced["client_integrity"], "noise");
        assert_eq!(surfaced["confidence_adjustment"], 0.0);
        let penalised: Value =
            serde_json::from_str(&client_integrity_impl(Some(noisy), true).unwrap()).unwrap();
        assert_eq!(penalised["client_integrity"], "noise");
        assert_eq!(
            penalised["confidence_adjustment"],
            -fingerprintd::signals::INTEGRITY_NOISE_PENALTY
        );
    }

    #[test]
    fn client_integrity_ok_absent_and_empty() {
        let clean = r#"{"canvas":"ok","webgl":"ok","audio":"ok","rect":"ok"}"#;
        let ok: Value =
            serde_json::from_str(&client_integrity_impl(Some(clean), true).unwrap()).unwrap();
        assert_eq!(ok["client_integrity"], "ok");
        assert_eq!(ok["confidence_adjustment"], 0.0);
        for raw in [None, Some("{}")] {
            let reply: Value =
                serde_json::from_str(&client_integrity_impl(raw, true).unwrap()).unwrap();
            assert_eq!(reply["client_integrity"], "unavailable", "{raw:?}");
            assert_eq!(reply["confidence_adjustment"], 0.0, "{raw:?}");
        }
    }

    #[test]
    fn client_integrity_rejects_malformed_input() {
        for raw in [
            "not json",
            "[]",
            r#""noise""#,
            r#"{"canvas":"ok","fonts":"ok"}"#,
            r#"{"canvas":1}"#,
            r#"{"canvas":"weird"}"#,
        ] {
            assert!(client_integrity_impl(Some(raw), true).is_err(), "{raw}");
        }
    }

    #[test]
    fn persona_coherence_label_mirrors_fingerprintd() {
        let windows_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/146.0.0.0";
        assert_eq!(
            persona_coherence_impl(Some(windows_ua), Some(r#"["Arial","Courier New"]"#)),
            "mismatch"
        );
        assert_eq!(
            persona_coherence_impl(Some(windows_ua), Some(r#"["Calibri"]"#)),
            "consistent"
        );
        assert_eq!(persona_coherence_impl(Some(windows_ua), None), "unknown");
        assert_eq!(
            persona_coherence_impl(Some(windows_ua), Some("not json")),
            "unknown"
        );
        assert_eq!(persona_coherence_impl(None, Some("[]")), "unknown");
    }
}
