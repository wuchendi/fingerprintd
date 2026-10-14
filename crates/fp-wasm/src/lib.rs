//! `fp-wasm` — the fingerprinting compute compiled to WebAssembly.
//!
//! This crate exposes two WASM surfaces backed by [`fingerprintd`]:
//!
//! - The **browser-collector probe** ([`probe`]): a probe-capable browser
//!   collector calls it with the one-time nonce advertised by `GET /challenge`
//!   and echoes the result on `POST /identify`. The transform is byte-for-byte
//!   identical to the server verifier (`crates/fp-core/src/probe.rs`,
//!   `ProbeVerifier::expected_hex`):
//!
//!   ```text
//!   probe(nonce) = hex(HMAC-SHA256(key, nonce))
//!   ```
//!
//!   matching the advertised `PROBE_ALG = "HMAC-SHA256"`, `PROBE_INPUT =
//!   "nonce"`, `PROBE_ENCODING = "hex"`. The parity proof is the native
//!   `#[cfg(test)]` vector below — it reproduces the server's `expected_probe`
//!   output with the shared test secret, so server/client agreement is verified
//!   without a browser.
//!
//! - The **server-side edge engine** ([`FpEngine`]): the pure compute a stateless
//!   Cloudflare Worker host (`apps/edge`, a later step) runs for a `/identify`
//!   request — blocking-key derivation, Fellegi–Sunter scoring, probe
//!   verification, and response signing — while the host owns the I/O (nonce
//!   Durable Object, D1 candidate index) around it. Every method delegates to
//!   [`fingerprintd`], so the Worker and the native Axum server share one
//!   implementation.
//!
//! ## Embedded key — depth, not a hard lock
//!
//! The browser-collector probe key is baked into this module at build time
//! ([`PROBE_KEY`], overridable via the `FP_PROBE_KEY` compile-time env var).
//! Because it ships inside the `.wasm` artifact, a determined attacker can
//! extract it — this is **defense in depth, not a decisive control** (architecture: "WASM
//! 纵深防御，非决定性"). The one-time nonce remains the primary anti-replay
//! guarantee; the probe only raises the bar against blind replay. In a real
//! deployment the build injects the same secret configured as the server's
//! `probe_key`. The server-side [`FpEngine`] instead takes its keys at runtime
//! (Worker Secrets), never embedding them.

use fingerprintd::fuzzy::FuzzyStore;
use fingerprintd::probe::ProbeVerifier;
use fingerprintd::signals::{ClientIntegrity, persona_coherence};
use fingerprintd::signals::{StaticIpIntel, compute};
use fingerprintd::signing::ResponseSigner;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use wasm_bindgen::prelude::{JsError, wasm_bindgen};

/// The probe HMAC key embedded at build time.
///
/// A deployment build overrides it with the server's `probe_key` via
/// `FP_PROBE_KEY=<secret> wasm-pack build ...`. The `fp-wasm-dev-probe-key`
/// fallback below applies ONLY to a build with `FP_PROBE_KEY` unset — it is NOT
/// the key in this repo's committed artifacts. The vendored WASM (both
/// `apps/edge/wasm` and `packages/client/wasm`) is instead baked with
/// `FP_PROBE_KEY=test-probe-secret` (the shared parity vector) so the headless
/// parity tests — `matches_server_probe_vector` here and the client
/// `probe.test.ts` — pass without a real deployment key. Extractable from the
/// shipped artifact — see the module docs on why this is depth, not a lock.
const PROBE_KEY: &str = match option_env!("FP_PROBE_KEY") {
    Some(key) => key,
    None => "fp-wasm-dev-probe-key",
};

/// Compute `hex(HMAC-SHA256(key, nonce))` — the injectable core.
///
/// Kept key-parametric so the native parity test can key it with the server's
/// shared secret. HMAC accepts a key of any length, so keying is infallible in
/// practice; `None` is returned only on the unreachable keying error rather than
/// panicking.
fn probe_with_key(key: &[u8], nonce: &str) -> Option<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(nonce.as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// Compute the probe for `nonce` using the embedded [`PROBE_KEY`].
///
/// This is the WASM export a browser collector calls: it returns the hex probe
/// echoed on `POST /identify`. Fails closed to an empty string on the
/// unreachable keying error rather than panicking.
#[wasm_bindgen]
pub fn probe(nonce: &str) -> String {
    probe_with_key(PROBE_KEY.as_bytes(), nonce).unwrap_or_default()
}

/// Passive-signals verdict for one request, computed exactly as the native
/// server ([`fingerprintd::signals::compute`]) does — so the edge Worker reaches the
/// SAME UA↔TLS / IP-risk verdict.
///
/// Needs no secrets (unlike [`FpEngine`]), so it is a free `#[wasm_bindgen]`
/// function. Constructs the dependency-free [`StaticIpIntel`] classifier, cross-
/// checks the trusted JA4 stack against the claimed UA, and returns JSON:
/// `{"ua_tls_consistent": <bool>, "ip_risk": "<low|medium|high>",
/// "confidence_adjustment": <f64>}`. A missing/unparseable JA4 auto-degrades
/// (neutral); a missing/unparseable IP defaults to `"low"` (§4.2).
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

/// Native-testable core of [`passive_signals`], returning the JSON `String`
/// directly so tests need not touch wasm-bindgen. Mirrors the `score_impl`
/// reply style.
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

/// Fuse the client's known-answer integrity probe verdicts (the request's
/// top-level `integrity` object, JSON-encoded) into the shared verdict + the
/// confidence adjustment (`fingerprintd::signals::ClientIntegrity`). The edge Worker
/// calls this so its `client_integrity` band and fusion are byte-identical to
/// the native server's. `None` / unparseable JSON ⇒ `unavailable`, adjustment
/// `0` (neutral). The penalty applies only when the deployment enabled it.
///
/// Owned `Option<String>` is the wasm-bindgen boundary shape; see
/// [`passive_signals`].
#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)]
pub fn client_integrity(integrity_json: Option<String>, penalty_enabled: bool) -> String {
    client_integrity_impl(integrity_json.as_deref(), penalty_enabled)
}

/// Native-testable core of [`client_integrity`], returning the JSON `String`.
fn client_integrity_impl(integrity_json: Option<&str>, penalty_enabled: bool) -> String {
    let parsed: Option<Value> = integrity_json.and_then(|raw| serde_json::from_str(raw).ok());
    let verdict = ClientIntegrity::from_json(parsed.as_ref());
    let reply = json!({
        "client_integrity": verdict.as_str(),
        "confidence_adjustment": verdict.confidence_adjustment(penalty_enabled),
    });
    reply.to_string()
}

/// Cross-check the UA-claimed OS family against the collected `fonts` set
/// (JSON array, as the SDK sends it) — `fingerprintd::signals::persona_coherence`.
/// Returns the wire label `consistent` | `mismatch` | `unknown`; `None` or
/// unparseable `fonts_json` reads `unknown` (neutral). Surfaced-only. Owned
/// `Option<String>` is the wasm-bindgen boundary shape (see [`passive_signals`]).
#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)]
pub fn persona_coherence_label(claimed_ua: Option<String>, fonts_json: Option<String>) -> String {
    persona_coherence_impl(claimed_ua.as_deref(), fonts_json.as_deref())
}

/// Native-testable core of [`persona_coherence_label`].
fn persona_coherence_impl(claimed_ua: Option<&str>, fonts_json: Option<&str>) -> String {
    let fonts: Option<Value> = fonts_json.and_then(|raw| serde_json::from_str(raw).ok());
    persona_coherence(claimed_ua, fonts.as_ref())
        .as_str()
        .to_owned()
}

/// Server-side edge compute, configured with a deployment's secrets.
///
/// A Cloudflare Worker host constructs one `FpEngine` per isolate from its
/// Worker Secrets and calls it for the pure compute of a `/identify` request. It
/// holds no request state: [`FpEngine::score`] rebuilds the recalled candidate
/// block in a transient store per call and discards it, leaving persistence to
/// the host.
#[wasm_bindgen]
pub struct FpEngine {
    /// Secret seeding the deterministic salt + `MinHash` family, so blocking keys
    /// and stored hashes are stable across isolates.
    salt_secret: Vec<u8>,
    /// Verifier for the client nonce probe (server role).
    probe: ProbeVerifier,
    /// Signer for `/identify` response bodies.
    signer: ResponseSigner,
}

#[wasm_bindgen]
impl FpEngine {
    /// Construct an engine from the deployment's configured secrets.
    ///
    /// `salt_secret` seeds the deterministic salt and `MinHash` family so
    /// blocking keys and stored hashes are reproducible across isolates;
    /// `probe_key` is the pre-shared nonce-probe key; `signing_key` signs
    /// response bodies. In a real deployment all three are Worker Secrets.
    #[wasm_bindgen(constructor)]
    pub fn new(salt_secret: &str, probe_key: &str, signing_key: &str) -> FpEngine {
        FpEngine {
            salt_secret: salt_secret.as_bytes().to_vec(),
            probe: ProbeVerifier::new(probe_key.as_bytes()),
            signer: ResponseSigner::new(signing_key.as_bytes()),
        }
    }

    /// Blocking keys for a probe's `components`, as a JSON array of hex strings.
    ///
    /// `components_json` is the raw component object from `POST /identify`; the
    /// host queries its candidate index (D1) with the returned keys. Invalid JSON
    /// surfaces as a thrown JS exception.
    pub fn blocking_keys(&self, components_json: &str) -> Result<String, JsError> {
        self.blocking_keys_impl(components_json)
            .map_err(|e| JsError::new(&e))
    }

    /// Names of the components the matcher stores for `components_json`, as a
    /// sorted JSON array — the client↔server contract check (what actually
    /// takes part in matching). Invalid JSON surfaces as a thrown JS exception.
    pub fn stored_components(&self, components_json: &str) -> Result<String, JsError> {
        self.stored_components_impl(components_json)
            .map_err(|e| JsError::new(&e))
    }

    /// Score a probe against host-supplied candidates and return the verdict as
    /// JSON, **without** mutating any state.
    ///
    /// `request_json` is `{ "components": {..}, "candidates": [{ "visitor_id":
    /// "..", "components": {..} }, ..] }` — the recalled candidate templates the
    /// host fetched from D1. The reply is
    /// `{ "visitor_id", "is_new_device", "decision", "confidence", "score",
    /// "compared_components", "collision_risk" }` (see [`fingerprintd`]'s
    /// `MatchOutcome`). The host applies its own persistence per the returned
    /// `decision` (drift a match, mint a new device, leave a review untouched).
    ///
    /// `u_i` rarity is estimated over the supplied candidate block, a local
    /// approximation of the native server's global frequency table; a global
    /// frequency snapshot is a later (D1) refinement. Invalid JSON surfaces as a
    /// thrown JS exception.
    pub fn score(&self, request_json: &str) -> Result<String, JsError> {
        self.score_impl(request_json).map_err(|e| JsError::new(&e))
    }

    /// Expected probe `hex(HMAC-SHA256(probe_key, nonce))` for `nonce` — the
    /// value a probe-capable client should echo, computed with the configured
    /// key. Fails closed to an empty string on the unreachable keying error.
    pub fn expected_probe(&self, nonce: &str) -> String {
        self.probe.expected_hex(nonce).unwrap_or_default()
    }

    /// Constant-time check that `candidate_hex` is the correct probe for `nonce`.
    /// A missing, malformed, or wrong probe fails closed to `false`.
    pub fn verify_probe(&self, nonce: &str, candidate_hex: &str) -> bool {
        self.probe.verify(nonce, candidate_hex)
    }

    /// Sign a response body: `hex(HMAC-SHA256(signing_key, issued_ms_be ++ body))`,
    /// carried in the `x-fp-signature` header alongside `x-fp-timestamp`.
    /// `issued_ms` is the server's issue time in Unix milliseconds. Fails closed
    /// to an empty string on the unreachable keying error.
    pub fn sign(&self, issued_ms: u64, body: &[u8]) -> String {
        self.signer.sign(issued_ms, body).unwrap_or_default()
    }
}

impl FpEngine {
    /// A fresh transient store seeded from the configured salt secret. Every
    /// per-request compute call builds one so the probe and candidate templates
    /// are salted identically and reproducibly.
    fn store(&self) -> FuzzyStore {
        FuzzyStore::deterministic(&self.salt_secret)
    }

    /// Native-testable core of [`FpEngine::blocking_keys`], erroring as a plain
    /// `String` so tests need not touch `JsError`.
    fn blocking_keys_impl(&self, components_json: &str) -> Result<String, String> {
        let components: Value = serde_json::from_str(components_json)
            .map_err(|e| format!("invalid components JSON: {e}"))?;
        let keys = self.store().blocking_key_hexes(&components);
        serde_json::to_string(&keys).map_err(|e| e.to_string())
    }

    /// Native-testable core of [`FpEngine::stored_components`].
    fn stored_components_impl(&self, components_json: &str) -> Result<String, String> {
        let components: Value = serde_json::from_str(components_json)
            .map_err(|e| format!("invalid components JSON: {e}"))?;
        let names = self.store().stored_component_names(&components);
        serde_json::to_string(&names).map_err(|e| e.to_string())
    }

    /// Native-testable core of [`FpEngine::score`], erroring as a plain `String`.
    fn score_impl(&self, request_json: &str) -> Result<String, String> {
        let request: ScoreRequest = serde_json::from_str(request_json)
            .map_err(|e| format!("invalid score request JSON: {e}"))?;
        let store = self.store();
        // Rebuild the recalled block in the transient store so the probe and
        // every candidate template are salted identically; the store is discarded
        // after scoring, leaving host state to the caller. The timestamp is
        // irrelevant to scoring (it only stamps record freshness), so use 0.
        for candidate in &request.candidates {
            store.observe(&candidate.visitor_id, &candidate.components, 0);
        }
        let outcome = store.score(&request.components);
        let reply = json!({
            "visitor_id": outcome.visitor_id,
            "is_new_device": outcome.is_new_device,
            "decision": outcome.decision.as_str(),
            "confidence": outcome.confidence,
            "score": outcome.score,
            "compared_components": outcome.compared_components,
            "collision_risk": outcome.collision_risk,
        });
        Ok(reply.to_string())
    }
}

impl core::fmt::Debug for FpEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never leak the salt secret or the redacted verifier/signer keys.
        f.debug_struct("FpEngine").finish_non_exhaustive()
    }
}

/// The `score` request body: the probe plus the host-recalled candidate block.
#[derive(Debug, Deserialize)]
struct ScoreRequest {
    /// Raw probe component object from `POST /identify`.
    components: Value,
    /// Candidate templates the host fetched from its index; empty ⇒ new device.
    #[serde(default)]
    candidates: Vec<Candidate>,
}

/// One recalled candidate: its id and its stored raw component object.
#[derive(Debug, Deserialize)]
struct Candidate {
    /// The candidate's resolved `visitorId`.
    visitor_id: String,
    /// The candidate's raw component object (re-salted inside the engine).
    components: Value,
}

#[cfg(test)]
mod tests {
    use super::{
        FpEngine, PROBE_KEY, client_integrity_impl, passive_signals_impl, persona_coherence_impl,
        probe, probe_with_key,
    };
    use serde_json::{Value, json};

    /// A JA4 whose structural counts read as a real browser (15 ciphers, 16 ext)
    /// — the same fixture shape fp-core's `signals` tests use.
    const BROWSER_JA4: &str = "t13d1516h2_8daaf6152771_02713d6af862";
    /// A JA4 whose structural counts read as a minimal automation stack (3/4).
    const AUTOMATION_JA4: &str = "t13d0304h1_aaaaaaaaaaaa_bbbbbbbbbbbb";
    /// A spoofed browser UA (headless automation self-reporting Chrome).
    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0";

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

    /// Server-parity proof — the browser collector reproduces `crates/fp-core`
    /// `expected_probe` keyed with the `test-probe-secret` shared secret over
    /// `fixed-nonce-000`. The expected hex is the shared vector in
    /// `tests/vectors/probe.json`.
    #[test]
    fn matches_server_probe_vector() {
        let got = probe_with_key(b"test-probe-secret", "fixed-nonce-000").unwrap();
        assert_eq!(
            got,
            "ad83144894f917b94072c2f7b3246af66d3bc5a450562ccf3671ed64d33137d0"
        );
    }

    /// The transform is deterministic and nonce-bound.
    #[test]
    fn is_deterministic_and_nonce_bound() {
        let a = probe_with_key(b"k", "nonce-1").unwrap();
        assert_eq!(a, probe_with_key(b"k", "nonce-1").unwrap());
        assert_ne!(a, probe_with_key(b"k", "nonce-2").unwrap());
    }

    /// The public export wraps the embedded key and yields non-empty hex.
    #[test]
    fn export_uses_embedded_key() {
        let via_export = probe("nonce-1");
        assert_eq!(
            via_export,
            probe_with_key(PROBE_KEY.as_bytes(), "nonce-1").unwrap()
        );
        assert_eq!(via_export.len(), 64); // hex of a 32-byte SHA-256 tag
    }

    /// The server-side engine reproduces the SAME shared probe vector through
    /// [`fingerprintd`]'s verifier — tying the edge host's probe check to the client.
    #[test]
    fn engine_expected_probe_matches_shared_vector() {
        let engine = FpEngine::new("salt", "test-probe-secret", "sign");
        assert_eq!(
            engine.expected_probe("fixed-nonce-000"),
            "ad83144894f917b94072c2f7b3246af66d3bc5a450562ccf3671ed64d33137d0"
        );
        assert!(engine.verify_probe(
            "fixed-nonce-000",
            "ad83144894f917b94072c2f7b3246af66d3bc5a450562ccf3671ed64d33137d0"
        ));
        assert!(!engine.verify_probe("fixed-nonce-000", "deadbeef"));
    }

    /// Signing round-trips the `fingerprintd` signer and binds timestamp + body.
    #[test]
    fn engine_sign_binds_timestamp_and_body() {
        let engine = FpEngine::new("salt", "pk", "signing-secret");
        let body = br#"{"visitorId":"abc"}"#;
        let sig = engine.sign(1_700_000_000_000, body);
        assert_eq!(sig.len(), 64);
        assert_eq!(sig, engine.sign(1_700_000_000_000, body));
        assert_ne!(sig, engine.sign(1_700_000_000_001, body));
        assert_ne!(
            sig,
            engine.sign(1_700_000_000_000, br#"{"visitorId":"xyz"}"#)
        );
    }

    /// Shared signing vector — the edge engine, keyed with the deployment's
    /// signing secret (a Worker Secret), reproduces the SAME
    /// `hex(HMAC-SHA256(key, issued_ms_be ++ body))` the native `fingerprintd` signer
    /// produces. The JS side (`apps/edge/tests/handler.test.ts`) asserts this
    /// exact hex too, so the signing-secret path is byte-identical native↔edge —
    /// the response-signing analogue of the `ad83…37d0` probe vector.
    #[test]
    fn engine_sign_matches_shared_vector() {
        let engine = FpEngine::new("salt", "pk", "test-signing-secret");
        assert_eq!(
            engine.sign(1_700_000_000_000, br#"{"visitorId":"abc"}"#),
            "11e764ff987d7be6e4f9e272c9c9fbb9c29fc8c5e3dcc5b935dfa11b9c751792"
        );
    }

    /// Blocking keys are non-empty for a rich probe and **deterministic** across
    /// separate engines sharing a salt secret — the stability an externalized
    /// index relies on. A different secret yields different keys.
    #[test]
    fn blocking_keys_are_stable_across_engines() {
        let a = FpEngine::new("salt-secret", "pk", "sk");
        let b = FpEngine::new("salt-secret", "pk", "sk");
        let probe = full_probe().to_string();

        let ka = a.blocking_keys_impl(&probe).unwrap();
        let kb = b.blocking_keys_impl(&probe).unwrap();
        assert_eq!(ka, kb, "same secret must yield identical keys");

        let parsed: Vec<String> = serde_json::from_str(&ka).unwrap();
        assert_ne!(parsed.len(), 0);
        assert!(parsed.iter().all(|k| k.len() == 64)); // hex of a 32-byte digest

        let other = FpEngine::new("other-secret", "pk", "sk");
        assert_ne!(
            other.blocking_keys_impl(&probe).unwrap(),
            ka,
            "a different salt secret must diverge"
        );
    }

    /// An empty candidate set is judged a new device with a derived id.
    #[test]
    fn stored_components_lists_the_storable_names() {
        let engine = FpEngine::new("s", "k", "k");
        let probe = json!({ "webgl": "x", "canvas": null, "math": { "sin": 1 } }).to_string();
        let names: Vec<String> =
            serde_json::from_str(&engine.stored_components_impl(&probe).unwrap()).unwrap();
        assert_eq!(names, ["webgl"]);
        assert!(engine.stored_components_impl("not json").is_err());
    }

    #[test]
    fn score_with_no_candidates_is_new_device() {
        let engine = FpEngine::new("salt-secret", "pk", "sk");
        let request = json!({ "components": full_probe(), "candidates": [] }).to_string();

        let reply: Value = serde_json::from_str(&engine.score_impl(&request).unwrap()).unwrap();
        assert_eq!(reply["decision"], "new_device");
        assert_eq!(reply["is_new_device"], true);
        assert_eq!(reply["visitor_id"].as_str().unwrap().len(), 64);
    }

    /// A candidate identical to the probe scores a match under its own id,
    /// without minting a new device.
    #[test]
    fn score_recalls_and_matches_an_identical_candidate() {
        let engine = FpEngine::new("salt-secret", "pk", "sk");
        let request = json!({
            "components": full_probe(),
            "candidates": [{ "visitor_id": "v1", "components": full_probe() }],
        })
        .to_string();

        let reply: Value = serde_json::from_str(&engine.score_impl(&request).unwrap()).unwrap();
        assert_eq!(reply["decision"], "match");
        assert_eq!(reply["is_new_device"], false);
        assert_eq!(reply["visitor_id"], "v1");
    }

    /// Malformed request JSON errors rather than panicking.
    #[test]
    fn score_rejects_invalid_json() {
        let engine = FpEngine::new("salt-secret", "pk", "sk");
        assert!(engine.score_impl("not json").is_err());
        assert!(engine.blocking_keys_impl("not json").is_err());
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
            serde_json::from_str(&client_integrity_impl(Some(noisy), false)).unwrap();
        assert_eq!(surfaced["client_integrity"], "noise");
        assert_eq!(surfaced["confidence_adjustment"], 0.0);
        let penalised: Value =
            serde_json::from_str(&client_integrity_impl(Some(noisy), true)).unwrap();
        assert_eq!(penalised["client_integrity"], "noise");
        assert_eq!(
            penalised["confidence_adjustment"],
            -fingerprintd::signals::INTEGRITY_NOISE_PENALTY
        );
    }

    #[test]
    fn client_integrity_ok_absent_and_malformed() {
        let clean = r#"{"canvas":"ok","webgl":"ok","audio":"ok","rect":"ok"}"#;
        let ok: Value = serde_json::from_str(&client_integrity_impl(Some(clean), true)).unwrap();
        assert_eq!(ok["client_integrity"], "ok");
        assert_eq!(ok["confidence_adjustment"], 0.0);
        for raw in [None, Some("not json"), Some("[]"), Some("{}")] {
            let reply: Value = serde_json::from_str(&client_integrity_impl(raw, true)).unwrap();
            assert_eq!(reply["client_integrity"], "unavailable", "{raw:?}");
            assert_eq!(reply["confidence_adjustment"], 0.0, "{raw:?}");
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
