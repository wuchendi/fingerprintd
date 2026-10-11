//! `fingerprintd` — server-side device fingerprinting service.
//!
//! This crate hosts the HTTP surface. The router is built by [`build_router`]
//! and exposes the challenge/response identification flow (architecture §5):
//! `GET /challenge` mints a one-time nonce and `POST /identify` consumes it,
//! rejecting expired or replayed nonces before running the weighted fuzzy
//! matching engine (fuzzy-matching §4/§5) to resolve the device.

#![forbid(unsafe_code)]

pub mod config;
pub mod fingerprint;
pub mod signals;
pub mod state;

// The framework-free compute and storage contracts live in `fp-core`; re-export
// them at their original paths so the HTTP layer (and its tests) reference the
// engine, nonce store, probe, and signer unchanged.
pub use fingerprintd::{fuzzy, nonce, probe, signing};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    config::SecretKey,
    nonce::NonceOutcome,
    signals::{ClientIntegrity, PassiveSignals, StaticIpIntel},
    signing::{ResponseSigner, SIGNATURE_HEADER, SIGNATURE_TIMESTAMP_HEADER},
    state::AppState,
};

/// Build the application router with shared [`AppState`].
///
/// Mounts:
/// - `GET /health` — liveness probe, always `200 OK`.
/// - `GET /challenge` — issue a one-time nonce (architecture §5).
/// - `POST /identify` — consume the nonce and resolve the device.
/// - `DELETE /visitor/{id}` — GDPR erasure, admin-key gated.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/challenge", get(challenge))
        .route("/identify", post(identify))
        .route("/visitor/{id}", delete(erase_visitor))
        .with_state(state)
}

/// Liveness handler: reports that the process is up.
async fn health() -> StatusCode {
    StatusCode::OK
}

/// `GET /challenge` — mint a one-time nonce and return the collection plan.
async fn challenge(State(state): State<AppState>) -> Json<ChallengeResponse> {
    let nonce = state.nonce_store.issue().await;
    // Advertise the nonce-probe transform only when probe enforcement is on, so
    // a probe-capable client knows to compute it (architecture §4.1 pt 3).
    let verify = state.probe.as_ref().map(|_| ProbeDescriptor::advertised());
    Json(ChallengeResponse {
        collect: Collect {
            stable: STABLE_PROBES.iter().map(|s| (*s).to_string()).collect(),
            challenge: ChallengeProbe {
                seed: nonce.clone(),
                targets: CHALLENGE_TARGETS.iter().map(|s| (*s).to_string()).collect(),
                verify,
            },
        },
        expires_in: state.nonce_ttl_secs,
        nonce,
    })
}

/// `POST /identify` — consume the nonce (anti-replay) then match the device.
///
/// A non-[`NonceOutcome::Valid`] nonce (expired, reused, or unknown) yields
/// `401` before any matching runs. On success the response carries the resolved
/// `visitorId` and the weighted engine's computed `confidence`, decision, and
/// collision flag (fuzzy-matching §5/§6).
///
/// The `headers` are read for the edge-injected passive signals (real client IP
/// and TLS JA4, architecture §4.2). They fuse into `confidence` **only** — never the
/// `visitorId` — and are trusted only behind a trusted edge (see
/// [`AppState::trust_edge_headers`]); a directly-reachable origin ignores any
/// client-supplied copy.
async fn identify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IdentifyRequest>,
) -> Response {
    match state.nonce_store.consume(&req.nonce).await {
        NonceOutcome::Valid => {
            // Depth check on top of the one-time nonce (architecture §4.1 pt 3): when
            // a probe key is configured, require a correct `probe` proving the
            // caller ran the advertised transform over this fresh nonce with the
            // shared key. A missing or forged probe is rejected before matching.
            if let Some(verifier) = &state.probe
                && !req
                    .probe
                    .as_deref()
                    .is_some_and(|probe| verifier.verify(&req.nonce, probe))
            {
                tracing::debug!("rejected identify: nonce probe verification failed");
                return StatusCode::UNAUTHORIZED.into_response();
            }

            let now = now_ms();

            // Timestamp window (architecture §4.1): when enabled, bound how long a
            // captured payload stays replayable by requiring the client `ts` to
            // sit within the configured skew of server time. Fail-closed once
            // enabled: a missing or out-of-window `ts` is rejected before matching.
            if state.enforce_ts_window
                && !req
                    .ts
                    .is_some_and(|ts| ts_in_window(ts, now, state.ts_skew_ms))
            {
                tracing::debug!("rejected identify: timestamp outside window");
                return StatusCode::UNAUTHORIZED.into_response();
            }

            // Cross-check the client-reported UA against the unforgeable
            // edge-observed TLS stack / IP. Trust edge headers only behind a
            // trusted edge; otherwise ignore any client-supplied copy (architecture §4.2
            // trusted-header requirement) — an untrusted request auto-degrades.
            let intel = StaticIpIntel::new();
            let claimed_ua = claimed_ua(&req.stable_components);
            let empty = HeaderMap::new();
            let trusted_headers = if state.trust_edge_headers {
                &headers
            } else {
                &empty
            };

            // Read the client IP and TLS JA4 from the same trusted headers
            // (untrusted origin -> None), so the cross-session new-device velocity
            // signals are keyed on the edge-observed values, never client-forged
            // ones. The JA4 feeds a secondary per-class velocity key (HARDEN-002)
            // alongside the per-IP key, catching a proxy-pool farm that shares one
            // Chrome JA4 class.
            let client_ip = trusted_headers
                .get(signals::CF_CONNECTING_IP)
                .and_then(|v| v.to_str().ok())
                .map(str::trim);
            let ja4 = trusted_headers
                .get(signals::JA4_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::trim);
            let outcome =
                state
                    .matcher
                    .identify_with_signals(&req.stable_components, now, client_ip, ja4);

            let signals = signals::extract(trusted_headers, claimed_ua, &intel);

            // Client-side known-answer integrity probes (red-team round 3): a
            // fingerprint-noising browser fails them from inside the collector,
            // the first single-request signal that sees such a browser. Always
            // surfaced; folded into confidence only behind the opt-in penalty
            // (legitimate privacy tooling trips the same probes).
            let integrity = ClientIntegrity::from_json(req.integrity.as_ref());
            // UA-claimed OS family vs the collected font set (surfaced-only): a
            // borrowed Windows persona on a Linux host has no Windows core fonts.
            let persona =
                signals::persona_coherence(claimed_ua, req.stable_components.get("fonts"));

            // Fuse the passive + integrity adjustments into confidence, clamped to
            // [0, 1] (fuzzy-matching §6). The visitorId and decision are unchanged.
            let confidence = (outcome.confidence
                + signals.confidence_adjustment()
                + integrity.confidence_adjustment(state.integrity_penalty_enabled))
            .clamp(0.0, 1.0);

            tracing::debug!(
                visitor_id = %outcome.visitor_id,
                is_new_device = outcome.is_new_device,
                decision = outcome.decision.as_str(),
                score = ?outcome.score,
                compared = outcome.compared_components,
                collision_risk = outcome.collision_risk,
                base_confidence = outcome.confidence,
                confidence,
                tls_consistency = signals.tls_consistency.as_str(),
                ip_risk = signals.ip_risk.as_str(),
                client_integrity = integrity.as_str(),
                persona_coherence = persona.as_str(),
                new_device_velocity = outcome.new_device_velocity.as_str(),
                new_device_velocity_ja4 = outcome.new_device_velocity_ja4.as_str(),
                "identified device",
            );
            let response = IdentifyResponse {
                visitor_id: outcome.visitor_id,
                confidence,
                is_new_device: outcome.is_new_device,
                decision: outcome.decision.as_str(),
                collision_risk: outcome.collision_risk,
                signals: Signals {
                    client_integrity: integrity.as_str(),
                    persona_coherence: persona.as_str(),
                    new_device_velocity: outcome.new_device_velocity.as_str(),
                    new_device_velocity_ja4: outcome.new_device_velocity_ja4.as_str(),
                    ..Signals::from(signals)
                },
            };
            // Serialize once and, when signing is enabled, attach the signature
            // headers over those exact bytes so what is signed equals what is
            // sent. The JSON body shape is unchanged either way.
            signed_json(&response, state.signer.as_deref(), now)
        }
        rejected => {
            tracing::debug!(?rejected, "rejected identify: nonce not valid");
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

/// `DELETE /visitor/{id}` — erase a visitor from the fingerprint library (GDPR
/// right-to-be-forgotten, architecture §7).
///
/// **Fail-closed** auth:
/// - No `admin_key` configured ⇒ the endpoint is disabled ⇒ `404 NOT_FOUND`.
/// - `admin_key` configured but the request is missing the credential or presents
///   a wrong one ⇒ `401 UNAUTHORIZED` (constant-time compare, [`ct_eq`]).
/// - Authorized ⇒ erase and return `204 NO_CONTENT`.
///
/// Erasure is idempotent: `204` is returned even when the visitor did not exist,
/// so the response never leaks whether a given id was present.
async fn erase_visitor(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> StatusCode {
    let Some(admin_key) = state.admin_key.as_deref() else {
        // Disabled when no key is provisioned: erasure is never open.
        return StatusCode::NOT_FOUND;
    };
    if !admin_authorized(&headers, admin_key) {
        tracing::debug!("rejected erase: missing or invalid admin credential");
        return StatusCode::UNAUTHORIZED;
    }
    let existed = state.matcher.erase(&id);
    tracing::info!(existed, "erased visitor (RTBF)");
    StatusCode::NO_CONTENT
}

/// Whether `headers` carry the correct admin credential as
/// `Authorization: Bearer <admin_key>`, compared in constant time.
fn admin_authorized(headers: &HeaderMap, admin_key: &SecretKey) -> bool {
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    ct_eq(token.as_bytes(), admin_key.as_bytes())
}

/// Length-checked constant-time byte equality: no early return on the first
/// differing byte, so a matching-length wrong credential reveals nothing through
/// timing. (A length mismatch short-circuits — an accepted, standard leak.)
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract the client-reported user agent from the stable components, trying the
/// common key spellings. This is the JS/UA-claimed browser the passive TLS
/// cross-check tests for forgery (signals §4.2); it is deliberately taken from
/// the client-reported body, not a trusted source.
fn claimed_ua(components: &Value) -> Option<&str> {
    ["userAgent", "user_agent", "ua"]
        .iter()
        .find_map(|k| components.get(k).and_then(Value::as_str))
        // The real SDK emits no top-level UA (FingerprintJS has no such
        // component); its UA rides under the BotD signals. Without this fallback
        // the UA↔TLS cross-check never fires for SDK traffic (red-team round 3).
        .or_else(|| {
            components
                .pointer("/botd/signals/userAgent/value")
                .and_then(Value::as_str)
        })
}

/// Current Unix time in milliseconds, saturating to `0` before the epoch — the
/// timestamp the matcher stamps onto observations.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Whether a client `ts` (Unix milliseconds) sits within `±skew_ms` of the
/// server's `now_ms` (architecture §4.1). Widened to `i128` so a future timestamp or
/// a pre-epoch clock cannot overflow or wrap the subtraction.
fn ts_in_window(client_ts: i64, now_ms: u64, skew_ms: u64) -> bool {
    (i128::from(now_ms) - i128::from(client_ts)).abs() <= i128::from(skew_ms)
}

/// Build the `/identify` success response, attaching the signature headers when
/// a [`ResponseSigner`] is configured.
///
/// The body is serialized once; the signer signs those exact bytes so the
/// signature covers what is sent. On the unreachable serialization or response
/// build error the handler fails with `500` rather than panicking.
fn signed_json(
    response: &IdentifyResponse,
    signer: Option<&ResponseSigner>,
    issued_ms: u64,
) -> Response {
    let body = match serde_json::to_vec(response) {
        Ok(body) => body,
        Err(err) => {
            tracing::error!(error = %err, "failed to serialize identify response");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(signer) = signer
        && let Some(signature) = signer.sign(issued_ms, &body)
    {
        builder = builder
            .header(SIGNATURE_TIMESTAMP_HEADER, issued_ms.to_string())
            .header(SIGNATURE_HEADER, signature);
    }

    builder.body(Body::from(body)).map_or_else(
        |err| {
            tracing::error!(error = %err, "failed to build identify response");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        },
        IntoResponse::into_response,
    )
}

/// Stable probe identifiers advertised in `GET /challenge` (static P0 plan).
const STABLE_PROBES: &[&str] = &["userAgent", "languages", "timezone", "platform"];
/// Active challenge targets seeded with the nonce.
const CHALLENGE_TARGETS: &[&str] = &["canvas", "audio"];

/// `GET /challenge` response body (architecture §5).
#[derive(Debug, Serialize)]
struct ChallengeResponse {
    /// The one-time nonce the client must echo on `identify`.
    nonce: String,
    /// Nonce lifetime in seconds.
    expires_in: u64,
    /// Client-side collection plan.
    collect: Collect,
}

/// Collection plan carried in a challenge response.
#[derive(Debug, Serialize)]
struct Collect {
    /// Stable probe identifiers to gather.
    stable: Vec<String>,
    /// Nonce-seeded active challenge.
    challenge: ChallengeProbe,
}

/// Active challenge descriptor (canvas/audio seeded with the nonce).
#[derive(Debug, Serialize)]
struct ChallengeProbe {
    /// Nonce used to seed the rendered challenge.
    seed: String,
    /// Probe targets to render.
    targets: Vec<String>,
    /// Nonce-probe transform the client must compute and echo on `identify`.
    /// Present only when probe enforcement is enabled; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    verify: Option<ProbeDescriptor>,
}

/// Advertised nonce-probe transform (architecture §4.1 pt 3): the client computes
/// `encoding(alg(shared_key, input))` — `hex(HMAC-SHA256(shared_key, nonce))` —
/// and returns it as `probe`. The shared key is not advertised; only the
/// transform is.
#[derive(Debug, Serialize)]
struct ProbeDescriptor {
    /// Keyed-hash algorithm, e.g. `HMAC-SHA256`.
    alg: &'static str,
    /// Transform input: the issued `nonce`.
    input: &'static str,
    /// Output encoding of the computed tag, e.g. `hex`.
    encoding: &'static str,
}

impl ProbeDescriptor {
    /// The fixed transform advertised to clients.
    fn advertised() -> Self {
        Self {
            alg: probe::PROBE_ALG,
            input: probe::PROBE_INPUT,
            encoding: probe::PROBE_ENCODING,
        }
    }
}

/// `POST /identify` request body.
///
/// `deny_unknown_fields` rejects an unrecognized *top-level* key
/// with `400`, so a caller cannot smuggle unmodeled fields; `stable_components`
/// is a free-form [`Value`], so arbitrary *nested* component keys still pass.
///
/// The `probe` field is the nonce-probe response: verified only when a
/// probe key is configured, otherwise ignored. The `ts` field is the client's
/// Unix-millisecond timestamp: checked against the server clock only when
/// `enforce_ts_window` is on, otherwise ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentifyRequest {
    /// The nonce previously minted by `GET /challenge`.
    nonce: String,
    /// Nonce-probe response: `hex(HMAC-SHA256(shared_key, nonce))`, as advertised
    /// by `GET /challenge` (architecture §4.1 pt 3). Required and verified only when a
    /// probe key is configured; a missing or wrong value then yields `401`.
    #[serde(default)]
    probe: Option<String>,
    /// Client timestamp in Unix milliseconds (architecture §4.1/§5). Required and
    /// checked against `±ts_skew_secs` only when `enforce_ts_window` is on; a
    /// missing or out-of-window value then yields `401`. Ignored otherwise.
    #[serde(default)]
    ts: Option<i64>,
    /// Raw stable components (no nonce mixed in).
    stable_components: Value,
    /// Known-answer client integrity probe verdicts (`canvas` / `webgl` / `audio`
    /// / `rect`, each `ok` | `noise` | `unavailable`), sent **top-level** by the
    /// SDK so they can never enter the matching input. Free-form JSON: an absent
    /// field or malformed verdicts read as unavailable (neutral). Always surfaced
    /// as `signals.client_integrity`; fused into `confidence` only when
    /// `integrity_penalty_enabled`.
    #[serde(default)]
    integrity: Option<Value>,
}

/// `POST /identify` success body (architecture §5).
#[derive(Debug, Serialize)]
struct IdentifyResponse {
    /// Stable device identifier.
    #[serde(rename = "visitorId")]
    visitor_id: String,
    /// Fused match confidence in `[0.0, 1.0]` (fuzzy-matching §6). This is **decision
    /// confidence, not identity trust**: a first-ever `new_device`
    /// can report a high confidence (confidently unrecognized) while its identity
    /// is unestablished — key trust off `is_new_device` / `decision`, not this
    /// value alone.
    confidence: f64,
    /// Whether this device was newly recorded.
    is_new_device: bool,
    /// Verdict from the weighted engine: `match`, `review`, or `new_device`
    /// (fuzzy-matching §5.4).
    decision: &'static str,
    /// Set when a runner-up candidate also cleared the match threshold within
    /// the collision margin (fuzzy-matching §5.4).
    collision_risk: bool,
    /// Passive network-signal risk summary for downstream consumers (architecture §5).
    signals: Signals,
}

/// Passive-signal risk summary surfaced to consumers (architecture §5): the UA/TLS
/// consistency verdict and the coarse IP reputation band, derived from the
/// edge-observed signals (`crate::signals`).
#[derive(Debug, Serialize)]
struct Signals {
    /// Whether the UA and TLS fingerprint agree.
    ua_tls_consistent: bool,
    /// Coarse IP risk band.
    ip_risk: &'static str,
    /// Fused verdict of the client's known-answer integrity probes
    /// (`ok` / `noise` / `unavailable`): `noise` means the browser returned a
    /// wrong answer to a question an unmodified Chromium answers exactly — the
    /// footprint of a fingerprint-noising (anti-detect) browser. Surfaced
    /// always; lowers `confidence` only when `integrity_penalty_enabled`. A risk
    /// band for downstream consumers, never folded into the `visitorId`.
    client_integrity: &'static str,
    /// UA-claimed OS family vs the collected `fonts` set
    /// (`consistent` / `mismatch` / `unknown`): `mismatch` means a Windows or
    /// macOS UA whose font set has none of that OS's core fonts — a borrowed
    /// persona. Surfaced-only; never moves `confidence` or the `visitorId`.
    persona_coherence: &'static str,
    /// Cross-session new-device production-rate band for the client IP
    /// (`low` / `medium` / `high`): an IP-keyed velocity signal that catches the
    /// fresh-seed-per-launch farm no single request can. Surfaced alongside
    /// `ip_risk`, never folded into the `visitorId`.
    new_device_velocity: &'static str,
    /// Cross-session new-device production-rate band for the client's coarse JA4
    /// **class** (`low` / `medium` / `high`): a secondary velocity signal keyed on
    /// the shared TLS shape, catching a proxy-pool farm that rotates IPs but keeps
    /// one Chrome JA4 class. Surfaced alongside `new_device_velocity`; low-entropy
    /// and shared by all real Chrome, so it is a reported band only — never folded
    /// into the `visitorId`, and (by default) not into `confidence`.
    new_device_velocity_ja4: &'static str,
}

impl From<PassiveSignals> for Signals {
    fn from(signals: PassiveSignals) -> Self {
        Self {
            ua_tls_consistent: signals.tls_consistency.ua_tls_consistent(),
            ip_risk: signals.ip_risk.as_str(),
            // Neutral defaults; the handler overrides these with the request's
            // integrity verdict and the engine's bands.
            client_integrity: "unavailable",
            persona_coherence: "unknown",
            new_device_velocity: "low",
            new_device_velocity_ja4: "low",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::build_router;
    use crate::{config::Config, nonce::InMemoryNonceStore, state::AppState};
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use serde_json::{Value, json};
    use std::{sync::Arc, time::Duration};
    use tower::ServiceExt;

    /// Build a router over default in-memory state.
    fn test_router() -> Router {
        build_router(AppState::from_config(&Config::default()))
    }

    /// GET a URI and return the response.
    async fn get(router: &Router, uri: &str) -> axum::response::Response {
        router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// POST `/identify` with a JSON body and return the response.
    async fn post_identify(router: &Router, body: Value) -> axum::response::Response {
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/identify")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// POST `/identify` with a JSON body and extra request headers.
    async fn post_identify_headers(
        router: &Router,
        body: Value,
        headers: &[(&str, &str)],
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/identify")
            .header(header::CONTENT_TYPE, "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        router
            .clone()
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    /// Read a response body into a JSON value.
    async fn json_body(resp: axum::response::Response) -> Value {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// GET `/challenge` and return its issued nonce.
    async fn fresh_nonce(router: &Router) -> String {
        let resp = get(router, "/challenge").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["expires_in"], json!(30));
        assert_eq!(body["collect"]["challenge"]["seed"], body["nonce"]);
        body["nonce"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn health_returns_200() {
        let resp = get(&test_router(), "/health").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn happy_path_identifies_new_device() {
        let router = test_router();
        let nonce = fresh_nonce(&router).await;

        let resp = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": 1, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert!(body["visitorId"].as_str().is_some());
        // A first-ever probe has no candidate: it is a new device with a
        // computed (no longer hardcoded) confidence in [0, 1].
        let confidence = body["confidence"].as_f64().unwrap();
        assert!((0.0..=1.0).contains(&confidence));
        assert_eq!(body["is_new_device"], json!(true));
        assert_eq!(body["decision"], json!("new_device"));
    }

    #[tokio::test]
    async fn unknown_nonce_rejected() {
        let resp = post_identify(
            &test_router(),
            json!({ "nonce": "never-issued", "ts": 1, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn reused_nonce_rejected() {
        let router = test_router();
        let nonce = fresh_nonce(&router).await;
        let body = json!({ "nonce": nonce, "ts": 1, "stable_components": {"ua": "x"} });

        let first = post_identify(&router, body.clone()).await;
        assert_eq!(first.status(), StatusCode::OK);

        // Same nonce a second time: replay is rejected.
        let second = post_identify(&router, body).await;
        assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_nonce_rejected() {
        // Build state with a store holding an already-expired nonce (zero TTL),
        // so expiry is exercised deterministically without sleeping.
        let store = Arc::new(InMemoryNonceStore::new(Duration::from_secs(30)));
        let nonce = store.issue_with_ttl(Duration::ZERO);
        let state = AppState {
            nonce_store: store,
            matcher: Arc::new(crate::fuzzy::FuzzyStore::new()),
            nonce_ttl_secs: 30,
            trust_edge_headers: false,
            integrity_penalty_enabled: false,
            probe: None,
            signer: None,
            enforce_ts_window: false,
            ts_skew_ms: 30_000,
            admin_key: None,
            retention_ms: 0,
        };
        let router = build_router(state);

        let resp = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": 1, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// A rich, realistic stable-component probe the fuzzy engine can score.
    fn probe_components() -> Value {
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

    /// POST `/identify` for `components` under a fresh nonce, returning the body.
    async fn identify_with(router: &Router, components: Value) -> Value {
        let nonce = fresh_nonce(router).await;
        json_body(
            post_identify(
                router,
                json!({ "nonce": nonce, "ts": 1, "stable_components": components }),
            )
            .await,
        )
        .await
    }

    #[tokio::test]
    async fn fuzzy_match_across_requests() {
        let router = test_router();

        // Same rich components, two fresh nonces -> same visitor, second matched.
        let first = identify_with(&router, probe_components()).await;
        let second = identify_with(&router, probe_components()).await;

        assert_eq!(first["visitorId"], second["visitorId"]);
        assert_eq!(first["is_new_device"], json!(true));
        assert_eq!(second["is_new_device"], json!(false));
        assert_eq!(second["decision"], json!("match"));

        // A disjoint device -> different visitor, marked new.
        let other = json!({
            "webgl": "Apple GPU",
            "platform": "iPhone",
            "timezone": "America/New_York",
            "audio": "35.7",
            "cpu_cores": 6,
            "device_memory": 4,
            "fonts": ["SF Pro", "Menlo", "Georgia", "Palatino"],
            "user_agent": "Safari/17",
        });
        let third = identify_with(&router, other).await;
        assert_ne!(third["visitorId"], first["visitorId"]);
        assert_eq!(third["is_new_device"], json!(true));
    }

    // --- Passive-signal fusion (fuzzy-matching §6, architecture §4.2) ---

    use crate::signals::{CF_CONNECTING_IP, JA4_HEADER};

    /// A JA4 whose structural counts read as a real browser (15 ciphers, 16 ext).
    const BROWSER_JA4: &str = "t13d1516h2_8daaf6152771_02713d6af862";
    /// A JA4 whose structural counts read as a minimal automation stack (3/4).
    const AUTOMATION_JA4: &str = "t13d0304h1_aaaaaaaaaaaa_bbbbbbbbbbbb";
    /// A spoofed browser UA (headless automation self-reporting Chrome).
    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0";

    /// Build a router whose state trusts (or not) edge-injected headers.
    fn router_with_trust(trust_edge_headers: bool) -> Router {
        build_router(AppState::from_config(&Config {
            trust_edge_headers,
            ..Config::default()
        }))
    }

    /// Identify a fixed single-device probe (claimed UA = Chrome) on a **fresh**
    /// router with the given trust setting and edge headers, returning the body.
    ///
    /// A fresh store per call keeps the probe a first-ever new device, so the
    /// engine's base confidence is identical across calls and only the passive
    /// fusion differs — letting the tests compare adjustments directly.
    async fn identify_signals(trust_edge_headers: bool, headers: &[(&str, &str)]) -> Value {
        let router = router_with_trust(trust_edge_headers);
        let nonce = fresh_nonce(&router).await;
        let body = json!({
            "nonce": nonce,
            "ts": 1,
            "stable_components": { "userAgent": CHROME_UA },
        });
        json_body(post_identify_headers(&router, body, headers).await).await
    }

    /// Read the `confidence` field as an `f64`.
    fn confidence(body: &Value) -> f64 {
        body["confidence"].as_f64().unwrap()
    }

    // --- Client integrity probes (red-team round 3) ---

    /// Identify a fixed probe on a **fresh** router with the given penalty
    /// setting and optional top-level `integrity`, returning the body. Fresh
    /// store per call ⇒ identical base confidence, so only the fusion differs.
    async fn identify_integrity(penalty_enabled: bool, integrity: Option<Value>) -> Value {
        let router = build_router(AppState::from_config(&Config {
            integrity_penalty_enabled: penalty_enabled,
            ..Config::default()
        }));
        let nonce = fresh_nonce(&router).await;
        let mut body = json!({
            "nonce": nonce,
            "ts": 1,
            "stable_components": { "userAgent": CHROME_UA },
        });
        if let Some(integrity) = integrity {
            body["integrity"] = integrity;
        }
        json_body(post_identify(&router, body).await).await
    }

    fn all_noise() -> Value {
        json!({ "canvas": "noise", "webgl": "noise", "audio": "noise", "rect": "noise" })
    }

    fn all_ok() -> Value {
        json!({ "canvas": "ok", "webgl": "ok", "audio": "ok", "rect": "ok" })
    }

    // --- Persona coherence + the BotD UA fallback (red-team round 3) ---

    /// A Windows Chrome UA as the real SDK reports it: under the `BotD` signals,
    /// not as a top-level component.
    fn sdk_like_components(fonts: &Value) -> Value {
        json!({
            "platform": "Win32",
            "fonts": fonts,
            "botd": { "signals": { "userAgent": { "value": CHROME_UA, "state": 0 } } },
        })
    }

    #[tokio::test]
    async fn persona_mismatch_is_surfaced_without_moving_confidence() {
        let router = test_router();
        let mismatch = identify_with(&router, sdk_like_components(&json!(["Arial"]))).await;
        assert_eq!(mismatch["signals"]["persona_coherence"], json!("mismatch"));
        let consistent =
            identify_with(&test_router(), sdk_like_components(&json!(["Calibri"]))).await;
        assert_eq!(
            consistent["signals"]["persona_coherence"],
            json!("consistent")
        );
        assert!((confidence(&mismatch) - confidence(&consistent)).abs() < 1e-12);
        // No fonts array / no UA → unknown.
        let unknown = identify_with(&test_router(), json!({ "platform": "Win32" })).await;
        assert_eq!(unknown["signals"]["persona_coherence"], json!("unknown"));
    }

    #[tokio::test]
    async fn claimed_ua_falls_back_to_the_botd_signal_so_ua_tls_mismatch_fires_for_sdk_traffic() {
        // Before the fallback an SDK payload (UA only under botd) could never be
        // caught by the UA↔TLS cross-check: no claimed UA ⇒ always consistent.
        let router = router_with_trust(true);
        let nonce = fresh_nonce(&router).await;
        let body = json!({
            "nonce": nonce,
            "ts": 1,
            "stable_components": sdk_like_components(&json!(["Calibri"])),
        });
        let forged =
            json_body(post_identify_headers(&router, body, &[(JA4_HEADER, AUTOMATION_JA4)]).await)
                .await;
        assert_eq!(forged["signals"]["ua_tls_consistent"], json!(false));
    }

    #[tokio::test]
    async fn integrity_absent_is_unavailable_and_neutral() {
        let body = identify_integrity(true, None).await;
        assert_eq!(body["signals"]["client_integrity"], json!("unavailable"));
        // Malformed material is neutral too — never manufactured into noise.
        let malformed = identify_integrity(true, Some(json!({ "canvas": 1 }))).await;
        assert_eq!(
            malformed["signals"]["client_integrity"],
            json!("unavailable")
        );
        assert!((confidence(&malformed) - confidence(&body)).abs() < 1e-12);
    }

    #[tokio::test]
    async fn integrity_noise_is_surfaced_but_not_penalised_by_default() {
        let base = identify_integrity(false, None).await;
        let noisy = identify_integrity(false, Some(all_noise())).await;
        assert_eq!(noisy["signals"]["client_integrity"], json!("noise"));
        assert!((confidence(&noisy) - confidence(&base)).abs() < 1e-12);
    }

    #[tokio::test]
    async fn integrity_noise_downgrades_confidence_only_when_enabled() {
        let base = identify_integrity(true, None).await;
        let noisy = identify_integrity(true, Some(all_noise())).await;
        assert_eq!(noisy["signals"]["client_integrity"], json!("noise"));
        assert!(confidence(&noisy) < confidence(&base));
        // An exact answer set is surfaced as ok and never moves confidence.
        let clean = identify_integrity(true, Some(all_ok())).await;
        assert_eq!(clean["signals"]["client_integrity"], json!("ok"));
        assert!((confidence(&clean) - confidence(&base)).abs() < 1e-12);
    }

    #[tokio::test]
    async fn passive_consistent_ua_tls_boosts_confidence() {
        // Baseline: trusted edge but Bot Management absent → degraded (neutral).
        let base = identify_signals(true, &[(CF_CONNECTING_IP, "198.51.100.7")]).await;
        // A browser JA4 consistent with the Chrome UA lifts confidence.
        let boosted = identify_signals(
            true,
            &[
                (CF_CONNECTING_IP, "198.51.100.7"),
                (JA4_HEADER, BROWSER_JA4),
            ],
        )
        .await;
        assert!(confidence(&boosted) > confidence(&base));
        assert_eq!(boosted["signals"]["ua_tls_consistent"], json!(true));
    }

    #[tokio::test]
    async fn passive_ua_tls_mismatch_downgrades_confidence() {
        // Baseline: no JA4 → degraded (neutral).
        let base = identify_signals(true, &[]).await;
        // Chrome UA riding a minimal automation TLS stack → strong downgrade.
        let downgraded = identify_signals(true, &[(JA4_HEADER, AUTOMATION_JA4)]).await;
        assert!(confidence(&downgraded) < confidence(&base));
        assert_eq!(downgraded["signals"]["ua_tls_consistent"], json!(false));
    }

    #[tokio::test]
    async fn absent_ja4_degrades_gracefully_without_penalty() {
        // Bot Management absent (no JA4 header) behind a trusted edge.
        let degraded = identify_signals(true, &[(CF_CONNECTING_IP, "198.51.100.7")]).await;
        let mismatched = identify_signals(true, &[(JA4_HEADER, AUTOMATION_JA4)]).await;
        let boosted = identify_signals(true, &[(JA4_HEADER, BROWSER_JA4)]).await;

        // Neutral: strictly above a forgery downgrade, strictly below a boost —
        // a missing connection signal neither penalises nor rewards (§4.2).
        assert!(confidence(&degraded) > confidence(&mismatched));
        assert!(confidence(&degraded) < confidence(&boosted));
        // Still a clean success, and degrade is not flagged as an inconsistency.
        assert_eq!(degraded["is_new_device"], json!(true));
        assert_eq!(degraded["signals"]["ua_tls_consistent"], json!(true));
        assert_eq!(degraded["signals"]["ip_risk"], json!("low"));
    }

    #[tokio::test]
    async fn signals_expose_the_ja4_class_velocity_band() {
        // A single request behind a trusted edge carrying a real-browser JA4: the
        // response surfaces the secondary per-class velocity band, at its neutral
        // `low` default (one device is far below the class threshold).
        let body = identify_signals(
            true,
            &[
                (CF_CONNECTING_IP, "198.51.100.7"),
                (JA4_HEADER, BROWSER_JA4),
            ],
        )
        .await;
        assert_eq!(body["signals"]["new_device_velocity_ja4"], json!("low"));
    }

    #[tokio::test]
    async fn client_supplied_edge_headers_are_ignored_when_untrusted() {
        // A direct client self-injects a browser-looking JA4 and a datacenter IP
        // to forge consistency and a clean IP band.
        let forged = &[(CF_CONNECTING_IP, "34.120.5.6"), (JA4_HEADER, BROWSER_JA4)];

        // Default (untrusted) origin: the client-supplied headers are ignored.
        let untrusted = identify_signals(false, forged).await;
        // The same headers behind a trusted edge would boost and flag the IP.
        let trusted = identify_signals(true, forged).await;

        // No forged boost: the untrusted request stays at the degraded baseline.
        assert!(confidence(&untrusted) < confidence(&trusted));
        // The client IP header is ignored → band stays low (edge-trusted: high).
        assert_eq!(untrusted["signals"]["ip_risk"], json!("low"));
        assert_eq!(trusted["signals"]["ip_risk"], json!("high"));
        // The forged JA4 buys no evidence-based consistency (degrade default).
        assert_eq!(untrusted["signals"]["ua_tls_consistent"], json!(true));
    }

    // --- Nonce probe verification (architecture §4.1 pt 3) ---

    use crate::probe::{PROBE_ALG, ProbeVerifier};

    /// Shared probe secret used by the probe-enforcing test router.
    const PROBE_SECRET: &str = "test-probe-secret";

    /// Build a router that enforces the nonce probe with [`PROBE_SECRET`].
    fn router_with_probe() -> Router {
        build_router(AppState::from_config(&Config {
            probe_key: Some(PROBE_SECRET.into()),
            ..Config::default()
        }))
    }

    /// The correct probe a legitimate client returns for `nonce`.
    fn expected_probe(nonce: &str) -> String {
        ProbeVerifier::new(PROBE_SECRET.as_bytes())
            .expected_hex(nonce)
            .unwrap()
    }

    #[tokio::test]
    async fn probe_challenge_advertises_transform() {
        // With a probe key configured, /challenge advertises the transform.
        let body = json_body(get(&router_with_probe(), "/challenge").await).await;
        let verify = &body["collect"]["challenge"]["verify"];
        assert_eq!(verify["alg"], json!(PROBE_ALG));
        assert_eq!(verify["input"], json!("nonce"));
        assert_eq!(verify["encoding"], json!("hex"));
    }

    #[tokio::test]
    async fn probe_happy_path_verifies_and_identifies() {
        let router = router_with_probe();
        let nonce = fresh_nonce(&router).await;
        let probe = expected_probe(&nonce);

        let resp = post_identify(
            &router,
            json!({ "nonce": nonce, "probe": probe, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(json_body(resp).await["visitorId"].as_str().is_some());
    }

    #[tokio::test]
    async fn probe_forged_response_rejected() {
        let router = router_with_probe();
        let nonce = fresh_nonce(&router).await;
        // A caller without the shared key computes the transform under the wrong
        // key, so its probe cannot match.
        let forged = ProbeVerifier::new(b"wrong-key")
            .expected_hex(&nonce)
            .unwrap();

        let resp = post_identify(
            &router,
            json!({ "nonce": nonce, "probe": forged, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn probe_missing_rejected_when_configured() {
        let router = router_with_probe();
        let nonce = fresh_nonce(&router).await;
        // No `probe` field: rejected before matching (fail-closed when enabled).
        let resp = post_identify(
            &router,
            json!({ "nonce": nonce, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn probe_valid_then_replayed_rejected() {
        let router = router_with_probe();
        let nonce = fresh_nonce(&router).await;
        let body = json!({ "nonce": nonce, "probe": expected_probe(&nonce), "stable_components": {"ua": "x"} });

        let first = post_identify(&router, body.clone()).await;
        assert_eq!(first.status(), StatusCode::OK);
        // Replaying the same nonce + valid probe still fails: the one-time nonce
        // is the primary anti-replay lock, the probe is only depth.
        let second = post_identify(&router, body).await;
        assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn no_probe_key_omits_descriptor_and_ignores_probe_field() {
        // Default router: no probe key → transform not advertised.
        let router = test_router();
        let body = json_body(get(&router, "/challenge").await).await;
        assert!(body["collect"]["challenge"].get("verify").is_none());

        // An arbitrary `probe` value is ignored when enforcement is off.
        let nonce = body["nonce"].as_str().unwrap().to_string();
        let resp = post_identify(
            &router,
            json!({ "nonce": nonce, "probe": "ignored", "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // --- Response signature + timestamp window (architecture §4.1) ---

    use crate::signing::{ResponseSigner, SIGNATURE_HEADER, SIGNATURE_TIMESTAMP_HEADER};

    /// Shared signing secret used by the response-signing test router.
    const SIGNING_SECRET: &str = "test-signing-secret";

    /// Build a router that signs `/identify` responses with [`SIGNING_SECRET`].
    fn router_with_signing() -> Router {
        build_router(AppState::from_config(&Config {
            response_signing_key: Some(SIGNING_SECRET.into()),
            ..Config::default()
        }))
    }

    /// Build a router that enforces the request timestamp window with `skew_secs`.
    fn router_with_ts_window(skew_secs: u64) -> Router {
        build_router(AppState::from_config(&Config {
            enforce_ts_window: true,
            ts_skew_secs: skew_secs,
            ..Config::default()
        }))
    }

    #[tokio::test]
    async fn no_signing_key_omits_signature_headers() {
        // Default router (no signing key): success carries no signature headers.
        let router = test_router();
        let nonce = fresh_nonce(&router).await;
        let resp = post_identify(
            &router,
            json!({ "nonce": nonce, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(SIGNATURE_HEADER).is_none());
        assert!(resp.headers().get(SIGNATURE_TIMESTAMP_HEADER).is_none());
    }

    #[tokio::test]
    async fn signing_key_signs_response_verifiably() {
        let router = router_with_signing();
        let nonce = fresh_nonce(&router).await;
        let resp = post_identify(
            &router,
            json!({ "nonce": nonce, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Pull the signature headers, then the exact body bytes that were signed.
        let issued_ms: u64 = resp
            .headers()
            .get(SIGNATURE_TIMESTAMP_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let signature = resp
            .headers()
            .get(SIGNATURE_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();

        // The body is still valid JSON with a visitorId (shape unchanged).
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed["visitorId"].as_str().is_some());

        let signer = ResponseSigner::new(SIGNING_SECRET.as_bytes());
        // The advertised signature recomputes over the received timestamp + body.
        assert_eq!(signer.sign(issued_ms, &body).unwrap(), signature);
        // Tamper: a modified body no longer verifies.
        let mut tampered = body.to_vec();
        tampered.push(b' ');
        assert_ne!(signer.sign(issued_ms, &tampered).unwrap(), signature);
        // A caller without the shared key cannot forge the signature.
        assert_ne!(
            ResponseSigner::new(b"wrong-key")
                .sign(issued_ms, &body)
                .unwrap(),
            signature
        );
    }

    #[tokio::test]
    async fn ts_window_accepts_fresh_rejects_stale_future_and_missing() {
        let router = router_with_ts_window(30);
        let now = i64::try_from(super::now_ms()).unwrap();

        // Fresh: server-now is within the skew → accepted.
        let nonce = fresh_nonce(&router).await;
        let fresh = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": now, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(fresh.status(), StatusCode::OK);

        // Stale: far in the past (beyond the 30s skew) → rejected.
        let nonce = fresh_nonce(&router).await;
        let stale = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": now - 60_000, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

        // Future: far ahead → rejected (skew is symmetric).
        let nonce = fresh_nonce(&router).await;
        let future = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": now + 60_000, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(future.status(), StatusCode::UNAUTHORIZED);

        // Missing `ts` while enforced → rejected (fail-closed once enabled).
        let nonce = fresh_nonce(&router).await;
        let missing = post_identify(
            &router,
            json!({ "nonce": nonce, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ts_ignored_when_window_disabled() {
        // Default router: a wildly stale `ts` is accepted because enforcement is
        // off — the timestamp window is opt-in.
        let router = test_router();
        let nonce = fresh_nonce(&router).await;
        let resp = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": 1, "stable_components": {"ua": "x"} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn ts_in_window_is_symmetric_around_now() {
        // Exactly at the edge (±skew) is inside; one past it is outside.
        assert!(super::ts_in_window(1_000, 1_500, 500));
        assert!(super::ts_in_window(2_000, 1_500, 500));
        assert!(!super::ts_in_window(999, 1_500, 500));
        assert!(!super::ts_in_window(2_001, 1_500, 500));
    }

    // --- deny_unknown_fields ---

    #[tokio::test]
    async fn identify_rejects_unknown_top_level_field() {
        let router = test_router();

        // An unrecognized top-level key is rejected before matching (non-2xx:
        // axum's Json extractor maps the deny_unknown_fields error to 4xx).
        let nonce = fresh_nonce(&router).await;
        let rejected = post_identify(
            &router,
            json!({
                "nonce": nonce,
                "ts": 1,
                "stable_components": {"ua": "x"},
                "challenge_response": {},
            }),
        )
        .await;
        assert!(!rejected.status().is_success());

        // Arbitrary *nested* component keys are still accepted (free-form Value).
        let nonce = fresh_nonce(&router).await;
        let ok = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": 1, "stable_components": {"ua": "x", "anything": 1} }),
        )
        .await;
        assert_eq!(ok.status(), StatusCode::OK);
    }

    // --- GDPR erasure endpoint (M6b) ---

    /// Admin credential used by the erasure-enabled test router.
    const ADMIN_KEY: &str = "test-admin-key";

    /// Build a probe-key-free router with the erasure endpoint enabled.
    fn router_with_admin() -> Router {
        build_router(AppState::from_config(&Config {
            admin_key: Some(ADMIN_KEY.into()),
            ..Config::default()
        }))
    }

    /// Issue `DELETE /visitor/{id}`, optionally with a bearer credential.
    async fn delete_visitor(
        router: &Router,
        id: &str,
        bearer: Option<&str>,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("DELETE")
            .uri(format!("/visitor/{id}"));
        if let Some(token) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        router
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn erase_disabled_without_admin_key() {
        // No admin key configured → the endpoint is disabled (fail-closed 404),
        // regardless of any supplied credential.
        let router = test_router();
        assert_eq!(
            delete_visitor(&router, "v1", None).await.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            delete_visitor(&router, "v1", Some("anything"))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn erase_rejects_missing_or_wrong_admin_key() {
        let router = router_with_admin();
        // Configured but no credential → 401.
        assert_eq!(
            delete_visitor(&router, "v1", None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        // Configured but wrong credential → 401.
        assert_eq!(
            delete_visitor(&router, "v1", Some("wrong-key"))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn erase_authorized_makes_device_new_again() {
        let router = router_with_admin();

        // Record a device, then confirm the revisit matches (record present).
        let first = identify_with(&router, probe_components()).await;
        let visitor = first["visitorId"].as_str().unwrap().to_string();
        assert_eq!(first["is_new_device"], json!(true));
        let second = identify_with(&router, probe_components()).await;
        assert_eq!(second["is_new_device"], json!(false));

        // Authorized erasure returns 204.
        let resp = delete_visitor(&router, &visitor, Some(ADMIN_KEY)).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Record + blocking entries are gone → the device re-identifies as new.
        let after = identify_with(&router, probe_components()).await;
        assert_eq!(after["is_new_device"], json!(true));

        // Idempotent: erasing again (absent now) still returns 204, no leak.
        let again = delete_visitor(&router, &visitor, Some(ADMIN_KEY)).await;
        assert_eq!(again.status(), StatusCode::NO_CONTENT);
    }
}
