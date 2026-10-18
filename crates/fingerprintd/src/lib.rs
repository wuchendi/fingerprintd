//! `fingerprintd` — server-side device fingerprinting service.
//!
//! This crate hosts the HTTP surface. The router is built by [`build_router`]
//! and exposes the challenge/response identification flow (architecture §5):
//! `GET /challenge` mints a one-time nonce and `POST /identify` consumes it,
//! rejecting expired or replayed nonces before running the weighted fuzzy
//! matching engine (fuzzy-matching §4/§5) to resolve the device. Every
//! successful identify is stored under its `request_id` for the
//! server-to-server events API (`GET /events/{request_id}`).
//!
//! All request and response bodies are `snake_case` JSON. Request bodies are a
//! closed schema: an unknown key at any level, a wrong type, a missing required
//! field, or malformed JSON is rejected with `400` (`415` for a non-JSON
//! content type) before any matching runs.

#![forbid(unsafe_code)]

pub mod config;
pub mod events;
pub mod signals;
pub mod state;

use std::{sync::Arc, time::Duration, time::Instant};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{FromRequest, Path, Request, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use fingerprintd::{
    fuzzy::{Components, IdentifyContext},
    nonce::NonceOutcome,
    signals::{Automation, Botd, ClientIntegrity, Integrity, StaticIpIntel, persona_coherence},
};
use rand::{Rng, rng};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::{config::SecretKey, state::AppState};

/// Build the application router with shared [`AppState`].
///
/// Mounts:
/// - `GET /health` — liveness probe, always `200 OK`.
/// - `GET /challenge` — issue a one-time nonce (architecture §5).
/// - `POST /identify` — consume the nonce and resolve the device.
/// - `GET /events/{request_id}` — fetch a stored identify result, API-key gated.
/// - `DELETE /visitor/{visitor_id}` — GDPR erasure, admin-key gated.
///
/// Every route runs under the [`with_limits`] timeout and global concurrency
/// cap.
pub fn build_router(state: AppState) -> Router {
    let timeout = state.request_timeout;
    let max_concurrent = state.max_concurrent_requests;
    let router = Router::new()
        .route("/health", get(health))
        .route("/challenge", get(challenge))
        .route("/identify", post(identify))
        .route("/events/{request_id}", get(get_event))
        .route("/visitor/{visitor_id}", delete(erase_visitor))
        .with_state(state);
    with_limits(router, timeout, max_concurrent)
}

/// Wrap `router` in the global load limits: at most `max_concurrent` requests
/// are processed at once (later ones wait for a slot), and a request not
/// answered within `timeout` — including time spent waiting for a slot — gets
/// `408 Request Timeout`.
pub fn with_limits(router: Router, timeout: Duration, max_concurrent: usize) -> Router {
    router
        .layer(GlobalConcurrencyLimitLayer::new(max_concurrent))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ))
}

/// Liveness handler: reports that the process is up.
async fn health() -> StatusCode {
    StatusCode::OK
}

/// `GET /challenge` — mint a one-time nonce.
async fn challenge(State(state): State<AppState>) -> Json<ChallengeResponse> {
    Json(ChallengeResponse {
        nonce: state.nonce_store.issue().await,
        expires_in: state.nonce_ttl_secs,
    })
}

/// `POST /identify` — consume the nonce (anti-replay) then match the device.
///
/// A non-[`NonceOutcome::Valid`] nonce (expired, reused, or unknown), or a `ts`
/// outside `±ts_skew_secs` of server time, yields `401` before any matching
/// runs. On success the response carries a fresh `request_id`, the resolved
/// `visitor_id`, and the weighted engine's computed `confidence`, decision, and
/// collision flag (fuzzy-matching §5/§6). When the events API is enabled
/// (`api_key` configured), the body is also stored under the `request_id` for
/// `GET /events/{request_id}`.
///
/// The `headers` are read for the edge-injected passive signals (real client IP
/// and TLS JA4, architecture §4.2). They fuse into `confidence` **only** — never
/// the `visitor_id` — and are trusted only behind a trusted edge (see
/// [`AppState::trust_edge_headers`]); a directly-reachable origin ignores any
/// client-supplied copy.
async fn identify(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(req): ApiJson<IdentifyRequest>,
) -> Response {
    let nonce = state.nonce_store.consume(&req.nonce).await;
    if nonce != NonceOutcome::Valid {
        tracing::debug!(?nonce, "rejected identify: nonce not valid");
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let now = now_ms();

    // Timestamp window (architecture §4.1): bound how long a captured payload
    // stays replayable by requiring the client `ts` to sit within the
    // configured skew of server time.
    if !ts_in_window(req.ts, now, state.ts_skew_ms) {
        tracing::debug!("rejected identify: timestamp outside window");
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // Trust edge headers only behind a trusted edge; otherwise ignore any
    // client-supplied copy (architecture §4.2) — an untrusted request
    // auto-degrades.
    let empty = HeaderMap::new();
    let trusted_headers = if state.trust_edge_headers {
        &headers
    } else {
        &empty
    };
    // The cross-session new-device velocity signal is keyed on the
    // edge-observed client IP, never a client-forged one.
    let client_ip = trusted_headers
        .get(signals::CF_CONNECTING_IP)
        .and_then(|v| v.to_str().ok())
        .map(|ip| ip.trim().to_owned());

    let IdentifyRequest {
        components,
        user_agent,
        botd,
        integrity,
        ..
    } = req;
    let claimed_ua = user_agent.as_deref();
    // UA-claimed OS family vs the collected font set (surfaced-only): a
    // borrowed Windows persona on a Linux host has no Windows core fonts.
    let persona = persona_coherence(claimed_ua, components.fonts.as_deref());

    // Matching is CPU-bound and takes the store's std locks: keep it off the
    // async workers.
    let matcher = Arc::clone(&state.matcher);
    let outcome = match tokio::task::spawn_blocking(move || {
        matcher.identify(&IdentifyContext {
            components: &components,
            now_ms: now,
            client_ip: client_ip.as_deref(),
        })
    })
    .await
    {
        Ok(outcome) => outcome,
        Err(err) => {
            tracing::error!(error = %err, "identify task failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    // `identify` resolves an id on every verdict.
    let Some(visitor_id) = outcome.visitor_id.clone() else {
        tracing::error!("identify resolved no visitor id");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    // Cross-check the client-reported UA against the unforgeable edge-observed
    // TLS stack / IP.
    let passive = signals::extract(trusted_headers, claimed_ua, &StaticIpIntel::new());
    // Client-side known-answer integrity probes: always surfaced; folded into
    // confidence only behind the opt-in penalty (legitimate privacy tooling
    // trips the same probes).
    let integrity = ClientIntegrity::from_integrity(integrity.as_ref());
    let automation = Automation::from_botd(botd.as_ref());

    // Fuse the passive + integrity adjustments into confidence, clamped to
    // [0, 1] (fuzzy-matching §6). The visitor_id and decision are unchanged.
    let confidence = (outcome.confidence
        + passive.confidence_adjustment()
        + integrity.confidence_adjustment(state.integrity_penalty_enabled))
    .clamp(0.0, 1.0);

    let request_id = new_request_id();
    tracing::debug!(
        request_id = %request_id,
        visitor_id = %visitor_id,
        is_new_device = outcome.is_new_device,
        decision = outcome.decision.as_str(),
        score = ?outcome.score,
        compared = outcome.compared_components,
        collision_risk = outcome.collision_risk,
        template_jump = outcome.template_jump,
        base_confidence = outcome.confidence,
        confidence,
        tls_consistency = passive.tls_consistency.as_str(),
        ip_risk = passive.ip_risk.as_str(),
        client_integrity = integrity.as_str(),
        persona_coherence = persona.as_str(),
        new_device_velocity = outcome.new_device_velocity.as_str(),
        automation = automation.as_str(),
        "identified device",
    );
    let response = IdentifyResponse {
        request_id,
        visitor_id,
        confidence,
        decision: outcome.decision.as_str(),
        is_new_device: outcome.is_new_device,
        collision_risk: outcome.collision_risk,
        signals: Signals {
            ua_tls_consistent: passive.tls_consistency.ua_tls_consistent(),
            ip_risk: passive.ip_risk.as_str(),
            client_integrity: integrity.as_str(),
            persona_coherence: persona.as_str(),
            new_device_velocity: outcome.new_device_velocity.as_str(),
            automation: automation.as_str(),
            template_jump: outcome.template_jump,
        },
    };
    store_and_respond(&state, &response)
}

/// Serialize an identify response, store it under its `request_id` for the
/// events API when that API is enabled, and return it.
fn store_and_respond(state: &AppState, response: &IdentifyResponse) -> Response {
    let body = match serde_json::to_vec(response) {
        Ok(body) => Bytes::from(body),
        Err(err) => {
            tracing::error!(error = %err, "failed to serialize identify response");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if state.api_key.is_some() {
        state.events.insert(
            response.request_id.clone(),
            response.visitor_id.clone(),
            body.clone(),
            Instant::now(),
        );
    }
    json_response(body)
}

/// `GET /events/{request_id}` — return the stored body of a past identify.
///
/// **Fail-closed** auth, like erasure:
/// - No `api_key` configured ⇒ the endpoint is disabled ⇒ `404 NOT_FOUND`.
/// - Missing or wrong `Authorization: Bearer` credential ⇒ `401 UNAUTHORIZED`
///   (constant-time compare, [`ct_eq`]).
/// - Unknown or expired `request_id` ⇒ `404 NOT_FOUND`.
/// - Otherwise `200` with the exact identify response body.
async fn get_event(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(api_key) = state.api_key.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !bearer_authorized(&headers, api_key) {
        tracing::debug!("rejected event fetch: missing or invalid api credential");
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.events.get(&request_id, Instant::now()) {
        Some(body) => json_response(body),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `DELETE /visitor/{visitor_id}` — erase a visitor from the fingerprint
/// library (GDPR right-to-be-forgotten, architecture §7).
///
/// **Fail-closed** auth:
/// - No `admin_key` configured ⇒ the endpoint is disabled ⇒ `404 NOT_FOUND`.
/// - `admin_key` configured but the request is missing the credential or presents
///   a wrong one ⇒ `401 UNAUTHORIZED` (constant-time compare, [`ct_eq`]).
/// - Authorized ⇒ erase the visitor's fingerprint record and every stored
///   identify event of that visitor (so `GET /events/{request_id}` no longer
///   returns it), then return `204 NO_CONTENT`.
///
/// Erasure is idempotent: `204` is returned even when the visitor did not exist,
/// so the response never leaks whether a given id was present. An erased id is
/// never minted again.
async fn erase_visitor(
    State(state): State<AppState>,
    Path(visitor_id): Path<String>,
    headers: HeaderMap,
) -> StatusCode {
    let Some(admin_key) = state.admin_key.as_deref() else {
        // Disabled when no key is provisioned: erasure is never open.
        return StatusCode::NOT_FOUND;
    };
    if !bearer_authorized(&headers, admin_key) {
        tracing::debug!("rejected erase: missing or invalid admin credential");
        return StatusCode::UNAUTHORIZED;
    }
    let matcher = Arc::clone(&state.matcher);
    let events = Arc::clone(&state.events);
    let erase = move || {
        (
            matcher.erase(&visitor_id),
            events.remove_visitor(&visitor_id),
        )
    };
    match tokio::task::spawn_blocking(erase).await {
        Ok((existed, events_removed)) => {
            tracing::info!(existed, events_removed, "erased visitor (RTBF)");
            StatusCode::NO_CONTENT
        }
        Err(err) => {
            tracing::error!(error = %err, "erase task failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// A `200` response carrying an already-serialized JSON body.
fn json_response(body: Bytes) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// Whether `headers` carry `key` as `Authorization: Bearer <key>`, compared in
/// constant time.
fn bearer_authorized(headers: &HeaderMap, key: &SecretKey) -> bool {
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    ct_eq(token.as_bytes(), key.as_bytes())
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

/// A random 128-bit request id as 32 lowercase hex characters.
fn new_request_id() -> String {
    let mut bytes = [0u8; 16];
    rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Current Unix time in milliseconds, saturating to `0` before the epoch — the
/// timestamp the matcher stamps onto observations.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Whether a client `ts` (Unix milliseconds) sits within `±skew_ms` of the
/// server's `now_ms` (architecture §4.1). Widened to `i128` so a future timestamp
/// or a pre-epoch clock cannot overflow or wrap the subtraction.
fn ts_in_window(client_ts: i64, now_ms: u64, skew_ms: u64) -> bool {
    (i128::from(now_ms) - i128::from(client_ts)).abs() <= i128::from(skew_ms)
}

/// JSON body extractor that normalizes every rejection to `400 Bad Request`
/// (`415 Unsupported Media Type` for a missing/non-JSON content type), instead
/// of axum's per-cause `400`/`413`/`422` split.
struct ApiJson<T>(T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(JsonRejection::MissingJsonContentType(_)) => {
                Err(StatusCode::UNSUPPORTED_MEDIA_TYPE)
            }
            Err(rejection) => {
                tracing::debug!(%rejection, "rejected request body");
                Err(StatusCode::BAD_REQUEST)
            }
        }
    }
}

/// `GET /challenge` response body (architecture §5).
#[derive(Debug, Serialize)]
struct ChallengeResponse {
    /// The one-time nonce the client must echo on `identify`.
    nonce: String,
    /// Nonce lifetime in seconds.
    expires_in: u64,
}

/// `POST /identify` request body.
///
/// Closed at every level: it and [`Components`], [`Botd`], and [`Integrity`]
/// accept only a JSON object and reject unknown fields, so a caller cannot
/// smuggle unmodeled fields into matching.
#[derive(Debug, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
struct IdentifyRequest {
    /// The nonce previously minted by `GET /challenge`.
    nonce: String,
    /// Client timestamp in Unix milliseconds (architecture §4.1/§5). Required; a
    /// value outside `±ts_skew_secs` of server time yields `401`.
    ts: i64,
    /// The collected components of the closed schema (no nonce mixed in).
    components: Components,
    /// The client-reported user agent: the JS/UA-claimed browser the passive
    /// TLS cross-check tests for forgery (signals §4.2) and the persona check
    /// reads. Deliberately taken from the client-reported body, not a trusted
    /// source; absent ⇒ both checks are neutral.
    #[serde(default)]
    user_agent: Option<String>,
    /// Client-side bot-detection verdict, surfaced as `signals.automation`.
    #[serde(default)]
    botd: Option<Botd>,
    /// Known-answer client integrity probe verdicts, sent **top-level** so they
    /// can never enter the matching input. Always surfaced as
    /// `signals.client_integrity`; fused into `confidence` only when
    /// `integrity_penalty_enabled`.
    #[serde(default)]
    integrity: Option<Integrity>,
}

fingerprintd::object_only_serde!(IdentifyRequest);

/// `POST /identify` success body (architecture §5), also served verbatim by
/// `GET /events/{request_id}`.
#[derive(Debug, Serialize)]
struct IdentifyResponse {
    /// Random 128-bit id of this identify call (32 lowercase hex chars).
    request_id: String,
    /// Device identifier.
    visitor_id: String,
    /// Fused match confidence in `[0.0, 1.0]` (fuzzy-matching §6). This is
    /// **decision confidence, not identity trust**: a first-ever `new_device`
    /// can report a high confidence (confidently unrecognized) while its identity
    /// is unestablished — key trust off `is_new_device` / `decision`, not this
    /// value alone.
    confidence: f64,
    /// Verdict from the weighted engine: `match`, `review`, or `new_device`
    /// (fuzzy-matching §5.4).
    decision: &'static str,
    /// Whether this device was newly recorded.
    is_new_device: bool,
    /// Set when a runner-up candidate also cleared the match threshold within
    /// the collision margin (fuzzy-matching §5.4).
    collision_risk: bool,
    /// Risk signals for downstream consumers (architecture §5).
    signals: Signals,
}

/// Risk signals surfaced to consumers (architecture §5). None of them moves the
/// `visitor_id`.
#[derive(Debug, Serialize)]
struct Signals {
    /// Whether the UA and TLS fingerprint agree.
    ua_tls_consistent: bool,
    /// Coarse IP risk band (`low` / `medium` / `high`).
    ip_risk: &'static str,
    /// Fused verdict of the client's known-answer integrity probes
    /// (`ok` / `noise` / `unavailable`): `noise` means the browser returned a
    /// wrong answer to a question an unmodified Chromium answers exactly — the
    /// footprint of a fingerprint-noising (anti-detect) browser. Lowers
    /// `confidence` only when `integrity_penalty_enabled`.
    client_integrity: &'static str,
    /// UA-claimed OS family vs the collected `fonts` set
    /// (`consistent` / `mismatch` / `unknown`): `mismatch` means a Windows or
    /// macOS UA whose font set has none of that OS's core fonts — a borrowed
    /// persona. Surfaced-only; never moves `confidence`.
    persona_coherence: &'static str,
    /// Cross-session new-device production-rate band for the client IP
    /// (`low` / `medium` / `high`), from the count of distinct visitors minted
    /// for that IP: catches the fresh-seed-per-launch farm no single request can.
    new_device_velocity: &'static str,
    /// Client-side bot-detection verdict (`detected` / `not_detected` /
    /// `unknown`). Surfaced-only.
    automation: &'static str,
    /// Whether a match was downgraded to `review` because the probe changed too
    /// many high-stability components of the matched template.
    template_jump: bool,
}

#[cfg(test)]
mod tests {
    use super::{build_router, with_limits};
    use crate::{config::Config, state::AppState};
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
        routing::get as get_route,
    };
    use fingerprintd::nonce::InMemoryNonceStore;
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

    /// POST `/identify` with a raw body and content type.
    async fn post_identify_raw(
        router: &Router,
        content_type: &str,
        body: &'static str,
    ) -> axum::response::Response {
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/identify")
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// The sorted key set of a JSON object.
    fn keys(value: &Value) -> Vec<&str> {
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys
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

    /// A fresh client timestamp (server-now, Unix milliseconds).
    fn now_ts() -> i64 {
        i64::try_from(super::now_ms()).unwrap()
    }

    /// GET `/challenge` and return its issued nonce.
    async fn fresh_nonce(router: &Router) -> String {
        let resp = get(router, "/challenge").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["expires_in"], json!(30));
        body["nonce"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn health_returns_200() {
        let resp = get(&test_router(), "/health").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn challenge_returns_exactly_nonce_and_expires_in() {
        let body = json_body(get(&test_router(), "/challenge").await).await;
        assert_eq!(keys(&body), ["expires_in", "nonce"]);
        assert!(body["nonce"].as_str().is_some_and(|n| !n.is_empty()));
        assert!(body["expires_in"].is_u64());
    }

    #[tokio::test]
    async fn happy_path_identifies_new_device() {
        let router = test_router();
        let nonce = fresh_nonce(&router).await;

        let resp = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": now_ts(), "components": {} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        assert!(body["visitor_id"].as_str().is_some());
        // A first-ever probe has no candidate: it is a new device with a
        // computed confidence in [0, 1].
        let confidence = body["confidence"].as_f64().unwrap();
        assert!((0.0..=1.0).contains(&confidence));
        assert_eq!(body["is_new_device"], json!(true));
        assert_eq!(body["decision"], json!("new_device"));
    }

    #[tokio::test]
    async fn identify_response_has_exactly_the_contract_keys() {
        let router = test_router();
        let nonce = fresh_nonce(&router).await;
        let resp = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": now_ts(), "components": probe_components() }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .keys()
                .all(|name| !name.as_str().starts_with("x-fp-")),
            "{:?}",
            resp.headers()
        );
        let body = json_body(resp).await;
        assert_eq!(
            keys(&body),
            [
                "collision_risk",
                "confidence",
                "decision",
                "is_new_device",
                "request_id",
                "signals",
                "visitor_id",
            ]
        );
        assert_eq!(
            keys(&body["signals"]),
            [
                "automation",
                "client_integrity",
                "ip_risk",
                "new_device_velocity",
                "persona_coherence",
                "template_jump",
                "ua_tls_consistent",
            ]
        );
        let request_id = body["request_id"].as_str().unwrap();
        assert_eq!(request_id.len(), 32);
        assert!(
            request_id
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
        assert_eq!(body["signals"]["automation"], json!("unknown"));
        assert_eq!(body["signals"]["template_jump"], json!(false));
        assert_eq!(body["signals"]["new_device_velocity"], json!("low"));
    }

    #[tokio::test]
    async fn request_ids_are_unique_per_call() {
        let router = test_router();
        let first = post_components(&router, probe_components()).await;
        let second = post_components(&router, probe_components()).await;
        assert_ne!(first["request_id"], second["request_id"]);
    }

    #[tokio::test]
    async fn botd_verdict_is_surfaced_as_automation() {
        let router = test_router();
        for (botd, expected) in [
            (
                json!({ "bot": true, "kind": "headless_chrome" }),
                "detected",
            ),
            (json!({ "bot": false }), "not_detected"),
        ] {
            let nonce = fresh_nonce(&router).await;
            let body = json_body(
                post_identify(
                    &router,
                    json!({ "nonce": nonce, "ts": now_ts(), "components": {}, "botd": botd }),
                )
                .await,
            )
            .await;
            assert_eq!(body["signals"]["automation"], json!(expected));
        }
    }

    #[tokio::test]
    async fn unknown_nonce_rejected() {
        let resp = post_identify(
            &test_router(),
            json!({ "nonce": "never-issued", "ts": now_ts(), "components": {} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn reused_nonce_rejected() {
        let router = test_router();
        let nonce = fresh_nonce(&router).await;
        let body = json!({ "nonce": nonce, "ts": now_ts(), "components": {} });

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
        let mut state = AppState::from_config(&Config::default());
        state.nonce_store = store;
        let router = build_router(state);

        let resp = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": now_ts(), "components": {} }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// A rich, realistic component probe the fuzzy engine can score.
    fn probe_components() -> Value {
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

    /// POST `/identify` for `components` under a fresh nonce, returning the body.
    async fn post_components(router: &Router, components: Value) -> Value {
        post_components_with_ua(router, components, None).await
    }

    /// POST `/identify` for `components` and an optional claimed `user_agent`
    /// under a fresh nonce, returning the body.
    async fn post_components_with_ua(
        router: &Router,
        components: Value,
        user_agent: Option<&str>,
    ) -> Value {
        let nonce = fresh_nonce(router).await;
        let mut body = json!({ "nonce": nonce, "ts": now_ts(), "components": components });
        if let Some(ua) = user_agent {
            body["user_agent"] = json!(ua);
        }
        json_body(post_identify(router, body).await).await
    }

    #[tokio::test]
    async fn fuzzy_match_across_requests() {
        let router = test_router();

        // Same rich components, two fresh nonces -> same visitor, second matched.
        let first = post_components(&router, probe_components()).await;
        let second = post_components(&router, probe_components()).await;

        assert_eq!(first["visitor_id"], second["visitor_id"]);
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
            "canvas": "f00d",
        });
        let third = post_components(&router, other).await;
        assert_ne!(third["visitor_id"], first["visitor_id"]);
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
            "ts": now_ts(),
            "components": {},
            "user_agent": CHROME_UA,
        });
        json_body(post_identify_headers(&router, body, headers).await).await
    }

    /// Read the `confidence` field as an `f64`.
    fn confidence(body: &Value) -> f64 {
        body["confidence"].as_f64().unwrap()
    }

    // --- Client integrity probes ---

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
            "ts": now_ts(),
            "components": {},
            "user_agent": CHROME_UA,
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

    // --- Persona coherence + the claimed UA ---

    /// A Windows-persona component set with the given `fonts`.
    fn windows_components(fonts: &Value) -> Value {
        json!({ "platform": "Win32", "fonts": fonts })
    }

    #[tokio::test]
    async fn persona_mismatch_is_surfaced_without_moving_confidence() {
        let mismatch = post_components_with_ua(
            &test_router(),
            windows_components(&json!(["Arial"])),
            Some(CHROME_UA),
        )
        .await;
        assert_eq!(mismatch["signals"]["persona_coherence"], json!("mismatch"));
        let consistent = post_components_with_ua(
            &test_router(),
            windows_components(&json!(["Calibri"])),
            Some(CHROME_UA),
        )
        .await;
        assert_eq!(
            consistent["signals"]["persona_coherence"],
            json!("consistent")
        );
        assert!((confidence(&mismatch) - confidence(&consistent)).abs() < 1e-12);
        // No fonts component / no UA → unknown.
        let no_fonts = post_components_with_ua(
            &test_router(),
            json!({ "platform": "Win32" }),
            Some(CHROME_UA),
        )
        .await;
        assert_eq!(no_fonts["signals"]["persona_coherence"], json!("unknown"));
        let no_ua = post_components(&test_router(), windows_components(&json!(["Arial"]))).await;
        assert_eq!(no_ua["signals"]["persona_coherence"], json!("unknown"));
    }

    #[tokio::test]
    async fn top_level_user_agent_is_the_claimed_ua_for_the_ua_tls_check() {
        let router = router_with_trust(true);
        let nonce = fresh_nonce(&router).await;
        let body = json!({
            "nonce": nonce,
            "ts": now_ts(),
            "components": windows_components(&json!(["Calibri"])),
            "user_agent": CHROME_UA,
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
        // Probes that report nothing usable are neutral too.
        let silent = identify_integrity(
            true,
            Some(json!({ "canvas": "unavailable", "webgl": "unavailable" })),
        )
        .await;
        assert_eq!(silent["signals"]["client_integrity"], json!("unavailable"));
        assert!((confidence(&silent) - confidence(&body)).abs() < 1e-12);
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

    // --- Request timestamp window (architecture §4.1) ---

    #[tokio::test]
    async fn ts_window_accepts_fresh_rejects_stale_future_and_missing() {
        let router = test_router();
        let now = now_ts();

        // Fresh: server-now is within the skew → accepted.
        let nonce = fresh_nonce(&router).await;
        let fresh = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": now, "components": {} }),
        )
        .await;
        assert_eq!(fresh.status(), StatusCode::OK);

        // Stale: far in the past (beyond the 30s skew) → rejected.
        let nonce = fresh_nonce(&router).await;
        let stale = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": now - 60_000, "components": {} }),
        )
        .await;
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

        // Future: far ahead → rejected (skew is symmetric).
        let nonce = fresh_nonce(&router).await;
        let future = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": now + 60_000, "components": {} }),
        )
        .await;
        assert_eq!(future.status(), StatusCode::UNAUTHORIZED);

        // Missing `ts` → the body fails to deserialize: 400.
        let nonce = fresh_nonce(&router).await;
        let missing = post_identify(&router, json!({ "nonce": nonce, "components": {} })).await;
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn ts_in_window_is_symmetric_around_now() {
        // Exactly at the edge (±skew) is inside; one past it is outside.
        assert!(super::ts_in_window(1_000, 1_500, 500));
        assert!(super::ts_in_window(2_000, 1_500, 500));
        assert!(!super::ts_in_window(999, 1_500, 500));
        assert!(!super::ts_in_window(2_001, 1_500, 500));
    }

    // --- Closed request schema ---

    /// POST `/identify` with a fresh nonce and `extra` merged into a valid body.
    async fn post_with(router: &Router, extra: Value) -> axum::response::Response {
        let nonce = fresh_nonce(router).await;
        let mut body = json!({ "nonce": nonce, "ts": now_ts(), "components": {} });
        for (key, value) in extra.as_object().unwrap() {
            body[key] = value.clone();
        }
        post_identify(router, body).await
    }

    #[tokio::test]
    async fn identify_rejects_unknown_keys_and_wrong_types_with_400() {
        let router = test_router();
        for extra in [
            json!({ "challenge_response": {} }),
            json!({ "botd": { "bot": true, "score": 1 } }),
            json!({ "botd": { "kind": "headless_chrome" } }),
            json!({ "integrity": { "canvas": "ok", "fonts": "ok" } }),
            json!({ "integrity": { "canvas": 1 } }),
            json!({ "integrity": { "canvas": "weird" } }),
            json!({ "ts": "now" }),
            json!({ "nonce": 7 }),
            json!({ "user_agent": 1 }),
            json!({ "components": "webgl" }),
            json!({ "components": [] }),
            json!({ "botd": [] }),
            json!({ "botd": [true] }),
            json!({ "integrity": [] }),
        ] {
            let resp = post_with(&router, extra.clone()).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{extra}");
        }
    }

    #[tokio::test]
    async fn identify_rejects_malformed_json_with_400_and_non_json_with_415() {
        let router = test_router();
        let malformed = post_identify_raw(&router, "application/json", "{\"nonce\":").await;
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        let array_body = post_identify_raw(&router, "application/json", r#"["n", 0, {}]"#).await;
        assert_eq!(array_body.status(), StatusCode::BAD_REQUEST);
        let not_json = post_identify_raw(&router, "text/plain", "{}").await;
        assert_eq!(not_json.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn identify_rejects_unknown_or_mistyped_component_key() {
        let router = test_router();
        for components in [
            json!({ "webgl": "x", "anything": 1 }),
            json!({ "user_agent": "Chrome/120" }),
            json!({ "touch_support": { "maxTouchPoints": 5 } }),
        ] {
            let nonce = fresh_nonce(&router).await;
            let rejected = post_identify(
                &router,
                json!({ "nonce": nonce, "ts": now_ts(), "components": components }),
            )
            .await;
            assert_eq!(rejected.status(), StatusCode::BAD_REQUEST, "{components}");
        }

        // A schema-only component set is accepted.
        let nonce = fresh_nonce(&router).await;
        let ok = post_identify(
            &router,
            json!({ "nonce": nonce, "ts": now_ts(), "components": { "webgl": "x", "cpu_cores": 8 } }),
        )
        .await;
        assert_eq!(ok.status(), StatusCode::OK);
    }

    // --- GDPR erasure endpoint ---

    /// Admin credential used by the erasure-enabled test router.
    const ADMIN_KEY: &str = "test-admin-key";

    /// Build a router with the erasure endpoint enabled.
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
        let first = post_components(&router, probe_components()).await;
        let visitor = first["visitor_id"].as_str().unwrap().to_string();
        assert_eq!(first["is_new_device"], json!(true));
        let second = post_components(&router, probe_components()).await;
        assert_eq!(second["is_new_device"], json!(false));

        // Authorized erasure returns 204.
        let resp = delete_visitor(&router, &visitor, Some(ADMIN_KEY)).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Record + blocking entries are gone → the device re-identifies as new,
        // under a different id: an erased id is never resurrected.
        let after = post_components(&router, probe_components()).await;
        assert_eq!(after["is_new_device"], json!(true));
        assert_ne!(after["visitor_id"], json!(visitor));

        // Idempotent: erasing again (absent now) still returns 204, no leak.
        let again = delete_visitor(&router, &visitor, Some(ADMIN_KEY)).await;
        assert_eq!(again.status(), StatusCode::NO_CONTENT);
    }

    // --- Events API ---

    /// Credential used by the events-enabled test router.
    const API_KEY: &str = "test-api-key";

    /// Build a router with the events API enabled and the given event TTL/cap.
    fn router_with_events(event_ttl_secs: u64, event_max: usize) -> Router {
        build_router(AppState::from_config(&Config {
            api_key: Some(API_KEY.into()),
            event_ttl_secs,
            event_max,
            ..Config::default()
        }))
    }

    /// GET `/events/{id}`, optionally with a bearer credential.
    async fn get_event(
        router: &Router,
        id: &str,
        bearer: Option<&str>,
    ) -> axum::response::Response {
        let mut builder = Request::builder().uri(format!("/events/{id}"));
        if let Some(token) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        router
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// Identify `probe_components()` and return `(request_id, raw body bytes)`.
    async fn identify_raw(router: &Router) -> (String, Vec<u8>) {
        let nonce = fresh_nonce(router).await;
        let resp = post_identify(
            router,
            json!({ "nonce": nonce, "ts": now_ts(), "components": probe_components() }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        (
            body["request_id"].as_str().unwrap().to_string(),
            bytes.to_vec(),
        )
    }

    #[tokio::test]
    async fn identify_stores_no_events_without_api_key() {
        let state = AppState::from_config(&Config::default());
        let router = build_router(state.clone());
        identify_raw(&router).await;
        assert_eq!(state.events.len(), 0);
    }

    #[tokio::test]
    async fn erase_removes_the_visitors_stored_events() {
        let router = build_router(AppState::from_config(&Config {
            api_key: Some(API_KEY.into()),
            admin_key: Some(ADMIN_KEY.into()),
            ..Config::default()
        }));
        let (erased_request, erased_body) = identify_raw(&router).await;
        let erased: Value = serde_json::from_slice(&erased_body).unwrap();
        let other = post_components(
            &router,
            json!({
                "webgl": "Apple GPU",
                "platform": "MacIntel",
                "timezone": "Europe/Berlin",
                "audio": "35.73",
                "cpu_cores": 10,
                "device_memory": 16,
                "fonts": ["Menlo", "Monaco", "Futura", "Optima", "Gill Sans"],
                "canvas": "deadbeef",
            }),
        )
        .await;
        assert_ne!(other["visitor_id"], erased["visitor_id"]);
        let other_request = other["request_id"].as_str().unwrap();

        let visitor = erased["visitor_id"].as_str().unwrap();
        let resp = delete_visitor(&router, visitor, Some(ADMIN_KEY)).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        assert_eq!(
            get_event(&router, &erased_request, Some(API_KEY))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get_event(&router, other_request, Some(API_KEY))
                .await
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn events_disabled_without_api_key() {
        let router = test_router();
        let (request_id, _) = identify_raw(&router).await;
        for bearer in [None, Some("anything")] {
            assert_eq!(
                get_event(&router, &request_id, bearer).await.status(),
                StatusCode::NOT_FOUND
            );
        }
        // An empty configured key also leaves the endpoint disabled.
        let empty = build_router(AppState::from_config(&Config {
            api_key: Some("".into()),
            ..Config::default()
        }));
        assert_eq!(
            get_event(&empty, "x", Some("")).await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn events_reject_missing_or_wrong_api_key() {
        let router = router_with_events(3600, 100);
        let (request_id, _) = identify_raw(&router).await;
        assert_eq!(
            get_event(&router, &request_id, None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get_event(&router, &request_id, Some("wrong-key"))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        // The admin credential is not an events credential.
        assert_eq!(
            get_event(&router, &request_id, Some(ADMIN_KEY))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn events_return_the_exact_identify_body() {
        let router = router_with_events(3600, 100);
        let (request_id, identify_body) = identify_raw(&router).await;
        let resp = get_event(&router, &request_id, Some(API_KEY)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/json");
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(bytes.to_vec(), identify_body);
    }

    #[tokio::test]
    async fn events_unknown_or_expired_id_is_404() {
        let router = router_with_events(3600, 100);
        assert_eq!(
            get_event(&router, "0123456789abcdef0123456789abcdef", Some(API_KEY))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        // A zero TTL expires every event as soon as it is stored.
        let expiring = router_with_events(0, 100);
        let (request_id, _) = identify_raw(&expiring).await;
        assert_eq!(
            get_event(&expiring, &request_id, Some(API_KEY))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn events_cap_evicts_the_oldest_event() {
        let router = router_with_events(3600, 2);
        let (oldest, _) = identify_raw(&router).await;
        let (middle, _) = identify_raw(&router).await;
        let (newest, _) = identify_raw(&router).await;
        assert_eq!(
            get_event(&router, &oldest, Some(API_KEY)).await.status(),
            StatusCode::NOT_FOUND
        );
        for id in [&middle, &newest] {
            assert_eq!(
                get_event(&router, id, Some(API_KEY)).await.status(),
                StatusCode::OK
            );
        }
    }

    // --- Load limits ---

    #[tokio::test]
    async fn slow_request_times_out_with_408() {
        let router = with_limits(
            Router::new().route(
                "/slow",
                get_route(|| async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    StatusCode::OK
                }),
            ),
            Duration::from_millis(20),
            4,
        );
        assert_eq!(
            get(&router, "/slow").await.status(),
            StatusCode::REQUEST_TIMEOUT
        );
    }

    #[tokio::test]
    async fn concurrency_limit_is_shared_across_routes() {
        // One slot shared by every route: a request to `/fast` waits until the
        // `/hold` request releases it (when its 200ms deadline fires).
        let router = with_limits(
            Router::new()
                .route(
                    "/hold",
                    get_route(|| async {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        StatusCode::OK
                    }),
                )
                .route("/fast", get_route(|| async { StatusCode::OK })),
            Duration::from_millis(200),
            1,
        );
        let holder = tokio::spawn({
            let router = router.clone();
            async move { get(&router, "/hold").await.status() }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let started = std::time::Instant::now();
        assert_eq!(get(&router, "/fast").await.status(), StatusCode::OK);
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert_eq!(holder.await.unwrap(), StatusCode::REQUEST_TIMEOUT);
    }
}
