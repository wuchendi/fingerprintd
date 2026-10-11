/**
 * Wire types for the fingerprintd HTTP surface, as served by this edge Worker.
 *
 * These MUST stay byte-compatible with the shipped Axum server
 * (`crates/fingerprintd/src/lib.rs`) and the browser SDK
 * (`packages/client/src/types.ts`) so a client works against EITHER deployment. The
 * server renames `visitor_id` -> `visitorId` via serde; keep that here too.
 */

/** Advertised nonce-probe transform. Present in `GET /challenge` only when
 *  the Worker has a probe key configured; omitted otherwise. The client computes
 *  `encoding(alg(shared_key, input))` — `hex(HMAC-SHA256(key, nonce))` — and
 *  echoes it as {@link IdentifyRequest.probe}. The shared key is never advertised. */
export interface ProbeDescriptor {
  /** Keyed-hash algorithm, e.g. `HMAC-SHA256`. */
  alg: string
  /** Transform input identifier — currently the string `nonce`. */
  input: string
  /** Output encoding of the computed tag, e.g. `hex`. */
  encoding: string
}

/** Active challenge descriptor (canvas/audio seeded with the nonce). */
export interface ChallengeProbe {
  /** Nonce used to seed the rendered challenge (equals the top-level nonce). */
  seed: string
  /** Probe targets to render, e.g. `['canvas', 'audio']`. */
  targets: string[]
  /** Nonce-probe transform to compute; present only under probe enforcement. */
  verify?: ProbeDescriptor
}

/** Client-side collection plan carried in a challenge response. */
export interface Collect {
  /** Stable probe identifiers to gather (e.g. userAgent, timezone). */
  stable: string[]
  /** Nonce-seeded active challenge. */
  challenge: ChallengeProbe
}

/** `GET /challenge` response body (architecture §5). */
export interface ChallengeResponse {
  /** The one-time nonce the client must echo on `identify`. */
  nonce: string
  /** Nonce lifetime in seconds. */
  expires_in: number
  /** Client-side collection plan. */
  collect: Collect
}

/**
 * `POST /identify` request body.
 *
 * Only `nonce` and `stable_components` are always meaningful. The Worker reads
 * `probe` and `ts` only when the matching enforcement is configured;
 * otherwise they are ignored. The request schema is strict: any unknown
 * top-level field is REJECTED with `400` — there is no forward-compat
 * `challenge_response` tolerance.
 */
export interface IdentifyRequest {
  /** The nonce previously minted by `GET /challenge`. */
  nonce: string
  /** Client timestamp in Unix milliseconds. Checked only when the Worker's
   *  timestamp window is enforced; a missing/out-of-window value then yields 401. */
  ts?: number
  /** Nonce-probe response `hex(HMAC-SHA256(shared_key, nonce))`. Verified
   *  only when the Worker has a probe key; a missing/wrong value then yields 401. */
  probe?: string
  /** Raw stable components (no nonce mixed in). Arbitrary JSON — the engine
   *  scores these but never derives an id from the client's copy. */
  stable_components: Record<string, unknown>
  /** Known-answer client integrity probe verdicts (`canvas` / `webgl` / `audio`
   *  / `rect`, each `ok` | `noise` | `unavailable`), top-level by design so they
   *  never enter the matching input. Optional; absent ⇒ neutral. */
  integrity?: Record<string, unknown>
}

/** Passive network-signal risk summary (architecture §5). */
export interface Signals {
  /** Whether the UA and edge-observed TLS fingerprint agree. */
  ua_tls_consistent: boolean
  /** Coarse IP risk band, e.g. `low` / `high`. */
  ip_risk: string
  /** Fused client-integrity verdict (`ok` / `noise` / `unavailable`) from the
   *  request's top-level `integrity` probes via the shared WASM
   *  `client_integrity` export — `noise` is the footprint of a
   *  fingerprint-noising browser. Surfaced always; moves confidence only when
   *  `FP_INTEGRITY_PENALTY_ENABLED`. Optional for the same assess pass-through
   *  reason as the velocity bands. */
  client_integrity?: string
  /** UA-claimed OS family vs the collected `fonts` set (`consistent` /
   *  `mismatch` / `unknown`) via the shared WASM `persona_coherence_label`
   *  export — `mismatch` is a borrowed persona (Windows UA, no Windows core
   *  fonts). Surfaced-only; never moves confidence. Optional for the assess
   *  pass-through. */
  persona_coherence?: string
  /** Cross-session new-device production-rate band for the client IP
   *  (`low` / `medium` / `high`). The `/identify` response always populates it;
   *  the edge is stateless and scores one request at a time with no cross-session
   *  velocity store, so it always reports the neutral `'low'` — the native server
   *  computes the real band. This mirrors how the edge treats an empty u_i/m_i
   *  store as neutral. Optional so the check-in `assess` pass-through — which does
   *  not consume it — can carry an identify body that omits it. */
  new_device_velocity?: string
  /** Secondary cross-session new-device band keyed on the coarse JA4 shape
   *  **class** (`low` / `medium` / `high`), mirroring the native
   *  `new_device_velocity_ja4`. Surfaced additively alongside
   *  {@link Signals.new_device_velocity}; computed edge-side from the same
   *  Durable Object on a `new_device` verdict when a trusted JA4 is present,
   *  else the neutral `'low'`. Surface-only — it never moves confidence. Optional
   *  for the same pass-through reason as {@link Signals.new_device_velocity}. */
  new_device_velocity_ja4?: string
}

/**
 * Passive-signal verdict returned by the shared WASM `passive_signals` export
 * (`fingerprintd_core::signals`). The host maps the boolean + band into {@link Signals} and
 * fuses `confidence_adjustment` into `/identify` confidence — never the visitorId.
 */
export interface PassiveVerdict {
  /** Whether the UA claim and the edge-observed TLS stack agree (false ⇒ forgery). */
  ua_tls_consistent: boolean
  /** Coarse IP risk band, `low` / `medium` / `high`. */
  ip_risk: string
  /** Signed confidence delta: positive boost, negative downgrade, `0` degraded. */
  confidence_adjustment: number
}

/**
 * Reply of the shared WASM `client_integrity` export
 * (`fingerprintd_core::signals::ClientIntegrity`): the fused verdict plus the confidence
 * delta (`0` unless the penalty is enabled and the verdict is `noise`).
 */
export interface IntegrityVerdict {
  client_integrity: string
  confidence_adjustment: number
}

/** `POST /identify` success body (architecture §5). */
export interface IdentifyResponse {
  /** Stable device identifier (server-computed; serde-renamed from visitor_id). */
  visitorId: string
  /** Fused match confidence in `[0.0, 1.0]`. This is DECISION confidence, not
   *  identity trust: a first-ever new device can carry a HIGH confidence yet
   *  is entirely unestablished. Consumers must key trust off `is_new_device` /
   *  `decision`, never off `confidence` alone. */
  confidence: number
  /** Whether this device was newly recorded. */
  is_new_device: boolean
  /** Verdict from the weighted engine. */
  decision: 'match' | 'review' | 'new_device'
  /** Set when a runner-up candidate also cleared the match threshold. */
  collision_risk: boolean
  /** Passive network-signal risk summary. */
  signals: Signals
}

/**
 * The raw verdict returned by the WASM engine's `score` (snake_case, from
 * `fingerprintd_core::fuzzy::MatchOutcome`). The host maps it into {@link IdentifyResponse},
 * dropping the diagnostic-only `score` / `compared_components` fields and adding
 * the host-owned `signals`.
 */
export interface ScoreOutcome {
  visitor_id: string
  is_new_device: boolean
  decision: 'match' | 'review' | 'new_device'
  confidence: number
  score: number | null
  compared_components: number
  collision_risk: boolean
}

/**
 * `POST /checkin/assess` request body.
 *
 * `accountId` is the core new dimension: the business identity the caller wants
 * scored for check-in farming. `identify` is the fingerprintd verdict the caller
 * already obtained and passes through. IP and timestamp are observed edge-side
 * (never client-reported), so they are deliberately NOT fields here.
 */
export interface AssessRequest {
  /** Business identity being assessed — the core new dimension. */
  accountId: string
  /** Scenario tag selecting a threshold profile. MVP: this value only. */
  action: 'daily_checkin'
  /** fingerprintd identify verdict, obtained and passed through by the caller. */
  identify: IdentifyResponse
}

/** A single reason contributing to an {@link AssessResponse} decision. */
export interface AssessReason {
  /** Stable machine code for the reason, e.g. `NEW_DEVICE`. */
  code: string
  /** Human-readable explanation for logs/debugging. */
  detail: string
}

/** `POST /checkin/assess` success body. */
export interface AssessResponse {
  /** Gate action the caller should take. */
  decision: 'allow' | 'challenge' | 'deny'
  /** Interpreted risk label. */
  verdict: 'human' | 'suspicious' | 'farming'
  /** Continuous risk score in `[0.0, 1.0]`. */
  risk: number
  /** Ordered reasons that produced the decision. */
  reasons: AssessReason[]
  /** The device identifier carried through from {@link IdentifyResponse}. */
  visitorId: string
}
