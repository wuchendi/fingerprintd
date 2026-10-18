/**
 * Wire types for the fingerprintd HTTP surface (Contract v1), as served by this
 * edge Worker, plus the WASM engine's reply shapes.
 *
 * The HTTP shapes are the same snake_case JSON the native Axum server
 * (`crates/fingerprintd/src/lib.rs`) serves, so a client works against either
 * deployment.
 */

/** A device verdict from the weighted engine (fuzzy-matching §5.4). */
export type Decision = 'match' | 'review' | 'new_device'

/** A coarse three-level band (IP risk, new-device velocity). */
export type Band = 'low' | 'medium' | 'high'

/** One client-side known-answer integrity probe verdict. */
export type IntegrityLabel = 'ok' | 'noise' | 'unavailable'

/** `GET /challenge` response body (architecture §5). */
export interface ChallengeResponse {
  /** The one-time nonce the client must echo on `identify`. */
  nonce: string
  /** Nonce lifetime in seconds. */
  expires_in: number
}

/** Client-side bot-detection verdict carried on `identify`. */
export interface Botd {
  bot: boolean
  kind?: string | null
}

/** Known-answer client integrity probe verdicts, top-level on `identify` so
 *  they never enter the matching input. */
export interface Integrity {
  canvas?: IntegrityLabel
  webgl?: IntegrityLabel
  audio?: IntegrityLabel
  rect?: IntegrityLabel
}

/**
 * `POST /identify` request body. Closed at every level: an unknown key here or
 * inside `components` / `botd` / `integrity`, or a wrongly-typed value, is a
 * `400`.
 */
export interface IdentifyRequest {
  /** The nonce previously minted by `GET /challenge`. */
  nonce: string
  /** Client timestamp in Unix milliseconds; outside `±FP_TS_SKEW_SECS` ⇒ 401. */
  ts: number
  /** The collected components of the closed schema (validated by the engine). */
  components: Record<string, unknown>
  /** The client-reported user agent the UA↔TLS and persona checks read. */
  user_agent?: string
  /** Client-side bot-detection verdict, surfaced as `signals.automation`. */
  botd?: Botd
  /** Client integrity probe verdicts, surfaced as `signals.client_integrity`. */
  integrity?: Integrity
}

/** Risk signals surfaced on `identify` (architecture §5). None of them moves
 *  the `visitor_id`. */
export interface Signals {
  /** Whether the claimed UA and the edge-observed TLS stack agree. */
  ua_tls_consistent: boolean
  /** Coarse IP risk band. */
  ip_risk: Band
  /** Fused verdict of the client's integrity probes; `noise` is the footprint
   *  of a fingerprint-noising browser. Moves confidence only when
   *  `FP_INTEGRITY_PENALTY_ENABLED`. */
  client_integrity: IntegrityLabel
  /** UA-claimed OS family vs the collected `fonts`. Surfaced-only. */
  persona_coherence: 'consistent' | 'mismatch' | 'unknown'
  /** Distinct new devices minted for the client IP in the trailing window,
   *  banded. A `medium`/`high` band lowers a new device's confidence. */
  new_device_velocity: Band
  /** Client-side bot-detection verdict. Surfaced-only. */
  automation: 'detected' | 'not_detected' | 'unknown'
  /** Whether a match was downgraded to `review` because too many
   *  high-stability components changed. */
  template_jump: boolean
}

/** `POST /identify` success body (architecture §5). */
export interface IdentifyResponse {
  /** Random 128-bit id of this identify call (32 lowercase hex chars). */
  request_id: string
  /** Device identifier: the matched/suspected visitor, or a freshly minted one. */
  visitor_id: string
  /** Fused match confidence in `[0, 1]`. This is DECISION confidence, not
   *  identity trust: a first-ever new device can carry a high confidence yet is
   *  unestablished. Key trust off `is_new_device` / `decision`. */
  confidence: number
  /** Verdict from the weighted engine. */
  decision: Decision
  /** Whether this device was newly recorded. */
  is_new_device: boolean
  /** Set when a runner-up candidate also cleared the match threshold. */
  collision_risk: boolean
  /** Risk signals for downstream consumers. */
  signals: Signals
}

/**
 * The salted stored form of a device (`fingerprintd::fuzzy::StoredComponents`):
 * an object keyed by component name holding only salted hashes / numerics.
 * Opaque to the host — it is persisted and handed back to the engine verbatim.
 */
export type StoredComponents = Record<string, unknown>

/** Reply of the WASM `passive_signals` export (`fingerprintd::signals`). */
export interface PassiveVerdict {
  /** Whether the UA claim and the edge-observed TLS stack agree. */
  ua_tls_consistent: boolean
  /** Coarse IP risk band. */
  ip_risk: Band
  /** Signed confidence delta: positive boost, negative downgrade, `0` degraded. */
  confidence_adjustment: number
}

/** Reply of the WASM `client_integrity` export: the fused verdict plus its
 *  confidence delta (`0` unless the penalty is enabled and the verdict is
 *  `noise`). */
export interface IntegrityVerdict {
  client_integrity: IntegrityLabel
  confidence_adjustment: number
}

/**
 * Reply of the WASM engine's `score`: the verdict plus what the host persists.
 *   - `match`      — `visitor_id` is the matched candidate; `template` is its
 *                    stored template drifted toward this observation.
 *   - `new_device` — `visitor_id` is `null` (the host mints one); `template` is
 *                    `probe_stored`.
 *   - `review`     — `visitor_id` is the suspected candidate; `template` is
 *                    `null` and nothing is persisted.
 * `template_blocking_keys` are the keys to index `template` under (`null` with
 * it).
 */
export interface ScoreOutcome {
  decision: Decision
  visitor_id: string | null
  is_new_device: boolean
  confidence: number
  score: number | null
  compared_components: number
  collision_risk: boolean
  template_jump: boolean
  probe_stored: StoredComponents
  template: StoredComponents | null
  template_blocking_keys: string[] | null
}
