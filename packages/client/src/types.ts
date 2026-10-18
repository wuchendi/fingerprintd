/**
 * Wire types for the fingerprintd HTTP surface. Keep in sync with the server
 * structs in `crates/fingerprintd/src/lib.rs`. Every field is snake_case; the
 * server rejects unknown keys at every level of the identify request.
 */

import type { Integrity } from './integrity'
import type { Components } from './schema'

/** `GET /challenge` response body. */
export interface ChallengeResponse {
  /** The one-time nonce the client must echo on `identify`. */
  nonce: string
  /** Nonce lifetime in seconds. */
  expires_in: number
}

/** Client-side BotD verdict. */
export interface Botd {
  /** Whether BotD flagged the browser as automated. */
  bot: boolean
  /** The detected automation kind (e.g. `headless_chrome`), when known. */
  kind?: string
}

/** `POST /identify` request body. */
export interface IdentifyRequest {
  /** The nonce previously minted by `GET /challenge`. */
  nonce: string
  /** Client timestamp in Unix milliseconds. */
  ts: number
  /** Matching input, restricted to the closed component schema. */
  components: Components
  /** `navigator.userAgent`. */
  user_agent?: string
  /** Client-side BotD verdict. */
  botd?: Botd
  /** Known-answer integrity probe verdicts — a risk signal, never matching
   *  input. */
  integrity?: Integrity
}

/** Risk signals the server surfaces alongside the identity. */
export interface Signals {
  /** Whether the UA and edge-observed TLS fingerprint agree. */
  ua_tls_consistent: boolean
  /** Coarse IP risk band. */
  ip_risk: 'low' | 'medium' | 'high'
  /** Fused verdict of the client's known-answer integrity probes. */
  client_integrity: 'ok' | 'noise' | 'unavailable'
  /** UA-claimed OS family vs the collected font set. */
  persona_coherence: 'consistent' | 'mismatch' | 'unknown'
  /** New-device production-rate band for the client IP. */
  new_device_velocity: 'low' | 'medium' | 'high'
  /** Automation verdict. */
  automation: 'detected' | 'not_detected' | 'unknown'
  /** Whether a match was downgraded to `review` because too many
   *  high-stability components of the matched template changed. */
  template_jump: boolean
}

/** `POST /identify` success body. Display-only in the browser: the
 *  authoritative result is `GET /events/{request_id}`, fetched server-side. */
export interface IdentifyResponse {
  /** Id of this identify event, for the server-side `GET /events/{request_id}`. */
  request_id: string
  /** Stable device identifier. */
  visitor_id: string
  /** Fused match confidence in `[0.0, 1.0]`. This is decision confidence, not
   *  identity trust: a first-ever device can carry high `confidence` yet is
   *  unestablished — key trust off `is_new_device` / `decision`. */
  confidence: number
  /** Verdict from the weighted engine. */
  decision: 'match' | 'review' | 'new_device'
  /** Whether this device was newly recorded. */
  is_new_device: boolean
  /** Set when a runner-up candidate also cleared the match threshold. */
  collision_risk: boolean
  /** Risk signals. */
  signals: Signals
}
