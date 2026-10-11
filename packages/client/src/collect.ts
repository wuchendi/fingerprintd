/**
 * Collection contract. A `Collector` turns a challenge into the client-observed
 * evidence the server will judge. Concrete collectors plug in here
 * (canvas/audio/webgl, stable components, nonce-probe computation); this module
 * ships only the interface plus a trivial stub.
 *
 * DESIGN: the client only COLLECTS — it never derives a visitorId or hash and
 * never mixes the nonce into the stable components. `stable_components` and the
 * `probe` stay SEPARATE: the latter is a freshness proof, never a matching
 * signal.
 *
 * ENVIRONMENT LIMIT: there is no headless browser in this environment, so real
 * canvas/audio/webgl collection cannot be exercised. The stub below returns
 * empty evidence; real collectors are validated by a human in a real browser.
 */

import type { Integrity } from './integrity'
import type { ChallengeResponse } from './types'

/** The evidence a collector produces from a challenge. */
export interface Collected {
  /** Raw stable components (no nonce mixed in) — the server's matching input. */
  stable_components: Record<string, unknown>
  /** Optional nonce-probe response `hex(HMAC-SHA256(key, nonce))`, computed
   *  when the challenge advertises `collect.challenge.verify` and the client
   *  holds the probe key. */
  probe?: string
  /** Optional client timestamp in Unix milliseconds. Stamped at collection
   *  and echoed on `/identify`; the server checks it only when its timestamp
   *  window is enforced. */
  ts?: number
  /** Optional known-answer integrity verdicts (`integrity.ts`). A risk signal
   *  the server surfaces — kept OUT of `stable_components` so it never enters
   *  the `visitorId` match. */
  integrity?: Integrity
}

/** Turns a challenge into collected evidence. Async because real collectors do
 *  async work (canvas readback, WebCrypto, WASM). */
export type Collector = (challenge: ChallengeResponse) => Promise<Collected>

/**
 * Trivial placeholder collector. Emits only the echoed challenge targets as a
 * marker so the flow is exercisable end-to-end in tests; it gathers NO real
 * fingerprint. Replace with a real collector before production.
 */
export const stubCollector: Collector = (challenge) =>
  Promise.resolve({
    stable_components: {
      // Not a fingerprint — a placeholder marking which targets a real collector
      // would render for this challenge.
      _stub: true,
      collected_targets: challenge.collect.challenge.targets,
    },
  })
