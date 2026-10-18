/**
 * Collection contract. A `Collector` gathers the client-observed evidence the
 * server judges. Collection is nonce-free: the nonce is fetched and echoed by
 * `run()`, never mixed into the evidence.
 *
 * DESIGN: the client only COLLECTS — it never derives a visitor id or hash.
 * `components` is the matching input; `user_agent`, `botd` and `integrity` are
 * separate top-level request fields the server reads as signals.
 */

import type { Integrity } from './integrity'
import type { Components } from './schema'
import type { Botd } from './types'

/** The evidence a collector produces. */
export interface Collected {
  /** Closed-schema components — the server's matching input. */
  components: Components
  /** `navigator.userAgent`. */
  user_agent?: string
  /** Client-side BotD verdict. */
  botd?: Botd
  /** Known-answer integrity verdicts (`integrity.ts`), kept outside
   *  `components` so they never enter the match. */
  integrity?: Integrity
}

/** Gathers evidence. Async because real collectors do async work (canvas
 *  readback, audio rendering, module loading). */
export type Collector = () => Promise<Collected>
