/**
 * The STABLE half of a real {@link Collector}: FingerprintJS (OSS) components,
 * the BotD verdict and the user agent. This is the "who is this device"
 * evidence the SERVER matches on — it is NOT a verdict.
 *
 * DESIGN:
 *  - FingerprintJS's raw `components` are adapted to the closed schema and its
 *    `visitorId` hash is DISCARDED. The client never ships a client-side id;
 *    the authoritative visitor id is whatever the server returns.
 *  - BotD's verdict is reduced to `{ bot, kind? }`; its raw signals stay in the
 *    browser.
 *
 * TREE-SHAKING: kept in its own module (not `collect.ts`) so importing the
 * interface does not pull in FingerprintJS or BotD. The heavy deps load only
 * when a consumer imports {@link createFingerprintCollector}.
 *
 * INJECTABLE: the loaders and the user-agent source are injectable so tests can
 * supply fakes and assert the wiring without a real browser.
 */

import { load as loadBotd } from '@fingerprintjs/botd'
import FingerprintJS from '@fingerprintjs/fingerprintjs'
import { adaptFingerprintComponents } from './adapter'
import type { Collected, Collector } from './collect'
import type { Botd } from './types'

/** Minimal structural view of a loaded FingerprintJS agent — only the surface
 *  this collector uses. `get()` returns the raw components plus the `visitorId`
 *  hash we deliberately throw away. */
export interface FingerprintAgent {
  get(): Promise<{ visitorId: string; components: Record<string, unknown> }>
}

/** Minimal structural view of a loaded BotD detector. `collect()` gathers the
 *  raw signals and `detect()` returns the client-side verdict. */
export interface BotdDetector {
  collect(): Promise<unknown>
  detect(): { bot: boolean; botKind?: string }
}

/** Injectable dependencies (defaulted to the real browser sources). */
export interface FingerprintCollectorDeps {
  /** Load a FingerprintJS agent. Defaults to `FingerprintJS.load()`. */
  loadFingerprint?: () => Promise<FingerprintAgent>
  /** Load a BotD detector. Defaults to `botd.load({ monitoring: false })` —
   *  monitoring is off so the OSS detector never phones home. */
  loadBotd?: () => Promise<BotdDetector>
  /** User-agent source. Defaults to `navigator.userAgent` when `navigator`
   *  exists. */
  userAgent?: () => string | undefined
}

const defaultUserAgent = (): string | undefined =>
  typeof navigator === 'undefined' ? undefined : navigator.userAgent

/**
 * Build a real {@link Collector} over FingerprintJS + BotD.
 *
 * The returned collector produces:
 *  - `components` — every FingerprintJS component adapted to the closed schema
 *    ({@link adaptFingerprintComponents}); the FJS `visitorId` is never read
 *    into the payload;
 *  - `botd` — `{ bot: true, kind }` when BotD detects automation, otherwise
 *    `{ bot: false }`;
 *  - `user_agent` — when a user agent is available.
 */
export function createFingerprintCollector(
  deps: FingerprintCollectorDeps = {},
): Collector {
  const loadFingerprint = deps.loadFingerprint ?? (() => FingerprintJS.load())
  const load = deps.loadBotd ?? (() => loadBotd({ monitoring: false }))
  const userAgent = deps.userAgent ?? defaultUserAgent

  return async (): Promise<Collected> => {
    const agent = await loadFingerprint()
    // Take the raw components only; the `visitorId` hash is discarded.
    const { components } = await agent.get()

    const detector = await load()
    await detector.collect()
    const detection = detector.detect()
    const botd: Botd =
      detection.bot && detection.botKind !== undefined
        ? { bot: true, kind: detection.botKind }
        : { bot: detection.bot }

    const collected: Collected = {
      components: adaptFingerprintComponents(components),
      botd,
    }
    const ua = userAgent()
    if (ua !== undefined) collected.user_agent = ua
    return collected
  }
}
