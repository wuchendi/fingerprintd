/**
 * The full {@link Collector} — the stable half plus the integrity probes,
 * assembled into the evidence `run()` submits:
 *
 *   { components, user_agent?, botd?, integrity }
 *
 *  - STABLE half (`createFingerprintCollector`) — the "who is this device"
 *    matching input, plus the user agent and BotD verdict.
 *  - INTEGRITY (`collectIntegrity`) — four known-answer probes that catch
 *    fingerprint noise. A risk signal, kept separate from `components`; a
 *    probe without its API reports `unavailable` (neutral).
 *
 * Every backend is injectable so the assembly is testable without a real
 * browser.
 */

import type { Collected, Collector } from './collect'
import type { FingerprintCollectorDeps } from './fingerprint'
import { createFingerprintCollector } from './fingerprint'
import type { IntegrityFn } from './integrity'
import { collectIntegrity } from './integrity'

/** Injectable backends for the full collector. All default to the real
 *  implementations; tests override them with deterministic fakes. */
export interface FullCollectorOptions {
  /** Stable-half (FingerprintJS + BotD) loaders. */
  fingerprint?: FingerprintCollectorDeps
  /** Integrity probes. Defaults to the real {@link collectIntegrity}. */
  integrity?: IntegrityFn
}

/** Build the full {@link Collector}: the stable half followed by the
 *  integrity probes. */
export function createCollector(options: FullCollectorOptions = {}): Collector {
  const stableCollector = createFingerprintCollector(options.fingerprint)
  const integrityFn = options.integrity ?? collectIntegrity

  return async (): Promise<Collected> => {
    const stable = await stableCollector()
    return { ...stable, integrity: await integrityFn() }
  }
}
