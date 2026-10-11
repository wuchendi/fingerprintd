/**
 * The FULL {@link Collector} — it composes the stable half plus the probe
 * and a client timestamp into the single evidence payload `run()` submits:
 *
 *   { stable_components, probe?, ts, integrity }
 *
 * DESIGN (architecture §4.1):
 *  - STABLE half (`createFingerprintCollector`) — the "who is this device"
 *    matching input.
 *  - PROBE (WASM, `wasmProbeFn`) — `hex(HMAC-SHA256(key, nonce))`,
 *    computed ONLY when the challenge advertises `collect.challenge.verify`
 *    (i.e. the server has a probe key configured). Kept SEPARATE from
 *    `stable_components`; it is NEVER a matching signal, only a freshness proof.
 *  - `ts` — the client clock at collection.
 *  - INTEGRITY (`collectIntegrity`) — four known-answer probes that catch
 *    fingerprint noise. A risk signal, kept SEPARATE from `stable_components`
 *    like the probe; a probe without its API reports `unavailable` (neutral).
 *
 * Every backend is injectable so the whole assembly is testable without a real
 * browser or the WASM (there is no headless browser in this environment).
 */

import type { Collected, Collector } from './collect'
import type { FingerprintCollectorDeps } from './fingerprint'
import { createFingerprintCollector } from './fingerprint'
import type { IntegrityFn } from './integrity'
import { collectIntegrity } from './integrity'
import type { ProbeFn } from './probe'
import { wasmProbeFn } from './probe'

/** Injectable backends for the full collector. All default to the real
 *  implementations; tests override them with deterministic fakes. */
export interface FullCollectorOptions {
  /** Stable-half (FingerprintJS + BotD) loaders. */
  fingerprint?: FingerprintCollectorDeps
  /** Nonce-probe function. Defaults to the WASM {@link wasmProbeFn}. */
  probe?: ProbeFn
  /** Client clock in Unix ms. Injectable for deterministic tests; defaults to
   *  `Date.now`. */
  now?: () => number
  /** Integrity probes. Defaults to the real {@link collectIntegrity}. */
  integrity?: IntegrityFn
}

/**
 * Build the full {@link Collector}.
 *
 * The returned collector runs the stable half, computes the probe when the
 * challenge asks to `verify` it, stamps the client `ts`, runs the integrity
 * probes, and returns the assembled evidence. `stable_components`, `probe` and
 * `integrity` stay separate by construction.
 */
export function createCollector(options: FullCollectorOptions = {}): Collector {
  const stableCollector = createFingerprintCollector(options.fingerprint)
  const probeFn = options.probe ?? wasmProbeFn
  const now = options.now ?? (() => Date.now())
  const integrityFn = options.integrity ?? collectIntegrity

  return async (challenge): Promise<Collected> => {
    const { stable_components } = await stableCollector(challenge)

    const collected: Collected = {
      stable_components,
      ts: now(),
      integrity: await integrityFn(),
    }
    // Compute the probe only when the server advertises it (probe_key set).
    if (challenge.collect.challenge.verify !== undefined) {
      collected.probe = await probeFn(challenge.nonce)
    }
    return collected
  }
}
