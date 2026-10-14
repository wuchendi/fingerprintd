/**
 * Browser entry for the red-team harness. Bundled by `run.sh` (`bun build`) and
 * served to the browser under test via `page.route`; the driver calls
 * `window.__fingerprintdHarness()` and stores the result.
 *
 * It runs the REAL SDK collector (FingerprintJS + BotD, adapted to the server
 * schema) so a capture is byte-for-byte what `/identify` would receive as
 * `stable_components`, plus the raw integrity measurements and the verdicts the
 * SDK would send as the top-level `integrity` field. `raw_components` is the
 * un-adapted FingerprintJS output — the input side of the client↔server
 * contract fixtures under `packages/client/tests/fixtures/fjs-raw/`.
 */
// scripts/ is not a workspace package: resolve FingerprintJS through the SDK's
// own dependency so the raw capture uses the exact version the SDK ships.
import FingerprintJS from '../../../../packages/client/node_modules/@fingerprintjs/fingerprintjs'
import { createFingerprintCollector } from '../../../../packages/client/src/fingerprint'
import type {
  Integrity,
  IntegrityMeasurements,
} from '../../../../packages/client/src/integrity'
import {
  evaluateIntegrity,
  measureIntegrity,
} from '../../../../packages/client/src/integrity'
import type { ChallengeResponse } from '../../../../packages/client/src/types'

export interface HarnessCapture {
  user_agent: string
  raw_components: Record<string, unknown>
  stable_components: Record<string, unknown>
  integrity_measurements: IntegrityMeasurements
  integrity: Integrity
}

declare global {
  interface Window {
    __fingerprintdHarness: () => Promise<HarnessCapture>
  }
}

// The fingerprint collector ignores the challenge by design (the stable half is
// nonce-free); a placeholder satisfies the signature.
const placeholderChallenge = {
  nonce: 'harness',
  expires_in: 0,
  collect: { challenge: { targets: [], verify: false } },
} as unknown as ChallengeResponse

window.__fingerprintdHarness = async () => {
  const collect = createFingerprintCollector()
  const { stable_components } = await collect(placeholderChallenge)
  const { components: raw_components } = await (
    await FingerprintJS.load()
  ).get()
  const integrity_measurements = await measureIntegrity()
  return {
    user_agent: navigator.userAgent,
    raw_components,
    stable_components,
    integrity_measurements,
    integrity: evaluateIntegrity(integrity_measurements),
  }
}
