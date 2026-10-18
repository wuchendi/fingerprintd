/**
 * `@cdlab/fingerprintd` — browser SDK for the fingerprintd challenge/identify
 * flow.
 *
 * The client only COLLECTS evidence; the SERVER judges. It sends closed-schema
 * components and discards any client-side id. The `/identify` response it gets
 * back is display-only: the customer backend fetches the authoritative result
 * server-to-server with `GET /events/{request_id}` (bearer API key), keyed by
 * the returned `request_id`.
 */

import type { ClientOptions, FetchLike } from './client'
import { getChallenge, identify } from './client'
import type { Collector } from './collect'
import type { IdentifyRequest, IdentifyResponse } from './types'

export type { ClientOptions, FetchLike } from './client'
export { getChallenge, identify } from './client'
export type { Collected, Collector } from './collect'
export type { FullCollectorOptions } from './collector'
export { createCollector } from './collector'
export type {
  BotdDetector,
  FingerprintAgent,
  FingerprintCollectorDeps,
} from './fingerprint'
export { createFingerprintCollector } from './fingerprint'
export type {
  Integrity,
  IntegrityFn,
  IntegrityMeasurements,
  ProbeVerdict,
} from './integrity'
export {
  collectIntegrity,
  evaluateIntegrity,
  measureIntegrity,
} from './integrity'
export type { ComponentKey, Components } from './schema'
export { COMPONENT_KEYS } from './schema'
export type {
  Botd,
  ChallengeResponse,
  IdentifyRequest,
  IdentifyResponse,
  Signals,
} from './types'

/** Options for the end-to-end {@link run} flow. */
export interface RunOptions {
  /** Base URL of the fingerprintd server (e.g. `https://fp.example.com`). */
  baseUrl: string
  /** Collector producing the evidence to submit. */
  collect: Collector
  /** Override the `fetch` implementation (for mocking/tests). */
  fetch?: FetchLike
}

/**
 * Run the full flow: `getChallenge` → `collect` → `identify`. `ts` is stamped
 * right before the POST.
 */
export async function run(options: RunOptions): Promise<IdentifyResponse> {
  const { baseUrl, collect } = options
  const clientOptions: ClientOptions = { fetch: options.fetch }

  const challenge = await getChallenge(baseUrl, clientOptions)
  const collected = await collect()

  const request: IdentifyRequest = {
    nonce: challenge.nonce,
    ts: Date.now(),
    components: collected.components,
  }
  if (collected.user_agent !== undefined) {
    request.user_agent = collected.user_agent
  }
  if (collected.botd !== undefined) request.botd = collected.botd
  if (collected.integrity !== undefined) request.integrity = collected.integrity

  return identify(baseUrl, request, clientOptions)
}
