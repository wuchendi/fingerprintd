/**
 * `@cdlab/fingerprintd-client` — browser SDK for the fingerprintd challenge/identify
 * flow.
 *
 * The client only COLLECTS evidence; the SERVER judges. It sends RAW stable
 * components and discards any client-side id — the visitorId is authoritative
 * only as returned by the server. The HMAC nonce probe is kept SEPARATE from the
 * stable components (freshness, never a matching signal).
 *
 * ENVIRONMENT LIMIT: no headless browser here → canvas/audio/webgl cannot be
 * exercised for real, and there is no real in-browser e2e. Tests are unit/mock
 * only (jsdom + mocked fetch). Real fingerprint certification is deferred to a
 * human; this package does not claim real fingerprint validation.
 */

import type { ClientOptions, FetchLike } from './client'
import { getChallenge, identify } from './client'
import type { Collector } from './collect'
import { verifySignature } from './signature'
import type { IdentifyRequest, IdentifyResponse } from './types'

export type { ClientOptions, FetchLike, IdentifyResult } from './client'
export { getChallenge, identify } from './client'
export type { Collected, Collector } from './collect'
export { stubCollector } from './collect'
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
export type { ProbeFn } from './probe'
export { initProbe, wasmProbeFn } from './probe'
export {
  SIGNATURE_HEADER,
  SIGNATURE_TIMESTAMP_HEADER,
  verifySignature,
} from './signature'
export type {
  ChallengeResponse,
  IdentifyRequest,
  IdentifyResponse,
  Signals,
} from './types'

/** Options for the end-to-end {@link run} flow. */
export interface RunOptions {
  /** Base URL of the fingerprintd server (e.g. `https://fp.example.com`). */
  baseUrl: string
  /** Collector producing the evidence to submit. Injected so a real collector
   *  wires in without changing this orchestration. */
  collect: Collector
  /** Shared response-signature key. When present, {@link run} verifies the
   *  `/identify` response signature. See the shared-secret caveat in
   *  `signature.ts` — embedding this in browser code is only shallow depth. */
  signingKey?: Uint8Array
  /** Override the `fetch` implementation (for mocking/tests). */
  fetch?: FetchLike
}

/** Outcome of {@link run}: the server's identity plus, when a signing key was
 *  supplied, whether the response signature verified. */
export interface RunResult {
  /** The server-judged identity (authoritative visitorId, decision, signals). */
  identity: IdentifyResponse
  /** Signature verification result: `true`/`false` when a `signingKey` was given
   *  AND the server actually signed the response; `undefined` otherwise. */
  signatureValid?: boolean
}

/**
 * Run the full flow: `getChallenge` → `collect` → `identify`, verifying the
 * response signature when a `signingKey` is provided.
 */
export async function run(options: RunOptions): Promise<RunResult> {
  const { baseUrl, collect, signingKey } = options
  const clientOptions: ClientOptions = { fetch: options.fetch }

  const challenge = await getChallenge(baseUrl, clientOptions)
  const collected = await collect(challenge)

  const request: IdentifyRequest = {
    nonce: challenge.nonce,
    stable_components: collected.stable_components,
  }
  if (collected.ts !== undefined) request.ts = collected.ts
  if (collected.probe !== undefined) request.probe = collected.probe
  if (collected.integrity !== undefined) request.integrity = collected.integrity

  const { result, bodyBytes, timestamp, signature } = await identify(
    baseUrl,
    request,
    clientOptions,
  )

  let signatureValid: boolean | undefined
  if (
    signingKey !== undefined &&
    timestamp !== undefined &&
    signature !== undefined
  ) {
    const issuedMs = Number(timestamp)
    signatureValid = await verifySignature(
      signingKey,
      issuedMs,
      bodyBytes,
      signature,
    )
  }

  return { identity: result, signatureValid }
}
