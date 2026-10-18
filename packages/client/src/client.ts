/**
 * Thin HTTP client for the two browser-facing fingerprintd endpoints. Transport
 * only — it does no collection and no judging. `fetch` is injectable so tests
 * can mock it without a network or a browser.
 */

import type {
  ChallengeResponse,
  IdentifyRequest,
  IdentifyResponse,
} from './types'

/** A `fetch`-compatible function. Defaults to `globalThis.fetch`. */
export type FetchLike = typeof globalThis.fetch

/** Options accepted by the request helpers. */
export interface ClientOptions {
  /** Override the `fetch` implementation (for mocking/tests). */
  fetch?: FetchLike
}

/** Join a base URL and a path without doubling or dropping the slash. */
function endpoint(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/+$/, '')}${path}`
}

/** GET `/challenge` — mint a one-time nonce. */
export async function getChallenge(
  baseUrl: string,
  options: ClientOptions = {},
): Promise<ChallengeResponse> {
  const doFetch = options.fetch ?? globalThis.fetch
  const response = await doFetch(endpoint(baseUrl, '/challenge'), {
    method: 'GET',
    headers: { accept: 'application/json' },
  })
  if (!response.ok) {
    throw new Error(`GET /challenge failed: ${response.status}`)
  }
  return (await response.json()) as ChallengeResponse
}

/** POST `/identify` — submit the collected evidence under the nonce. A non-2xx
 *  status throws before parsing. */
export async function identify(
  baseUrl: string,
  body: IdentifyRequest,
  options: ClientOptions = {},
): Promise<IdentifyResponse> {
  const doFetch = options.fetch ?? globalThis.fetch
  const response = await doFetch(endpoint(baseUrl, '/identify'), {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    throw new Error(`POST /identify failed: ${response.status}`)
  }
  return (await response.json()) as IdentifyResponse
}
