/** Test helpers: a mocked `fetch` and canned Contract v1 response bodies. */

import type { ChallengeResponse, IdentifyResponse } from '../src/types'

/** A single canned HTTP exchange for the mock fetch. */
export interface MockRoute {
  status?: number
  /** Raw body string the response returns. Objects are JSON-encoded. */
  body: string | object
}

/** A recorded request the mock fetch saw. */
export interface RecordedRequest {
  url: string
  method: string
  body: string | undefined
}

/** Build a mock `fetch` that answers `/challenge` then `/identify` in order,
 *  recording every request it received into `recorded`. */
export function mockFetch(
  routes: { challenge?: MockRoute; identify?: MockRoute },
  recorded: RecordedRequest[] = [],
): typeof globalThis.fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    recorded.push({
      url,
      method: init?.method ?? 'GET',
      body: typeof init?.body === 'string' ? init.body : undefined,
    })
    const route = url.endsWith('/challenge')
      ? routes.challenge
      : routes.identify
    if (!route) throw new Error(`no mock route for ${url}`)
    const body =
      typeof route.body === 'string' ? route.body : JSON.stringify(route.body)
    return new Response(body, {
      status: route.status ?? 200,
      headers: { 'content-type': 'application/json' },
    })
  }) as typeof globalThis.fetch
}

/** A valid `/challenge` body. */
export function sampleChallenge(): ChallengeResponse {
  return { nonce: 'nonce-abc', expires_in: 30 }
}

/** A valid `/identify` success body. */
export function sampleIdentify(): IdentifyResponse {
  return {
    request_id: '0123456789abcdef0123456789abcdef',
    visitor_id: 'fedcba9876543210fedcba9876543210',
    confidence: 0.87,
    decision: 'new_device',
    is_new_device: true,
    collision_risk: false,
    signals: {
      ua_tls_consistent: true,
      ip_risk: 'low',
      client_integrity: 'ok',
      persona_coherence: 'consistent',
      new_device_velocity: 'low',
      automation: 'not_detected',
      template_jump: false,
    },
  }
}

/** Top-level keys an identify request may carry. */
export const IDENTIFY_REQUEST_KEYS = [
  'nonce',
  'ts',
  'components',
  'user_agent',
  'botd',
  'integrity',
]

const NUMERIC = new Set(['cpu_cores', 'device_memory'])
const SET = new Set(['fonts', 'plugins'])

/**
 * Every schema violation in `components`: a key outside `COMPONENT_KEYS`, or a
 * value whose JS type does not match its component kind (Numeric → number,
 * Set → string[], Category → string | number | boolean). Empty when valid.
 */
export function schemaViolations(
  components: object,
  keys: readonly string[],
): string[] {
  const out: string[] = []
  for (const [key, value] of Object.entries(components)) {
    if (!keys.includes(key)) {
      out.push(`${key}: not in COMPONENT_KEYS`)
    } else if (NUMERIC.has(key)) {
      if (typeof value !== 'number') out.push(`${key}: not a number`)
    } else if (SET.has(key)) {
      if (!Array.isArray(value) || !value.every((v) => typeof v === 'string')) {
        out.push(`${key}: not a string array`)
      }
    } else if (!['string', 'number', 'boolean'].includes(typeof value)) {
      out.push(`${key}: not a category scalar`)
    }
  }
  return out
}
