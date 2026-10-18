import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { count } from 'drizzle-orm'
import { beforeAll, describe, expect, it } from 'vitest'
import type { Deps } from '../src/app'
import { createApp } from '../src/app'
import type { Env } from '../src/config'
import { resolveConfig } from '../src/config'
import { templates } from '../src/db/schema'
import type { NewDeviceVelocityStore } from '../src/lib/do/velocity-do'
import type { CandidateSource } from '../src/lib/state'
import type { ChallengeResponse, IdentifyResponse } from '../src/lib/types'
import { EventStore } from '../src/modules/events'
import {
  EdgeEngine,
  FingerprintStore,
  initEngineRuntime,
} from '../src/modules/fingerprint'
import {
  fakeStores,
  InMemoryEventLog,
  InMemoryNonceStore,
  memoryDb,
} from './helpers/fakes'

/** Drive the Hono app with injected deps; state lives in `deps`, so a fresh app
 *  per call is fine. */
const handleRequest = (req: Request, deps: Deps) => createApp(deps).request(req)

// Load the vendored WASM engine once for the whole suite (mirrors how the
// Worker inits per isolate, but from disk bytes instead of an `import`).
beforeAll(() => {
  const wasmPath = fileURLToPath(
    new URL('../wasm/fp_wasm_bg.wasm', import.meta.url).href,
  )
  initEngineRuntime(readFileSync(wasmPath))
})

/** Test salt every config in this suite resolves with. */
const SALT = 'test-salt'

const HEX32 = /^[0-9a-f]{32}$/

/** A JA4 whose structural counts read as a real browser (15 ciphers, 16 ext). */
const BROWSER_JA4 = 't13d1516h2_8daaf6152771_02713d6af862'
/** A JA4 whose counts read as a minimal automation stack (3/4). */
const AUTOMATION_JA4 = 't13d0304h1_aaaaaaaaaaaa_bbbbbbbbbbbb'
/** A browser UA claiming Chrome. */
const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0'

/** Build injected deps + fresh fake state for a given environment. */
function makeDeps(env: Env = {}, overrides: Partial<Deps> = {}): Deps {
  const config = resolveConfig({ FP_SALT_SECRET: SALT, ...env })
  return {
    engine: new EdgeEngine(config.saltSecret),
    config,
    ...fakeStores(config.nonceTtlSecs),
    ...overrides,
  }
}

const get = (path: string) =>
  new Request(`https://edge.test${path}`, { method: 'GET' })

/** A POST /identify with a JSON body, extra headers and an optional `cf`
 *  enrichment object (what the Workers runtime attaches to a request). */
function postIdentify(
  body: unknown,
  headers: Record<string, string> = {},
  cf?: Record<string, unknown>,
): Request {
  const req = new Request('https://edge.test/identify', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })
  if (cf) (req as unknown as { cf: unknown }).cf = cf
  return req
}

/** GET /challenge and return its parsed body. */
async function challenge(deps: Deps): Promise<ChallengeResponse> {
  const resp = await handleRequest(get('/challenge'), deps)
  expect(resp.status).toBe(200)
  return (await resp.json()) as ChallengeResponse
}

/** A rich, realistic component probe in the closed schema. */
function probeComponents(): Record<string, unknown> {
  return {
    webgl: 'ANGLE (Intel)',
    platform: 'Linux x86_64',
    timezone: 'Asia/Shanghai',
    audio: '124.04',
    cpu_cores: 8,
    device_memory: 8,
    fonts: ['Arial', 'Helvetica', 'Courier', 'Times', 'Verdana'],
  }
}

/** A valid identify body over a fresh nonce, with `extra` merged in. */
async function body(
  deps: Deps,
  extra: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const { nonce } = await challenge(deps)
  return { nonce, ts: Date.now(), components: probeComponents(), ...extra }
}

/** challenge → identify, asserting 200, returning the parsed body. */
async function identify(
  deps: Deps,
  extra: Record<string, unknown> = {},
  headers: Record<string, string> = {},
  cf?: Record<string, unknown>,
): Promise<IdentifyResponse> {
  const resp = await handleRequest(
    postIdentify(await body(deps, extra), headers, cf),
    deps,
  )
  expect(resp.status).toBe(200)
  return (await resp.json()) as IdentifyResponse
}

describe('routing', () => {
  it('health returns 200', async () => {
    const resp = await handleRequest(get('/health'), makeDeps())
    expect(resp.status).toBe(200)
  })

  it('unknown route returns 404', async () => {
    const resp = await handleRequest(get('/nope'), makeDeps())
    expect(resp.status).toBe(404)
  })
})

describe('GET /challenge', () => {
  it('returns exactly nonce and expires_in', async () => {
    const resp = await handleRequest(get('/challenge'), makeDeps())
    expect(resp.headers.get('content-type')).toBe('application/json')
    const json = (await resp.json()) as Record<string, unknown>
    expect(Object.keys(json).sort()).toEqual(['expires_in', 'nonce'])
    expect(typeof json.nonce).toBe('string')
    expect(json.expires_in).toBe(30)
  })
})

describe('POST /identify contract', () => {
  it('identifies a first-ever probe as a new device with exactly the contract keys', async () => {
    const deps = makeDeps()
    const resp = await handleRequest(postIdentify(await body(deps)), deps)
    expect(resp.status).toBe(200)
    expect(resp.headers.get('content-type')).toBe('application/json')
    expect(
      [...resp.headers.keys()].filter((name) => name.startsWith('x-fp-')),
    ).toEqual([])
    const json = (await resp.json()) as IdentifyResponse
    expect(Object.keys(json).sort()).toEqual([
      'collision_risk',
      'confidence',
      'decision',
      'is_new_device',
      'request_id',
      'signals',
      'visitor_id',
    ])
    expect(json.request_id).toMatch(HEX32)
    expect(json.visitor_id).toMatch(HEX32)
    expect(json.decision).toBe('new_device')
    expect(json.is_new_device).toBe(true)
    expect(json.confidence).toBeGreaterThanOrEqual(0)
    expect(json.confidence).toBeLessThanOrEqual(1)
    expect(json.signals).toEqual({
      ua_tls_consistent: true,
      ip_risk: 'low',
      client_integrity: 'unavailable',
      persona_coherence: 'unknown',
      new_device_velocity: 'low',
      automation: 'unknown',
      template_jump: false,
    })
  })

  it('mints a unique request_id per call', async () => {
    const deps = makeDeps()
    const first = await identify(deps)
    const second = await identify(deps)
    expect(first.request_id).not.toBe(second.request_id)
  })

  it('re-identifies a returning device through the real store', async () => {
    const deps = makeDeps(
      {},
      { candidates: new FingerprintStore(await memoryDb()) },
    )
    const first = await identify(deps)
    const second = await identify(deps)
    expect(second.decision).toBe('match')
    expect(second.is_new_device).toBe(false)
    expect(second.visitor_id).toBe(first.visitor_id)
    expect(second.request_id).not.toBe(first.request_id)
  })
})

describe('POST /identify request validation', () => {
  /** POST `raw` (already-serialized) with a content type; return the status. */
  async function postRaw(
    deps: Deps,
    raw: string,
    contentType: string | undefined,
  ): Promise<number> {
    const headers: Record<string, string> = {}
    if (contentType !== undefined) headers['content-type'] = contentType
    const resp = await handleRequest(
      new Request('https://edge.test/identify', {
        method: 'POST',
        headers,
        body: raw,
      }),
      deps,
    )
    return resp.status
  }

  it('rejects a non-JSON or missing content type with 415', async () => {
    const deps = makeDeps()
    const valid = JSON.stringify(await body(deps))
    expect(await postRaw(deps, valid, 'text/plain')).toBe(415)
    expect(await postRaw(deps, valid, undefined)).toBe(415)
  })

  it('accepts a JSON content type with parameters', async () => {
    const deps = makeDeps()
    const valid = JSON.stringify(await body(deps))
    expect(await postRaw(deps, valid, 'application/json; charset=utf-8')).toBe(
      200,
    )
  })

  it('rejects malformed JSON with 400', async () => {
    expect(await postRaw(makeDeps(), '{"nonce":', 'application/json')).toBe(400)
  })

  const invalid: Array<[string, Record<string, unknown>]> = [
    ['an unknown top-level key', { signature: 'x' }],
    ['a missing ts', { ts: undefined }],
    ['a non-integer ts', { ts: 1.5 }],
    ['an unknown component key', { components: { userAgent: 'Chrome' } }],
    ['a wrongly-typed component', { components: { cpu_cores: 'eight' } }],
    ['a non-object components', { components: ['webgl'] }],
    ['an unknown botd key', { botd: { bot: true, signals: {} } }],
    ['a wrongly-typed botd', { botd: { bot: 'yes' } }],
    ['an unknown integrity key', { integrity: { other: 'noise' } }],
    ['a bad integrity verdict', { integrity: { canvas: 'broken' } }],
    ['a non-string user_agent', { user_agent: 42 }],
  ]
  for (const [name, extra] of invalid) {
    it(`rejects ${name} with 400 without burning the nonce`, async () => {
      const deps = makeDeps()
      const good = await body(deps)
      const bad = { ...good, ...extra }
      const rejected = await handleRequest(postIdentify(bad), deps)
      expect(rejected.status).toBe(400)
      // The nonce survived the 400: the corrected body is accepted.
      const accepted = await handleRequest(postIdentify(good), deps)
      expect(accepted.status).toBe(200)
    })
  }
})

describe('POST /identify anti-replay', () => {
  it('rejects an unknown nonce with 401', async () => {
    const deps = makeDeps()
    const resp = await handleRequest(
      postIdentify({ ...(await body(deps)), nonce: 'never-issued' }),
      deps,
    )
    expect(resp.status).toBe(401)
  })

  it('rejects a reused nonce with 401', async () => {
    const deps = makeDeps()
    const once = await body(deps)
    expect((await handleRequest(postIdentify(once), deps)).status).toBe(200)
    expect((await handleRequest(postIdentify(once), deps)).status).toBe(401)
  })

  it('rejects an expired nonce with 401', async () => {
    const deps = makeDeps({}, { nonces: new InMemoryNonceStore(-1) })
    const resp = await handleRequest(postIdentify(await body(deps)), deps)
    expect(resp.status).toBe(401)
  })

  it('accepts a fresh ts and rejects a stale or future one with 401', async () => {
    const deps = makeDeps()
    const now = Date.now()
    const status = async (ts: number) =>
      (await handleRequest(postIdentify(await body(deps, { ts })), deps)).status
    expect(await status(now)).toBe(200)
    expect(await status(now - 60_000)).toBe(401)
    expect(await status(now + 60_000)).toBe(401)
  })

  it('honours a configured skew', async () => {
    const deps = makeDeps({ FP_TS_SKEW_SECS: '120' })
    const resp = await handleRequest(
      postIdentify(await body(deps, { ts: Date.now() - 60_000 })),
      deps,
    )
    expect(resp.status).toBe(200)
  })
})

describe('signals', () => {
  it('surfaces the botd verdict as automation', async () => {
    const deps = makeDeps()
    const detected = await identify(deps, {
      botd: { bot: true, kind: 'headless_chrome' },
    })
    const human = await identify(deps, { botd: { bot: false } })
    const nullKind = await identify(deps, { botd: { bot: false, kind: null } })
    expect(detected.signals.automation).toBe('detected')
    expect(human.signals.automation).toBe('not_detected')
    expect(nullKind.signals.automation).toBe('not_detected')
    expect(detected.confidence).toBe(human.confidence)
  })

  it('cross-checks the top-level user_agent against the cf JA4', async () => {
    const deps = makeDeps()
    const cf = (ja4: string) => ({ botManagement: { ja4 } })
    const neutral = await identify(deps, { user_agent: CHROME_UA })
    const consistent = await identify(
      deps,
      { user_agent: CHROME_UA },
      {},
      cf(BROWSER_JA4),
    )
    const forged = await identify(
      deps,
      { user_agent: CHROME_UA },
      {},
      cf(AUTOMATION_JA4),
    )
    expect(neutral.signals.ua_tls_consistent).toBe(true)
    expect(consistent.signals.ua_tls_consistent).toBe(true)
    expect(consistent.confidence).toBeGreaterThan(neutral.confidence)
    expect(forged.signals.ua_tls_consistent).toBe(false)
    expect(forged.confidence).toBeLessThan(neutral.confidence)
  })

  it('ignores a client-supplied cf-bot-management-ja4 header', async () => {
    const deps = makeDeps()
    const neutral = await identify(deps, { user_agent: CHROME_UA })
    const header = await identify(
      deps,
      { user_agent: CHROME_UA },
      { 'cf-bot-management-ja4': AUTOMATION_JA4 },
    )
    expect(header.signals.ua_tls_consistent).toBe(true)
    expect(header.confidence).toBe(neutral.confidence)
  })

  it('reads the claimed UA only from the top-level user_agent', async () => {
    const deps = makeDeps()
    // Without a claimed UA the TLS cross-check has nothing to contradict.
    const noUa = await identify(
      deps,
      {},
      {},
      {
        botManagement: { ja4: AUTOMATION_JA4 },
      },
    )
    expect(noUa.signals.ua_tls_consistent).toBe(true)
  })

  it('bands the cf-connecting-ip and raises it for a hosting ASN', async () => {
    const deps = makeDeps()
    const residential = await identify(
      deps,
      {},
      {
        'cf-connecting-ip': '203.0.113.9',
      },
    )
    expect(residential.signals.ip_risk).toBe('low')
    const hosting = await identify(
      deps,
      {},
      { 'cf-connecting-ip': '203.0.113.9' },
      { asn: 16509, asOrganization: 'Amazon.com, Inc.' },
    )
    expect(hosting.signals.ip_risk).toBe('high')
  })

  it('flags a borrowed persona from user_agent vs fonts, surfaced-only', async () => {
    const deps = makeDeps()
    const windowsUa =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/146.0.0.0 Safari/537.36'
    const withFonts = (fonts: string[]) => ({
      user_agent: windowsUa,
      components: { platform: 'Win32', fonts },
    })
    const mismatch = await identify(deps, withFonts(['Arial', 'Courier New']))
    const consistent = await identify(deps, withFonts(['Calibri']))
    expect(mismatch.signals.persona_coherence).toBe('mismatch')
    expect(consistent.signals.persona_coherence).toBe('consistent')
    const noUa = await identify(deps, { components: { fonts: ['Arial'] } })
    expect(noUa.signals.persona_coherence).toBe('unknown')
  })

  describe('client integrity', () => {
    const allNoise = {
      canvas: 'noise',
      webgl: 'noise',
      audio: 'noise',
      rect: 'noise',
    }

    it('surfaces noise without moving confidence by default', async () => {
      const deps = makeDeps()
      const base = await identify(deps)
      const noisy = await identify(deps, { integrity: allNoise })
      expect(base.signals.client_integrity).toBe('unavailable')
      expect(noisy.signals.client_integrity).toBe('noise')
      expect(noisy.confidence).toBe(base.confidence)
    })

    it('lowers confidence on noise only when the penalty is enabled', async () => {
      const deps = makeDeps({ FP_INTEGRITY_PENALTY_ENABLED: '1' })
      const base = await identify(deps)
      const noisy = await identify(deps, { integrity: allNoise })
      const clean = await identify(deps, { integrity: { canvas: 'ok' } })
      expect(noisy.confidence).toBeLessThan(base.confidence)
      expect(clean.signals.client_integrity).toBe('ok')
      expect(clean.confidence).toBe(base.confidence)
    })
  })
})

describe('new-device velocity', () => {
  /** Distinct visitor ids per IP, like the Durable Object (no expiry here). */
  class CountingVelocity implements NewDeviceVelocityStore {
    readonly calls: Array<[string, string, number]> = []
    private readonly seen = new Map<string, Set<string>>()
    newDeviceVelocityIp(
      ip: string,
      visitor_id: string,
      windowMs: number,
    ): Promise<number> {
      this.calls.push([ip, visitor_id, windowMs])
      const ids = this.seen.get(ip) ?? new Set<string>()
      ids.add(visitor_id)
      this.seen.set(ip, ids)
      return Promise.resolve(ids.size)
    }
  }

  it('bands distinct new devices per IP and lowers confidence at high', async () => {
    const velocity = new CountingVelocity()
    const deps = makeDeps({}, { velocity })
    const ip = { 'cf-connecting-ip': '198.51.100.7' }
    const results: IdentifyResponse[] = []
    for (let i = 0; i < 20; i++) results.push(await identify(deps, {}, ip))

    const [first] = results
    const fifth = results[4]
    const twentieth = results[19]
    expect(first?.signals.new_device_velocity).toBe('low')
    expect(fifth?.signals.new_device_velocity).toBe('medium')
    expect(twentieth?.signals.new_device_velocity).toBe('high')
    // The high-band penalty comes from the engine; medium carries none.
    const penalty = deps.engine.velocityPenalty('high')
    expect(penalty).toBeGreaterThan(0)
    expect(fifth?.confidence).toBe(first?.confidence)
    expect(twentieth?.confidence).toBeCloseTo(
      (first?.confidence ?? 0) - penalty,
      12,
    )
    // Keyed on the IP, member = the minted visitor id, over the 3600 s window.
    expect(velocity.calls[0]).toEqual([
      '198.51.100.7',
      first?.visitor_id,
      3_600_000,
    ])
  })

  it('stays low without a client IP or off a new device', async () => {
    const velocity = new CountingVelocity()
    const deps = makeDeps(
      {},
      { velocity, candidates: new FingerprintStore(await memoryDb()) },
    )
    const noIp = await identify(deps)
    expect(noIp.signals.new_device_velocity).toBe('low')
    expect(velocity.calls).toHaveLength(0)

    const ip = { 'cf-connecting-ip': '198.51.100.8' }
    const matched = await identify(deps, {}, ip)
    expect(matched.decision).toBe('match')
    expect(matched.signals.new_device_velocity).toBe('low')
    expect(velocity.calls).toHaveLength(0)
  })

  it('propagates a velocity store failure as a 500', async () => {
    const failing: NewDeviceVelocityStore = {
      newDeviceVelocityIp: () => Promise.reject(new Error('DO unavailable')),
    }
    const deps = makeDeps({}, { velocity: failing })
    const resp = await handleRequest(
      postIdentify(await body(deps), { 'cf-connecting-ip': '198.51.100.9' }),
      deps,
    )
    expect(resp.status).toBe(500)
  })
})

describe('GET /events/:request_id', () => {
  const API = { FP_API_KEY: 'api-secret' }
  const AUTH = 'Bearer api-secret'
  const event = (id: string, authorization?: string) =>
    new Request(`https://edge.test/events/${id}`, {
      headers: authorization ? { authorization } : {},
    })

  it('returns 404 when no API key is configured (endpoint disabled)', async () => {
    const deps = makeDeps()
    const first = await identify(deps)
    expect(
      (await handleRequest(event(first.request_id, AUTH), deps)).status,
    ).toBe(404)
  })

  it('stores nothing when no API key is configured', async () => {
    const events = new InMemoryEventLog()
    await identify(makeDeps({}, { events }))
    expect(events.events.size).toBe(0)
  })

  it('returns 401 on a missing or wrong bearer credential', async () => {
    const deps = makeDeps(API)
    const first = await identify(deps)
    expect((await handleRequest(event(first.request_id), deps)).status).toBe(
      401,
    )
    expect(
      (await handleRequest(event(first.request_id, 'Bearer nope'), deps))
        .status,
    ).toBe(401)
    expect(
      (await handleRequest(event(first.request_id, 'api-secret'), deps)).status,
    ).toBe(401)
  })

  it('returns 404 for an unknown request id', async () => {
    const deps = makeDeps(API)
    await identify(deps)
    expect(
      (await handleRequest(event('f'.repeat(32), AUTH), deps)).status,
    ).toBe(404)
  })

  it('returns 404 once the event has expired', async () => {
    const deps = makeDeps({ ...API, FP_EVENT_TTL_SECS: '0' })
    const first = await identify(deps)
    expect(
      (await handleRequest(event(first.request_id, AUTH), deps)).status,
    ).toBe(404)
  })

  it('returns the exact identify body with the client IP recorded', async () => {
    const db = await memoryDb()
    const deps = makeDeps(API, {
      candidates: new FingerprintStore(db),
      events: new EventStore(db),
    })
    const resp = await handleRequest(
      postIdentify(await body(deps), { 'cf-connecting-ip': '198.51.100.7' }),
      deps,
    )
    const sent = await resp.text()
    const { request_id } = JSON.parse(sent) as IdentifyResponse

    const got = await handleRequest(event(request_id, AUTH), deps)
    expect(got.status).toBe(200)
    expect(got.headers.get('content-type')).toBe('application/json')
    expect(await got.text()).toBe(sent)
    expect((await deps.events.get(request_id, Date.now()))?.ip).toBe(
      '198.51.100.7',
    )
  })

  it('serves an event until its TTL elapses', async () => {
    const events = new InMemoryEventLog()
    const deps = makeDeps({ ...API, FP_EVENT_TTL_SECS: '60' }, { events })
    const before = Date.now()
    const first = await identify(deps)
    const expiresAt = events.events.get(first.request_id)?.expiresAt ?? 0
    expect(expiresAt).toBeGreaterThanOrEqual(before + 60_000)
    expect(expiresAt).toBeLessThanOrEqual(Date.now() + 60_000)
  })
})

describe('DELETE /visitor/:id erasure', () => {
  const del = (id: string, authorization?: string) =>
    new Request(`https://edge.test/visitor/${id}`, {
      method: 'DELETE',
      headers: authorization ? { authorization } : {},
    })

  it('returns 404 when no admin key is configured (endpoint disabled)', async () => {
    const resp = await handleRequest(del('v1', 'Bearer x'), makeDeps())
    expect(resp.status).toBe(404)
  })

  it('returns 401 on a missing or wrong bearer credential', async () => {
    const deps = makeDeps({ FP_ADMIN_KEY: 'admin-secret' })
    expect((await handleRequest(del('v1'), deps)).status).toBe(401)
    expect((await handleRequest(del('v1', 'Bearer nope'), deps)).status).toBe(
      401,
    )
    expect(
      (await handleRequest(del('v1', 'Basic admin-secret'), deps)).status,
    ).toBe(401)
  })

  it('erases with 204, idempotently, and never re-mints the erased id', async () => {
    const store = new FingerprintStore(await memoryDb())
    const deps = makeDeps(
      { FP_ADMIN_KEY: 'admin-secret' },
      { candidates: store },
    )
    const first = await identify(deps)

    const auth = 'Bearer admin-secret'
    expect(
      (await handleRequest(del(first.visitor_id, auth), deps)).status,
    ).toBe(204)
    expect(
      (await handleRequest(del(first.visitor_id, auth), deps)).status,
    ).toBe(204)

    // The same device returns as a brand-new visitor under a fresh id.
    const again = await identify(deps)
    expect(again.decision).toBe('new_device')
    expect(again.visitor_id).toMatch(HEX32)
    expect(again.visitor_id).not.toBe(first.visitor_id)
  })

  it('erases the identify events of the visitor too', async () => {
    const db = await memoryDb()
    const deps = makeDeps(
      { FP_ADMIN_KEY: 'admin-secret', FP_API_KEY: 'api-secret' },
      { candidates: new FingerprintStore(db), events: new EventStore(db) },
    )
    const first = await identify(deps)
    const fetchEvent = () =>
      handleRequest(
        new Request(`https://edge.test/events/${first.request_id}`, {
          headers: { authorization: 'Bearer api-secret' },
        }),
        deps,
      )
    expect((await fetchEvent()).status).toBe(200)
    expect(
      (await handleRequest(del(first.visitor_id, 'Bearer admin-secret'), deps))
        .status,
    ).toBe(204)
    expect((await fetchEvent()).status).toBe(404)
  })

  it('does not write back a match whose visitor was erased mid-request', async () => {
    const db = await memoryDb()
    const store = new FingerprintStore(db)
    const deps = makeDeps({}, { candidates: store })
    const first = await identify(deps)

    // Erase between recall and persist, as a concurrent DELETE would.
    const racing: CandidateSource = {
      recall: async (keys) => {
        const recalled = await store.recall(keys)
        await store.erase(first.visitor_id)
        return recalled
      },
      persist: (outcome, nowMs) => store.persist(outcome, nowMs),
      erase: (id) => store.erase(id),
    }
    const matched = await identify({ ...deps, candidates: racing })
    expect(matched.decision).toBe('match')
    expect(matched.visitor_id).toBe(first.visitor_id)

    const [row] = await db.select({ n: count() }).from(templates)
    expect(row?.n).toBe(0)
  })
})

describe('CORS (browser playground)', () => {
  const ORIGIN = 'https://app.test'
  const corsDeps = () =>
    makeDeps({ FP_CORS_ORIGINS: `${ORIGIN}, https://other.test` })

  const withOrigin = (path: string, origin: string) =>
    new Request(`https://edge.test${path}`, {
      method: 'GET',
      headers: { origin },
    })

  it('answers preflight for an allowed origin with the POST method allowed', async () => {
    const resp = await handleRequest(
      new Request('https://edge.test/identify', {
        method: 'OPTIONS',
        headers: {
          origin: ORIGIN,
          'access-control-request-method': 'POST',
          'access-control-request-headers': 'content-type',
        },
      }),
      corsDeps(),
    )
    expect(resp.status).toBe(204)
    expect(resp.headers.get('access-control-allow-origin')).toBe(ORIGIN)
    expect(resp.headers.get('access-control-allow-methods')).toContain('POST')
  })

  it('reflects an allowed origin without exposing extra headers', async () => {
    const resp = await handleRequest(
      withOrigin('/challenge', ORIGIN),
      corsDeps(),
    )
    expect(resp.status).toBe(200)
    expect(resp.headers.get('access-control-allow-origin')).toBe(ORIGIN)
    expect(resp.headers.get('access-control-expose-headers')).toBeNull()
  })

  it('does not echo an unlisted origin', async () => {
    const resp = await handleRequest(
      withOrigin('/challenge', 'https://evil.test'),
      corsDeps(),
    )
    expect(resp.headers.get('access-control-allow-origin')).not.toBe(
      'https://evil.test',
    )
  })

  it('emits no CORS headers when unconfigured', async () => {
    const resp = await handleRequest(
      withOrigin('/challenge', ORIGIN),
      makeDeps(),
    )
    expect(resp.headers.get('access-control-allow-origin')).toBeNull()
  })
})
