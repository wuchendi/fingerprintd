import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import type { Deps } from '../src/app'
import { createApp } from '../src/app'
import type { Env } from '../src/config'
import { resolveConfig } from '../src/config'
import type { NewDeviceVelocityStore } from '../src/lib/do/velocity-do'
import {
  SIGNATURE_HEADER,
  SIGNATURE_TIMESTAMP_HEADER,
} from '../src/lib/signature'
import { EmptyCandidateSource, InMemoryNonceStore } from '../src/lib/state'
import type { ChallengeResponse, IdentifyResponse } from '../src/lib/types'
import { EmptyCheckinStore } from '../src/modules/checkin/checkin-state'
import {
  EdgeEngine,
  initEngineRuntime,
} from '../src/modules/fingerprint/engine'

/** Drive the Hono app with injected deps; state lives in `deps`, so a fresh app
 *  per call is fine (a shim over the pre-Hono `handleRequest(req, deps)`). */
const handleRequest = (req: Request, deps: Deps) => createApp(deps).request(req)

// Load the vendored WASM engine once for the whole suite (mirrors how the
// Worker inits per isolate, but from disk bytes instead of an `import`).
beforeAll(() => {
  const wasmPath = fileURLToPath(
    new URL('../wasm/fp_wasm_bg.wasm', import.meta.url).href,
  )
  const bytes = readFileSync(wasmPath)
  initEngineRuntime(bytes)
})

/** Build injected deps + a fresh STUBBED state for a given environment. */
function makeDeps(env: Env = {}): Deps {
  const config = resolveConfig(env)
  return {
    engine: new EdgeEngine(config),
    nonces: new InMemoryNonceStore(config.nonceTtlSecs),
    candidates: new EmptyCandidateSource(),
    config,
    checkin: new EmptyCheckinStore(),
  }
}

const get = (path: string) =>
  new Request(`https://edge.test${path}`, { method: 'GET' })

const postIdentify = (body: unknown) =>
  new Request('https://edge.test/identify', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

/** GET /challenge and return its parsed body. */
async function challenge(deps: Deps): Promise<ChallengeResponse> {
  const resp = await handleRequest(get('/challenge'), deps)
  expect(resp.status).toBe(200)
  return (await resp.json()) as ChallengeResponse
}

/** A rich, realistic stable-component probe the fuzzy engine can score. */
function probeComponents(): Record<string, unknown> {
  return {
    webgl: 'ANGLE (Intel)',
    platform: 'Linux x86_64',
    timezone: 'Asia/Shanghai',
    audio: '124.04',
    cpu_cores: 8,
    device_memory: 8,
    fonts: ['Arial', 'Helvetica', 'Courier', 'Times', 'Verdana'],
    user_agent: 'Chrome/120',
  }
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
  it('mints a nonce with the collection plan (probe transform omitted by default)', async () => {
    const body = await challenge(makeDeps())
    expect(typeof body.nonce).toBe('string')
    expect(body.expires_in).toBe(30)
    expect(body.collect.challenge.seed).toBe(body.nonce)
    expect(body.collect.stable).toContain('userAgent')
    expect(body.collect.challenge.targets).toEqual(['canvas', 'audio'])
    // No probe key ⇒ transform not advertised.
    expect(body.collect.challenge.verify).toBeUndefined()
  })

  it('advertises the probe transform when a probe key is configured', async () => {
    const body = await challenge(
      makeDeps({ FP_PROBE_KEY: 'test-probe-secret' }),
    )
    expect(body.collect.challenge.verify).toEqual({
      alg: 'HMAC-SHA256',
      input: 'nonce',
      encoding: 'hex',
    })
  })
})

describe('POST /identify', () => {
  it('identifies a first-ever probe as a new device', async () => {
    const deps = makeDeps()
    const { nonce } = await challenge(deps)
    const resp = await handleRequest(
      postIdentify({ nonce, stable_components: probeComponents() }),
      deps,
    )
    expect(resp.status).toBe(200)
    const body = (await resp.json()) as IdentifyResponse
    expect(typeof body.visitorId).toBe('string')
    expect(body.is_new_device).toBe(true)
    expect(body.decision).toBe('new_device')
    expect(body.confidence).toBeGreaterThanOrEqual(0)
    expect(body.confidence).toBeLessThanOrEqual(1)
    // Neutral degraded signals when no Bot Management headers are present. With
    // no velocity binding injected the velocity bands stay the neutral `low`.
    expect(body.signals).toEqual({
      ua_tls_consistent: true,
      ip_risk: 'low',
      client_integrity: 'unavailable',
      persona_coherence: 'unknown',
      new_device_velocity: 'low',
      new_device_velocity_ja4: 'low',
    })
  })

  it('rejects an unknown top-level field with 400 (strict schema)', async () => {
    const deps = makeDeps()
    const { nonce } = await challenge(deps)
    // A stray `challenge_response` (or any extra top-level key) is no longer
    // tolerated: the strict schema fails zValidator, yielding a 400 before the
    // handler runs — the nonce is NOT consumed.
    const resp = await handleRequest(
      postIdentify({
        nonce,
        stable_components: { ua: 'x' },
        challenge_response: { canvas: 'abc' },
      }),
      deps,
    )
    expect(resp.status).toBe(400)
  })

  it('rejects an unknown nonce with 401', async () => {
    const resp = await handleRequest(
      postIdentify({ nonce: 'never-issued', stable_components: { ua: 'x' } }),
      makeDeps(),
    )
    expect(resp.status).toBe(401)
  })

  it('rejects a replayed nonce with 401', async () => {
    const deps = makeDeps()
    const { nonce } = await challenge(deps)
    const body = { nonce, stable_components: { ua: 'x' } }
    expect((await handleRequest(postIdentify(body), deps)).status).toBe(200)
    // Same nonce again: the one-time nonce is burned.
    expect((await handleRequest(postIdentify(body), deps)).status).toBe(401)
  })
})

describe('nonce-probe enforcement', () => {
  const env: Env = { FP_PROBE_KEY: 'test-probe-secret' }

  it('accepts a correct probe and rejects a missing/forged one', async () => {
    const deps = makeDeps(env)

    // Missing probe when enforced ⇒ 401.
    const { nonce: n1 } = await challenge(deps)
    expect(
      (
        await handleRequest(
          postIdentify({ nonce: n1, stable_components: { ua: 'x' } }),
          deps,
        )
      ).status,
    ).toBe(401)

    // Correct probe ⇒ 200.
    const { nonce: n2 } = await challenge(deps)
    const probe = deps.engine.expectedProbe(n2)
    expect(
      (
        await handleRequest(
          postIdentify({ nonce: n2, probe, stable_components: { ua: 'x' } }),
          deps,
        )
      ).status,
    ).toBe(200)

    // Forged probe ⇒ 401.
    const { nonce: n3 } = await challenge(deps)
    expect(
      (
        await handleRequest(
          postIdentify({
            nonce: n3,
            probe: 'deadbeef',
            stable_components: { ua: 'x' },
          }),
          deps,
        )
      ).status,
    ).toBe(401)
  })

  it('reproduces the shared probe parity vector', () => {
    // Ties the edge probe check to the browser collector's vendored artifact
    // (packages/client) and the native server — same key, same nonce, same hex.
    const engine = new EdgeEngine(
      resolveConfig({ FP_PROBE_KEY: 'test-probe-secret' }),
    )
    expect(engine.expectedProbe('fixed-nonce-000')).toBe(
      'ad83144894f917b94072c2f7b3246af66d3bc5a450562ccf3671ed64d33137d0',
    )
  })
})

describe('response signing', () => {
  it('omits signature headers when no signing key is configured', async () => {
    const deps = makeDeps()
    const { nonce } = await challenge(deps)
    const resp = await handleRequest(
      postIdentify({ nonce, stable_components: { ua: 'x' } }),
      deps,
    )
    expect(resp.headers.get(SIGNATURE_HEADER)).toBeNull()
    expect(resp.headers.get(SIGNATURE_TIMESTAMP_HEADER)).toBeNull()
  })

  it('signs the exact response bytes when a signing key is configured', async () => {
    const deps = makeDeps({ FP_SIGNING_KEY: 'test-signing-secret' })
    const { nonce } = await challenge(deps)
    const resp = await handleRequest(
      postIdentify({ nonce, stable_components: { ua: 'x' } }),
      deps,
    )
    expect(resp.status).toBe(200)

    const issuedMs = Number(resp.headers.get(SIGNATURE_TIMESTAMP_HEADER))
    const signature = resp.headers.get(SIGNATURE_HEADER)
    expect(signature).toMatch(/^[0-9a-f]{64}$/)

    // The advertised signature recomputes over the received timestamp + body.
    const bodyBytes = new Uint8Array(await resp.arrayBuffer())
    expect(deps.engine.sign(issuedMs, bodyBytes)).toBe(signature)

    // Tampering the body breaks the signature.
    const tampered = new Uint8Array([...bodyBytes, 0x20])
    expect(deps.engine.sign(issuedMs, tampered)).not.toBe(signature)
  })

  it('reproduces the shared signing vector', () => {
    // Ties the edge signer to the native `fp_core::signing::ResponseSigner`
    // (crates/fp-wasm `engine_sign_matches_shared_vector`): same signing key,
    // same timestamp + body, same hex — the response-signing analogue of the
    // probe parity vector, proving the signing Worker Secret path is identical.
    const engine = new EdgeEngine(
      resolveConfig({ FP_SIGNING_KEY: 'test-signing-secret' }),
    )
    const body = new TextEncoder().encode('{"visitorId":"abc"}')
    expect(engine.sign(1_700_000_000_000, body)).toBe(
      '11e764ff987d7be6e4f9e272c9c9fbb9c29fc8c5e3dcc5b935dfa11b9c751792',
    )
  })
})

describe('timestamp window', () => {
  const env: Env = { FP_ENFORCE_TS_WINDOW: '1', FP_TS_SKEW_SECS: '30' }

  it('accepts a fresh ts and rejects stale/future/missing', async () => {
    const deps = makeDeps(env)
    const now = Date.now()
    const send = async (extra: Record<string, unknown>) => {
      const { nonce } = await challenge(deps)
      return handleRequest(
        postIdentify({ nonce, stable_components: { ua: 'x' }, ...extra }),
        deps,
      )
    }
    expect((await send({ ts: now })).status).toBe(200)
    expect((await send({ ts: now - 60_000 })).status).toBe(401)
    expect((await send({ ts: now + 60_000 })).status).toBe(401)
    expect((await send({})).status).toBe(401)
  })
})

describe('passive signals (edge JA4/IP fusion)', () => {
  // Shared JA4/UA vectors, identical to the native `signals` tests
  // (crates/fingerprintd/src/signals.rs) so the edge verdict is provably the same.
  /** A JA4 whose structural counts read as a real browser (15 ciphers, 16 ext). */
  const BROWSER_JA4 = 't13d1516h2_8daaf6152771_02713d6af862'
  /** A JA4 whose counts read as a minimal automation stack (3/4). */
  const AUTOMATION_JA4 = 't13d0304h1_aaaaaaaaaaaa_bbbbbbbbbbbb'

  const postIdentifyWith = (body: unknown, headers: Record<string, string>) =>
    new Request('https://edge.test/identify', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
    })

  /** Run a full challenge→identify and return the parsed body. `probeComponents`
   *  reports a Chrome UA (`user_agent`), so a browser JA4 is consistent and an
   *  automation JA4 is the forgery. The candidate source is empty ⇒ the base
   *  score is identical across calls, so confidences are comparable. */
  async function identifyWith(
    deps: Deps,
    headers: Record<string, string>,
  ): Promise<IdentifyResponse> {
    const { nonce } = await challenge(deps)
    const resp = await handleRequest(
      postIdentifyWith(
        { nonce, stable_components: probeComponents() },
        headers,
      ),
      deps,
    )
    expect(resp.status).toBe(200)
    return (await resp.json()) as IdentifyResponse
  }

  const trustedDeps = () => makeDeps({ FP_TRUST_EDGE_HEADERS: '1' })

  it('trusted browser JA4 over a Chrome UA is consistent and boosts confidence', async () => {
    const deps = trustedDeps()
    // Degraded baseline: trusted edge, but no Bot Management header present.
    const degraded = await identifyWith(deps, {})
    expect(degraded.signals).toEqual({
      ua_tls_consistent: true,
      ip_risk: 'low',
      client_integrity: 'unavailable',
      persona_coherence: 'unknown',
      new_device_velocity: 'low',
      new_device_velocity_ja4: 'low',
    })

    const consistent = await identifyWith(deps, {
      'cf-bot-management-ja4': BROWSER_JA4,
    })
    expect(consistent.signals.ua_tls_consistent).toBe(true)
    // The consistency boost (fuzzy-matching §6) lifts confidence above the degraded base.
    expect(consistent.confidence).toBeGreaterThan(degraded.confidence)
  })

  it('trusted automation JA4 under a Chrome UA is a forgery: inconsistent + downgraded', async () => {
    const deps = trustedDeps()
    const degraded = await identifyWith(deps, {})
    const forgery = await identifyWith(deps, {
      'cf-bot-management-ja4': AUTOMATION_JA4,
    })
    // The anti-forgery core (architecture §4.2): Chrome UA riding an automation TLS stack.
    expect(forgery.signals.ua_tls_consistent).toBe(false)
    expect(forgery.confidence).toBeLessThan(degraded.confidence)
  })

  it('cf-connecting-ip drives the ip_risk band (datacenter high / residential low)', async () => {
    const deps = trustedDeps()
    const datacenter = await identifyWith(deps, {
      'cf-bot-management-ja4': BROWSER_JA4,
      'cf-connecting-ip': '34.120.5.6',
    })
    expect(datacenter.signals.ip_risk).toBe('high')

    const residential = await identifyWith(deps, {
      'cf-bot-management-ja4': BROWSER_JA4,
      'cf-connecting-ip': '198.51.100.7',
    })
    expect(residential.signals.ip_risk).toBe('low')

    // No IP header at all ⇒ low (no adverse evidence).
    const absent = await identifyWith(deps, {
      'cf-bot-management-ja4': BROWSER_JA4,
    })
    expect(absent.signals.ip_risk).toBe('low')
  })

  it('trusted edge with JA4 absent auto-degrades: consistent, low, no penalty', async () => {
    const deps = trustedDeps()
    const baseline = await identifyWith(deps, {})
    // IP present but Bot Management absent ⇒ degraded (neutral), IP still classified.
    const degraded = await identifyWith(deps, {
      'cf-connecting-ip': '198.51.100.7',
    })
    expect(degraded.signals.ua_tls_consistent).toBe(true)
    expect(degraded.signals.ip_risk).toBe('low')
    // A missing connection signal never penalises (§4.2 auto-degrade).
    expect(degraded.confidence).toBeCloseTo(baseline.confidence, 12)
  })

  it('untrusted edge ignores a forged client-supplied JA4/IP copy', async () => {
    // trustEdgeHeaders defaults OFF: a request-supplied automation JA4 +
    // datacenter IP must NOT be trusted — the untrusted path auto-degrades.
    const deps = makeDeps()
    const baseline = await identifyWith(deps, {})
    const forged = await identifyWith(deps, {
      'cf-bot-management-ja4': AUTOMATION_JA4,
      'cf-connecting-ip': '34.120.5.6',
    })
    expect(forged.signals).toEqual({
      ua_tls_consistent: true,
      ip_risk: 'low',
      client_integrity: 'unavailable',
      persona_coherence: 'unknown',
      new_device_velocity: 'low',
      new_device_velocity_ja4: 'low',
    })
    // The forged copy neither downgrades confidence nor raises the IP band.
    expect(forged.confidence).toBeCloseTo(baseline.confidence, 12)
  })
})

describe('ASN IP-risk band (edge cf enrichment)', () => {
  const BROWSER_JA4 = 't13d1516h2_8daaf6152771_02713d6af862'

  /** Build an /identify request with an optional Cloudflare `cf` enrichment
   *  object attached (the field the Worker runtime injects; absent in the base
   *  Request), so `cfAsn` has an ASN to read on the trusted path. */
  const postIdentifyCf = (
    body: unknown,
    headers: Record<string, string>,
    cf?: Record<string, unknown>,
  ) => {
    const req = new Request('https://edge.test/identify', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
    })
    if (cf) (req as unknown as { cf: unknown }).cf = cf
    return req
  }

  async function identifyCf(
    deps: Deps,
    headers: Record<string, string>,
    cf?: Record<string, unknown>,
  ): Promise<IdentifyResponse> {
    const { nonce } = await challenge(deps)
    const resp = await handleRequest(
      postIdentifyCf(
        { nonce, stable_components: probeComponents() },
        headers,
        cf,
      ),
      deps,
    )
    expect(resp.status).toBe(200)
    return (await resp.json()) as IdentifyResponse
  }

  const trustedDeps = () => makeDeps({ FP_TRUST_EDGE_HEADERS: '1' })

  it('raises ip_risk to high for a hosting ASN whose IP is outside the CIDR table', async () => {
    const deps = trustedDeps()
    // Residential-looking IP (WASM band `low`, outside fp-core's CIDR table) but
    // a curated hosting ASN (AWS 16509) → the ASN reputation raises the surfaced
    // band to `high` (max(wasmBand, asnBand)).
    const body = await identifyCf(
      deps,
      {
        'cf-bot-management-ja4': BROWSER_JA4,
        'cf-connecting-ip': '198.51.100.7',
      },
      { asn: 16509, asOrganization: 'AMAZON-02' },
    )
    expect(body.signals.ip_risk).toBe('high')
  })

  it('keeps the WASM band for a residential ASN', async () => {
    const deps = trustedDeps()
    // A non-hosting residential ASN (Comcast 7922) never bumps the band — the
    // ASN can only raise, so the WASM `low` is preserved.
    const body = await identifyCf(
      deps,
      {
        'cf-bot-management-ja4': BROWSER_JA4,
        'cf-connecting-ip': '198.51.100.7',
      },
      { asn: 7922, asOrganization: 'COMCAST-7922' },
    )
    expect(body.signals.ip_risk).toBe('low')
  })

  it('never reads cf on an untrusted edge (hosting ASN ignored)', async () => {
    // trustEdgeHeaders defaults OFF: even a hosting cf.asn + datacenter IP must
    // be ignored — the untrusted path returns the neutral degraded verdict and
    // never touches `cf`.
    const deps = makeDeps()
    const body = await identifyCf(
      deps,
      {
        'cf-bot-management-ja4': BROWSER_JA4,
        'cf-connecting-ip': '34.120.5.6',
      },
      { asn: 16509, asOrganization: 'AMAZON-02' },
    )
    expect(body.signals).toEqual({
      ua_tls_consistent: true,
      ip_risk: 'low',
      client_integrity: 'unavailable',
      persona_coherence: 'unknown',
      new_device_velocity: 'low',
      new_device_velocity_ja4: 'low',
    })
  })
})

describe('new-device velocity (edge DO band)', () => {
  const BROWSER_JA4 = 't13d1516h2_8daaf6152771_02713d6af862'

  /** A fake {@link NewDeviceVelocityStore} returning fixed counts and recording
   *  the keys/args it was called with, so a test can assert the derived band and
   *  the JA4-class key derivation without a live Durable Object. */
  class FakeVelocity implements NewDeviceVelocityStore {
    ipCalls: Array<[string, string, number]> = []
    ja4Calls: Array<[string, string, number]> = []
    constructor(
      private readonly ipCount: number,
      private readonly ja4Count: number,
    ) {}
    newDeviceVelocityIp(ip: string, v: string, w: number): Promise<number> {
      this.ipCalls.push([ip, v, w])
      return Promise.resolve(this.ipCount)
    }
    newDeviceVelocityJa4(cls: string, v: string, w: number): Promise<number> {
      this.ja4Calls.push([cls, v, w])
      return Promise.resolve(this.ja4Count)
    }
  }

  /** A store that always throws, to exercise the fail-open path. */
  class ThrowingVelocity implements NewDeviceVelocityStore {
    newDeviceVelocityIp(): Promise<number> {
      return Promise.reject(new Error('DO unavailable'))
    }
    newDeviceVelocityJa4(): Promise<number> {
      return Promise.reject(new Error('DO unavailable'))
    }
  }

  const trustedDepsWith = (velocity?: NewDeviceVelocityStore): Deps => ({
    ...makeDeps({ FP_TRUST_EDGE_HEADERS: '1' }),
    velocity,
  })

  /** Full challenge→identify (empty candidate source ⇒ always a new device). */
  async function identify(
    deps: Deps,
    headers: Record<string, string>,
  ): Promise<IdentifyResponse> {
    const { nonce } = await challenge(deps)
    const resp = await handleRequest(
      new Request('https://edge.test/identify', {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify({
          nonce,
          stable_components: probeComponents(),
        }),
      }),
      deps,
    )
    expect(resp.status).toBe(200)
    return (await resp.json()) as IdentifyResponse
  }

  it('bands a new device from the DO-backed counts on a NewDevice verdict', async () => {
    // HIGH per-IP count (20) and MEDIUM per-JA4-class count (100).
    const velocity = new FakeVelocity(20, 100)
    const deps = trustedDepsWith(velocity)
    const body = await identify(deps, {
      'cf-bot-management-ja4': BROWSER_JA4,
      'cf-connecting-ip': '198.51.100.7',
    })
    expect(body.is_new_device).toBe(true)
    expect(body.signals.new_device_velocity).toBe('high')
    expect(body.signals.new_device_velocity_ja4).toBe('medium')
    // Keyed on the edge-observed IP and the coarse JA4 shape class (the
    // `(protocol, tls_version, sni, alpn)` shape, mirroring `ja4_class`), over
    // the 3600s window, member = the minted visitorId.
    expect(velocity.ipCalls[0]).toEqual([
      '198.51.100.7',
      body.visitorId,
      3600 * 1000,
    ])
    expect(velocity.ja4Calls[0]).toEqual([
      't13dh2',
      body.visitorId,
      3600 * 1000,
    ])
  })

  it('fails open to low when no velocity binding is present', async () => {
    // Trusted headers + a new device, but the binding is unbound (undefined).
    const body = await identify(trustedDepsWith(undefined), {
      'cf-bot-management-ja4': BROWSER_JA4,
      'cf-connecting-ip': '198.51.100.7',
    })
    expect(body.signals.new_device_velocity).toBe('low')
    expect(body.signals.new_device_velocity_ja4).toBe('low')
  })

  it('fails open to low when the DO throws', async () => {
    const body = await identify(trustedDepsWith(new ThrowingVelocity()), {
      'cf-bot-management-ja4': BROWSER_JA4,
      'cf-connecting-ip': '198.51.100.7',
    })
    // A DO error must never block or error the request — it degrades to neutral.
    expect(body.signals.new_device_velocity).toBe('low')
    expect(body.signals.new_device_velocity_ja4).toBe('low')
  })

  it('stays neutral on an untrusted edge (velocity never keyed on forged headers)', async () => {
    // trustEdgeHeaders OFF: even with a velocity store, the client-supplied
    // IP/JA4 are untrusted, so no velocity is recorded (mirrors native's None).
    const velocity = new FakeVelocity(20, 100)
    const deps: Deps = { ...makeDeps(), velocity }
    const body = await identify(deps, {
      'cf-bot-management-ja4': BROWSER_JA4,
      'cf-connecting-ip': '198.51.100.7',
    })
    expect(body.signals.new_device_velocity).toBe('low')
    expect(body.signals.new_device_velocity_ja4).toBe('low')
    expect(velocity.ipCalls).toHaveLength(0)
    expect(velocity.ja4Calls).toHaveLength(0)
  })
})

describe('DELETE /visitor/:id erasure (M6b)', () => {
  /** Deps with an injected candidate source whose `erase` is spy-able. */
  function eraseDeps(env: Env = {}) {
    const candidates = new EmptyCandidateSource()
    const erase = vi.spyOn(candidates, 'erase')
    return { deps: { ...makeDeps(env), candidates }, erase }
  }

  const del = (id: string, headers: Record<string, string> = {}) =>
    new Request(`https://edge.test/visitor/${id}`, {
      method: 'DELETE',
      headers,
    })

  it('returns 404 when no admin key is configured (endpoint disabled)', async () => {
    const { deps, erase } = eraseDeps()
    const resp = await handleRequest(
      del('v1', { authorization: 'Bearer x' }),
      deps,
    )
    expect(resp.status).toBe(404)
    expect(erase).not.toHaveBeenCalled()
  })

  it('returns 401 on a missing or wrong bearer credential', async () => {
    const { deps, erase } = eraseDeps({ FP_ADMIN_KEY: 'admin-secret' })
    // Missing header.
    expect((await handleRequest(del('v1'), deps)).status).toBe(401)
    // Wrong key.
    expect(
      (await handleRequest(del('v1', { authorization: 'Bearer nope' }), deps))
        .status,
    ).toBe(401)
    // Not a bearer scheme.
    expect(
      (await handleRequest(del('v1', { authorization: 'admin-secret' }), deps))
        .status,
    ).toBe(401)
    expect(erase).not.toHaveBeenCalled()
  })

  it('returns 204 and erases the visitor when authorized', async () => {
    const { deps, erase } = eraseDeps({ FP_ADMIN_KEY: 'admin-secret' })
    const resp = await handleRequest(
      del('visitor-42', { authorization: 'Bearer admin-secret' }),
      deps,
    )
    expect(resp.status).toBe(204)
    expect(erase).toHaveBeenCalledWith('visitor-42')
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

  it('reflects an allowed origin and exposes the signature headers', async () => {
    const resp = await handleRequest(
      withOrigin('/challenge', ORIGIN),
      corsDeps(),
    )
    expect(resp.status).toBe(200)
    expect(resp.headers.get('access-control-allow-origin')).toBe(ORIGIN)
    expect(
      resp.headers.get('access-control-expose-headers')?.toLowerCase(),
    ).toContain(SIGNATURE_HEADER)
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

describe('client integrity probes (top-level `integrity`, shared WASM verdict)', () => {
  const allNoise = {
    canvas: 'noise',
    webgl: 'noise',
    audio: 'noise',
    rect: 'noise',
  }
  const allOk = { canvas: 'ok', webgl: 'ok', audio: 'ok', rect: 'ok' }

  /** Identify a fixed probe on FRESH deps (identical base confidence) with an
   *  optional top-level `integrity`, returning the body. */
  async function identifyIntegrity(
    env: Env,
    integrity?: Record<string, unknown>,
  ): Promise<IdentifyResponse> {
    const deps = makeDeps(env)
    const { nonce } = await challenge(deps)
    const body: Record<string, unknown> = {
      nonce,
      stable_components: probeComponents(),
    }
    if (integrity !== undefined) body.integrity = integrity
    const resp = await handleRequest(postIdentify(body), deps)
    expect(resp.status).toBe(200)
    return (await resp.json()) as IdentifyResponse
  }

  it('surfaces noise without moving confidence by default', async () => {
    const base = await identifyIntegrity({})
    const noisy = await identifyIntegrity({}, allNoise)
    expect(base.signals.client_integrity).toBe('unavailable')
    expect(noisy.signals.client_integrity).toBe('noise')
    expect(noisy.confidence).toBe(base.confidence)
  })

  it('downgrades confidence on noise only when the penalty is enabled', async () => {
    const env: Env = { FP_INTEGRITY_PENALTY_ENABLED: '1' }
    const base = await identifyIntegrity(env)
    const noisy = await identifyIntegrity(env, allNoise)
    expect(noisy.signals.client_integrity).toBe('noise')
    expect(noisy.confidence).toBeLessThan(base.confidence)
    const clean = await identifyIntegrity(env, allOk)
    expect(clean.signals.client_integrity).toBe('ok')
    expect(clean.confidence).toBe(base.confidence)
  })

  it('reads malformed material as unavailable (neutral), never as noise', async () => {
    const env: Env = { FP_INTEGRITY_PENALTY_ENABLED: '1' }
    const base = await identifyIntegrity(env)
    const malformed = await identifyIntegrity(env, {
      canvas: 1,
      other: 'noise',
    })
    expect(malformed.signals.client_integrity).toBe('unavailable')
    expect(malformed.confidence).toBe(base.confidence)
  })
})

describe('persona coherence (UA OS family vs fonts, shared WASM label)', () => {
  const WINDOWS_UA =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'

  /** An SDK-shaped payload: the UA rides under botd, not as a top-level key. */
  function sdkLike(fonts: unknown): Record<string, unknown> {
    return {
      platform: 'Win32',
      fonts,
      botd: { signals: { userAgent: { value: WINDOWS_UA, state: 0 } } },
    }
  }

  async function identifyComponents(
    components: Record<string, unknown>,
  ): Promise<IdentifyResponse> {
    const deps = makeDeps()
    const { nonce } = await challenge(deps)
    const resp = await handleRequest(
      postIdentify({ nonce, stable_components: components }),
      deps,
    )
    expect(resp.status).toBe(200)
    return (await resp.json()) as IdentifyResponse
  }

  it('flags a Windows UA with no Windows core fonts as a mismatch, surfaced-only', async () => {
    const mismatch = await identifyComponents(sdkLike(['Arial', 'Courier New']))
    const consistent = await identifyComponents(sdkLike(['Calibri']))
    expect(mismatch.signals.persona_coherence).toBe('mismatch')
    expect(consistent.signals.persona_coherence).toBe('consistent')
    expect(mismatch.confidence).toBe(consistent.confidence)
  })

  it('reads unknown without a fonts array or a curated OS family', async () => {
    const noFonts = await identifyComponents(sdkLike(undefined))
    expect(noFonts.signals.persona_coherence).toBe('unknown')
    const linux = await identifyComponents({
      ...sdkLike([]),
      botd: {
        signals: {
          userAgent: {
            value: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/149',
            state: 0,
          },
        },
      },
    })
    expect(linux.signals.persona_coherence).toBe('unknown')
  })
})
