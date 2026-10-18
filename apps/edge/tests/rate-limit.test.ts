import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import type { Deps } from '../src/app'
import { createApp } from '../src/app'
import { resolveConfig } from '../src/config'
import {
  EdgeEngine,
  initEngineRuntime,
} from '../src/modules/fingerprint/engine'
import { FakeRateLimiter, fakeStores } from './helpers/fakes'

// Per-IP rate limiting: `/identify` + `/checkin/assess` share one limiter and
// `/challenge` has its own, so neither can drain the other's bucket. A denied key
// short-circuits with 429 before any store is touched; `/health` is never limited.
beforeAll(() => {
  const wasmPath = fileURLToPath(
    new URL('../wasm/fp_wasm_bg.wasm', import.meta.url).href,
  )
  initEngineRuntime(readFileSync(wasmPath))
})

function makeDeps(
  rateLimiter: FakeRateLimiter,
  challengeRateLimiter = new FakeRateLimiter(),
): Deps {
  const config = resolveConfig({ FP_SALT_SECRET: 'test-salt' })
  return {
    engine: new EdgeEngine(config),
    config,
    ...fakeStores(config.nonceTtlSecs),
    rateLimiter,
    challengeRateLimiter,
  }
}

const post = (path: string, headers: Record<string, string> = {}) =>
  new Request(`https://edge.test${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify({}),
  })

const get = (path: string, headers: Record<string, string> = {}) =>
  new Request(`https://edge.test${path}`, { headers })

describe('per-IP rate limit', () => {
  it('returns 429 on /identify without consuming a nonce when denied', async () => {
    const deps = makeDeps(new FakeRateLimiter(false))
    const consume = vi.spyOn(deps.nonces, 'consume')
    const recall = vi.spyOn(deps.candidates, 'recall')
    const resp = await createApp(deps).request(post('/identify'))
    expect(resp.status).toBe(429)
    expect(consume).not.toHaveBeenCalled()
    expect(recall).not.toHaveBeenCalled()
  })

  it('returns 429 on /checkin/assess without touching the store when denied', async () => {
    const deps = makeDeps(new FakeRateLimiter(false))
    const record = vi.spyOn(deps.checkin, 'record')
    const aggregates = vi.spyOn(deps.checkin, 'getAggregates')
    const resp = await createApp(deps).request(post('/checkin/assess'))
    expect(resp.status).toBe(429)
    expect(record).not.toHaveBeenCalled()
    expect(aggregates).not.toHaveBeenCalled()
  })

  it('passes through to the route when allowed', async () => {
    const limiter = new FakeRateLimiter(true)
    const app = createApp(makeDeps(limiter))
    // An empty body is a validation error, proving the route itself ran.
    expect((await app.request(post('/identify'))).status).toBe(400)
    expect((await app.request(post('/checkin/assess'))).status).toBe(400)
    expect(limiter.keys).toHaveLength(2)
  })

  it('keys on the trimmed cf-connecting-ip, else "unknown"', async () => {
    const limiter = new FakeRateLimiter(true)
    const app = createApp(makeDeps(limiter))
    await app.request(
      post('/identify', { 'cf-connecting-ip': ' 203.0.113.9 ' }),
    )
    await app.request(post('/checkin/assess'))
    expect(limiter.keys).toEqual(['203.0.113.9', 'unknown'])
  })

  it('returns 429 on /challenge without issuing a nonce when denied', async () => {
    const deps = makeDeps(new FakeRateLimiter(), new FakeRateLimiter(false))
    const issue = vi.spyOn(deps.nonces, 'issue')
    const resp = await createApp(deps).request(get('/challenge'))
    expect(resp.status).toBe(429)
    expect(await resp.text()).toBe('too many requests')
    expect(issue).not.toHaveBeenCalled()
  })

  it('keys /challenge on the trimmed cf-connecting-ip, else "unknown"', async () => {
    const challenge = new FakeRateLimiter()
    const app = createApp(makeDeps(new FakeRateLimiter(), challenge))
    await app.request(
      get('/challenge', { 'cf-connecting-ip': ' 203.0.113.9 ' }),
    )
    await app.request(get('/challenge'))
    expect(challenge.keys).toEqual(['203.0.113.9', 'unknown'])
  })

  it('keeps /challenge and /identify in separate buckets', async () => {
    const identify = new FakeRateLimiter(false)
    const challenge = new FakeRateLimiter()
    const app = createApp(makeDeps(identify, challenge))
    expect((await app.request(get('/challenge'))).status).toBe(200)
    expect(identify.keys).toHaveLength(0)
    expect(challenge.keys).toHaveLength(1)

    const identifyOpen = new FakeRateLimiter()
    const challengeShut = new FakeRateLimiter(false)
    const app2 = createApp(makeDeps(identifyOpen, challengeShut))
    expect((await app2.request(post('/identify'))).status).toBe(400)
    expect((await app2.request(post('/checkin/assess'))).status).toBe(400)
    expect(challengeShut.keys).toHaveLength(0)
    expect(identifyOpen.keys).toHaveLength(2)
  })

  it('never limits /health', async () => {
    const identify = new FakeRateLimiter(false)
    const challenge = new FakeRateLimiter(false)
    const app = createApp(makeDeps(identify, challenge))
    expect((await app.request(get('/health'))).status).toBe(200)
    expect(identify.keys).toHaveLength(0)
    expect(challenge.keys).toHaveLength(0)
  })
})
