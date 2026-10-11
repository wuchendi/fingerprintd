/**
 * FULL collector assembly. Proves `createCollector` composes the stable
 * half + probe + `ts` + `integrity` into ONE payload and that `run()` forwards
 * every field to `/identify`, with `stable_components`, `probe` and `integrity`
 * kept SEPARATE.
 *
 * There is no headless browser here, so every backend is injected with a
 * deterministic fake — this exercises the WIRING, not real fingerprint values.
 * A final case uses the real vendored WASM to prove the probe flows end-to-end.
 */

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { createCollector } from '../../src/collector'
import type { BotdDetector, FingerprintAgent } from '../../src/fingerprint'
import { run } from '../../src/index'
import type { Integrity } from '../../src/integrity'
import { initProbe } from '../../src/probe'
import type { ChallengeResponse } from '../../src/types'
import type { RecordedRequest } from '../helpers'
import { mockFetch, sampleIdentify } from '../helpers'

function fakeFingerprint(
  components: Record<string, unknown>,
): () => Promise<FingerprintAgent> {
  return () =>
    Promise.resolve({
      get: () => Promise.resolve({ visitorId: 'DISCARDED', components }),
    })
}

function fakeBotd(): () => Promise<BotdDetector> {
  return () =>
    Promise.resolve({
      collect: () => Promise.resolve(undefined),
      detect: () => ({ bot: false }),
      getComponents: () => ({ webdriver: false }),
    })
}

/** A challenge that advertises the probe transform (server has a probe key). */
function challengeWithVerify(): ChallengeResponse {
  return {
    nonce: 'nonce-abc',
    expires_in: 30,
    collect: {
      stable: ['userAgent'],
      challenge: {
        seed: 'nonce-abc',
        targets: ['canvas', 'audio'],
        verify: { alg: 'HMAC-SHA256', input: 'nonce', encoding: 'hex' },
      },
    },
  }
}

/** Same challenge but WITHOUT a probe transform (server has no probe key). */
function challengeNoVerify(): ChallengeResponse {
  const challenge = challengeWithVerify()
  challenge.collect.challenge.verify = undefined
  return challenge
}

const fakeIntegrity: Integrity = {
  canvas: 'noise',
  webgl: 'ok',
  audio: 'ok',
  rect: 'unavailable',
}

const deps = {
  fingerprint: {
    loadFingerprint: fakeFingerprint({ ua: { value: 'Chrome/120' } }),
    loadBotd: fakeBotd(),
  },
  integrity: () => Promise.resolve(fakeIntegrity),
}

describe('createCollector', () => {
  it('assembles stable + probe + ts, kept separate', async () => {
    const collector = createCollector({
      ...deps,
      probe: (nonce) => Promise.resolve(`probe:${nonce}`),
      now: () => 1_700_000_000_123,
    })

    const collected = await collector(challengeWithVerify())

    // Stable half: component adapted to the server schema (`ua` is an
    // unmapped scalar, so the FJS `{ value }` wrapper is unwrapped), probe NOT
    // mixed in.
    expect(collected.stable_components.ua).toBe('Chrome/120')
    expect(JSON.stringify(collected.stable_components)).not.toContain('probe:')
    // Probe + ts + integrity stamped, separate from the matching input.
    expect(collected.probe).toBe('probe:nonce-abc')
    expect(collected.ts).toBe(1_700_000_000_123)
    expect(collected.integrity).toEqual(fakeIntegrity)
    expect(JSON.stringify(collected.stable_components)).not.toContain('noise')
  })

  it('reports every probe unavailable where the browser APIs are missing', async () => {
    // jsdom has no 2d/webgl canvas, no OfflineAudioContext and no layout, so
    // the DEFAULT integrity backend must degrade to `unavailable` (neutral
    // server-side) rather than throw or report `noise`.
    const collector = createCollector({ fingerprint: deps.fingerprint })
    const collected = await collector(challengeNoVerify())
    expect(collected.integrity).toEqual({
      canvas: 'unavailable',
      webgl: 'unavailable',
      audio: 'unavailable',
      rect: 'unavailable',
    })
  })

  it('omits the probe when the challenge does not advertise verify', async () => {
    let probeCalls = 0
    const collector = createCollector({
      ...deps,
      probe: (nonce) => {
        probeCalls++
        return Promise.resolve(`probe:${nonce}`)
      },
    })

    const collected = await collector(challengeNoVerify())

    expect(collected.probe).toBeUndefined()
    expect(probeCalls).toBe(0)
    // The stable half + ts are still produced.
    expect(collected.stable_components.ua).toBe('Chrome/120')
    expect(collected.ts).toBeTypeOf('number')
  })

  it('run() forwards nonce, ts, probe, integrity and stable_components', async () => {
    const recorded: RecordedRequest[] = []
    const fetch = mockFetch(
      {
        challenge: { body: challengeWithVerify() },
        identify: { body: sampleIdentify() },
      },
      recorded,
    )

    await run({
      baseUrl: 'https://fp.example.com',
      collect: createCollector({
        ...deps,
        probe: (nonce) => Promise.resolve(`probe:${nonce}`),
        now: () => 1_700_000_000_123,
      }),
      fetch,
    })

    const identifyRequest = recorded.find((r) => r.url.endsWith('/identify'))
    const sent = JSON.parse(identifyRequest?.body ?? '{}')
    expect(sent.nonce).toBe('nonce-abc')
    expect(sent.ts).toBe(1_700_000_000_123)
    expect(sent.probe).toBe('probe:nonce-abc')
    expect(sent.stable_components.ua).toBe('Chrome/120')
    // Top-level, never nested under the matching input.
    expect(sent.integrity).toEqual(fakeIntegrity)
    expect(sent.stable_components.integrity).toBeUndefined()
  })

  it('computes the real WASM probe end-to-end (vendored dev key)', async () => {
    // Pre-init the WASM singleton with the vendored bytes so the default
    // `wasmProbeFn` resolves without a browser URL fetch.
    const wasmPath = resolve(process.cwd(), 'wasm/fp_wasm_bg.wasm')
    await initProbe(new Uint8Array(readFileSync(wasmPath)))

    // No `probe` injected -> the default WASM probe is used.
    const collector = createCollector(deps)
    const collected = await collector(challengeWithVerify())

    // Vendored wasm is keyed with the vector secret -> matches the shared vector
    // for the challenge nonce would only hold for "fixed-nonce-000"; here we just
    // assert a well-formed hex digest bound to the nonce.
    expect(collected.probe).toMatch(/^[0-9a-f]{64}$/)
  })
})
