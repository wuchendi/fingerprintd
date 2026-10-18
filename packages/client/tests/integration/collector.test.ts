/**
 * FULL collector assembly. Proves `createCollector` composes the stable half
 * and the integrity probes into ONE payload and that `run()` forwards every
 * field to `/identify` as a Contract v1 top-level key, with `components` and
 * `integrity` kept separate.
 *
 * There is no headless browser here, so every backend is injected with a
 * deterministic fake — this exercises the wiring, not real fingerprint values.
 */

import { describe, expect, it } from 'vitest'
import { createCollector } from '../../src/collector'
import type { BotdDetector, FingerprintAgent } from '../../src/fingerprint'
import { run } from '../../src/index'
import type { Integrity } from '../../src/integrity'
import type { RecordedRequest } from '../helpers'
import {
  IDENTIFY_REQUEST_KEYS,
  mockFetch,
  sampleChallenge,
  sampleIdentify,
} from '../helpers'

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
    })
}

const fakeIntegrity: Integrity = {
  canvas: 'noise',
  webgl: 'ok',
  audio: 'ok',
  rect: 'unavailable',
}

const deps = {
  fingerprint: {
    loadFingerprint: fakeFingerprint({ platform: { value: 'Win32' } }),
    loadBotd: fakeBotd(),
    userAgent: () => 'Chrome/120',
  },
  integrity: () => Promise.resolve(fakeIntegrity),
}

describe('createCollector', () => {
  it('assembles components, user_agent, botd and integrity, kept separate', async () => {
    const collected = await createCollector(deps)()

    expect(collected).toEqual({
      components: { platform: 'Win32' },
      user_agent: 'Chrome/120',
      botd: { bot: false },
      integrity: fakeIntegrity,
    })
  })

  it('reports every probe unavailable where the browser APIs are missing', async () => {
    // jsdom has no 2d/webgl canvas, no OfflineAudioContext and no layout, so
    // the DEFAULT integrity backend must degrade to `unavailable` (neutral
    // server-side) rather than throw or report `noise`.
    const collected = await createCollector({
      fingerprint: deps.fingerprint,
    })()
    expect(collected.integrity).toEqual({
      canvas: 'unavailable',
      webgl: 'unavailable',
      audio: 'unavailable',
      rect: 'unavailable',
    })
  })

  it('run() forwards every field as a Contract v1 top-level key', async () => {
    const recorded: RecordedRequest[] = []
    const fetch = mockFetch(
      {
        challenge: { body: sampleChallenge() },
        identify: { body: sampleIdentify() },
      },
      recorded,
    )

    await run({
      baseUrl: 'https://fp.example.com',
      collect: createCollector(deps),
      fetch,
    })

    const identifyRequest = recorded.find((r) => r.url.endsWith('/identify'))
    const sent = JSON.parse(identifyRequest?.body ?? '{}')
    expect(Object.keys(sent).sort()).toEqual([...IDENTIFY_REQUEST_KEYS].sort())
    expect(sent.nonce).toBe('nonce-abc')
    expect(sent.ts).toBeTypeOf('number')
    expect(sent.components).toEqual({ platform: 'Win32' })
    expect(sent.user_agent).toBe('Chrome/120')
    expect(sent.botd).toEqual({ bot: false })
    expect(sent.integrity).toEqual(fakeIntegrity)
  })
})
