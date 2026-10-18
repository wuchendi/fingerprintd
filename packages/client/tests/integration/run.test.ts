import { describe, expect, it } from 'vitest'
import type { Collector } from '../../src/collect'
import { run } from '../../src/index'
import type { RecordedRequest } from '../helpers'
import {
  IDENTIFY_REQUEST_KEYS,
  mockFetch,
  sampleChallenge,
  sampleIdentify,
} from '../helpers'

function sentIdentify(recorded: RecordedRequest[]): Record<string, unknown> {
  const request = recorded.find((r) => r.url.endsWith('/identify'))
  return JSON.parse(request?.body ?? '{}')
}

describe('run', () => {
  it('drives challenge -> collect -> identify and returns the response', async () => {
    const recorded: RecordedRequest[] = []
    const fetch = mockFetch(
      {
        challenge: { body: sampleChallenge() },
        identify: { body: sampleIdentify() },
      },
      recorded,
    )
    const collect: Collector = () =>
      Promise.resolve({
        components: { platform: 'Win32', fonts: ['Arial'] },
        user_agent: 'Chrome/120',
        botd: { bot: true, kind: 'headless_chrome' },
        integrity: { canvas: 'ok', webgl: 'ok', audio: 'ok', rect: 'ok' },
      })

    const before = Date.now()
    const result = await run({
      baseUrl: 'https://fp.example.com',
      collect,
      fetch,
    })

    expect(result).toEqual(sampleIdentify())
    expect(result.request_id).toMatch(/^[0-9a-f]{32}$/)

    const sent = sentIdentify(recorded)
    expect(Object.keys(sent).sort()).toEqual([...IDENTIFY_REQUEST_KEYS].sort())
    expect(sent.nonce).toBe('nonce-abc')
    expect(sent.ts).toBeTypeOf('number')
    expect(sent.ts as number).toBeGreaterThanOrEqual(before)
    expect(sent.components).toEqual({ platform: 'Win32', fonts: ['Arial'] })
    expect(sent.user_agent).toBe('Chrome/120')
    expect(sent.botd).toEqual({ bot: true, kind: 'headless_chrome' })
  })

  it('omits optional fields the collector left unset but always sends ts', async () => {
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
      collect: () => Promise.resolve({ components: {} }),
      fetch,
    })

    const sent = sentIdentify(recorded)
    expect(Object.keys(sent).sort()).toEqual(['components', 'nonce', 'ts'])
    expect(sent.ts).toBeTypeOf('number')
  })
})
