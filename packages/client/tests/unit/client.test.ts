import { describe, expect, it } from 'vitest'
import { getChallenge, identify } from '../../src/client'
import type { IdentifyRequest } from '../../src/types'
import type { RecordedRequest } from '../helpers'
import { mockFetch, sampleChallenge, sampleIdentify } from '../helpers'

describe('getChallenge', () => {
  it('fetches and parses the challenge body', async () => {
    const recorded: RecordedRequest[] = []
    const fetch = mockFetch(
      { challenge: { body: sampleChallenge() } },
      recorded,
    )

    const challenge = await getChallenge('https://fp.example.com/', { fetch })

    expect(challenge).toEqual({ nonce: 'nonce-abc', expires_in: 30 })
    // Trailing slash collapsed, GET to /challenge.
    expect(recorded[0]?.url).toBe('https://fp.example.com/challenge')
    expect(recorded[0]?.method).toBe('GET')
  })

  it('throws on a non-ok status', async () => {
    const fetch = mockFetch({ challenge: { status: 500, body: {} } })
    await expect(
      getChallenge('https://fp.example.com', { fetch }),
    ).rejects.toThrow('GET /challenge failed: 500')
  })
})

describe('identify', () => {
  it('posts the body verbatim and returns the parsed response', async () => {
    const recorded: RecordedRequest[] = []
    const fetch = mockFetch({ identify: { body: sampleIdentify() } }, recorded)

    const body: IdentifyRequest = {
      nonce: 'n1',
      ts: 1_700_000_000_000,
      components: { platform: 'Win32', cpu_cores: 8 },
      user_agent: 'Chrome/120',
      botd: { bot: false },
      integrity: { canvas: 'ok', webgl: 'ok', audio: 'ok', rect: 'ok' },
    }
    const result = await identify('https://fp.example.com', body, { fetch })

    expect(JSON.parse(recorded[0]?.body ?? '{}')).toEqual(body)
    expect(recorded[0]?.url).toBe('https://fp.example.com/identify')
    expect(recorded[0]?.method).toBe('POST')
    expect(result).toEqual(sampleIdentify())
  })

  it('throws on a non-ok status', async () => {
    const fetch = mockFetch({ identify: { status: 400, body: {} } })
    await expect(
      identify(
        'https://fp.example.com',
        { nonce: 'n1', ts: 1, components: {} },
        { fetch },
      ),
    ).rejects.toThrow('POST /identify failed: 400')
  })
})
