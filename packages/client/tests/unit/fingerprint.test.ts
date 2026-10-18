/**
 * Unit tests for the STABLE-half collector. There is NO headless browser here,
 * so FingerprintJS/BotD are MOCKED: we inject fake loaders (and, once, mock the
 * modules themselves) and assert the wiring, never real fingerprint values.
 *
 * Contract under test:
 *  - FingerprintJS components are adapted into closed-schema `components`;
 *  - the FingerprintJS `visitorId`/hash is DISCARDED (never in the payload);
 *  - BotD's verdict maps to `{ bot, kind? }`;
 *  - the user agent rides as `user_agent`.
 */

import { describe, expect, it, vi } from 'vitest'
import type { BotdDetector, FingerprintAgent } from '../../src/fingerprint'
import { createFingerprintCollector } from '../../src/fingerprint'

/** A fake FingerprintJS agent returning canned components + a hash to discard. */
function fakeFingerprint(
  components: Record<string, unknown>,
  visitorId = 'HASH_SHOULD_BE_DISCARDED',
): () => Promise<FingerprintAgent> {
  return () =>
    Promise.resolve({ get: () => Promise.resolve({ visitorId, components }) })
}

/** A fake BotD detector recording call order and returning a canned verdict. */
function fakeBotd(
  detection: { bot: boolean; botKind?: string },
  order: string[] = [],
): () => Promise<BotdDetector> {
  return () =>
    Promise.resolve({
      collect: () => {
        order.push('collect')
        return Promise.resolve(undefined)
      },
      detect: () => {
        order.push('detect')
        return detection
      },
    })
}

describe('createFingerprintCollector', () => {
  it('adapts FingerprintJS components into the closed schema', async () => {
    const collect = createFingerprintCollector({
      loadFingerprint: fakeFingerprint({
        fonts: { value: ['Arial'], duration: 3 },
        timezone: { value: 'UTC', duration: 1 },
        colorDepth: { value: 24, duration: 0 },
      }),
      loadBotd: fakeBotd({ bot: false }),
    })

    const { components } = await collect()

    expect(components).toEqual({ fonts: ['Arial'], timezone: 'UTC' })
  })

  it('discards the FingerprintJS visitorId/hash (never in the payload)', async () => {
    const collect = createFingerprintCollector({
      loadFingerprint: fakeFingerprint(
        { platform: { value: 'x' } },
        'v_client_side',
      ),
      loadBotd: fakeBotd({ bot: false }),
    })

    const collected = await collect()

    expect(JSON.stringify(collected)).not.toContain('v_client_side')
  })

  it('maps a BotD detection to { bot: true, kind }', async () => {
    const order: string[] = []
    const collect = createFingerprintCollector({
      loadFingerprint: fakeFingerprint({}),
      loadBotd: fakeBotd({ bot: true, botKind: 'headless_chrome' }, order),
    })

    const { botd } = await collect()

    expect(botd).toEqual({ bot: true, kind: 'headless_chrome' })
    // detect() must run only after collect() gathered sources.
    expect(order).toEqual(['collect', 'detect'])
  })

  it('maps a clean BotD verdict to { bot: false }', async () => {
    const collect = createFingerprintCollector({
      loadFingerprint: fakeFingerprint({}),
      loadBotd: fakeBotd({ bot: false }),
    })

    expect((await collect()).botd).toEqual({ bot: false })
  })

  it('emits the injected user agent and no other top-level keys', async () => {
    const collect = createFingerprintCollector({
      loadFingerprint: fakeFingerprint({}),
      loadBotd: fakeBotd({ bot: false }),
      userAgent: () => 'Chrome/120',
    })

    const collected = await collect()

    expect(collected.user_agent).toBe('Chrome/120')
    expect(Object.keys(collected).sort()).toEqual([
      'botd',
      'components',
      'user_agent',
    ])
  })

  it('omits user_agent when none is available', async () => {
    const collect = createFingerprintCollector({
      loadFingerprint: fakeFingerprint({}),
      loadBotd: fakeBotd({ bot: false }),
      userAgent: () => undefined,
    })

    expect('user_agent' in (await collect())).toBe(false)
  })
})

describe('createFingerprintCollector default loaders', () => {
  it('loads the real FingerprintJS + BotD modules and navigator.userAgent', async () => {
    // MOCK the modules to prove the DEFAULT wiring calls their `load()`.
    vi.resetModules()
    const fpGet = vi.fn().mockResolvedValue({
      visitorId: 'v',
      components: { platform: { value: 'Linux x86_64' } },
    })
    const fpLoad = vi.fn().mockResolvedValue({ get: fpGet })
    const botdLoad = vi.fn().mockResolvedValue({
      collect: vi.fn().mockResolvedValue(undefined),
      detect: vi.fn().mockReturnValue({ bot: false }),
    })
    vi.doMock('@fingerprintjs/fingerprintjs', () => ({
      default: { load: fpLoad },
    }))
    vi.doMock('@fingerprintjs/botd', () => ({ load: botdLoad }))

    const { createFingerprintCollector: create } = await import(
      '../../src/fingerprint'
    )
    const collected = await create()()

    expect(fpLoad).toHaveBeenCalledOnce()
    // BotD monitoring must be OFF so the OSS detector never phones home.
    expect(botdLoad).toHaveBeenCalledWith({ monitoring: false })
    expect(collected).toEqual({
      components: { platform: 'Linux x86_64' },
      botd: { bot: false },
      user_agent: navigator.userAgent,
    })

    vi.doUnmock('@fingerprintjs/fingerprintjs')
    vi.doUnmock('@fingerprintjs/botd')
    vi.resetModules()
  })
})
