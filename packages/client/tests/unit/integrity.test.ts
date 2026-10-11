/**
 * Integrity-probe verdicts, driven by REAL captures.
 *
 * The fixtures under `crates/fp-core/tests/fixtures/cloakbrowser/` were
 * produced by `scripts/redteam/cloak/run.sh`: the SDK collector plus the raw
 * integrity measurements run inside the CloakBrowser free binary (a
 * fingerprint-noising Chromium, several seeds) and inside stock Chromium as the
 * negative control. `evaluateIntegrity` is pure, so the verdict logic is
 * certified here from that material without a browser; the MEASURE step is
 * exercised by the harness itself.
 */

import { readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import type { Integrity } from '../../src/integrity'
import { evaluateIntegrity } from '../../src/integrity'

const FIXTURES = resolve(
  process.cwd(),
  '../../crates/fp-core/tests/fixtures/cloakbrowser',
)

interface Capture {
  meta: { label: string; mode: 'cloak' | 'stock' }
  integrity_measurements: unknown
}

function captures(): Capture[] {
  return readdirSync(FIXTURES)
    .filter((f) => f.endsWith('.json'))
    .map((f) => JSON.parse(readFileSync(resolve(FIXTURES, f), 'utf8')))
}

const ALL_NOISE: Integrity = {
  canvas: 'noise',
  webgl: 'noise',
  audio: 'noise',
  rect: 'noise',
}
const ALL_OK: Integrity = { canvas: 'ok', webgl: 'ok', audio: 'ok', rect: 'ok' }
const ALL_UNAVAILABLE: Integrity = {
  canvas: 'unavailable',
  webgl: 'unavailable',
  audio: 'unavailable',
  rect: 'unavailable',
}

describe('evaluateIntegrity (fixture-driven)', () => {
  const all = captures()
  const cloak = all.filter((c) => c.meta.mode === 'cloak')
  const stock = all.filter((c) => c.meta.mode === 'stock')

  it('has the curated capture set', () => {
    expect(cloak.length).toBeGreaterThanOrEqual(5)
    expect(stock.length).toBeGreaterThanOrEqual(2)
  })

  it('reads noise on all four probes for every CloakBrowser capture', () => {
    // Including `--fingerprint=off`: the binary noises unconditionally.
    for (const c of cloak) {
      expect(evaluateIntegrity(c.integrity_measurements), c.meta.label).toEqual(
        ALL_NOISE,
      )
    }
  })

  it('reads ok on all four probes for every stock Chromium capture', () => {
    for (const c of stock) {
      expect(evaluateIntegrity(c.integrity_measurements), c.meta.label).toEqual(
        ALL_OK,
      )
    }
  })
})

describe('evaluateIntegrity (malformed input stays neutral)', () => {
  it('reads unavailable for missing, non-object or error material', () => {
    expect(evaluateIntegrity(undefined)).toEqual(ALL_UNAVAILABLE)
    expect(evaluateIntegrity(null)).toEqual(ALL_UNAVAILABLE)
    expect(evaluateIntegrity('nope')).toEqual(ALL_UNAVAILABLE)
    expect(evaluateIntegrity({})).toEqual(ALL_UNAVAILABLE)
    expect(
      evaluateIntegrity({
        canvas: { error: 'TypeError: 2d context unavailable' },
        webgl: { error: 'webgl context unavailable' },
        audio: { error: 'ReferenceError: OfflineAudioContext' },
        rect: { error: 'boom' },
      }),
    ).toEqual(ALL_UNAVAILABLE)
  })

  it('never upgrades malformed shapes to noise', () => {
    expect(
      evaluateIntegrity({
        canvas: { diff_bytes: -1, total_bytes: 0 },
        webgl: { distinct: [], expected: 'x' },
        audio: { distinct: ['0.5'], expected: 0.5 },
        rect: { actual: [1, 2], expected: [1, 2, 3, 4] },
      }),
    ).toEqual(ALL_UNAVAILABLE)
    // A zero-sized box = the element never got layout (jsdom, hidden
    // document): that is "no measurement", not noise.
    expect(
      evaluateIntegrity({
        rect: { actual: [0, 0, 0, 0], expected: [10.5, 20.25, 100.75, 50.5] },
      }).rect,
    ).toBe('unavailable')
  })

  it('reads the exact answer as ok and any deviation as noise', () => {
    expect(
      evaluateIntegrity({
        canvas: { diff_bytes: 0, total_bytes: 40000 },
        webgl: { distinct: ['51,102,153,255'], expected: '51,102,153,255' },
        audio: { distinct: [0.5], expected: 0.5 },
        rect: {
          actual: [10.5, 20.25, 100.75, 50.5],
          expected: [10.5, 20.25, 100.75, 50.5],
        },
      }),
    ).toEqual(ALL_OK)
    expect(
      evaluateIntegrity({
        canvas: { diff_bytes: 1, total_bytes: 40000 },
        webgl: {
          distinct: ['51,102,153,255', '50,102,153,255'],
          expected: '51,102,153,255',
        },
        audio: { distinct: [0.5000031590461731], expected: 0.5 },
        rect: {
          actual: [10.515625, 20.25, 100.75, 50.5],
          expected: [10.5, 20.25, 100.75, 50.5],
        },
      }),
    ).toEqual(ALL_NOISE)
  })
})
