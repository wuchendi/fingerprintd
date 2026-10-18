/**
 * CLIENT ↔ SERVER CONTRACT — real-browser FingerprintJS output through the
 * adapter into the closed component schema.
 *
 * Fixtures in `tests/fixtures/fjs-raw/` are UN-ADAPTED `components` captured
 * from stock Chromium / Firefox / WebKit by `scripts/redteam/cloak/run.sh`
 * (`SKIP_CLOAK=1`), not hand-written shapes, so the adapter is checked against
 * what real browsers emit.
 *
 * Contract: every schema key whose FingerprintJS source carried a value is
 * emitted, with a value of its component kind, and nothing outside the schema
 * is emitted.
 */

import { readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { adaptFingerprintComponents } from '../../src/adapter'
import { COMPONENT_KEYS } from '../../src/schema'
import { schemaViolations } from '../helpers'

const FIXTURE_DIR = resolve(process.cwd(), 'tests/fixtures/fjs-raw')

interface RawCapture {
  raw_components: Record<string, { value?: unknown }>
}

const fixtures = readdirSync(FIXTURE_DIR)
  .filter((f) => f.endsWith('.json'))
  .map((f) => ({
    file: f,
    capture: JSON.parse(
      readFileSync(resolve(FIXTURE_DIR, f), 'utf8'),
    ) as RawCapture,
  }))

/** Schema key → its FingerprintJS source component. */
const SOURCE: Record<string, string> = {
  webgl: 'webGlBasics',
  webgl_extensions: 'webGlExtensions',
  platform: 'platform',
  timezone: 'timezone',
  languages: 'languages',
  audio: 'audio',
  canvas: 'canvas',
  cpu_cores: 'hardwareConcurrency',
  device_memory: 'deviceMemory',
  screen: 'screenResolution',
  fonts: 'fonts',
  plugins: 'plugins',
  font_preferences: 'fontPreferences',
  screen_frame: 'screenFrame',
  math: 'math',
  touch_support: 'touchSupport',
  dom_blockers: 'domBlockers',
  user_agent_data: 'userAgentData',
}

/**
 * Sources that carried a value but are dropped ON PURPOSE. Each entry is a
 * predicate over the raw value; nothing else may be lost.
 */
const DROPPED: Record<string, (value: unknown) => boolean> = {
  // FJS "no WebGL context" status codes (-1/-2), not a GPU identity.
  webGlBasics: (v) => typeof v === 'number',
  webGlExtensions: (v) => typeof v === 'number',
}

describe('FingerprintJS → closed schema contract (real-browser captures)', () => {
  it('has one capture per stock engine', () => {
    expect(fixtures.map((f) => f.file).sort()).toEqual([
      'chromium-149.json',
      'firefox-151.json',
      'webkit-26.5.json',
    ])
  })

  it('maps every schema key to a source', () => {
    expect(Object.keys(SOURCE)).toEqual([...COMPONENT_KEYS])
  })

  for (const { file, capture } of fixtures) {
    describe(file, () => {
      const raw = capture.raw_components
      const adapted = adaptFingerprintComponents(raw)

      it('emits only schema keys of the right kind', () => {
        expect(schemaViolations(adapted, COMPONENT_KEYS)).toEqual([])
      })

      it('emits every schema key whose source carried a value', () => {
        const lost: string[] = []
        for (const key of COMPONENT_KEYS) {
          const source = SOURCE[key] as string
          const value = raw[source]?.value
          if (value === null || value === undefined) continue
          if (DROPPED[source]?.(value)) continue
          if (!(key in adapted)) lost.push(`${source} → ${key}`)
        }
        expect(lost).toEqual([])
      })
    })
  }
})
