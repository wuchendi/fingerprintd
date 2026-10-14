/**
 * REAL-DEVICE PAYLOADS — `stable_components` exactly as the SDK sent them to
 * `/identify` from a real device (`tests/fixtures/sdk-payload/`), checked
 * against the real matcher (vendored `fp-wasm`).
 *
 * Complements `fjs-contract.test.ts`: those fixtures are raw FingerprintJS
 * output from headless container browsers (no fonts, software GPU); these are
 * the adapted output of real hardware, so they exercise real fonts, a real
 * GPU string, and the font-based persona check. They are adapted payloads,
 * not raw captures, so they do NOT go through the adapter here.
 */

import { readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'
import initWasm, {
  FpEngine,
  persona_coherence_label,
} from '../../wasm/fp_wasm.js'

const WASM_PATH = resolve(process.cwd(), 'wasm/fp_wasm_bg.wasm')
const FIXTURE_DIR = resolve(process.cwd(), 'tests/fixtures/sdk-payload')

interface Payload {
  user_agent: string
  stable_components: Record<string, unknown>
}

const fixtures = readdirSync(FIXTURE_DIR)
  .filter((f) => f.endsWith('.json'))
  .map((f) => ({
    file: f,
    payload: JSON.parse(
      readFileSync(resolve(FIXTURE_DIR, f), 'utf8'),
    ) as Payload,
  }))

describe('real-device SDK payloads', () => {
  let engine: FpEngine

  beforeAll(async () => {
    await initWasm({ module_or_path: new Uint8Array(readFileSync(WASM_PATH)) })
    engine = new FpEngine('payload-salt', 'k', 'k')
  })

  it('has at least one real-device payload', () => {
    expect(fixtures.length).toBeGreaterThan(0)
  })

  for (const { file, payload } of fixtures) {
    describe(file, () => {
      const components = payload.stable_components

      it('stores every component the SDK sent', () => {
        const kept = new Set<string>(
          JSON.parse(engine.stored_components(JSON.stringify(components))),
        )
        expect(Object.keys(components).filter((k) => !kept.has(k))).toEqual([])
      })

      it('emits the webgl+platform+timezone blocking key', () => {
        const keys = (c: Record<string, unknown>) =>
          JSON.parse(engine.blocking_keys(JSON.stringify(c))).length
        const { webgl: _, ...noWebgl } = components
        expect(keys(components)).toBe(keys(noWebgl) + 1)
      })

      it('reads the UA persona as consistent with the font set', () => {
        expect(
          persona_coherence_label(
            payload.user_agent,
            JSON.stringify(components.fonts),
          ),
        ).toBe('consistent')
      })
    })
  }
})
