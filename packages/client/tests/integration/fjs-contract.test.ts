/**
 * CLIENT ↔ SERVER CONTRACT — real-browser FingerprintJS output through the
 * adapter into the real matcher (vendored `fp-wasm` `FpEngine`, the same
 * `crates/fp-core` the server runs).
 *
 * Fixtures in `tests/fixtures/fjs-raw/` are UN-ADAPTED `components` captured
 * from stock Chromium / Firefox / WebKit by `scripts/redteam/cloak/run.sh`
 * (`SKIP_CLOAK=1`), not hand-written shapes: hand-written fixtures mirrored the
 * server's assumptions and let the adapter silently drop most components.
 *
 * Contract: every FJS component that carried a value reaches the matcher as a
 * STORED component (`FpEngine.stored_components` — the names the engine keeps
 * for matching after its own `classify()` / type checks).
 */

import { readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'
import { adaptFingerprintComponents } from '../../src/adapter'
import initWasm, { FpEngine } from '../../wasm/fp_wasm.js'

const WASM_PATH = resolve(process.cwd(), 'wasm/fp_wasm_bg.wasm')
const FIXTURE_DIR = resolve(process.cwd(), 'tests/fixtures/fjs-raw')

interface RawCapture {
  meta: { label: string }
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

/**
 * Components that carried a value but are dropped ON PURPOSE. Each entry is a
 * predicate over the raw value plus the reason; nothing else may be lost.
 */
const EXCLUDED: Record<string, (value: unknown) => boolean> = {
  // FJS "no WebGL context" status codes (-1/-2), not a GPU identity.
  webGlBasics: (v) => typeof v === 'number',
  webGlExtensions: (v) => typeof v === 'number',
}

function stored(engine: FpEngine, components: Record<string, unknown>) {
  return new Set<string>(
    JSON.parse(engine.stored_components(JSON.stringify(components))),
  )
}

describe('FingerprintJS → server contract (real-browser captures)', () => {
  let engine: FpEngine

  beforeAll(async () => {
    await initWasm({ module_or_path: new Uint8Array(readFileSync(WASM_PATH)) })
    engine = new FpEngine('contract-salt', 'k', 'k')
  })

  it('has one capture per stock engine', () => {
    expect(fixtures.map((f) => f.file).sort()).toEqual([
      'chromium-149.json',
      'firefox-151.json',
      'webkit-26.5.json',
    ])
  })

  for (const { file, capture } of fixtures) {
    describe(file, () => {
      const raw = capture.raw_components
      const adapted = adaptFingerprintComponents(raw)

      it('stores every FJS component that carried a value', () => {
        const kept = stored(engine, adapted)
        const lost: string[] = []
        for (const [name, entry] of Object.entries(raw)) {
          if (entry.value === null || entry.value === undefined) continue
          if (EXCLUDED[name]?.(entry.value)) continue
          // The adapted fields this one FJS component produced.
          const { [name]: _, ...without } = raw
          const rest = adaptFingerprintComponents(without)
          const derived = Object.keys(adapted).filter((k) => !(k in rest))
          if (derived.length === 0) lost.push(`${name} (adapter dropped it)`)
          for (const key of derived) {
            if (!kept.has(key)) lost.push(`${name} → ${key} (not stored)`)
          }
        }
        expect(lost).toEqual([])
      })

      it('emits the webgl+platform+timezone blocking key when WebGL is available', () => {
        if (typeof raw.webGlBasics?.value !== 'object') return
        const withWebgl = JSON.parse(
          engine.blocking_keys(JSON.stringify(adapted)),
        )
        const { webgl: _, ...noWebgl } = adapted
        const withoutWebgl = JSON.parse(
          engine.blocking_keys(JSON.stringify(noWebgl)),
        )
        // K1 is the only key gated on webgl; K0 changes too but stays present.
        expect(withWebgl.length).toBe(withoutWebgl.length + 1)
      })
    })
  }
})
