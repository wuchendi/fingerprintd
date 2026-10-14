/**
 * CROSS-STACK ACCEPTANCE PROOF — the FingerprintJS→server-schema adapter
 * against the REAL matcher, headlessly (no browser).
 *
 * This proves the two halves of the adapter end to end by running
 * {@link adaptFingerprintComponents} output through the vendored `fp-wasm`
 * `FpEngine` — the SAME Rust matching core (`crates/fp-core`) the server runs:
 *
 *  1. RECALL — adapted components produce non-empty `blocking_keys`, so the
 *     server can index/recall the probe. The RAW (un-adapted) FJS fixture, whose
 *     `{ value, duration }` wrappers the matcher cannot store, yields NO keys —
 *     proving the adapter is exactly what makes recall work.
 *  2. MATCH — two adapted probes derived from ONE FJS fixture (one lightly
 *     drifted) score as the SAME device via `FpEngine.score`.
 *
 * The wasm is instantiated headlessly by feeding the `.wasm` bytes to the
 * wasm-bindgen default init (mirroring `tests/unit/probe.test.ts`); `--target
 * web`'s URL fetch would fail in Node.
 */

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'
import { adaptFingerprintComponents } from '../../src/adapter'
// The vendored wasm-bindgen glue; the default export instantiates the module.
import initWasm, { FpEngine } from '../../wasm/fp_wasm.js'

// vitest runs with cwd = packages/client; resolve the vendored wasm from there.
const WASM_PATH = resolve(process.cwd(), 'wasm/fp_wasm_bg.wasm')

/**
 * A raw FingerprintJS capture from stock Chromium (`tests/fixtures/fjs-raw/`):
 * each component is the FJS `{ value, duration }` wrapper under FJS key names,
 * with real value shapes (object webgl/canvas, array screen/languages, …).
 */
function fjsFixture(): Record<string, unknown> {
  return JSON.parse(
    readFileSync(
      resolve(process.cwd(), 'tests/fixtures/fjs-raw/chromium-149.json'),
      'utf8',
    ),
  ).raw_components
}

describe('adapter cross-stack proof (FpEngine)', () => {
  beforeAll(async () => {
    // Feed the raw bytes so the glue instantiates them directly (no URL fetch).
    await initWasm({ module_or_path: new Uint8Array(readFileSync(WASM_PATH)) })
  })

  it('RECALL: adapted components yield blocking keys; raw FJS wrappers yield none', () => {
    const engine = new FpEngine('cross-stack-salt', 'k', 'k')

    const adapted = adaptFingerprintComponents(fjsFixture())
    const adaptedKeys = JSON.parse(
      engine.blocking_keys(JSON.stringify(adapted)),
    )
    // The adapted, server-schema components are recognized and indexable.
    expect(Array.isArray(adaptedKeys)).toBe(true)
    expect(adaptedKeys.length).toBeGreaterThan(0)

    // The raw FJS fixture — nested `{ value, duration }` objects the matcher
    // cannot store — recalls nothing. The adapter is what makes recall work.
    const rawKeys = JSON.parse(
      engine.blocking_keys(JSON.stringify(fjsFixture())),
    )
    expect(rawKeys).toEqual([])
  })

  it('MATCH: two adapted probes from one FJS fixture identify as the same device', () => {
    const engine = new FpEngine('cross-stack-salt', 'k', 'k')

    // Two probes from the SAME device: B drifts one low-stability field.
    const adaptedA = adaptFingerprintComponents(fjsFixture())
    const adaptedB = adaptFingerprintComponents({
      ...fjsFixture(),
      colorDepth: { value: 24, duration: 1 }, // unmapped low-stability passthrough
    })

    const reply = JSON.parse(
      engine.score(
        JSON.stringify({
          components: adaptedB,
          candidates: [{ visitor_id: 'v1', components: adaptedA }],
        }),
      ),
    )

    // The Rust `Decision` serializes to "match" / "review" / "new_device".
    expect(reply.decision).toBe('match')
    expect(reply.visitor_id).toBe('v1')
  })
})
