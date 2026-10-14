/**
 * Unit tests for the FingerprintJS → server-schema adapter.
 *
 * Fixtures are FJS-SHAPED: real FJS key names with values wrapped as
 * `{ value, duration }`, value shapes as captured from real browsers
 * (`tests/fixtures/fjs-raw/`). The assertions pin the transforms the server
 * (`crates/fp-core/src/fuzzy/mod.rs` `classify()`) requires — wrapper unwrap,
 * key-name mapping, and per-component canonicalization into storable kinds.
 */

import { describe, expect, it } from 'vitest'
import { adaptFingerprintComponents } from '../../src/adapter'

/** A real-shape FJS `webGlBasics` value (Chromium, unmasked strings present). */
const WEBGL_BASICS = {
  version: 'WebGL 1.0 (OpenGL ES 2.0 Chromium)',
  vendor: 'WebKit',
  vendorUnmasked: 'Google Inc. (Intel)',
  renderer: 'WebKit WebGL',
  rendererUnmasked: 'ANGLE (Intel)',
  shadingLanguageVersion: 'WebGL GLSL ES 1.0',
}

describe('adaptFingerprintComponents', () => {
  it('unwraps the { value, duration } wrapper to a bare scalar', () => {
    const out = adaptFingerprintComponents({
      timezone: { value: 'Asia/Shanghai', duration: 1 },
    })
    expect(out.timezone).toBe('Asia/Shanghai')
  })

  it('never emits a { value, duration } wrapper', () => {
    const out = adaptFingerprintComponents({
      timezone: { value: 'UTC', duration: 1 },
      hardwareConcurrency: { value: 8, duration: 0 },
      colorDepth: { value: 24, duration: 0 },
    })
    for (const v of Object.values(out)) {
      expect(v).not.toHaveProperty('value')
      expect(v).not.toHaveProperty('duration')
    }
  })

  it('applies the FJS → server key-name map', () => {
    const out = adaptFingerprintComponents({
      hardwareConcurrency: { value: 8, duration: 0 },
      deviceMemory: { value: 8, duration: 0 },
      screenResolution: { value: [1080, 1920], duration: 0 },
      webGlBasics: { value: WEBGL_BASICS, duration: 5 },
    })
    expect(out.cpu_cores).toBe(8)
    expect(out.device_memory).toBe(8)
    expect(out.screen).toBe('1080x1920')
    expect(out.webgl).toBe('Google Inc. (Intel)|ANGLE (Intel)')
    // Original FJS names must not survive the rename.
    expect(out).not.toHaveProperty('hardwareConcurrency')
    expect(out).not.toHaveProperty('deviceMemory')
    expect(out).not.toHaveProperty('webGlBasics')
  })

  it('keeps an array for a Set field (fonts)', () => {
    const out = adaptFingerprintComponents({
      fonts: { value: ['Arial', 'Helvetica'], duration: 3 },
    })
    expect(out.fonts).toEqual(['Arial', 'Helvetica'])
  })

  it('drops a Set field whose unwrapped value is not an array', () => {
    const out = adaptFingerprintComponents({
      fonts: { value: 'Arial', duration: 3 },
      plugins: { value: { count: 2 }, duration: 1 },
    })
    expect(out).not.toHaveProperty('fonts')
    expect(out).not.toHaveProperty('plugins')
  })

  it('reduces plugins to their names (the server Set keeps strings only)', () => {
    const out = adaptFingerprintComponents({
      plugins: {
        value: [
          { name: 'PDF Viewer', description: 'PDF', mimeTypes: [] },
          { name: 'Chrome PDF Viewer', description: 'PDF', mimeTypes: [] },
        ],
        duration: 1,
      },
    })
    expect(out.plugins).toEqual(['PDF Viewer', 'Chrome PDF Viewer'])
  })

  it('canonicalizes webGlBasics to vendor|renderer, falling back to masked names', () => {
    const masked = adaptFingerprintComponents({
      webGlBasics: {
        value: { ...WEBGL_BASICS, vendorUnmasked: '', rendererUnmasked: '' },
        duration: 5,
      },
    })
    expect(masked.webgl).toBe('WebKit|WebKit WebGL')
  })

  it('drops the webgl status codes (no GL context) instead of storing them', () => {
    const out = adaptFingerprintComponents({
      webGlBasics: { value: -1, duration: 1 },
      webGlExtensions: { value: -2, duration: 1 },
    })
    expect(out).not.toHaveProperty('webgl')
    expect(out).not.toHaveProperty('webgl_extensions')
  })

  it('hashes webGlExtensions into its own webgl_extensions field', () => {
    const out = adaptFingerprintComponents({
      webGlBasics: { value: WEBGL_BASICS, duration: 1 },
      webGlExtensions: {
        value: { extensions: ['EXT_a'], parameters: ['p=1'] },
        duration: 1,
      },
    })
    expect(out.webgl).toBe('Google Inc. (Intel)|ANGLE (Intel)')
    expect(out.webgl_extensions).toMatch(/^[0-9a-f]{32}$/)
  })

  it('hashes the canvas object into a stable category value', () => {
    const canvas = { winding: true, geometry: 'skipped', text: 'skipped' }
    const a = adaptFingerprintComponents({
      canvas: { value: canvas, duration: 9 },
    })
    const b = adaptFingerprintComponents({
      canvas: {
        value: { text: 'skipped', geometry: 'skipped', winding: true },
        duration: 3,
      },
    })
    expect(a.canvas).toMatch(/^[0-9a-f]{32}$/)
    expect(b.canvas).toBe(a.canvas)
    const c = adaptFingerprintComponents({
      canvas: { value: { ...canvas, winding: false }, duration: 9 },
    })
    expect(c.canvas).not.toBe(a.canvas)
  })

  it('formats screenResolution as WxH and drops it when a dimension is null', () => {
    const ok = adaptFingerprintComponents({
      screenResolution: { value: [1440, 2560], duration: 0 },
    })
    expect(ok.screen).toBe('1440x2560')
    const partial = adaptFingerprintComponents({
      screenResolution: { value: [null, 1080], duration: 0 },
    })
    expect(partial).not.toHaveProperty('screen')
  })

  it('flattens languages in order without duplicates', () => {
    const out = adaptFingerprintComponents({
      languages: { value: [['en-US'], ['en-US', 'en']], duration: 0 },
    })
    expect(out.languages).toBe('en-US,en')
  })

  it('passes an unmapped scalar through under its FJS name', () => {
    const out = adaptFingerprintComponents({
      colorDepth: { value: 24, duration: 0 },
    })
    expect(out.colorDepth).toBe(24)
  })

  it('hashes an unmapped non-scalar under its FJS name, independent of key order', () => {
    const out = adaptFingerprintComponents({
      domBlockers: { value: ['x'], duration: 2 },
      touchSupport: {
        value: { maxTouchPoints: 5, touchEvent: true, touchStart: true },
        duration: 4,
      },
    })
    expect(out.domBlockers).toMatch(/^[0-9a-f]{32}$/)
    const reordered = adaptFingerprintComponents({
      touchSupport: {
        value: { touchStart: true, touchEvent: true, maxTouchPoints: 5 },
        duration: 1,
      },
    })
    expect(reordered.touchSupport).toBe(out.touchSupport)
  })

  it('drops null-valued components (FJS "not available")', () => {
    const out = adaptFingerprintComponents({
      osCpu: { value: null, duration: 0 },
      userAgentData: { value: undefined, duration: 0 },
    })
    expect(Object.keys(out)).toHaveLength(0)
  })

  it('drops an FJS error component (no value property)', () => {
    const out = adaptFingerprintComponents({
      audio: { error: 'unsupported', duration: 2 },
    })
    expect(out).not.toHaveProperty('audio')
    expect(Object.keys(out)).toHaveLength(0)
  })

  it('lets a mapped value win a collision with an unmapped passthrough', () => {
    // An unmapped FJS key literally named `cpu_cores` must not shadow the
    // mapped hardwareConcurrency target (rule 5: mapped wins).
    const out = adaptFingerprintComponents({
      cpu_cores: { value: 2, duration: 0 },
      hardwareConcurrency: { value: 8, duration: 0 },
    })
    expect(out.cpu_cores).toBe(8)
  })

  it('treats a stray visitorId component as a plain scalar passthrough', () => {
    // The adapter only receives `components`; discarding the FJS visitorId hash
    // is fingerprint.ts's job. If a `visitorId` slips in as a component it is
    // just an unmapped scalar passthrough — not special-cased here.
    const out = adaptFingerprintComponents({
      visitorId: { value: 'v', duration: 0 },
    })
    expect(out.visitorId).toBe('v')
  })
})
