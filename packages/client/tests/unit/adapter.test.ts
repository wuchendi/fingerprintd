/**
 * Unit tests for the FingerprintJS → closed component schema adapter.
 *
 * Inputs are FJS-SHAPED: real FJS key names with values wrapped as
 * `{ value, duration }`, value shapes as captured from real browsers
 * (`tests/fixtures/fjs-raw/`). The assertions pin the transforms the server
 * requires — wrapper unwrap, key-name mapping, unknown-key drop, and
 * per-component normalization into the component's kind.
 */

import { readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { adaptFingerprintComponents } from '../../src/adapter'
import { COMPONENT_KEYS } from '../../src/schema'
import { schemaViolations } from '../helpers'

const FIXTURE_DIR = resolve(process.cwd(), 'tests/fixtures/fjs-raw')
const fixtures = readdirSync(FIXTURE_DIR)
  .filter((f) => f.endsWith('.json'))
  .map((f) => ({
    file: f,
    raw: JSON.parse(readFileSync(resolve(FIXTURE_DIR, f), 'utf8'))
      .raw_components as Record<string, unknown>,
  }))

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
      platform: { value: 'Win32', duration: 0 },
    })
    for (const v of Object.values(out)) {
      expect(v).not.toHaveProperty('value')
      expect(v).not.toHaveProperty('duration')
    }
  })

  it('applies the FJS → schema key-name map', () => {
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

  it('reduces plugins to their names (a Set holds strings only)', () => {
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

  it('drops every unmapped FJS component', () => {
    const out = adaptFingerprintComponents({
      colorDepth: { value: 24, duration: 0 },
      vendor: { value: 'Google Inc.', duration: 0 },
      fooBar: { value: { a: 1 }, duration: 0 },
      visitorId: { value: 'v', duration: 0 },
      cpu_cores: { value: 2, duration: 0 },
      toString: { value: 'x', duration: 0 },
    })
    expect(out).toEqual({})
  })

  it('maps all 18 FJS components onto the schema keys', () => {
    const out = adaptFingerprintComponents({
      webGlBasics: { value: WEBGL_BASICS, duration: 0 },
      webGlExtensions: { value: { extensions: ['EXT_a'] }, duration: 0 },
      platform: { value: 'Win32', duration: 0 },
      timezone: { value: 'UTC', duration: 0 },
      languages: { value: [['en-US']], duration: 0 },
      audio: { value: 124.04, duration: 0 },
      canvas: { value: { winding: true }, duration: 0 },
      hardwareConcurrency: { value: 8, duration: 0 },
      deviceMemory: { value: 8, duration: 0 },
      screenResolution: { value: [1920, 1080], duration: 0 },
      fonts: { value: ['Arial'], duration: 0 },
      plugins: { value: [{ name: 'PDF Viewer' }], duration: 0 },
      fontPreferences: { value: { default: 147.5 }, duration: 0 },
      screenFrame: { value: [0, 0, 40, 0], duration: 0 },
      math: { value: { acos: 1.4 }, duration: 0 },
      touchSupport: { value: { maxTouchPoints: 0 }, duration: 0 },
      domBlockers: { value: ['x'], duration: 0 },
      userAgentData: { value: { mobile: false }, duration: 0 },
    })
    expect(Object.keys(out).sort()).toEqual([...COMPONENT_KEYS].sort())
    expect(schemaViolations(out, COMPONENT_KEYS)).toEqual([])
  })

  it('digests object/array Category values independent of key order', () => {
    const out = adaptFingerprintComponents({
      domBlockers: { value: ['x'], duration: 2 },
      touchSupport: {
        value: { maxTouchPoints: 5, touchEvent: true, touchStart: true },
        duration: 4,
      },
    })
    expect(out.dom_blockers).toMatch(/^[0-9a-f]{32}$/)
    expect(out.touch_support).toMatch(/^[0-9a-f]{32}$/)
    const reordered = adaptFingerprintComponents({
      touchSupport: {
        value: { touchStart: true, touchEvent: true, maxTouchPoints: 5 },
        duration: 1,
      },
    })
    expect(reordered.touch_support).toBe(out.touch_support)
  })

  it('keeps only finite numbers for Numeric components', () => {
    const out = adaptFingerprintComponents({
      hardwareConcurrency: { value: '8', duration: 0 },
      deviceMemory: { value: Number.NaN, duration: 0 },
    })
    expect(out).toEqual({})
  })

  it('keeps only string arrays for Set components', () => {
    const out = adaptFingerprintComponents({
      fonts: { value: ['Arial', 3], duration: 0 },
    })
    expect(out).not.toHaveProperty('fonts')
  })

  it('drops null-valued components (FJS "not available")', () => {
    const out = adaptFingerprintComponents({
      deviceMemory: { value: null, duration: 0 },
      userAgentData: { value: undefined, duration: 0 },
    })
    expect(Object.keys(out)).toHaveLength(0)
  })

  it('drops an FJS error component (no value property)', () => {
    const out = adaptFingerprintComponents({
      audio: { error: 'unsupported', duration: 2 },
    })
    expect(Object.keys(out)).toHaveLength(0)
  })

  for (const { file, raw } of fixtures) {
    it(`emits only schema keys of the right kind for ${file}`, () => {
      const out = adaptFingerprintComponents(raw)
      expect(Object.keys(out).length).toBeGreaterThan(0)
      expect(schemaViolations(out, COMPONENT_KEYS)).toEqual([])
    })
  }
})
