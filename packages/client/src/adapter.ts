/**
 * FingerprintJS → closed component schema adapter.
 *
 * FingerprintJS `get()` returns each component as a `{ value, duration }`
 * wrapper keyed by FJS names (`hardwareConcurrency`, `webGlBasics`, …). The
 * server accepts only the closed snake_case schema in `schema.ts`, each value of
 * its component's kind, and rejects anything else.
 *
 * This module is the pure, browser-free transform from FJS `components` to
 * {@link Components}:
 *  1. unwrap the `{ value, duration }` wrapper (dropping FJS error components,
 *     which carry `{ error, duration }` and no `value`, and null values);
 *  2. map FJS names to schema keys ({@link KEY_MAP}); every unmapped FJS
 *     component is dropped;
 *  3. normalize each value to its component kind: object/array values are
 *     canonicalized per field ({@link CANONICALIZERS}), any other object/array
 *     for a Category key is digested; values of the wrong kind are dropped.
 *
 * The contract against real browser output is
 * `tests/integration/fjs-contract.test.ts`.
 */

import { murmurX64Hash128 } from '@fingerprintjs/fingerprintjs'
import type { ComponentKey, Components } from './schema'

/**
 * FJS component name → schema key, one entry per {@link ComponentKey}.
 * FingerprintJS exposes no raw userAgent among its components; the UA travels
 * as the request's top-level `user_agent`.
 */
const KEY_MAP: Record<string, ComponentKey> = {
  hardwareConcurrency: 'cpu_cores',
  deviceMemory: 'device_memory',
  screenResolution: 'screen',
  languages: 'languages',
  timezone: 'timezone',
  platform: 'platform',
  fonts: 'fonts',
  plugins: 'plugins',
  audio: 'audio',
  canvas: 'canvas',
  webGlBasics: 'webgl',
  webGlExtensions: 'webgl_extensions',
  fontPreferences: 'font_preferences',
  screenFrame: 'screen_frame',
  math: 'math',
  touchSupport: 'touch_support',
  domBlockers: 'dom_blockers',
  userAgentData: 'user_agent_data',
}

/** Numeric components: kept only as finite numbers. */
const NUMERIC_KEYS = new Set<ComponentKey>(['cpu_cores', 'device_memory'])
/** Set components: kept only as string arrays. Every other key is a Category. */
const SET_KEYS = new Set<ComponentKey>(['fonts', 'plugins'])

/** A Category scalar. */
function isScalar(value: unknown): value is string | number | boolean {
  return (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  )
}

/** JSON with object keys sorted, so a hash does not depend on key order. */
function stableJson(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    v !== null && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(
          Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        )
      : v,
  )
}

/** Compact, order-independent digest of a bulky object/array value. The
 *  server salts and hashes it again; this only keeps the payload small. */
function digest(value: unknown): string {
  return murmurX64Hash128(stableJson(value))
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v)

/**
 * Per-FJS-key canonicalizers for object/array values, returning the storable
 * value or `undefined` to drop. FJS reports "no WebGL context" as the numeric
 * status `-1`/`-2`; those are dropped rather than stored as a GPU identity.
 */
const CANONICALIZERS: Record<string, (value: unknown) => unknown> = {
  webGlBasics: (v) => {
    if (!isObject(v)) return undefined
    const vendor = v.vendorUnmasked || v.vendor
    const renderer = v.rendererUnmasked || v.renderer
    return `${vendor ?? ''}|${renderer ?? ''}`
  },
  webGlExtensions: (v) => (isObject(v) ? digest(v) : undefined),
  canvas: (v) => (isObject(v) ? digest(v) : undefined),
  // Already sorted longer-side first by FJS, so rotation does not change it.
  screenResolution: (v) =>
    Array.isArray(v) && v.length === 2 && v.every((d) => typeof d === 'number')
      ? `${v[0]}x${v[1]}`
      : undefined,
  languages: (v) =>
    Array.isArray(v)
      ? [...new Set(v.flat().filter((l) => typeof l === 'string'))].join(',')
      : undefined,
  plugins: (v) =>
    Array.isArray(v)
      ? v
          .map((p) => (isObject(p) ? p.name : p))
          .filter((n): n is string => typeof n === 'string')
      : undefined,
}

/** Normalize `value` to the kind of `key`; `undefined` drops it. */
function toKind(key: ComponentKey, value: unknown): unknown {
  if (NUMERIC_KEYS.has(key)) {
    return typeof value === 'number' && Number.isFinite(value)
      ? value
      : undefined
  }
  if (SET_KEYS.has(key)) {
    return Array.isArray(value) && value.every((v) => typeof v === 'string')
      ? value
      : undefined
  }
  if (isScalar(value)) return value
  return typeof value === 'object' ? digest(value) : undefined
}

/**
 * Reshape raw FingerprintJS `components` into the closed component schema.
 *
 * Per entry: unwrap `{ value, duration }` (dropping error components without a
 * `value`), drop unmapped FJS names, canonicalize via {@link CANONICALIZERS},
 * drop `null`/`undefined`, then normalize to the key's kind.
 */
export function adaptFingerprintComponents(
  components: Record<string, unknown>,
): Components {
  const out: Record<string, unknown> = {}

  for (const [name, entry] of Object.entries(components)) {
    if (!Object.hasOwn(KEY_MAP, name)) continue
    const key = KEY_MAP[name] as ComponentKey
    // An entry without an own `value` (an FJS error component
    // `{ error, duration }`, or any non-object) is dropped.
    if (
      typeof entry !== 'object' ||
      entry === null ||
      !Object.hasOwn(entry, 'value')
    ) {
      continue
    }
    const raw = (entry as { value: unknown }).value
    const canonicalize = CANONICALIZERS[name]
    const value = canonicalize ? canonicalize(raw) : raw
    if (value === null || value === undefined) continue

    const kinded = toKind(key, value)
    if (kinded !== undefined) out[key] = kinded
  }

  return out as Components
}
