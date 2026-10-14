/**
 * FingerprintJS → server-schema adapter (part a).
 *
 * PROBLEM: FingerprintJS `get()` returns each component as a nested
 * `{ value, duration }` wrapper keyed by FJS names (`hardwareConcurrency`,
 * `webGlBasics`, …). The Rust server's fuzzy matcher
 * (`crates/fp-core/src/fuzzy/mod.rs` `classify()` + `canonical_scalar` /
 * `value_to_i64`) recognizes a FIXED schema of snake_case names and stores only
 * scalars (Category/Numeric) or string arrays (Set) — it silently drops objects
 * and unknown-shaped values. Spreading FJS output verbatim therefore leaves real
 * probes unmatchable.
 *
 * This module is the pure, browser-free transform that reshapes FJS `components`
 * into the server schema:
 *  1. unwrap the `{ value, duration }` wrapper (dropping FJS error components,
 *     which carry `{ error, duration }` and no `value`);
 *  2. rename FJS keys to their server-schema counterparts ({@link KEY_MAP});
 *  3. normalize each value to the storable kind the server expects: object/array
 *     values are canonicalized per field ({@link CANONICALIZERS}), any other
 *     non-scalar is hashed under its FJS name, so no component carrying a value
 *     is silently dropped.
 *
 * The contract against real browser output is
 * `tests/integration/fjs-contract.test.ts`.
 */

import { murmurX64Hash128 } from '@fingerprintjs/fingerprintjs'

/**
 * FJS component name → server-schema name. The target names are exactly the set
 * `crates/fp-core/src/fuzzy/component.rs` `classify()` recognizes; keep this
 * table in sync with that authoritative list.
 *
 * FingerprintJS exposes NO raw userAgent among its stable components, so
 * `user_agent` is intentionally left unmapped — the UA rides separately under
 * `botd`, which this unit does not touch.
 */
const KEY_MAP: Record<string, string> = {
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
}

/**
 * Server-schema targets stored as a Set (`classify()` → `Kind::Set`), which the
 * server keeps only when the value is a string array. Every other mapped target
 * is a scalar Category/Numeric field.
 */
const SET_TARGETS = new Set(['fonts', 'plugins'])

/** A value the server can store as a scalar (Category / Numeric). */
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

/**
 * Reshape raw FingerprintJS `components` into the Rust server's matching schema.
 *
 * Per entry: unwrap `{ value, duration }` (dropping error components without a
 * `value`), canonicalize via {@link CANONICALIZERS}, drop `null`/`undefined`,
 * then either rename via {@link KEY_MAP} and type-normalize, or — for
 * unrecognized names — pass the value through under its ORIGINAL FJS name
 * (hashed when it is an object/array). On a name collision the mapped value wins.
 */
export function adaptFingerprintComponents(
  components: Record<string, unknown>,
): Record<string, unknown> {
  // Passthroughs are written first; mapped targets are spread last so a mapped
  // value always wins a collision against an unmapped passthrough of the same
  // name (rule 5).
  const passthrough: Record<string, unknown> = {}
  const mapped: Record<string, unknown> = {}

  for (const [key, entry] of Object.entries(components)) {
    // Unwrap the FJS wrapper. An entry without an own `value` (an FJS error
    // component `{ error, duration }`, or any non-object) is dropped.
    if (
      typeof entry !== 'object' ||
      entry === null ||
      !Object.hasOwn(entry, 'value')
    ) {
      continue
    }
    const raw = (entry as { value: unknown }).value
    const canonicalize = CANONICALIZERS[key]
    const value = canonicalize ? canonicalize(raw) : raw
    if (value === null || value === undefined) continue

    const target = KEY_MAP[key]
    if (target !== undefined) {
      if (SET_TARGETS.has(target)) {
        // Set fields keep only arrays; the server drops non-array Set values.
        if (Array.isArray(value)) {
          mapped[target] = value
        }
      } else if (isScalar(value)) {
        mapped[target] = value
      }
    } else if (isScalar(value)) {
      // Unknown FJS name: the server defaults it to a medium-stability category.
      passthrough[key] = value
    } else {
      // Unmapped object/array (touchSupport, userAgentData, math, …): hash it
      // so its entropy still reaches the matcher as a category value.
      passthrough[key] = digest(value)
    }
  }

  return { ...passthrough, ...mapped }
}
