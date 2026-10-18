/**
 * Client integrity probes — known-answer checks that catch fingerprint noise.
 *
 * Each probe asks the browser a question whose answer is fixed by construction
 * in an unmodified Chromium: a lossless PNG round-trip of opaque pixels, a flat
 * GPU clear, a constant audio source, a layout offset representable in 1/64 px
 * LayoutUnits. A fingerprint-noising binary (an anti-detect browser perturbing
 * canvas / WebGL / audio / DOMRect output) returns a *wrong* answer. The noise
 * is deterministic per process, so the checks compare independent code paths
 * against the known answer rather than reading the same path twice.
 *
 * Two steps, kept apart so the verdict is unit-testable without a browser:
 *  - {@link measureIntegrity} — browser APIs only; returns raw material
 *    (diff counts, distinct values, actual vs expected), never a verdict.
 *  - {@link evaluateIntegrity} — pure function of that material.
 *
 * The result rides as the TOP-LEVEL `integrity` field of the identify request —
 * deliberately outside `components`, so it can never enter the visitor match. It is a risk signal for the server to surface, not identity
 * material. A probe whose API is missing or throws reports `unavailable`, which
 * the server treats as neutral. Legitimate privacy tooling (Brave farbling,
 * canvas blockers) trips the same probes — downstream must treat `noise` as a
 * band, not proof of automation.
 *
 * Depth, not a lock: this runs in page JavaScript and can be hooked like any
 * other client code.
 */

/** Verdict of one probe. */
export type ProbeVerdict = 'ok' | 'noise' | 'unavailable'

/** The four probe verdicts sent as the request's top-level `integrity`. */
export interface Integrity {
  canvas: ProbeVerdict
  webgl: ProbeVerdict
  audio: ProbeVerdict
  rect: ProbeVerdict
}

export interface CanvasMeasurement {
  /** Bytes that differ between `getImageData` and the decoded `toDataURL` PNG. */
  diff_bytes: number
  total_bytes: number
}

export interface WebglMeasurement {
  /** Distinct `r,g,b,a` strings read back after a flat clear. */
  distinct: string[]
  /** The single value an exact clear produces. */
  expected: string
}

export interface AudioMeasurement {
  /** Distinct sample values rendered from a constant source (capped). */
  distinct: number[]
  expected: number
}

export interface RectMeasurement {
  /** `[x, y, width, height]` from `getBoundingClientRect`. */
  actual: number[]
  /** The CSS values the element was positioned with. */
  expected: number[]
}

export interface MeasurementError {
  error: string
}

/** Raw material from {@link measureIntegrity}; input to {@link evaluateIntegrity}. */
export interface IntegrityMeasurements {
  canvas: CanvasMeasurement | MeasurementError
  webgl: WebglMeasurement | MeasurementError
  audio: AudioMeasurement | MeasurementError
  rect: RectMeasurement | MeasurementError
}

/** Produces the integrity verdicts; injectable for tests. */
export type IntegrityFn = () => Promise<Integrity>

// ---------------------------------------------------------------------------
// Measure
// ---------------------------------------------------------------------------

const CANVAS_W = 200
const CANVAS_H = 50
const WEBGL_EXPECTED = '51,102,153,255'
const AUDIO_EXPECTED = 0.5
const RECT_EXPECTED = [10.5, 20.25, 100.75, 50.5]

function errorOf(e: unknown): MeasurementError {
  return { error: e instanceof Error ? `${e.name}: ${e.message}` : String(e) }
}

async function measureCanvas(): Promise<CanvasMeasurement> {
  const canvas = document.createElement('canvas')
  canvas.width = CANVAS_W
  canvas.height = CANVAS_H
  const ctx = canvas.getContext('2d', { willReadFrequently: true })
  if (!ctx) throw new Error('2d context unavailable')
  // Opaque fill under the text keeps every pixel alpha=255, so PNG encode/decode
  // is lossless and premultiplication cannot introduce legitimate differences.
  ctx.fillStyle = '#f60'
  ctx.fillRect(0, 0, CANVAS_W, CANVAS_H)
  ctx.fillStyle = '#069'
  ctx.font = '16pt Arial'
  ctx.fillText('Cwm fjord \u{1F603}', 2, 30)
  const direct = ctx.getImageData(0, 0, CANVAS_W, CANVAS_H).data
  const dataUrl = canvas.toDataURL()

  const decoded = await new Promise<Uint8ClampedArray>((resolve, reject) => {
    const img = new Image()
    img.onload = () => {
      const back = document.createElement('canvas')
      back.width = CANVAS_W
      back.height = CANVAS_H
      const bctx = back.getContext('2d', { willReadFrequently: true })
      if (!bctx) return reject(new Error('2d context unavailable (decode)'))
      bctx.drawImage(img, 0, 0)
      resolve(bctx.getImageData(0, 0, CANVAS_W, CANVAS_H).data)
    }
    img.onerror = () => reject(new Error('toDataURL decode failed'))
    img.src = dataUrl
  })

  let diff = 0
  for (let i = 0; i < direct.length; i++) if (direct[i] !== decoded[i]) diff++
  return { diff_bytes: diff, total_bytes: direct.length }
}

function measureWebgl(): WebglMeasurement {
  const canvas = document.createElement('canvas')
  canvas.width = 16
  canvas.height = 16
  const gl = canvas.getContext('webgl', { preserveDrawingBuffer: true })
  if (!gl) throw new Error('webgl context unavailable')
  gl.clearColor(0.2, 0.4, 0.6, 1.0)
  gl.clear(gl.COLOR_BUFFER_BIT)
  const px = new Uint8Array(16 * 16 * 4)
  gl.readPixels(0, 0, 16, 16, gl.RGBA, gl.UNSIGNED_BYTE, px)
  const distinct = new Set<string>()
  for (let i = 0; i < px.length; i += 4) {
    distinct.add(`${px[i]},${px[i + 1]},${px[i + 2]},${px[i + 3]}`)
  }
  return { distinct: [...distinct].sort(), expected: WEBGL_EXPECTED }
}

async function measureAudio(): Promise<AudioMeasurement> {
  const ctx = new OfflineAudioContext(1, 1000, 44100)
  const source = ctx.createConstantSource()
  source.offset.value = AUDIO_EXPECTED
  source.connect(ctx.destination)
  source.start(0)
  const buffer = await ctx.startRendering()
  const data = buffer.getChannelData(0)
  const distinct = new Set<number>()
  // Skip the first samples: a constant source may ramp in on some engines.
  for (let i = 100; i < data.length && distinct.size < 16; i++) {
    distinct.add(data[i] as number)
  }
  return { distinct: [...distinct], expected: AUDIO_EXPECTED }
}

function measureRect(): RectMeasurement {
  const el = document.createElement('div')
  el.style.cssText =
    'position:absolute;left:10.5px;top:20.25px;width:100.75px;height:50.5px;' +
    'margin:0;padding:0;border:0;pointer-events:none'
  document.body.appendChild(el)
  try {
    const r = el.getBoundingClientRect()
    return { actual: [r.x, r.y, r.width, r.height], expected: RECT_EXPECTED }
  } finally {
    el.remove()
  }
}

/** Run all four probes; a failing probe reports an `error` instead of throwing. */
export async function measureIntegrity(): Promise<IntegrityMeasurements> {
  const guard = async <T>(
    f: () => T | Promise<T>,
  ): Promise<T | MeasurementError> => {
    try {
      return await f()
    } catch (e) {
      return errorOf(e)
    }
  }
  return {
    canvas: await guard(measureCanvas),
    webgl: await guard(measureWebgl),
    audio: await guard(measureAudio),
    rect: await guard(measureRect),
  }
}

// ---------------------------------------------------------------------------
// Evaluate (pure)
// ---------------------------------------------------------------------------

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null
}

function isNumberArray(v: unknown): v is number[] {
  return Array.isArray(v) && v.every((x) => typeof x === 'number')
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === 'string')
}

function evaluateCanvas(m: unknown): ProbeVerdict {
  if (!isRecord(m)) return 'unavailable'
  const diff = m.diff_bytes
  const total = m.total_bytes
  if (!Number.isInteger(diff) || !Number.isInteger(total)) return 'unavailable'
  if ((total as number) <= 0 || (diff as number) < 0) return 'unavailable'
  return diff === 0 ? 'ok' : 'noise'
}

function evaluateWebgl(m: unknown): ProbeVerdict {
  if (!isRecord(m) || !isStringArray(m.distinct)) return 'unavailable'
  if (m.distinct.length === 0 || typeof m.expected !== 'string') {
    return 'unavailable'
  }
  return m.distinct.length === 1 && m.distinct[0] === m.expected
    ? 'ok'
    : 'noise'
}

function evaluateAudio(m: unknown): ProbeVerdict {
  if (!isRecord(m) || !isNumberArray(m.distinct)) return 'unavailable'
  if (m.distinct.length === 0 || typeof m.expected !== 'number') {
    return 'unavailable'
  }
  return m.distinct.length === 1 && m.distinct[0] === m.expected
    ? 'ok'
    : 'noise'
}

function evaluateRect(m: unknown): ProbeVerdict {
  if (!isRecord(m) || !isNumberArray(m.actual) || !isNumberArray(m.expected)) {
    return 'unavailable'
  }
  if (m.actual.length !== 4 || m.expected.length !== 4) return 'unavailable'
  // An all-zero box means the element never got layout (no layout engine, a
  // hidden document): no measurement happened, so no verdict.
  if (m.actual[2] === 0 || m.actual[3] === 0) return 'unavailable'
  return m.actual.every((v, i) => v === (m.expected as number[])[i])
    ? 'ok'
    : 'noise'
}

/**
 * Turn raw measurements into verdicts. Tolerant of malformed input (anything
 * that is not a well-formed measurement reads `unavailable`, never `noise`):
 * an absent capability must stay neutral downstream.
 */
export function evaluateIntegrity(measurements: unknown): Integrity {
  const m = isRecord(measurements) ? measurements : {}
  return {
    canvas: evaluateCanvas(m.canvas),
    webgl: evaluateWebgl(m.webgl),
    audio: evaluateAudio(m.audio),
    rect: evaluateRect(m.rect),
  }
}

/** Measure then evaluate — the default {@link IntegrityFn}. Never throws. */
export const collectIntegrity: IntegrityFn = async () => {
  try {
    return evaluateIntegrity(await measureIntegrity())
  } catch {
    return evaluateIntegrity({})
  }
}
