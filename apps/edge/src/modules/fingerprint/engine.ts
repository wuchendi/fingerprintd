/**
 * Typed host wrapper around the WASM compute engine (`crates/fp-wasm`).
 *
 * The WASM module is the single source of the fingerprinting compute, shared
 * with the native Axum server: the closed component schema, the salted stored
 * form, blocking-key derivation, Fellegi–Sunter scoring with template drift,
 * and the passive / integrity / persona / automation / velocity signals. This
 * module owns the wasm-bindgen lifecycle (a one-time `initSync`) and marshals
 * the JSON string boundary so the routes deal in typed values.
 *
 * The engine holds NO request state and mints no ids: `score` rebuilds the
 * host-recalled candidate block in a transient store per call and returns what
 * the host must persist. All persistence is the host's.
 */

import {
  automation,
  client_integrity,
  component_keys,
  FpEngine,
  initSync,
  passive_signals,
  persona_coherence_label,
  velocity_band,
  velocity_penalty,
} from '../../../wasm/fp_wasm.js'
import type { Candidate } from '../../lib/state'
import type {
  Band,
  Botd,
  Integrity,
  IntegrityVerdict,
  PassiveVerdict,
  ScoreOutcome,
  Signals,
  StoredComponents,
} from '../../lib/types'

/** One-time wasm-bindgen module init (the module is a process-wide singleton). */
let initialized = false

/**
 * Initialize the WASM runtime from a compiled module or raw bytes (idempotent).
 *
 * - In the Worker, `src/index.ts` passes the `import`ed `.wasm` module, which
 *   wrangler bundles as a `WebAssembly.Module`.
 * - In tests (Node), the caller passes the `.wasm` bytes read from disk.
 *
 * We use `initSync` (never the default async `__wbg_init`) because the latter's
 * fallback resolves the artifact via `import.meta.url`, which is not meaningful
 * in the Workers runtime.
 */
export function initEngineRuntime(
  module: WebAssembly.Module | BufferSource,
): void {
  if (initialized) return
  initSync({ module })
  initialized = true
}

/**
 * A configured, state-free compute engine for one isolate. Construct once per
 * isolate from the salt secret; call per request. Methods taking `components`
 * throw on an unknown key or a wrongly-typed value (the closed schema).
 */
export class EdgeEngine {
  private readonly inner: FpEngine

  /** {@link initEngineRuntime} MUST have run before constructing this. */
  constructor(saltSecret: string) {
    this.inner = new FpEngine(saltSecret)
  }

  /** The closed component schema's keys, in schema order. */
  componentKeys(): string[] {
    return JSON.parse(component_keys()) as string[]
  }

  /** The salted stored form of `components` — the only form the host stores. */
  storedForm(components: Record<string, unknown>): StoredComponents {
    return JSON.parse(
      this.inner.stored_form(JSON.stringify(components)),
    ) as StoredComponents
  }

  /** Blocking keys (hex) for a probe's components. The first key is the exact
   *  all-scalar key. */
  blockingKeys(components: Record<string, unknown>): string[] {
    return JSON.parse(
      this.inner.blocking_keys(JSON.stringify(components)),
    ) as string[]
  }

  /** Blocking keys (hex) of a stored form — identical to the keys of its source
   *  components. */
  blockingKeysStored(stored: StoredComponents): string[] {
    return JSON.parse(
      this.inner.blocking_keys_stored(JSON.stringify(stored)),
    ) as string[]
  }

  /** Score a probe against host-recalled candidates, without mutating state. */
  score(
    components: Record<string, unknown>,
    candidates: Candidate[],
  ): ScoreOutcome {
    const request = JSON.stringify({ components, candidates })
    return JSON.parse(this.inner.score(request)) as ScoreOutcome
  }

  /**
   * UA↔TLS / IP-risk verdict for one request (`fingerprintd::signals::compute`).
   * A missing JA4 degrades to neutral (`ua_tls_consistent: true`, adjustment
   * `0`); a missing IP reads `low`.
   */
  passiveSignals(
    ja4?: string,
    clientIp?: string,
    claimedUa?: string,
  ): PassiveVerdict {
    return JSON.parse(
      passive_signals(ja4, clientIp, claimedUa),
    ) as PassiveVerdict
  }

  /**
   * Fused client-integrity verdict. Absent reads `unavailable` with a `0`
   * adjustment; the `noise` penalty applies only when `penaltyEnabled`.
   */
  clientIntegrity(
    integrity: Integrity | undefined,
    penaltyEnabled: boolean,
  ): IntegrityVerdict {
    const raw = integrity === undefined ? undefined : JSON.stringify(integrity)
    return JSON.parse(client_integrity(raw, penaltyEnabled)) as IntegrityVerdict
  }

  /** UA-claimed OS family vs the `fonts` component. Surfaced-only; a missing
   *  UA or fonts list, or an OS outside the curated set, reads `unknown`. */
  personaCoherence(
    claimedUa: string | undefined,
    fonts: unknown,
  ): Signals['persona_coherence'] {
    const raw = fonts === undefined ? undefined : JSON.stringify(fonts)
    return persona_coherence_label(
      claimedUa,
      raw,
    ) as Signals['persona_coherence']
  }

  /** The automation verdict for the client's bot-detection result; absent
   *  reads `unknown`. */
  automation(botd: Botd | undefined): Signals['automation'] {
    const raw = botd === undefined ? undefined : JSON.stringify(botd)
    return automation(raw) as Signals['automation']
  }

  /** The velocity band for `n` distinct new devices from one IP in the window. */
  velocityBand(n: number): Band {
    return velocity_band(n) as Band
  }

  /** The confidence penalty for a velocity band. */
  velocityPenalty(band: Band): number {
    return velocity_penalty(band)
  }
}
