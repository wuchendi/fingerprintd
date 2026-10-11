/**
 * Typed host wrapper around the WASM compute engine (`crates/fp-wasm`).
 *
 * The `FpEngine` WASM class is the SINGLE source of the fingerprinting compute,
 * shared with the native Axum server via `fp-core`: blocking-key derivation,
 * Fellegi–Sunter scoring, probe verification, and response signing. This module
 * owns the wasm-bindgen module lifecycle (a one-time `initSync`) and marshals
 * the JSON string boundary so the router in `handler.ts` deals in typed values.
 *
 * The engine holds NO request state: `score` rebuilds the host-recalled candidate
 * block in a transient store per call and discards it. All persistence (nonce
 * burn, candidate recall, drift write-back) is the host's, so this stays pure.
 */

import {
  client_integrity,
  FpEngine,
  initSync,
  passive_signals,
  persona_coherence_label,
} from '../../../wasm/fp_wasm.js'
import type { EdgeConfig } from '../../config'
import type { Candidate } from '../../lib/state'
import type {
  IntegrityVerdict,
  PassiveVerdict,
  ScoreOutcome,
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
 * isolate from the resolved secrets; call per request.
 */
export class EdgeEngine {
  private readonly inner: FpEngine

  /** {@link initEngineRuntime} MUST have run before constructing this. */
  constructor(config: EdgeConfig) {
    // Probe / signing keys are only consulted when their feature is enabled;
    // when unset, an empty key is harmless because the host never calls the
    // corresponding method. The salt secret is always meaningful.
    this.inner = new FpEngine(
      config.saltSecret,
      config.probeKey ?? '',
      config.signingKey ?? '',
    )
  }

  /** Blocking keys (hex) for a probe's components — the host queries its
   *  candidate index with these. */
  blockingKeys(components: Record<string, unknown>): string[] {
    return JSON.parse(
      this.inner.blocking_keys(JSON.stringify(components)),
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
   * Passive-signal verdict for one request, computed by the shared WASM free
   * export (`fp_core::signals::compute`) so the edge reaches the SAME UA↔TLS /
   * IP-risk verdict as the native server. Secret-free — unlike the other methods
   * it does not touch the engine instance.
   *
   * A missing (`undefined`) JA4 auto-degrades to the neutral verdict
   * (`ua_tls_consistent: true`, `confidence_adjustment: 0`); a missing IP defaults
   * to `"low"` (§4.2). `undefined` marshals to the wasm `Option::None`.
   */
  passiveSignals(
    ja4: string | undefined,
    clientIp: string | undefined,
    claimedUa: string | undefined,
  ): PassiveVerdict {
    return JSON.parse(
      passive_signals(ja4, clientIp, claimedUa),
    ) as PassiveVerdict
  }

  /**
   * Fused client-integrity verdict for one request, computed by the shared WASM
   * free export (`fp_core::signals::ClientIntegrity`) so the edge reaches the
   * SAME band and confidence delta as the native server. Secret-free.
   *
   * `undefined` (field absent) or malformed material reads `unavailable` with a
   * `0` adjustment; the `noise` penalty applies only when the deployment opted
   * in (`integrityPenaltyEnabled`).
   */
  clientIntegrity(
    integrity: Record<string, unknown> | undefined,
    penaltyEnabled: boolean,
  ): IntegrityVerdict {
    const raw = integrity === undefined ? undefined : JSON.stringify(integrity)
    return JSON.parse(client_integrity(raw, penaltyEnabled)) as IntegrityVerdict
  }

  /**
   * UA-claimed OS family vs the collected `fonts` set, computed by the shared
   * WASM free export (`fp_core::signals::persona_coherence`) so the edge reaches
   * the SAME label as native. Surfaced-only. A missing UA, an OS family outside
   * the curated set or a non-array `fonts` reads `unknown` (neutral).
   */
  personaCoherence(claimedUa: string | undefined, fonts: unknown): string {
    const raw = fonts === undefined ? undefined : JSON.stringify(fonts)
    return persona_coherence_label(claimedUa, raw)
  }

  /** Constant-time check that `probe` is the correct nonce probe. */
  verifyProbe(nonce: string, probe: string): boolean {
    return this.inner.verify_probe(nonce, probe)
  }

  /** The expected probe `hex(HMAC-SHA256(probe_key, nonce))` a client should
   *  echo, computed with the configured key. Used to exercise the probe path. */
  expectedProbe(nonce: string): string {
    return this.inner.expected_probe(nonce)
  }

  /** `hex(HMAC-SHA256(signing_key, issued_ms_be ++ body))` over the exact
   *  response bytes. `issuedMs` is Unix milliseconds. */
  sign(issuedMs: number, body: Uint8Array): string {
    return this.inner.sign(BigInt(issuedMs), body)
  }
}
