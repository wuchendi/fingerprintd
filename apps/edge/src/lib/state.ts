/**
 * STUBBED host state.
 *
 * The edge architecture externalizes all request state the native server keeps
 * in-process: the one-time nonce belongs in a Durable Object (atomic
 * check-and-burn), and the fingerprint / blocking index belongs in D1. Those
 * are wired in production. This module provides in-isolate stand-ins with the
 * SAME async interfaces the DO/D1 adapters will implement, so the production
 * adapters are a drop-in swap and the router in `handler.ts` never changes.
 *
 * WHY THESE ARE STUBS, NOT PRODUCTION: a Worker isolate is ephemeral and not
 * shared, so an in-memory `Map` nonce store neither survives isolate recycling
 * nor coordinates across isolates — a nonce issued by one isolate is unknown to
 * the next, and burns do not replicate. It is correct only for single-isolate
 * local `wrangler dev` / tests. The candidate source always recalls nothing, so
 * every `/identify` resolves to a new device. Both are replaced in production.
 */

import type { ScoreOutcome } from './types'

/** The outcome of consuming a nonce, mirroring `fingerprintd_core::nonce::NonceOutcome`.
 *  Only `valid` admits the request; every other value yields `401`. */
export type NonceOutcome = 'valid' | 'expired' | 'reused' | 'unknown'

/** Issues and burns one-time nonces. Implemented here in-memory (stub); by a
 *  Durable Object in production. */
export interface NonceStore {
  /** Mint a fresh nonce and its lifetime in seconds. */
  issue(): Promise<{ nonce: string; ttlSecs: number }>
  /** Atomically consume a nonce, returning why it was (or was not) valid. A
   *  `valid` nonce is burned so a replay of the same value is rejected. */
  consume(nonce: string): Promise<NonceOutcome>
}

/** A recalled candidate template: the stored id plus its raw component object,
 *  re-salted inside the WASM engine. Matches the `score` request's candidate. */
export interface Candidate {
  visitor_id: string
  components: Record<string, unknown>
}

/**
 * The fingerprint library behind stage-one recall and drift persistence:
 * recalls candidate templates for a probe's blocking keys and folds an
 * observation back in per the scorer's verdict. Implemented here as an empty
 * stub; by the D1-backed template + blocking index in production.
 */
export interface CandidateSource {
  /** Fetch every stored template sharing any of `blockingKeys`. */
  recall(blockingKeys: string[]): Promise<Candidate[]>

  /**
   * Fold an observation into the library per the scorer's `outcome`, mirroring
   * `fingerprintd_core::fuzzy::FuzzyStore::identify`'s persistence (fuzzy-matching §7):
   *   - `match`      — drift the matched template toward `components` and index
   *                    the observed `blockingKeys` under its id.
   *   - `new_device` — store the freshly minted template and index its keys.
   *   - `review`     — no write (anti-poisoning).
   * `blockingKeys` are the keys derived from `components`; `nowMs` stamps
   * freshness. A `review` verdict is a no-op.
   */
  persist(
    outcome: ScoreOutcome,
    components: Record<string, unknown>,
    blockingKeys: string[],
    nowMs: number,
  ): Promise<void>

  /**
   * GDPR erasure: remove every trace of `visitorId` — its template and all
   * of its blocking-index rows — so a recall can no longer surface it. Idempotent:
   * erasing an unknown id is a successful no-op (the caller must not leak whether
   * the id existed).
   */
  erase(visitorId: string): Promise<void>
}

/**
 * In-memory one-time nonce store (STUB). Burns on consume; expires by TTL.
 *
 * Distinguishing `reused` from `unknown` would need a tombstone set; for the
 * stub both collapse to `unknown` (a burned nonce is simply gone), which still
 * yields the correct `401` on replay. The DO in production restores that
 * distinction.
 */
export class InMemoryNonceStore implements NonceStore {
  /** nonce -> Unix-millisecond expiry. */
  private readonly live = new Map<string, number>()

  constructor(private readonly ttlSecs: number) {}

  issue(): Promise<{ nonce: string; ttlSecs: number }> {
    const nonce = crypto.randomUUID()
    this.live.set(nonce, Date.now() + this.ttlSecs * 1000)
    return Promise.resolve({ nonce, ttlSecs: this.ttlSecs })
  }

  consume(nonce: string): Promise<NonceOutcome> {
    const expiry = this.live.get(nonce)
    if (expiry === undefined) return Promise.resolve('unknown')
    // Burn first: even an expired nonce is removed so it cannot be retried.
    this.live.delete(nonce)
    if (Date.now() > expiry) return Promise.resolve('expired')
    return Promise.resolve('valid')
  }
}

/** Candidate source that always recalls nothing and never persists (STUB) —
 *  every probe is judged a new device. Replaced by the D1-backed index in
 *  production. */
export class EmptyCandidateSource implements CandidateSource {
  recall(_blockingKeys: string[]): Promise<Candidate[]> {
    return Promise.resolve([])
  }

  persist(): Promise<void> {
    return Promise.resolve()
  }

  erase(_visitorId: string): Promise<void> {
    return Promise.resolve()
  }
}
