/**
 * Host state interfaces for the fingerprint routes.
 *
 * The edge keeps no request state in the isolate: the one-time nonce lives in a
 * Durable Object (atomic check-and-burn) and the fingerprint library + blocking
 * index live in the database. The routes depend only on these async
 * interfaces, so `src/index.ts` wires the durable implementations and tests
 * inject fakes.
 */

import type { ScoreOutcome } from './types'

/** The outcome of consuming a nonce, mirroring `fingerprintd::nonce::NonceOutcome`.
 *  Only `valid` admits the request; every other value yields `401`. */
export type NonceOutcome = 'valid' | 'expired' | 'reused' | 'unknown'

/** Issues and burns one-time nonces. Implemented by the `NONCE` Durable Object
 *  (`lib/do/nonce-do.ts`). */
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
 * observation back in per the scorer's verdict. Implemented by the
 * database-backed template + blocking index (`FingerprintStore`).
 */
export interface CandidateSource {
  /** Fetch every stored template sharing any of `blockingKeys`. */
  recall(blockingKeys: string[]): Promise<Candidate[]>

  /**
   * Fold an observation into the library per the scorer's `outcome`, mirroring
   * `fingerprintd::fuzzy::FuzzyStore::identify`'s persistence (fuzzy-matching §7):
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
