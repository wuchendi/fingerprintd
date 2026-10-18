/**
 * Host state interfaces for the fingerprint, events and check-in routes.
 *
 * The edge keeps no request state in the isolate: the one-time nonce lives in a
 * Durable Object (atomic check-and-burn) and the fingerprint library, blocking
 * index and identify events live in the database. The routes depend only on these async
 * interfaces, so `src/index.ts` wires the durable implementations and tests
 * inject fakes.
 */

import type { ScoreOutcome, StoredComponents } from './types'

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

/** A recalled candidate: the visitor id plus its salted stored template —
 *  exactly the `score` request's candidate shape. */
export interface Candidate {
  visitor_id: string
  stored: StoredComponents
}

/**
 * The fingerprint library behind candidate recall and drift persistence.
 * Implemented by the database-backed template + blocking index
 * (`FingerprintStore`). Only salted stored forms are ever persisted.
 */
export interface CandidateSource {
  /** Recall a bounded candidate block for a probe's blocking keys, the first
   *  key (the exact all-scalar key) first and the rest rarest first. */
  recall(blockingKeys: string[]): Promise<Candidate[]>

  /**
   * Persist the scorer's `outcome` (fuzzy-matching §7) and return the visitor
   * id to report:
   *   - `match`      — write the drifted template back to the matched visitor
   *                    (only while it still exists) and index its keys.
   *   - `new_device` — mint a random id that was never erased, store the
   *                    template under it and index its keys.
   *   - `review`     — no write (anti-poisoning); the suspected id.
   * `nowMs` stamps freshness.
   */
  persist(outcome: ScoreOutcome, nowMs: number): Promise<string>

  /**
   * GDPR erasure: remove the visitor's template, blocking-index rows and
   * identify events, and tombstone the id so it is never minted or written
   * again. Idempotent: an unknown id is a successful no-op (the caller must not
   * leak existence).
   */
  erase(id: string): Promise<void>
}

/** A stored identify event: the exact response body served back by
 *  `GET /events/{request_id}`, plus what check-in reads from it. */
export interface StoredEvent {
  request_id: string
  visitor_id: string
  /** Edge-observed client IP of the identify; `null` when absent. */
  ip: string | null
  /** The serialized identify response, byte-for-byte as sent. */
  body: string
}

/**
 * The bounded-lifetime identify event log. Implemented by the database-backed
 * `EventStore` (`modules/events`); erasure removes a visitor's events in the
 * fingerprint store's erase batch.
 */
export interface EventLog {
  /** Store one event, readable until `expiresAt` (Unix ms). */
  put(event: StoredEvent, expiresAt: number): Promise<void>
  /** The event for `requestId`, or `undefined` when unknown or expired as of
   *  `nowMs`. */
  get(requestId: string, nowMs: number): Promise<StoredEvent | undefined>
}

/** A random 128-bit id as 32 lowercase hex chars — the shape of every minted
 *  `visitor_id` and `request_id`. */
export function randomId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}
