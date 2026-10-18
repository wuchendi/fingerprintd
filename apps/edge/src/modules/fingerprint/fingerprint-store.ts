/**
 * The fingerprint library: bounded candidate recall, drift persistence, and
 * erasure — the externalized form of `fingerprintd::fuzzy`'s record store +
 * blocking index.
 *
 * Three tables (see `src/db/fingerprint.schema.ts`): `templates` holds each
 * visitor's salted stored form (never raw component values), `blocking_index`
 * is the `key -> visitor_id` inverted index recall walks, and `erased_visitors`
 * tombstones erased ids so they are never minted or written again. Erasure
 * also drops the visitor's identify events (`events`).
 * Persistence follows the engine's verdict (fuzzy-matching §7): a match writes
 * the drifted template back, a new device is stored under a host-minted id, a
 * review writes nothing.
 *
 * Queries go through Drizzle on the database client (`src/db/client.ts`, libSQL
 * or D1), so the store is driver-neutral. Every statement binds well under D1's
 * 100-parameter cap.
 */

import { count, desc, eq, inArray, lt, sql } from 'drizzle-orm'
import type { Db } from '../../db/client'
import {
  blockingIndex,
  erasedVisitors,
  events,
  templates,
} from '../../db/schema'
import type { Candidate, CandidateSource } from '../../lib/state'
import { randomId } from '../../lib/state'
import type { ScoreOutcome, StoredComponents } from '../../lib/types'

/** Most visitors recalled through one blocking key (most recently seen first),
 *  so a hot key (e.g. stock iPhone Safari) cannot flood the block. */
export const PER_KEY_CAP = 256

/** Most candidates one recall returns across all keys. */
export const MAX_CANDIDATES = 1024

/** Erasure tombstones kept by {@link FingerprintStore.trimTombstones}, oldest
 *  dropped first (mirrors the native `TOMBSTONE_CAP`). */
export const TOMBSTONE_CAP = 100_000

/** Upper bound on blocking keys per recall: the engine emits fewer than 40, and
 *  the block-size query binds one parameter per key. */
const MAX_RECALL_KEYS = 90

/** Attempts to mint an id that is neither tombstoned nor taken. */
const MINT_ATTEMPTS = 3

/**
 * Recall + persist over the database via Drizzle. Construct once per isolate
 * from the client `getDb` returns. Holds no state itself — every method is a
 * query against the shared database.
 */
export class FingerprintStore implements CandidateSource {
  constructor(
    private readonly db: Db,
    private readonly perKeyCap: number = PER_KEY_CAP,
    private readonly maxCandidates: number = MAX_CANDIDATES,
  ) {}

  /**
   * Ordered, bounded recall (fuzzy-matching §4). One `GROUP BY key` query sizes
   * every block; keys are then visited in priority order — the first key (the
   * exact all-scalar key) first, the rest rarest first (ties keep their order).
   * Each key contributes at most `perKeyCap` visitors, most recently seen
   * first, de-duplicated across keys, until `maxCandidates` are collected. A
   * truncated key or a hit total cap is warned once.
   */
  async recall(blockingKeys: string[]): Promise<Candidate[]> {
    if (blockingKeys.length === 0) return []
    if (blockingKeys.length > MAX_RECALL_KEYS) {
      throw new Error(
        `recall: ${blockingKeys.length} blocking keys exceed ${MAX_RECALL_KEYS}`,
      )
    }
    const sizes = new Map<string, number>()
    const rows = await this.db
      .select({ key: blockingIndex.key, n: count() })
      .from(blockingIndex)
      .where(inArray(blockingIndex.key, blockingKeys))
      .groupBy(blockingIndex.key)
    for (const row of rows) sizes.set(row.key, row.n)

    const [first, ...rest] = blockingKeys
    const ordered = [
      first,
      ...rest
        .map((key, i) => ({ key, i, n: sizes.get(key) ?? 0 }))
        .sort((a, b) => a.n - b.n || a.i - b.i)
        .map((entry) => entry.key),
    ].filter((key): key is string => key !== undefined && sizes.has(key))

    const candidates = new Map<string, StoredComponents>()
    let truncated = false
    for (const key of ordered) {
      if (candidates.size >= this.maxCandidates) {
        truncated = true
        break
      }
      if ((sizes.get(key) ?? 0) > this.perKeyCap) truncated = true
      const block = await this.db
        .select({ visitor_id: templates.visitor_id, stored: templates.stored })
        .from(blockingIndex)
        .innerJoin(
          templates,
          eq(templates.visitor_id, blockingIndex.visitor_id),
        )
        .where(eq(blockingIndex.key, key))
        .orderBy(desc(templates.lastSeen))
        .limit(this.perKeyCap)
      for (const row of block) {
        if (candidates.size >= this.maxCandidates) {
          truncated = true
          break
        }
        if (!candidates.has(row.visitor_id)) {
          candidates.set(
            row.visitor_id,
            JSON.parse(row.stored) as StoredComponents,
          )
        }
      }
    }
    if (truncated) {
      console.warn(
        `recall truncated: ${blockingKeys.length} blocking key(s), per-key cap ${this.perKeyCap}, total cap ${this.maxCandidates}`,
      )
    }
    return Array.from(candidates, ([visitor_id, stored]) => ({
      visitor_id,
      stored,
    }))
  }

  /** Persist the verdict and return the visitor id to report (see
   *  {@link CandidateSource.persist}). */
  async persist(outcome: ScoreOutcome, nowMs: number): Promise<string> {
    switch (outcome.decision) {
      case 'new_device':
        return this.mint(outcome, nowMs)
      case 'match':
        await this.writeBack(outcome, nowMs)
        return requireId(outcome)
      case 'review':
        return requireId(outcome)
    }
  }

  /**
   * Store a new device under a freshly minted id, in one batch: the template
   * insert is skipped when the id is tombstoned (or already taken), and the
   * index rows are written only while that id's template exists. A skipped
   * insert retries with a fresh id.
   */
  private async mint(outcome: ScoreOutcome, nowMs: number): Promise<string> {
    const { template, keys } = requireTemplate(outcome)
    const stored = JSON.stringify(template)
    for (let attempt = 0; attempt < MINT_ATTEMPTS; attempt++) {
      const id = randomId()
      const insert = this.db
        .insert(templates)
        .select(
          sql`SELECT ${id}, ${stored}, ${nowMs}, ${nowMs}, 1 WHERE NOT EXISTS (SELECT 1 FROM ${erasedVisitors} WHERE ${erasedVisitors.visitor_id} = ${id})`,
        )
        .onConflictDoNothing()
        .returning({ visitor_id: templates.visitor_id })
      const [inserted] = await this.db.batch([
        insert,
        ...this.indexIfExists(id, keys),
      ])
      if (inserted.length > 0) return id
    }
    throw new Error(`could not mint a visitor id in ${MINT_ATTEMPTS} attempts`)
  }

  /**
   * Write a match's drifted template back and (re)index its keys, in one batch
   * whose every statement requires the template to still exist — a match never
   * resurrects a visitor erased concurrently.
   */
  private async writeBack(outcome: ScoreOutcome, nowMs: number): Promise<void> {
    const id = requireId(outcome)
    const { template, keys } = requireTemplate(outcome)
    const update = this.db
      .update(templates)
      .set({
        stored: JSON.stringify(template),
        lastSeen: nowMs,
        observationCount: sql`${templates.observationCount} + 1`,
      })
      .where(eq(templates.visitor_id, id))
    await this.db.batch([update, ...this.indexIfExists(id, keys)])
  }

  /** One idempotent index insert per key, each conditional on `id`'s
   *  template existing. */
  private indexIfExists(id: string, keys: string[]) {
    return keys.map((key) =>
      this.db
        .insert(blockingIndex)
        .select(
          sql`SELECT ${key}, ${id} WHERE EXISTS (SELECT 1 FROM ${templates} WHERE ${templates.visitor_id} = ${id})`,
        )
        .onConflictDoNothing(),
    )
  }

  /**
   * GDPR erasure: drop the template, its blocking-index rows and every
   * identify event of the visitor, and tombstone the id, in one atomic batch.
   * Idempotent — an unknown id deletes nothing and still succeeds (re-erasing
   * refreshes the tombstone).
   */
  async erase(id: string): Promise<void> {
    const now = Date.now()
    await this.db.batch([
      this.db.delete(blockingIndex).where(eq(blockingIndex.visitor_id, id)),
      this.db.delete(templates).where(eq(templates.visitor_id, id)),
      this.db.delete(events).where(eq(events.visitor_id, id)),
      this.db
        .insert(erasedVisitors)
        .values({ visitor_id: id, erasedAt: now })
        .onConflictDoUpdate({
          target: erasedVisitors.visitor_id,
          set: { erasedAt: now },
        }),
    ])
  }

  /**
   * Retention purge: delete every template last seen before `nowMs -
   * maxAgeMs` and their blocking-index rows, returning how many templates were
   * removed. `maxAgeMs <= 0` disables retention (returns 0 without touching the
   * table). Run from the scheduled cron (`index.ts`).
   *
   * Both deletes select the stale set by the cutoff (the index rows through a
   * subquery on `templates`), so each statement binds one parameter however
   * many rows are stale. Index rows go first, in the same batch, while their
   * templates still identify them.
   */
  async purgeOlderThan(nowMs: number, maxAgeMs: number): Promise<number> {
    if (maxAgeMs <= 0) return 0
    const cutoff = nowMs - maxAgeMs
    const stale = lt(templates.lastSeen, cutoff)
    const row = await this.db
      .select({ n: count() })
      .from(templates)
      .where(stale)
      .get()
    const removed = row?.n ?? 0
    if (removed === 0) return 0
    const staleIds = this.db
      .select({ visitor_id: templates.visitor_id })
      .from(templates)
      .where(stale)
    await this.db.batch([
      this.db
        .delete(blockingIndex)
        .where(inArray(blockingIndex.visitor_id, staleIds)),
      this.db.delete(templates).where(stale),
    ])
    return removed
  }

  /**
   * Bound the tombstone table to the newest `cap` entries, deleting the oldest
   * beyond it in one statement (one bound parameter), and return how many were
   * removed. Run from the scheduled cron alongside the template purge.
   */
  async trimTombstones(cap: number = TOMBSTONE_CAP): Promise<number> {
    const row = await this.db.select({ n: count() }).from(erasedVisitors).get()
    const removed = Math.max(0, (row?.n ?? 0) - cap)
    if (removed === 0) return 0
    const oldest = this.db
      .select({ visitor_id: erasedVisitors.visitor_id })
      .from(erasedVisitors)
      .orderBy(erasedVisitors.erasedAt, erasedVisitors.visitor_id)
      .limit(removed)
    await this.db
      .delete(erasedVisitors)
      .where(inArray(erasedVisitors.visitor_id, oldest))
    return removed
  }
}

/** The outcome's visitor id, present on `match` and `review`. */
function requireId(outcome: ScoreOutcome): string {
  if (outcome.visitor_id === null) {
    throw new Error(`score returned no visitor id for ${outcome.decision}`)
  }
  return outcome.visitor_id
}

/** The template + keys the engine returns with `match` / `new_device`. */
function requireTemplate(outcome: ScoreOutcome): {
  template: StoredComponents
  keys: string[]
} {
  if (outcome.template === null || outcome.template_blocking_keys === null) {
    throw new Error(`score returned no template for ${outcome.decision}`)
  }
  return { template: outcome.template, keys: outcome.template_blocking_keys }
}
