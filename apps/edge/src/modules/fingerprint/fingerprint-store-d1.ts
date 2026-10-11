/**
 * The D1-backed fingerprint library: stage-one candidate recall plus
 * drift persistence, the externalized form of `fingerprintd::fuzzy`'s in-memory
 * `RecordStore` + `BlockingIndex`.
 *
 * Two tables (see `src/db/schema.ts`): `templates` holds each visitor's RAW
 * component object (the WASM engine re-salts it on recall, so no salted state is
 * stored here), and `blocking_index` is the `key -> visitorId` inverted index
 * recall unions over. Persistence mirrors the native `identify` verdict handling
 * (fuzzy-matching §7): a match drifts the template, a new device stores a fresh one, a
 * review writes nothing.
 *
 * Queries go through Drizzle (`drizzle-orm/d1`); the emitted SQL is equivalent
 * to the hand-written statements it replaced, so the cross-stack parity holds.
 */

import { eq, inArray, lt, sql } from 'drizzle-orm'
import type { Db } from '../../db/client'
import { getDb } from '../../db/client'
import { blockingIndex, templates } from '../../db/schema'
import type { Candidate, CandidateSource } from '../../lib/state'
import type { ScoreOutcome } from '../../lib/types'

/**
 * Per-recall candidate cap, mirroring `fingerprintd::fuzzy::blocking::DEFAULT_MAX_BLOCK`.
 * A hot blocking key (e.g. stock iPhone Safari) unions into a huge, low-information
 * block; leaving it unbounded means every candidate is re-scored in-isolate by WASM
 * plus its D1 read cost (P99 blowup). Bounding recall matches the native index,
 * whose per-block size cap drops over-capacity members (fuzzy-matching §4). The edge has no
 * metrics sink, so a truncated recall is surfaced via `console.warn` rather than a
 * dropped counter — the native "not silently truncated" rule, edge-shaped.
 */
export const DEFAULT_MAX_BLOCK = 1024

/**
 * Recall + persist over D1 via Drizzle. Construct once per isolate from the `DB`
 * binding. Holds no state itself — every method is a query against the shared
 * database.
 */
export class D1FingerprintStore implements CandidateSource {
  private readonly db: Db
  /** Max candidates a single `recall()` returns; over-cap blocks are truncated. */
  private readonly maxBlock: number

  constructor(d1: D1Database, maxBlock: number = DEFAULT_MAX_BLOCK) {
    this.db = getDb(d1)
    this.maxBlock = maxBlock
  }

  /**
   * Union of every stored template sharing any of `blockingKeys` (fuzzy-matching §4).
   * Empty keys ⇒ nothing to recall. `selectDistinct` collapses a visitor matched
   * by several keys to one candidate; the inner join drops any index row whose
   * template was not (yet) written. The union is bounded to `maxBlock`
   * candidates; a hot key that would recall more is truncated (and warned).
   */
  async recall(blockingKeys: string[]): Promise<Candidate[]> {
    if (blockingKeys.length === 0) return []
    const rows = await this.db
      .selectDistinct({
        visitorId: templates.visitorId,
        components: templates.components,
      })
      .from(templates)
      .innerJoin(
        blockingIndex,
        eq(blockingIndex.visitorId, templates.visitorId),
      )
      .where(inArray(blockingIndex.key, blockingKeys))
      .limit(this.maxBlock)
    if (rows.length >= this.maxBlock) {
      // Over-capacity block: the recall hit the cap and was truncated. Surfaced,
      // not silent — the edge analogue of the native drop accounting.
      console.warn(
        `recall over capacity: ${blockingKeys.length} blocking key(s) recalled at least ${this.maxBlock} candidates; truncated to cap`,
      )
    }
    return rows.map((row) => ({
      visitor_id: row.visitorId,
      components: JSON.parse(row.components) as Record<string, unknown>,
    }))
  }

  /**
   * Fold the observation in per the verdict (fuzzy-matching §7). A review is a no-op
   * (anti-poisoning); a match drifts the matched template toward `components` by
   * a per-component merge (present values overwrite, absent ones are retained —
   * mirroring `RecordStore::observe`); a new device is stored whole. Either
   * write also indexes `blockingKeys` under the resolved id.
   */
  async persist(
    outcome: ScoreOutcome,
    components: Record<string, unknown>,
    blockingKeys: string[],
    nowMs: number,
  ): Promise<void> {
    if (outcome.decision === 'review') return

    let toStore = components
    if (outcome.decision === 'match') {
      const existing = await this.storedComponents(outcome.visitor_id)
      // Per-component merge: the new observation overwrites present values and
      // leaves absent ones intact, so a browser upgrade drifts the template
      // without erasing components this probe happened not to report.
      if (existing) toStore = { ...existing, ...components }
    }
    await this.write(outcome.visitor_id, toStore, blockingKeys, nowMs)
  }

  /** The stored raw components for `visitorId`, or `undefined` if unknown. */
  private async storedComponents(
    visitorId: string,
  ): Promise<Record<string, unknown> | undefined> {
    const row = await this.db
      .select({ components: templates.components })
      .from(templates)
      .where(eq(templates.visitorId, visitorId))
      .get()
    if (row === undefined) return undefined
    return JSON.parse(row.components) as Record<string, unknown>
  }

  /**
   * Upsert the template and index its blocking keys in one atomic batch. The
   * upsert stamps `last_seen`/`observation_count` on an existing row and seeds
   * `first_seen` on a new one; indexing is idempotent via the composite key.
   */
  private async write(
    visitorId: string,
    components: Record<string, unknown>,
    blockingKeys: string[],
    nowMs: number,
  ): Promise<void> {
    const upsert = this.db
      .insert(templates)
      .values({
        visitorId,
        components: JSON.stringify(components),
        firstSeen: nowMs,
        lastSeen: nowMs,
        observationCount: 1,
      })
      .onConflictDoUpdate({
        target: templates.visitorId,
        set: {
          components: sql`excluded.components`,
          lastSeen: sql`excluded.last_seen`,
          observationCount: sql`${templates.observationCount} + 1`,
        },
      })
    const index = blockingKeys.map((key) =>
      this.db
        .insert(blockingIndex)
        .values({ key, visitorId })
        .onConflictDoNothing(),
    )
    await this.db.batch([upsert, ...index])
  }

  /**
   * GDPR erasure: drop the visitor's template and all of its blocking-index
   * rows in one atomic batch, so a subsequent recall cannot surface it.
   * Idempotent — an unknown id deletes zero rows and still succeeds, so the
   * caller never leaks whether the id existed.
   */
  async erase(visitorId: string): Promise<void> {
    await this.db.batch([
      this.db.delete(templates).where(eq(templates.visitorId, visitorId)),
      this.db
        .delete(blockingIndex)
        .where(eq(blockingIndex.visitorId, visitorId)),
    ])
  }

  /**
   * Retention purge: delete every template last seen before `nowMs -
   * maxAgeMs` and their blocking-index rows, returning how many templates were
   * removed. `maxAgeMs <= 0` disables retention (returns 0 without touching the
   * table). Run from the scheduled cron (`index.ts`); also directly unit-tested.
   */
  async purgeOlderThan(nowMs: number, maxAgeMs: number): Promise<number> {
    if (maxAgeMs <= 0) return 0
    const cutoff = nowMs - maxAgeMs
    const stale = await this.db
      .select({ visitorId: templates.visitorId })
      .from(templates)
      .where(lt(templates.lastSeen, cutoff))
    if (stale.length === 0) return 0
    const ids = stale.map((row) => row.visitorId)
    await this.db.batch([
      this.db
        .delete(blockingIndex)
        .where(inArray(blockingIndex.visitorId, ids)),
      this.db.delete(templates).where(inArray(templates.visitorId, ids)),
    ])
    return ids.length
  }
}
