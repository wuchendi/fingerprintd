/**
 * The identify event log behind `GET /events/{request_id}` and
 * `POST /checkin/assess`: one row per identify, holding the exact response
 * body until its TTL (`FP_EVENT_TTL_SECS`) elapses — the database form of the
 * native bounded TTL event store.
 *
 * Queries go through Drizzle on the database client (`src/db/client.ts`, libSQL
 * or D1), so the store is driver-neutral; every statement binds a handful of
 * parameters. Erasure lives in the fingerprint store's erase batch.
 */

import { and, count, eq, gt, lte } from 'drizzle-orm'
import type { Db } from '../../db/client'
import { events } from '../../db/schema'
import type { EventLog, StoredEvent } from '../../lib/state'

/** Insert + lookup + purge over the database. Holds no state itself. */
export class EventStore implements EventLog {
  constructor(private readonly db: Db) {}

  async put(event: StoredEvent, expiresAt: number): Promise<void> {
    await this.db.insert(events).values({ ...event, expires_at: expiresAt })
  }

  async get(
    requestId: string,
    nowMs: number,
  ): Promise<StoredEvent | undefined> {
    return this.db
      .select({
        request_id: events.request_id,
        visitor_id: events.visitor_id,
        ip: events.ip,
        body: events.body,
      })
      .from(events)
      .where(
        and(eq(events.request_id, requestId), gt(events.expires_at, nowMs)),
      )
      .get()
  }

  /**
   * Delete every event expired as of `nowMs` (`expires_at <= nowMs`) and return
   * how many were removed. The delete selects by the cutoff alone, so it binds
   * one parameter however many rows expired. Run from the scheduled cron.
   */
  async purgeExpired(nowMs: number): Promise<number> {
    const expired = lte(events.expires_at, nowMs)
    const row = await this.db
      .select({ n: count() })
      .from(events)
      .where(expired)
      .get()
    const removed = row?.n ?? 0
    if (removed === 0) return 0
    await this.db.delete(events).where(expired)
    return removed
  }
}
