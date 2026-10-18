/**
 * The check-in event store: the relationship-graph state the rule engine and
 * the `/assess` endpoint consume. Like `../fingerprint/fingerprint-store.ts` it
 * is a stateless Drizzle wrapper over the database client (libSQL or D1), but
 * instead of recall/drift it appends check-in events and derives the windowed
 * farming aggregates from them.
 *
 * One table (`src/db/schema.ts`): `checkin_events(account_id, visitor_id, ip,
 * ts)`. Every aggregate is a `COUNT(DISTINCT ...)` (or a small last-N scan)
 * bounded by a `ts >= now - window` range served by one of the composite
 * indexes. Pure aggregate query logic only — NO risk scoring lives here; this
 * layer answers "how many distinct X in window W", nothing more.
 */

import { and, desc, eq, gte, lt, sql } from 'drizzle-orm'
import type { Db } from '../../db/client'
import { checkinEvents } from '../../db/schema'

/** One hour / one day in milliseconds — the units the windows below are cut in. */
const HOUR_MS = 60 * 60 * 1000
const DAY_MS = 24 * HOUR_MS
/** One minute in milliseconds — the `batch_clustering` bucket width. */
const MINUTE_MS = 60 * 1000

/**
 * How many of an account's most-recent events feed `account_new_device_rate`
 * ("last N"). Bounds the scan to a small tail so a long-lived account
 * is judged on recent churn, not lifetime history.
 */
export const NEW_DEVICE_SAMPLE = 20
/**
 * How many of an account's most-recent timestamps feed
 * `checkin_interval_regularity` ("last K"). Needs at least 2 to form
 * one interval; more sharpens the regularity estimate.
 */
export const INTERVAL_SAMPLE = 10

/** A single check-in observation appended by {@link CheckinEventStore.record}. */
export interface CheckinEvent {
  /** Business identity being assessed. */
  accountId: string
  /** Device identifier carried through from the fingerprintd verdict. */
  visitorId: string
  /** Edge-observed client IP (never client-reported). */
  ip: string
  /** Observation time (Unix ms, edge-stamped). */
  ts: number
}

/**
 * The aggregate bundle returned by {@link CheckinEventStore.getAggregates}.
 * Top-level keys match the aggregate names EXACTLY so this is structurally
 * compatible with the canonical `Aggregates` type defined in parallel
 * (`src/config/risk-config.ts`); the endpoint reconciles the two. Every value is a plain
 * count / ratio — no thresholds or scores are applied here.
 */
export interface AggregateResult {
  /** Distinct accounts this DEVICE checked into — device-farm fan-out. */
  device_account_fanout: {
    /** …in the last 24 hours. */
    h24: number
    /** …in the last 7 days. */
    d7: number
  }
  /** Distinct devices this ACCOUNT checked in from — account cultivation. */
  account_device_count: {
    /** …in the last 7 days. */
    d7: number
    /** …in the last 30 days. */
    d30: number
  }
  /** Device churn over the account's last {@link NEW_DEVICE_SAMPLE} events —
   *  fingerprint reset / emulator recycling. */
  account_new_device_rate: {
    /** Distinct devices ÷ events sampled, in `[0, 1]` (0 when no events). */
    rate: number
    /** How many recent events the rate was computed over (≤ N). */
    sampled: number
  }
  /** Distinct accounts sharing this IP — datacenter / proxy batch. */
  ip_account_count: {
    /** …in the last 1 hour. */
    h1: number
    /** …in the last 24 hours. */
    h24: number
  }
  /** Timing regularity of the account's last {@link INTERVAL_SAMPLE} check-ins —
   *  scripted cadence. */
  checkin_interval_regularity: {
    /** `1 / (1 + cv)` of consecutive intervals, in `(0, 1]`; 1 ⇒ perfectly
     *  regular (scripted), → 0 ⇒ irregular (human). 0 when < 2 intervals. */
    regularity: number
    /** How many intervals the estimate used (events − 1, ≥ 0). */
    samples: number
  }
  /** Burst size in the current minute bucket — live batch spikes. */
  batch_clustering: {
    /** Events from this DEVICE in the current minute. */
    device: number
    /** Events from this IP in the current minute. */
    ip: number
  }
}

/**
 * Append + aggregate over the database via Drizzle. Construct once per isolate
 * from the client `getDb` returns. Holds no state itself — every method is a
 * query against the shared database.
 */
export class CheckinEventStore {
  private readonly db: Db

  constructor(db: Db) {
    this.db = db
  }

  /** Append one check-in event. Rows are never updated — the append-only log is
   *  the source of truth every aggregate is derived from. */
  async record(event: CheckinEvent): Promise<void> {
    await this.db.insert(checkinEvents).values(event)
  }

  /**
   * Compute every aggregate for the `(accountId, visitorId, ip)` triple
   * as of `now` (Unix ms). Independent queries are issued concurrently — the
   * database serves each from a composite index — and folded into one
   * {@link AggregateResult}.
   */
  async getAggregates(
    accountId: string,
    visitorId: string,
    ip: string,
    now: number,
  ): Promise<AggregateResult> {
    const [
      fanoutH24,
      fanoutD7,
      deviceD7,
      deviceD30,
      newDeviceRate,
      ipH1,
      ipH24,
      regularity,
      burstDevice,
      burstIp,
    ] = await Promise.all([
      this.distinctAccountsForVisitor(visitorId, now - DAY_MS),
      this.distinctAccountsForVisitor(visitorId, now - 7 * DAY_MS),
      this.distinctVisitorsForAccount(accountId, now - 7 * DAY_MS),
      this.distinctVisitorsForAccount(accountId, now - 30 * DAY_MS),
      this.newDeviceRate(accountId),
      this.distinctAccountsForIp(ip, now - HOUR_MS),
      this.distinctAccountsForIp(ip, now - 24 * HOUR_MS),
      this.intervalRegularity(accountId),
      this.burstForVisitor(visitorId, bucketStart(now)),
      this.burstForIp(ip, bucketStart(now)),
    ])
    return {
      device_account_fanout: { h24: fanoutH24, d7: fanoutD7 },
      account_device_count: { d7: deviceD7, d30: deviceD30 },
      account_new_device_rate: newDeviceRate,
      ip_account_count: { h1: ipH1, h24: ipH24 },
      checkin_interval_regularity: regularity,
      batch_clustering: { device: burstDevice, ip: burstIp },
    }
  }

  /** Distinct accounts this device checked into since `sinceTs` (device fan-out). */
  private async distinctAccountsForVisitor(
    visitorId: string,
    sinceTs: number,
  ): Promise<number> {
    return this.countDistinct(
      checkinEvents.accountId,
      and(
        eq(checkinEvents.visitorId, visitorId),
        gte(checkinEvents.ts, sinceTs),
      ),
    )
  }

  /** Distinct devices this account checked in from since `sinceTs` (cultivation). */
  private async distinctVisitorsForAccount(
    accountId: string,
    sinceTs: number,
  ): Promise<number> {
    return this.countDistinct(
      checkinEvents.visitorId,
      and(
        eq(checkinEvents.accountId, accountId),
        gte(checkinEvents.ts, sinceTs),
      ),
    )
  }

  /** Distinct accounts sharing this IP since `sinceTs` (proxy/datacenter batch). */
  private async distinctAccountsForIp(
    ip: string,
    sinceTs: number,
  ): Promise<number> {
    return this.countDistinct(
      checkinEvents.accountId,
      and(eq(checkinEvents.ip, ip), gte(checkinEvents.ts, sinceTs)),
    )
  }

  /**
   * Device-churn rate over the account's last {@link NEW_DEVICE_SAMPLE} events:
   * `distinct(visitorId) / sampled`. A high ratio means the account keeps
   * presenting fresh devices (fingerprint reset / emulator recycling); a stable
   * human is ≈ `1 / sampled`. Zero events ⇒ rate 0.
   */
  private async newDeviceRate(
    accountId: string,
  ): Promise<AggregateResult['account_new_device_rate']> {
    const rows = await this.db
      .select({ visitorId: checkinEvents.visitorId })
      .from(checkinEvents)
      .where(eq(checkinEvents.accountId, accountId))
      .orderBy(desc(checkinEvents.ts))
      .limit(NEW_DEVICE_SAMPLE)
    const sampled = rows.length
    if (sampled === 0) return { rate: 0, sampled: 0 }
    const distinct = new Set(rows.map((r) => r.visitorId)).size
    return { rate: distinct / sampled, sampled }
  }

  /**
   * Timing regularity over the account's last {@link INTERVAL_SAMPLE} check-ins.
   * Takes the consecutive gaps, and returns `1 / (1 + cv)` where `cv` is their
   * coefficient of variation (stddev ÷ mean): perfectly regular scripted cadence
   * ⇒ `cv = 0` ⇒ `1`, human jitter ⇒ larger `cv` ⇒ toward `0`. Fewer than two
   * intervals (≤ 2 events) is undecidable ⇒ `regularity: 0`.
   */
  private async intervalRegularity(
    accountId: string,
  ): Promise<AggregateResult['checkin_interval_regularity']> {
    const rows = await this.db
      .select({ ts: checkinEvents.ts })
      .from(checkinEvents)
      .where(eq(checkinEvents.accountId, accountId))
      .orderBy(desc(checkinEvents.ts))
      .limit(INTERVAL_SAMPLE)
    const times = rows.map((r) => r.ts)
    const intervals: number[] = []
    for (let i = 0; i < times.length - 1; i++) {
      // Rows are newest-first; the gap between adjacent check-ins is positive.
      intervals.push((times[i] as number) - (times[i + 1] as number))
    }
    if (intervals.length < 2)
      return { regularity: 0, samples: intervals.length }
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length
    if (mean === 0) return { regularity: 1, samples: intervals.length }
    const variance =
      intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length
    const cv = Math.sqrt(variance) / mean
    return { regularity: 1 / (1 + cv), samples: intervals.length }
  }

  /** Events from this device in the current minute bucket (live batch spike). */
  private async burstForVisitor(
    visitorId: string,
    bucketStartTs: number,
  ): Promise<number> {
    return this.countRows(
      and(
        eq(checkinEvents.visitorId, visitorId),
        gte(checkinEvents.ts, bucketStartTs),
      ),
    )
  }

  /** Events from this IP in the current minute bucket (live batch spike). */
  private async burstForIp(ip: string, bucketStartTs: number): Promise<number> {
    return this.countRows(
      and(eq(checkinEvents.ip, ip), gte(checkinEvents.ts, bucketStartTs)),
    )
  }

  /** `COUNT(DISTINCT column) WHERE <where>` as a plain number. */
  private async countDistinct(
    column: typeof checkinEvents.accountId | typeof checkinEvents.visitorId,
    where: ReturnType<typeof and>,
  ): Promise<number> {
    const row = await this.db
      .select({ n: sql<number>`count(distinct ${column})` })
      .from(checkinEvents)
      .where(where)
      .get()
    return row?.n ?? 0
  }

  /** `COUNT(*) WHERE <where>` as a plain number. */
  private async countRows(where: ReturnType<typeof and>): Promise<number> {
    const row = await this.db
      .select({ n: sql<number>`count(*)` })
      .from(checkinEvents)
      .where(where)
      .get()
    return row?.n ?? 0
  }

  /**
   * Retention purge (mirrors `FingerprintStore.purgeOlderThan`): delete every
   * event stamped before `cutoffTs`, returning how many rows were removed. Run
   * from the scheduled cron (`index.ts`); also directly unit-tested. Counts
   * first so the caller can log the reclaim without a second scan.
   */
  async purgeOlderThan(cutoffTs: number): Promise<number> {
    const row = await this.db
      .select({ n: sql<number>`count(*)` })
      .from(checkinEvents)
      .where(lt(checkinEvents.ts, cutoffTs))
      .get()
    const stale = row?.n ?? 0
    if (stale === 0) return 0
    await this.db.delete(checkinEvents).where(lt(checkinEvents.ts, cutoffTs))
    return stale
  }
}

/** Start (Unix ms) of the one-minute bucket containing `now`. */
function bucketStart(now: number): number {
  return Math.floor(now / MINUTE_MS) * MINUTE_MS
}
