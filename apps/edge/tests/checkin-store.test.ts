import { createClient } from '@libsql/client'
import { drizzle } from 'drizzle-orm/libsql'
import { migrate } from 'drizzle-orm/libsql/migrator'
import { beforeEach, describe, expect, it } from 'vitest'
import type { Db } from '../src/db/client'
import * as schema from '../src/db/schema'
import type { CheckinEvent } from '../src/modules/checkin/checkin-store'
import {
  CheckinEventStore,
  INTERVAL_SAMPLE,
  NEW_DEVICE_SAMPLE,
} from '../src/modules/checkin/checkin-store'

// The check-in store against a real libSQL database migrated from the
// committed `./drizzle` set: the event log is seeded and the windowed
// aggregates are read back. The setup file (`tests/d1-param-guard.ts`) makes
// any statement binding more than 100 parameters fail, as it would on D1.

const HOUR = 60 * 60 * 1000
const DAY = 24 * HOUR
const MINUTE = 60 * 1000
// A fixed "now" so every window boundary in the assertions is exact.
const NOW = 1_000_000_000_000

/** Seed one event; `ts` defaults to NOW. */
function ev(
  accountId: string,
  visitorId: string,
  ip: string,
  ts: number = NOW,
): CheckinEvent {
  return { accountId, visitorId, ip, ts }
}

async function seed(
  store: CheckinEventStore,
  events: CheckinEvent[],
): Promise<void> {
  for (const e of events) await store.record(e)
}

let db: Db

beforeEach(async () => {
  const client = createClient({ url: ':memory:' })
  const libsql = drizzle(client, { schema })
  await migrate(libsql, { migrationsFolder: './drizzle' })
  db = libsql as unknown as Db
})

describe('device_account_fanout (device farm)', () => {
  it('counts distinct accounts per device within 24h and 7d', async () => {
    const store = new CheckinEventStore(db)
    await seed(store, [
      // Device `farm` fans out across 3 accounts inside 24h...
      ev('a1', 'farm', 'ip1', NOW - 1 * HOUR),
      ev('a2', 'farm', 'ip1', NOW - 2 * HOUR),
      ev('a3', 'farm', 'ip1', NOW - 3 * HOUR),
      // ...a repeat account does not inflate the distinct count...
      ev('a1', 'farm', 'ip1', NOW - 30 * MINUTE),
      // ...a 4th account only within the 7d window (3 days ago)...
      ev('a4', 'farm', 'ip1', NOW - 3 * DAY),
      // ...and one outside 7d is excluded from both.
      ev('a5', 'farm', 'ip1', NOW - 8 * DAY),
    ])

    const agg = await store.getAggregates('a1', 'farm', 'ip1', NOW)
    expect(agg.device_account_fanout.h24).toBe(3)
    expect(agg.device_account_fanout.d7).toBe(4)
  })
})

describe('account_device_count (account cultivation)', () => {
  it('counts distinct devices per account within 7d and 30d', async () => {
    const store = new CheckinEventStore(db)
    await seed(store, [
      ev('acct', 'd1', 'ip1', NOW - 1 * DAY),
      ev('acct', 'd2', 'ip1', NOW - 2 * DAY),
      ev('acct', 'd2', 'ip1', NOW - 3 * DAY), // repeat device
      ev('acct', 'd3', 'ip1', NOW - 20 * DAY), // 7d excludes, 30d includes
      ev('acct', 'd4', 'ip1', NOW - 40 * DAY), // outside both
    ])

    const agg = await store.getAggregates('acct', 'd1', 'ip1', NOW)
    expect(agg.account_device_count.d7).toBe(2)
    expect(agg.account_device_count.d30).toBe(3)
  })
})

describe('account_new_device_rate (fingerprint reset)', () => {
  it('is ~1 when every recent check-in is a fresh device', async () => {
    const store = new CheckinEventStore(db)
    // 5 check-ins, all distinct devices ⇒ rate 1.
    await seed(store, [
      ev('reset', 'v1', 'ip1', NOW - 5 * HOUR),
      ev('reset', 'v2', 'ip1', NOW - 4 * HOUR),
      ev('reset', 'v3', 'ip1', NOW - 3 * HOUR),
      ev('reset', 'v4', 'ip1', NOW - 2 * HOUR),
      ev('reset', 'v5', 'ip1', NOW - 1 * HOUR),
    ])

    const agg = await store.getAggregates('reset', 'v5', 'ip1', NOW)
    expect(agg.account_new_device_rate.sampled).toBe(5)
    expect(agg.account_new_device_rate.rate).toBe(1)
  })

  it('is low for a stable single-device account', async () => {
    const store = new CheckinEventStore(db)
    await seed(store, [
      ev('human', 'phone', 'ip1', NOW - 3 * DAY),
      ev('human', 'phone', 'ip1', NOW - 2 * DAY),
      ev('human', 'phone', 'ip1', NOW - 1 * DAY),
      ev('human', 'phone', 'ip1', NOW - 1 * HOUR),
    ])

    const agg = await store.getAggregates('human', 'phone', 'ip1', NOW)
    expect(agg.account_new_device_rate.sampled).toBe(4)
    expect(agg.account_new_device_rate.rate).toBeCloseTo(0.25)
  })

  it('samples only the most-recent N events', async () => {
    const store = new CheckinEventStore(db)
    // Older events are all one shared device; the newest N are all distinct.
    const events: CheckinEvent[] = []
    for (let i = 0; i < 10; i++) {
      events.push(
        ev('acct', 'old', 'ip1', NOW - (NEW_DEVICE_SAMPLE + 10 - i) * HOUR),
      )
    }
    for (let i = 0; i < NEW_DEVICE_SAMPLE; i++) {
      events.push(
        ev('acct', `fresh-${i}`, 'ip1', NOW - (NEW_DEVICE_SAMPLE - i) * MINUTE),
      )
    }
    await seed(store, events)

    const agg = await store.getAggregates('acct', 'fresh-0', 'ip1', NOW)
    // Only the newest N (all fresh) are sampled; the shared-device tail is unseen.
    expect(agg.account_new_device_rate.sampled).toBe(NEW_DEVICE_SAMPLE)
    expect(agg.account_new_device_rate.rate).toBe(1)
  })

  it('is 0 for an account with no events', async () => {
    const store = new CheckinEventStore(db)
    const agg = await store.getAggregates('nobody', 'v0', 'ip0', NOW)
    expect(agg.account_new_device_rate).toEqual({ rate: 0, sampled: 0 })
  })
})

describe('ip_account_count (datacenter / proxy batch)', () => {
  it('counts distinct accounts per IP within 1h and 24h', async () => {
    const store = new CheckinEventStore(db)
    await seed(store, [
      ev('a1', 'v1', 'proxy', NOW - 10 * MINUTE),
      ev('a2', 'v2', 'proxy', NOW - 20 * MINUTE),
      ev('a2', 'v2', 'proxy', NOW - 25 * MINUTE), // repeat account
      ev('a3', 'v3', 'proxy', NOW - 5 * HOUR), // 1h excludes, 24h includes
      ev('a4', 'v4', 'proxy', NOW - 30 * HOUR), // outside both
    ])

    const agg = await store.getAggregates('a1', 'v1', 'proxy', NOW)
    expect(agg.ip_account_count.h1).toBe(2)
    expect(agg.ip_account_count.h24).toBe(3)
  })
})

describe('checkin_interval_regularity (scripted timing)', () => {
  it('approaches 1 for perfectly regular scripted check-ins', async () => {
    const store = new CheckinEventStore(db)
    // Exactly one hour between every check-in ⇒ zero variance ⇒ regularity 1.
    const events: CheckinEvent[] = []
    for (let i = 0; i < INTERVAL_SAMPLE; i++) {
      events.push(ev('bot', 'botdev', 'ip1', NOW - i * HOUR))
    }
    await seed(store, events)

    const agg = await store.getAggregates('bot', 'botdev', 'ip1', NOW)
    expect(agg.checkin_interval_regularity.samples).toBe(INTERVAL_SAMPLE - 1)
    expect(agg.checkin_interval_regularity.regularity).toBe(1)
  })

  it('is lower for irregular human timing', async () => {
    const store = new CheckinEventStore(db)
    // Wildly uneven gaps ⇒ high coefficient of variation ⇒ regularity well below 1.
    await seed(store, [
      ev('human', 'phone', 'ip1', NOW),
      ev('human', 'phone', 'ip1', NOW - 5 * MINUTE),
      ev('human', 'phone', 'ip1', NOW - 5 * MINUTE - 3 * HOUR),
      ev('human', 'phone', 'ip1', NOW - 5 * MINUTE - 3 * HOUR - 40 * MINUTE),
      ev(
        'human',
        'phone',
        'ip1',
        NOW - 5 * MINUTE - 3 * HOUR - 40 * MINUTE - 11 * HOUR,
      ),
    ])

    const agg = await store.getAggregates('human', 'phone', 'ip1', NOW)
    expect(agg.checkin_interval_regularity.regularity).toBeLessThan(0.7)
  })

  it('is 0 when there are fewer than two intervals', async () => {
    const store = new CheckinEventStore(db)
    await seed(store, [
      ev('acct', 'v1', 'ip1', NOW),
      ev('acct', 'v1', 'ip1', NOW - 1 * HOUR),
    ])
    const agg = await store.getAggregates('acct', 'v1', 'ip1', NOW)
    // Two events = one interval < 2 ⇒ undecidable.
    expect(agg.checkin_interval_regularity).toEqual({
      regularity: 0,
      samples: 1,
    })
  })
})

describe('batch_clustering (live minute burst)', () => {
  it('counts device and IP events within the current minute bucket', async () => {
    const store = new CheckinEventStore(db)
    // Pin `now` to the middle of a minute so the whole bucket is in the past.
    const now = Math.floor(NOW / MINUTE) * MINUTE + 30 * 1000
    const bucketStart = Math.floor(now / MINUTE) * MINUTE
    await seed(store, [
      // 3 events for the device inside the bucket...
      ev('a1', 'burstdev', 'burstip', bucketStart + 1000),
      ev('a2', 'burstdev', 'burstip', bucketStart + 2000),
      ev('a3', 'burstdev', 'otherip', bucketStart + 3000),
      // ...one just before the bucket started (excluded)...
      ev('a4', 'burstdev', 'burstip', bucketStart - 1000),
      // ...and an extra IP hit inside the bucket from a different device.
      ev('a5', 'otherdev', 'burstip', bucketStart + 4000),
    ])

    const agg = await store.getAggregates('a1', 'burstdev', 'burstip', now)
    // burstdev: 3 in-bucket (the pre-bucket one is excluded).
    expect(agg.batch_clustering.device).toBe(3)
    // burstip: 3 in-bucket (burstdev x2 + otherdev x1); the pre-bucket one excluded.
    expect(agg.batch_clustering.ip).toBe(3)
  })
})

describe('purgeOlderThan (retention)', () => {
  it('deletes events before the cutoff and returns the count', async () => {
    const store = new CheckinEventStore(db)
    await seed(store, [
      ev('a1', 'v1', 'ip1', NOW - 40 * DAY), // stale
      ev('a2', 'v2', 'ip1', NOW - 35 * DAY), // stale
      ev('a3', 'v3', 'ip1', NOW - 1 * DAY), // fresh
    ])

    const cutoff = NOW - 30 * DAY
    expect(await store.purgeOlderThan(cutoff)).toBe(2)
    // Only the fresh event remains — visible via its account's device count.
    const agg = await store.getAggregates('a3', 'v3', 'ip1', NOW)
    expect(agg.account_device_count.d30).toBe(1)
    // A second purge with nothing stale removes nothing.
    expect(await store.purgeOlderThan(cutoff)).toBe(0)
  })
})
