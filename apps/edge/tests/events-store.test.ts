import { count } from 'drizzle-orm'
import { beforeEach, describe, expect, it } from 'vitest'
import type { Db } from '../src/db/client'
import { events } from '../src/db/schema'
import type { StoredEvent } from '../src/lib/state'
import { EventStore } from '../src/modules/events'
import { FingerprintStore } from '../src/modules/fingerprint'
import { memoryDb } from './helpers/fakes'

// The identify event store against a real libSQL database migrated from the
// committed `./drizzle` set. The setup file (`tests/d1-param-guard.ts`) makes
// any statement binding more than 100 parameters fail, as it would on D1.

const NOW = 1_000_000_000_000

/** A stored event for `visitor_id`; the body is opaque to the store. */
function event(request_id: string, visitor_id = 'v1'): StoredEvent {
  return {
    request_id,
    visitor_id,
    ip: '203.0.113.7',
    body: `{"request_id":"${request_id}"}`,
  }
}

let db: Db
let store: EventStore

beforeEach(async () => {
  db = await memoryDb()
  store = new EventStore(db)
})

async function rows(): Promise<number> {
  const row = await db.select({ n: count() }).from(events).get()
  return row?.n ?? 0
}

describe('EventStore', () => {
  it('returns a stored event verbatim until it expires', async () => {
    await store.put(event('r1'), NOW + 1000)
    expect(await store.get('r1', NOW)).toEqual(event('r1'))
    expect(await store.get('r1', NOW + 999)).toEqual(event('r1'))
    // `expires_at <= now` is expired.
    expect(await store.get('r1', NOW + 1000)).toBeUndefined()
  })

  it('returns undefined for an unknown request id', async () => {
    expect(await store.get('nope', NOW)).toBeUndefined()
  })

  it('keeps a null ip', async () => {
    await store.put({ ...event('r1'), ip: null }, NOW + 1000)
    expect((await store.get('r1', NOW))?.ip).toBeNull()
  })

  it('purges expired events only and reports the count', async () => {
    await store.put(event('old-1'), NOW - 1)
    await store.put(event('old-2'), NOW)
    await store.put(event('fresh'), NOW + 1)
    expect(await store.purgeExpired(NOW)).toBe(2)
    expect(await rows()).toBe(1)
    expect(await store.get('fresh', NOW)).toBeDefined()
    expect(await store.purgeExpired(NOW)).toBe(0)
  })

  it('purges more expired events than D1 can bind in one statement', async () => {
    for (let i = 0; i < 150; i++) {
      await store.put(event(`r-${i}`), NOW - 1)
    }
    expect(await store.purgeExpired(NOW)).toBe(150)
    expect(await rows()).toBe(0)
  })

  it('is erased with its visitor, leaving other visitors intact', async () => {
    await store.put(event('r1', 'gone'), NOW + 1000)
    await store.put(event('r2', 'gone'), NOW + 1000)
    await store.put(event('r3', 'kept'), NOW + 1000)
    await new FingerprintStore(db).erase('gone')
    expect(await store.get('r1', NOW)).toBeUndefined()
    expect(await store.get('r2', NOW)).toBeUndefined()
    expect(await store.get('r3', NOW)).toBeDefined()
  })
})
