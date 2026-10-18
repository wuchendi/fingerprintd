import { createClient } from '@libsql/client'
import { count } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/libsql'
import { migrate } from 'drizzle-orm/libsql/migrator'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Db } from '../src/db/client'
import * as schema from '../src/db/schema'
import { blockingIndex, templates } from '../src/db/schema'
import type { ScoreOutcome } from '../src/lib/types'
import {
  DEFAULT_MAX_BLOCK,
  FingerprintStore,
} from '../src/modules/fingerprint/fingerprint-store'

// The fingerprint store against a real libSQL database migrated from the
// committed `./drizzle` set. The setup file (`tests/d1-param-guard.ts`) makes
// any statement binding more than 100 parameters fail, as it would on D1.

/** A minimal ScoreOutcome for a given decision + id (the fields persist reads). */
function outcome(
  decision: ScoreOutcome['decision'],
  visitorId: string,
): ScoreOutcome {
  return {
    visitor_id: visitorId,
    is_new_device: decision === 'new_device',
    decision,
    confidence: 0.9,
    score: decision === 'new_device' ? null : 20,
    compared_components: 4,
    collision_risk: false,
  }
}

let db: Db

beforeEach(async () => {
  const client = createClient({ url: ':memory:' })
  const libsql = drizzle(client, { schema })
  await migrate(libsql, { migrationsFolder: './drizzle' })
  db = libsql as unknown as Db
})

describe('fingerprint store (recall + drift)', () => {
  it('recalls nothing for empty or unknown keys', async () => {
    const store = new FingerprintStore(db)
    expect(await store.recall([])).toEqual([])
    expect(await store.recall(['no-such-key'])).toEqual([])
  })

  it('persists a new device and recalls it by any of its keys', async () => {
    const store = new FingerprintStore(db)
    const components = { platform: 'Linux', webgl: 'Intel' }
    await store.persist(
      outcome('new_device', 'v1'),
      components,
      ['k1', 'k2'],
      1000,
    )

    const byK1 = await store.recall(['k1'])
    expect(byK1).toEqual([{ visitor_id: 'v1', components }])
    // A visitor matched by several supplied keys is returned once.
    expect(await store.recall(['k1', 'k2'])).toHaveLength(1)
  })

  it('drifts a matched template: overwrites present, retains absent, adds keys', async () => {
    const store = new FingerprintStore(db)
    await store.persist(
      outcome('new_device', 'v1'),
      { platform: 'Linux', user_agent: 'Chrome/120' },
      ['k1'],
      1000,
    )

    // A later observation upgrades the UA and adds a font; platform is absent
    // here and must be retained. A fresh blocking key extends recall.
    await store.persist(
      outcome('match', 'v1'),
      { user_agent: 'Chrome/121', fonts: ['Arial'] },
      ['k2'],
      2000,
    )

    const [candidate] = await store.recall(['k1'])
    expect(candidate).toEqual({
      visitor_id: 'v1',
      components: {
        platform: 'Linux', // retained (absent from the drift observation)
        user_agent: 'Chrome/121', // overwritten
        fonts: ['Arial'], // added
      },
    })
    // The drift indexed k2 under the same visitor.
    expect(await store.recall(['k2'])).toEqual([candidate])
  })

  it('does not write on a review verdict (anti-poisoning)', async () => {
    const store = new FingerprintStore(db)
    await store.persist(
      outcome('review', 'v9'),
      { platform: 'Linux' },
      ['k9'],
      1000,
    )
    expect(await store.recall(['k9'])).toEqual([])
  })

  it('caps a hot block at maxBlock and warns on truncation', async () => {
    // Shipped default stays 1024; the cap is injected small here so we can seed
    // over-capacity without writing 1024+ rows. Five visitors all index under one
    // hot key; a cap of three must truncate the recall to three and surface it.
    expect(DEFAULT_MAX_BLOCK).toBe(1024)
    const store = new FingerprintStore(db, 3)
    for (let i = 0; i < 5; i++) {
      await store.persist(
        outcome('new_device', `hot-${i}`),
        { platform: 'Linux', idx: i },
        ['hot'],
        1000 + i,
      )
    }

    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const recalled = await store.recall(['hot'])
      expect(recalled).toHaveLength(3)
      expect(warn).toHaveBeenCalledTimes(1)
    } finally {
      warn.mockRestore()
    }
  })

  it('does not warn when a block is under the cap', async () => {
    const store = new FingerprintStore(db, 3)
    await store.persist(
      outcome('new_device', 'v1'),
      { platform: 'Linux' },
      ['cool'],
      1000,
    )

    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      expect(await store.recall(['cool'])).toHaveLength(1)
      expect(warn).not.toHaveBeenCalled()
    } finally {
      warn.mockRestore()
    }
  })

  it('erases a visitor: template and blocking-index rows gone, others intact', async () => {
    const store = new FingerprintStore(db)
    await store.persist(
      outcome('new_device', 'v1'),
      { platform: 'Linux' },
      ['k1', 'shared'],
      1000,
    )
    await store.persist(
      outcome('new_device', 'v2'),
      { platform: 'macOS' },
      ['k2', 'shared'],
      1000,
    )

    await store.erase('v1')

    // v1 is gone by every one of its keys; v2 (which shared a key) is untouched.
    expect(await store.recall(['k1'])).toEqual([])
    expect(await store.recall(['shared'])).toEqual([
      { visitor_id: 'v2', components: { platform: 'macOS' } },
    ])
    // Erasing an unknown id is an idempotent no-op.
    await expect(store.erase('never-existed')).resolves.toBeUndefined()
  })
})

describe('fingerprint store retention purge', () => {
  it('purges templates older than the retention window', async () => {
    const store = new FingerprintStore(db)
    // A stale template (last seen at t=1000) and a fresh one (t=100000).
    await store.persist(outcome('new_device', 'old'), { a: 1 }, ['ko'], 1000)
    await store.persist(outcome('new_device', 'new'), { a: 2 }, ['kn'], 100_000)

    // now=200000, maxAge=150000 ⇒ cutoff=50000: only `old` (1000) is stale.
    const purged = await store.purgeOlderThan(200_000, 150_000)
    expect(purged).toBe(1)
    expect(await store.recall(['ko'])).toEqual([])
    expect(await store.recall(['kn'])).toEqual([
      { visitor_id: 'new', components: { a: 2 } },
    ])

    // A zero/negative window disables retention: nothing is purged.
    expect(await store.purgeOlderThan(200_000, 0)).toBe(0)
    expect(await store.recall(['kn'])).toHaveLength(1)
  })

  it('returns 0 when nothing is stale', async () => {
    const store = new FingerprintStore(db)
    await store.persist(outcome('new_device', 'v1'), { a: 1 }, ['k1'], 100_000)
    expect(await store.purgeOlderThan(200_000, 150_000)).toBe(0)
    expect(await store.recall(['k1'])).toHaveLength(1)
  })

  it('purges more stale templates than D1 can bind in one statement', async () => {
    const store = new FingerprintStore(db)
    // 150 stale visitors, each with its own key plus a shared one, and 5 fresh.
    for (let i = 0; i < 150; i++) {
      await store.persist(
        outcome('new_device', `stale-${i}`),
        { i },
        [`ks-${i}`, 'shared'],
        1000,
      )
    }
    for (let i = 0; i < 5; i++) {
      await store.persist(
        outcome('new_device', `fresh-${i}`),
        { i },
        [`kf-${i}`, 'shared'],
        100_000,
      )
    }

    expect(await store.purgeOlderThan(200_000, 150_000)).toBe(150)

    const [tpl] = await db.select({ n: count() }).from(templates)
    const [idx] = await db.select({ n: count() }).from(blockingIndex)
    expect(tpl?.n).toBe(5)
    // Only the fresh visitors' rows remain: one own key + `shared` each.
    expect(idx?.n).toBe(10)
    expect(await store.recall(['ks-0', 'ks-149'])).toEqual([])
    expect(await store.recall(['shared'])).toHaveLength(5)
  })
})
