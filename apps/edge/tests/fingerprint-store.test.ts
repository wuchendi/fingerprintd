import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { count, eq } from 'drizzle-orm'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Db } from '../src/db/client'
import { blockingIndex, erasedVisitors, templates } from '../src/db/schema'
import type { ScoreOutcome } from '../src/lib/types'
import { EdgeEngine, initEngineRuntime } from '../src/modules/fingerprint'
import {
  FingerprintStore,
  MAX_CANDIDATES,
  PER_KEY_CAP,
  TOMBSTONE_CAP,
} from '../src/modules/fingerprint/fingerprint-store'
import { memoryDb } from './helpers/fakes'

// The fingerprint store against a real libSQL database migrated from the
// committed `./drizzle` set. The setup file (`tests/d1-param-guard.ts`) makes
// any statement binding more than 100 parameters fail, as it would on D1.

const HEX32 = /^[0-9a-f]{32}$/

/** A stored-form stand-in: the store treats `stored` as opaque JSON. */
const stored = (tag: string | number) => ({ webgl: { category: `h-${tag}` } })

/** A minimal new-device outcome persisting `template` under `keys`. */
function newDevice(
  keys: string[],
  template: Record<string, unknown> = stored(0),
): ScoreOutcome {
  return {
    decision: 'new_device',
    visitor_id: null,
    is_new_device: true,
    confidence: 0.5,
    score: null,
    compared_components: 0,
    collision_risk: false,
    template_jump: false,
    probe_stored: template,
    template,
    template_blocking_keys: keys,
  }
}

/** A match outcome writing `template` back to `id` under `keys`. */
function match(
  id: string,
  keys: string[],
  template: Record<string, unknown>,
): ScoreOutcome {
  return {
    ...newDevice(keys, template),
    decision: 'match',
    visitor_id: id,
    is_new_device: false,
    score: 20,
  }
}

let db: Db

beforeEach(async () => {
  db = await memoryDb()
})

async function rowCount(table: typeof templates | typeof blockingIndex) {
  const [row] = await db.select({ n: count() }).from(table)
  return row?.n ?? 0
}

describe('persist', () => {
  it('mints a random 32-hex id for a new device and recalls it by any key', async () => {
    const store = new FingerprintStore(db)
    const a = await store.persist(newDevice(['k1', 'k2'], stored('a')), 1000)
    const b = await store.persist(newDevice(['k3'], stored('b')), 1000)
    expect(a).toMatch(HEX32)
    expect(b).toMatch(HEX32)
    expect(a).not.toBe(b)

    expect(await store.recall(['k1'])).toEqual([
      { visitor_id: a, stored: stored('a') },
    ])
    // A visitor reached through several keys is returned once.
    expect(await store.recall(['k1', 'k2'])).toHaveLength(1)
  })

  it('writes a match back: template replaced, keys added, counters bumped', async () => {
    const store = new FingerprintStore(db)
    const id = await store.persist(newDevice(['k1'], stored('v1')), 1000)

    expect(
      await store.persist(match(id, ['k1', 'k2'], stored('v2')), 2000),
    ).toBe(id)

    expect(await store.recall(['k2'])).toEqual([
      { visitor_id: id, stored: stored('v2') },
    ])
    const row = await db
      .select()
      .from(templates)
      .where(eq(templates.visitor_id, id))
      .get()
    expect(row).toMatchObject({
      firstSeen: 1000,
      lastSeen: 2000,
      observationCount: 2,
    })
  })

  it('does not write on a review verdict (anti-poisoning)', async () => {
    const store = new FingerprintStore(db)
    const review: ScoreOutcome = {
      ...newDevice(['k9']),
      decision: 'review',
      visitor_id: 'suspect',
      is_new_device: false,
      template: null,
      template_blocking_keys: null,
    }
    expect(await store.persist(review, 1000)).toBe('suspect')
    expect(await rowCount(templates)).toBe(0)
    expect(await rowCount(blockingIndex)).toBe(0)
  })

  it('stores only the salted stored form, never a raw component value', async () => {
    initEngineRuntime(
      readFileSync(
        fileURLToPath(new URL('../wasm/fp_wasm_bg.wasm', import.meta.url).href),
      ),
    )
    const engine = new EdgeEngine('store-test-salt')
    const components = {
      webgl: 'ANGLE (Intel UHD 620)',
      platform: 'Linux x86_64',
      timezone: 'Asia/Shanghai',
      audio: '124.04',
      cpu_cores: 8,
      fonts: ['Arial', 'Helvetica', 'Verdana'],
    }
    const outcome = engine.score(components, [])
    const store = new FingerprintStore(db)
    const id = await store.persist(outcome, 1000)

    const row = await db
      .select({ stored: templates.stored })
      .from(templates)
      .where(eq(templates.visitor_id, id))
      .get()
    expect(row).toBeDefined()
    for (const raw of [
      'ANGLE (Intel UHD 620)',
      'Linux x86_64',
      'Asia/Shanghai',
      '124.04',
      'Arial',
      'Helvetica',
      'Verdana',
    ]) {
      expect(row?.stored).not.toContain(raw)
    }
    // The stored form round-trips to the same blocking keys it was indexed by.
    const keys = engine.blockingKeys(components)
    expect(engine.blockingKeysStored(JSON.parse(row?.stored ?? '{}'))).toEqual(
      keys,
    )
    expect(await store.recall(keys)).toHaveLength(1)
  })
})

describe('ordered recall', () => {
  it('exports the shipped caps', () => {
    expect(PER_KEY_CAP).toBe(256)
    expect(MAX_CANDIDATES).toBe(1024)
    expect(TOMBSTONE_CAP).toBe(100_000)
  })

  it('recalls nothing for empty or unknown keys', async () => {
    const store = new FingerprintStore(db)
    expect(await store.recall([])).toEqual([])
    expect(await store.recall(['no-such-key'])).toEqual([])
  })

  it('visits the first key first, then the rest rarest first', async () => {
    // Total cap 3: whichever keys are visited first fill the block.
    const store = new FingerprintStore(db, 10, 3)
    const exact = await store.persist(newDevice(['k0']), 1)
    const common: string[] = []
    for (let i = 0; i < 4; i++) {
      common.push(await store.persist(newDevice(['common']), 10 + i))
    }
    const rare = await store.persist(newDevice(['rare']), 2)

    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      // `common` precedes `rare` in key order, but `rare` is the smaller block.
      const ids = (await store.recall(['k0', 'common', 'rare'])).map(
        (c) => c.visitor_id,
      )
      // K0 first, then the rarest key, then the most recent of `common`.
      expect(ids).toEqual([exact, rare, common[3]])
      expect(warn).toHaveBeenCalledTimes(1)
    } finally {
      warn.mockRestore()
    }
  })

  it('keeps the first key first even when it is the largest block', async () => {
    const store = new FingerprintStore(db)
    const big: string[] = []
    for (let i = 0; i < 3; i++) {
      big.push(await store.persist(newDevice(['k0']), 10 + i))
    }
    const rare = await store.persist(newDevice(['rare']), 1)
    const ids = (await store.recall(['k0', 'rare'])).map((c) => c.visitor_id)
    // Most recently seen first within a key.
    expect(ids).toEqual([big[2], big[1], big[0], rare])
  })

  it('caps each key at the per-key cap, most recently seen first, and warns', async () => {
    const store = new FingerprintStore(db, 2, 100)
    const hot: string[] = []
    for (let i = 0; i < 5; i++) {
      hot.push(await store.persist(newDevice(['hot']), 100 + i))
    }
    const other = await store.persist(newDevice(['other']), 1)

    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const ids = (await store.recall(['hot', 'other'])).map(
        (c) => c.visitor_id,
      )
      expect(ids).toEqual([hot[4], hot[3], other])
      expect(warn).toHaveBeenCalledTimes(1)
    } finally {
      warn.mockRestore()
    }
  })

  it('does not warn when nothing is truncated', async () => {
    const store = new FingerprintStore(db, 2, 3)
    await store.persist(newDevice(['cool']), 1)
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      expect(await store.recall(['cool'])).toHaveLength(1)
      expect(warn).not.toHaveBeenCalled()
    } finally {
      warn.mockRestore()
    }
  })

  it('recalls with as many keys as the engine emits under the parameter cap', async () => {
    const store = new FingerprintStore(db)
    const keys = Array.from({ length: 40 }, (_, i) => `key-${i}`)
    await store.persist(newDevice(keys), 1)
    expect(await store.recall(keys)).toHaveLength(1)
  })
})

describe('erasure tombstones', () => {
  it('erases a visitor: template and index rows gone, others intact, idempotent', async () => {
    const store = new FingerprintStore(db)
    const v1 = await store.persist(newDevice(['k1', 'shared'], stored(1)), 1)
    const v2 = await store.persist(newDevice(['k2', 'shared'], stored(2)), 1)

    await store.erase(v1)
    await store.erase(v1)

    expect(await store.recall(['k1'])).toEqual([])
    expect(await store.recall(['shared'])).toEqual([
      { visitor_id: v2, stored: stored(2) },
    ])
    await expect(store.erase('never-existed')).resolves.toBeUndefined()
  })

  it('never mints a tombstoned id', async () => {
    const store = new FingerprintStore(db)
    // Pin the RNG: the first draw collides with a tombstone, the second not.
    const tombstoned = 'aa'.repeat(16)
    await store.erase(tombstoned)
    const draws = [0xaa, 0xbb]
    const spy = vi
      .spyOn(crypto, 'getRandomValues')
      .mockImplementation(<T extends ArrayBufferView | null>(array: T): T => {
        ;(array as unknown as Uint8Array).fill(draws.shift() ?? 0xcc)
        return array
      })
    try {
      const id = await store.persist(newDevice(['k1']), 1)
      expect(id).toBe('bb'.repeat(16))
    } finally {
      spy.mockRestore()
    }
    expect(await store.recall(['k1'])).toEqual([
      { visitor_id: 'bb'.repeat(16), stored: stored(0) },
    ])
  })

  it('throws after the bounded mint attempts all hit tombstones', async () => {
    const store = new FingerprintStore(db)
    await store.erase('aa'.repeat(16))
    const spy = vi
      .spyOn(crypto, 'getRandomValues')
      .mockImplementation(<T extends ArrayBufferView | null>(array: T): T => {
        ;(array as unknown as Uint8Array).fill(0xaa)
        return array
      })
    try {
      await expect(store.persist(newDevice(['k1']), 1)).rejects.toThrow(
        'could not mint',
      )
    } finally {
      spy.mockRestore()
    }
    expect(await rowCount(templates)).toBe(0)
    expect(await rowCount(blockingIndex)).toBe(0)
  })

  it('a match after erase writes nothing (no resurrection)', async () => {
    const store = new FingerprintStore(db)
    const id = await store.persist(newDevice(['k1']), 1)
    await store.erase(id)

    await store.persist(match(id, ['k1', 'k2'], stored('late')), 2)

    expect(await rowCount(templates)).toBe(0)
    expect(await rowCount(blockingIndex)).toBe(0)
  })
})

describe('retention', () => {
  it('purges templates older than the retention window', async () => {
    const store = new FingerprintStore(db)
    const old = await store.persist(newDevice(['ko'], stored('o')), 1000)
    const fresh = await store.persist(newDevice(['kn'], stored('n')), 100_000)

    // now=200000, maxAge=150000 ⇒ cutoff=50000: only `old` (1000) is stale.
    expect(await store.purgeOlderThan(200_000, 150_000)).toBe(1)
    expect(await store.recall(['ko'])).toEqual([])
    expect(await store.recall(['kn'])).toEqual([
      { visitor_id: fresh, stored: stored('n') },
    ])
    expect(old).not.toBe(fresh)

    // A zero window disables retention; nothing stale returns 0.
    expect(await store.purgeOlderThan(200_000, 0)).toBe(0)
    expect(await store.purgeOlderThan(200_000, 150_000)).toBe(0)
  })

  it('purges more stale templates than D1 can bind in one statement', async () => {
    const store = new FingerprintStore(db)
    for (let i = 0; i < 150; i++) {
      await store.persist(newDevice([`ks-${i}`, 'shared']), 1000)
    }
    for (let i = 0; i < 5; i++) {
      await store.persist(newDevice([`kf-${i}`, 'shared']), 100_000)
    }

    expect(await store.purgeOlderThan(200_000, 150_000)).toBe(150)
    expect(await rowCount(templates)).toBe(5)
    // Only the fresh visitors' rows remain: one own key + `shared` each.
    expect(await rowCount(blockingIndex)).toBe(10)
    expect(await store.recall(['shared'])).toHaveLength(5)
  })

  it('trims the oldest tombstones beyond the cap in one param-safe statement', async () => {
    const store = new FingerprintStore(db)
    const now = vi.spyOn(Date, 'now')
    try {
      for (let i = 0; i < 150; i++) {
        now.mockReturnValue(1000 + i)
        await store.erase(`gone-${String(i).padStart(3, '0')}`)
      }
    } finally {
      now.mockRestore()
    }

    expect(await store.trimTombstones(120)).toBe(30)
    expect(await store.trimTombstones(120)).toBe(0)
    const rows = await db
      .select({ visitor_id: erasedVisitors.visitor_id })
      .from(erasedVisitors)
      .orderBy(erasedVisitors.erasedAt)
    expect(rows).toHaveLength(120)
    // The 30 oldest went first.
    expect(rows[0]?.visitor_id).toBe('gone-030')
    expect(await store.trimTombstones()).toBe(0)
  })
})
