import { afterEach, describe, expect, it } from 'vitest'
import type { Env } from '../src/config'
import { getDb, resetDb } from '../src/db/client'

// The driver selector. Building a libSQL client does not connect, so an
// unreachable URL is enough to check which driver `getDb` picked; the D1
// branch only needs something in the `DB` slot.

/** The underlying driver client Drizzle wraps. */
function driverOf(db: ReturnType<typeof getDb>): unknown {
  return (db as unknown as { $client: unknown }).$client
}

const fakeD1 = { prepare: () => undefined } as unknown as D1Database

afterEach(() => resetDb())

describe('getDb driver selection', () => {
  it('defaults to libSQL over HTTP when DB_TYPE is unset', () => {
    const db = getDb({ LIBSQL_URL: ' http://127.0.0.1:9 ' })
    expect(driverOf(db)).toMatchObject({ protocol: 'http' })
  })

  it('treats an empty DB_TYPE as libSQL', () => {
    const db = getDb({ DB_TYPE: ' ', LIBSQL_URL: 'http://127.0.0.1:9' })
    expect(driverOf(db)).toMatchObject({ protocol: 'http' })
  })

  it('uses the D1 binding when DB_TYPE is d1', () => {
    const db = getDb({ DB_TYPE: 'd1', DB: fakeD1 })
    expect(driverOf(db)).toBe(fakeD1)
  })

  it('requires LIBSQL_URL for libSQL', () => {
    const message =
      'DB_TYPE=libsql needs LIBSQL_URL (and LIBSQL_AUTH_TOKEN unless the server is unauthenticated)'
    expect(() => getDb({})).toThrow(message)
    expect(() => getDb({ DB_TYPE: 'libsql', LIBSQL_URL: '  ' })).toThrow(
      message,
    )
    // A D1 binding does not satisfy the libSQL default.
    expect(() => getDb({ DB: fakeD1 })).toThrow(message)
  })

  it('requires the DB binding for D1', () => {
    expect(() => getDb({ DB_TYPE: 'd1' })).toThrow(
      'DB_TYPE=d1 needs the D1 binding "DB" (enable the d1_databases block, see scripts/d1-config.ts)',
    )
  })

  it('rejects an unknown DB_TYPE', () => {
    expect(() => getDb({ DB_TYPE: 'bogus' })).toThrow(
      'DB_TYPE must be "libsql" or "d1", got "bogus"',
    )
  })
})

describe('getDb memoization', () => {
  it('returns the same client until resetDb()', () => {
    const env: Env = { LIBSQL_URL: 'http://127.0.0.1:9' }
    const first = getDb(env)
    // Memoized per isolate: a later env is ignored until the cache is reset.
    expect(getDb({ DB_TYPE: 'd1', DB: fakeD1 })).toBe(first)

    resetDb()
    const second = getDb({ DB_TYPE: 'd1', DB: fakeD1 })
    expect(second).not.toBe(first)
    expect(driverOf(second)).toBe(fakeD1)
  })
})
