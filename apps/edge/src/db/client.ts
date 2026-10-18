import { createClient } from '@libsql/client/web'
import type { DrizzleD1Database } from 'drizzle-orm/d1'
import { drizzle as drizzleD1 } from 'drizzle-orm/d1'
import { drizzle as drizzleLibsql } from 'drizzle-orm/libsql'
import type { Env } from '../config'
import * as schema from './schema'

/**
 * A Drizzle client over the edge database + its schema (fingerprint state + the
 * check-in event log, via the `./schema` barrel). `DB_TYPE` picks the driver:
 *   - `libsql` (default): a libSQL server such as Turso or self-hosted sqld,
 *     reached over HTTP with `LIBSQL_URL` and the optional `LIBSQL_AUTH_TOKEN`.
 *   - `d1`: the Cloudflare D1 binding `DB`.
 * Both drivers expose the same async SQLite query builder (select, insert,
 * update, delete, batch), which is all the stores use, so the libSQL client is
 * typed as the D1 one.
 */
export type Db = DrizzleD1Database<typeof schema>

/** Bindings and vars are stable per isolate, so the client is memoized after
 *  the first build. */
let cached: Db | undefined

/** Test-only: forget the memoized client. */
export function resetDb(): void {
  cached = undefined
}

/** The database client for `env`, built once per isolate. Throws on a missing
 *  or unknown driver configuration. */
export function getDb(env: Env): Db {
  cached ??= createDb(env)
  return cached
}

/** Build a fresh (non-memoized) client for the driver `env.DB_TYPE` selects. */
function createDb(env: Env): Db {
  const type = env.DB_TYPE?.trim() || 'libsql'
  if (type === 'libsql') {
    const url = env.LIBSQL_URL?.trim()
    if (!url) {
      throw new Error(
        'DB_TYPE=libsql needs LIBSQL_URL (and LIBSQL_AUTH_TOKEN unless the server is unauthenticated)',
      )
    }
    const authToken = env.LIBSQL_AUTH_TOKEN?.trim()
    const client = createClient(authToken ? { url, authToken } : { url })
    return drizzleLibsql(client, { schema }) as unknown as Db
  }
  if (type === 'd1') {
    if (!env.DB) {
      throw new Error(
        'DB_TYPE=d1 needs the D1 binding "DB" (enable the d1_databases block, see scripts/d1-config.ts)',
      )
    }
    return drizzleD1(env.DB, { schema })
  }
  throw new Error(`DB_TYPE must be "libsql" or "d1", got "${type}"`)
}
