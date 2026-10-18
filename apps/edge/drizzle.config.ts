import process from 'node:process'
import type { Config } from 'drizzle-kit'
import { defineConfig } from 'drizzle-kit'

// Schema -> migrations (out: ./drizzle). The `./src/db/schema.ts` barrel
// aggregates both domains (fingerprint state + the check-in event log), so one
// migration set covers the whole database. `DB_TYPE` follows the Worker
// (`src/db/client.ts`): `libsql` (default) | `d1`. `generate` only reads the
// schema, so it runs with no env at all; the connecting commands (`migrate`,
// `studio`, `push`, `pull`) use the selected backend.
const {
  DB_TYPE = 'libsql',
  LIBSQL_URL = '',
  LIBSQL_AUTH_TOKEN = undefined,
  CLOUDFLARE_ACCOUNT_ID = '',
  CLOUDFLARE_DATABASE_ID = '',
  CLOUDFLARE_API_TOKEN = '',
} = process.env

const base = {
  schema: './src/db/schema.ts',
  out: './drizzle',
} as const

/** libSQL server such as Turso. `db:migrate` applies migrations with
 *  `drizzle-kit migrate`, tracked in `__drizzle_migrations`. */
function libsql() {
  const connects = ['migrate', 'studio', 'push', 'pull'].some((command) =>
    process.argv.includes(command),
  )
  if (!LIBSQL_URL && connects) {
    throw new Error(
      'DB_TYPE=libsql needs LIBSQL_URL (and LIBSQL_AUTH_TOKEN unless the server is unauthenticated)',
    )
  }
  return {
    ...base,
    dialect: 'turso',
    dbCredentials: { url: LIBSQL_URL, authToken: LIBSQL_AUTH_TOKEN },
  } as const satisfies Config
}

/** D1 over the Cloudflare HTTP API. D1 migrations are applied with
 *  `wrangler d1 migrations apply` (`cf:remotedb`), tracked in `d1_migrations`;
 *  `drizzle-kit migrate` tracks `__drizzle_migrations` instead, cannot see what
 *  wrangler applied and would re-run every migration, so it is refused. */
function d1() {
  if (process.argv.includes('migrate')) {
    throw new Error(
      'drizzle-kit migrate is for DB_TYPE=libsql; apply D1 migrations with `bun run cf:remotedb`',
    )
  }
  return {
    ...base,
    dialect: 'sqlite',
    driver: 'd1-http',
    dbCredentials: {
      accountId: CLOUDFLARE_ACCOUNT_ID,
      databaseId: CLOUDFLARE_DATABASE_ID,
      token: CLOUDFLARE_API_TOKEN,
    },
  } as const satisfies Config
}

export default defineConfig(DB_TYPE === 'd1' ? d1() : libsql())
