import {
  cloudflareTest,
  readD1Migrations,
} from '@cloudflare/vitest-pool-workers'
import { defineConfig } from 'vitest/config'

// The state suite (`*.workers.test.ts`) runs inside real workerd/miniflare with
// the wrangler.jsonc bindings live — the Durable Objects and the WASM-loading
// Worker entry — plus high-ceiling `RATE_LIMIT` / `CHALLENGE_RATE_LIMIT` and a local D1 database selected with `DB_TYPE=d1` (the D1
// block is commented out in wrangler.jsonc, so the pool declares it here). The
// Durable Object burn and the Worker's D1 recall/persist round-trips are thus
// exercised against the actual runtime, not a fake. Miniflare needs no
// Cloudflare account. The router contract and the store queries stay in the
// Node project (`vitest.node.config.ts`); this is the other half.
//
// The worker pool is wired as the `cloudflareTest(...)` Vite plugin. Storage
// isolation is per test FILE (not per test), so state suites reset D1 in
// `beforeEach`.
export default defineConfig(async () => {
  const migrations = await readD1Migrations('./drizzle')
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: './wrangler.jsonc' },
        miniflare: {
          // Required by the Workers pool; harmless for this Worker.
          compatibilityFlags: ['nodejs_compat'],
          // The Worker's database for this pool: a local D1 bound as `DB`.
          d1Databases: ['DB'],
          // The Worker requires both rate limiters; bind them with a limit the
          // suites never reach so the production caps cannot fail a test.
          ratelimits: {
            RATE_LIMIT: {
              namespace_id: '1001',
              simple: { limit: 100000, period: 60 },
            },
            CHALLENGE_RATE_LIMIT: {
              namespace_id: '1002',
              simple: { limit: 100000, period: 60 },
            },
          },
          // Read at config time, applied by the setup file. `FP_SALT_SECRET`
          // pins the deterministic salt so the cross-stack parity suite
          // (`parity.workers.test.ts`) reproduces the native reference — it MUST
          // equal `salt_secret` in `crates/fingerprintd/tests/fixtures/
          // parity.json` (the suite asserts the coupling). In a real deployment this is a Worker Secret.
          bindings: {
            DB_TYPE: 'd1',
            TEST_MIGRATIONS: migrations,
            FP_SALT_SECRET: 'fp-parity-vector-secret',
          },
        },
      }),
    ],
    test: {
      // Explicit, slash-free project name: the default (package.json
      // `@cdlab/fingerprintd-edge`) leaks a `/` into the Durable Object storage path
      // and workerd rejects it.
      name: 'workers',
      include: ['tests/**/*.workers.test.ts'],
      setupFiles: ['./tests/apply-migrations.ts'],
    },
  }
})
