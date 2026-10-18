/// <reference types="@cloudflare/vitest-pool-workers/types" />

// Types for the `env` exposed by the miniflare-backed Workers test pool: the
// state bindings from wrangler.jsonc, the D1 database + `DB_TYPE` the pool
// config adds, and the migrations the setup file applies. Only the
// `*.workers.test.ts` suite (real workerd) uses these.
//
// pool-workers types `env` as `Cloudflare.Env`, so the bindings are declared
// by augmenting that global interface.

import type { D1Migration } from 'cloudflare:test'

declare global {
  namespace Cloudflare {
    interface Env {
      /** Database driver selector, pinned to `d1` for this pool. */
      DB_TYPE: string
      /** D1 database — fingerprint state + check-in event log (created locally
       *  by miniflare). */
      DB: D1Database
      /** Nonce Durable Object namespace. */
      NONCE: DurableObjectNamespace
      /** Velocity Durable Object namespace (new-device velocity counters). */
      VELOCITY: DurableObjectNamespace
      /** Per-IP rate limiter, bound with a high ceiling for this pool. */
      RATE_LIMIT: RateLimit
      /** Per-IP `/challenge` rate limiter, bound with a high ceiling for this pool. */
      CHALLENGE_RATE_LIMIT: RateLimit
      /** Schema migrations, read at config time and applied in setup. */
      TEST_MIGRATIONS: D1Migration[]
      /** Deterministic salt secret, pinned to the parity fixture's `salt_secret`
       *  so the cross-stack parity suite reproduces the native reference. */
      FP_SALT_SECRET: string
    }
  }
}
