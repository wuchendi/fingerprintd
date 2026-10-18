/**
 * Cloudflare Worker entry point for the fingerprintd edge deployment.
 *
 * This is the ONLY module that imports the `.wasm` artifact (wrangler bundles it
 * as a `WebAssembly.Module`), so the Hono app and its dependencies stay
 * importable by Node tests without the Workers `.wasm` loader. Per isolate it
 * initializes the WASM runtime once, builds the configured engine and the host
 * state, and hands each request to the Hono app in `app.ts`.
 *
 * State: the fingerprint index and the check-in event log live in the database
 * `getDb` selects (libSQL by default, D1 with `DB_TYPE=d1`); nonces and
 * new-device velocity live in the `NONCE` / `VELOCITY` Durable Objects; the
 * `RATE_LIMIT` / `CHALLENGE_RATE_LIMIT` bindings cap per-IP request rates. Every one of these, plus
 * `FP_SALT_SECRET`, is required: a missing piece throws on the first request
 * instead of running degraded. The Durable Object classes are re-exported here
 * so wrangler can bind them.
 */

import wasmModule from '../wasm/fp_wasm_bg.wasm'
import type { Deps } from './app'
import { createApp } from './app'
import type { Env } from './config'
import { resolveConfig } from './config'
import { getDb } from './db/client'
import { DurableNonceStore } from './lib/do/nonce-do'
import { VelocityStore } from './lib/do/velocity-do'
import { CheckinEventStore } from './modules/checkin'
import {
  EdgeEngine,
  FingerprintStore,
  initEngineRuntime,
} from './modules/fingerprint'

export { NonceDurableObject } from './lib/do/nonce-do'
export { VelocityDurableObject } from './lib/do/velocity-do'

/** Per-isolate singletons, lazily built on the first request. */
let deps: Deps | undefined
let app: ReturnType<typeof createApp> | undefined

/** Build (once per isolate) the engine + host state from the environment. */
function buildDeps(env: Env): Deps {
  if (deps) return deps
  if (!env.NONCE) throw new Error('NONCE Durable Object binding is required')
  if (!env.VELOCITY) {
    throw new Error('VELOCITY Durable Object binding is required')
  }
  if (!env.RATE_LIMIT) {
    throw new Error('RATE_LIMIT rate-limit binding is required')
  }
  if (!env.CHALLENGE_RATE_LIMIT) {
    throw new Error('CHALLENGE_RATE_LIMIT rate-limit binding is required')
  }
  const config = resolveConfig(env)
  const db = getDb(env)
  initEngineRuntime(wasmModule)
  deps = {
    engine: new EdgeEngine(config),
    nonces: new DurableNonceStore(env.NONCE, config.nonceTtlSecs),
    candidates: new FingerprintStore(db),
    config,
    checkin: new CheckinEventStore(db),
    velocity: new VelocityStore(env.VELOCITY),
    rateLimiter: env.RATE_LIMIT,
    challengeRateLimiter: env.CHALLENGE_RATE_LIMIT,
  }
  return deps
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    app ??= createApp(buildDeps(env))
    return app.fetch(request)
  },

  /**
   * Database retention purge, driven by the `wrangler.jsonc` cron trigger. Two
   * independent purges run in this one invocation:
   *   - fingerprint templates: when `FP_RETENTION_SECS` > 0, delete every
   *     template last seen beyond the window plus its blocking-index rows;
   *   - check-in events: when `CHECKIN_RETENTION_SECS` > 0, delete every
   *     check-in event older than the window.
   * Either disabled (0) ⇒ that purge is a no-op. The purge queries live on the
   * respective stores so they are unit-testable without the cron.
   */
  async scheduled(
    _controller: ScheduledController,
    env: Env,
    _ctx: ExecutionContext,
  ): Promise<void> {
    const config = resolveConfig(env)
    if (config.retentionMs > 0) {
      const purged = await new FingerprintStore(getDb(env)).purgeOlderThan(
        Date.now(),
        config.retentionMs,
      )
      if (purged > 0) {
        console.log(`retention purge: removed ${purged} stale template(s)`)
      }
    }
    if (config.checkinRetentionMs > 0) {
      const purged = await new CheckinEventStore(getDb(env)).purgeOlderThan(
        Date.now() - config.checkinRetentionMs,
      )
      if (purged > 0) {
        console.log(
          `retention purge: removed ${purged} stale check-in event(s)`,
        )
      }
    }
  },
}
