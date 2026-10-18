/**
 * Route aggregation layer — the single place that composes the edge's HTTP
 * surface. It registers the bare `GET /health` and mounts the domain
 * sub-routers (fingerprint: `GET /challenge`, `POST /identify`,
 * `DELETE /visitor/:id`; events: `GET /events/:request_id`; check-in:
 * `POST /checkin/assess`) over the injected {@link Deps}, with per-IP rate
 * limits in front of `POST /identify` + `POST /checkin/assess` (one shared
 * bucket) and `GET /challenge` (its own). `app.ts` mounts this aggregate; the
 * handler bodies themselves live in each module's `*.routes.ts`.
 */

import type { MiddlewareHandler } from 'hono'
import { Hono } from 'hono'
import type { Deps, RateLimiter } from '../app'
import { checkinRoutes } from '../modules/checkin'
import { eventsRoutes } from '../modules/events'
import { fingerprintRoutes } from '../modules/fingerprint'

/** Paths whose POSTs are rate limited per client IP. */
const RATE_LIMITED_PATHS = ['/identify', '/checkin/assess']

/**
 * Per-IP rate limit keyed on the edge-observed `cf-connecting-ip` (missing ⇒
 * the shared `'unknown'` bucket). A denied key gets a `429` before the route
 * runs, so no nonce is burned and no store is touched.
 */
function rateLimit(limiter: RateLimiter): MiddlewareHandler {
  return async (c, next) => {
    const key = c.req.header('cf-connecting-ip')?.trim() || 'unknown'
    const { success } = await limiter.limit({ key })
    if (!success) return c.text('too many requests', 429)
    await next()
  }
}

/** Build the aggregate router over the injected {@link Deps}. */
export function routes(deps: Deps): Hono {
  const app = new Hono()

  app.get('/health', (c) => c.body(null, 200))

  // Registered before the domain routers so a denied request never reaches them.
  for (const path of RATE_LIMITED_PATHS) {
    app.post(path, rateLimit(deps.rateLimiter))
  }
  app.get('/challenge', rateLimit(deps.challengeRateLimiter))

  // Mount the domain sub-routers. Each takes the structurally-compatible slice
  // of `deps` it needs; the domains share no imports (only `lib/`).
  app.route('/', fingerprintRoutes(deps))
  app.route('/', eventsRoutes(deps))
  app.route('/', checkinRoutes(deps))

  return app
}
