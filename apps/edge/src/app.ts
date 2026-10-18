/**
 * The edge Hono app (architecture §5), state-free and dependency-injected so it is
 * unit-testable without the Workers runtime.
 *
 * It composes the domain sub-routers — the fingerprint routes
 * (`GET /challenge`, `POST /identify`, `DELETE /visitor/:id`) and the check-in
 * route (`POST /checkin/assess`) — plus the bare `GET /health`, serving the same
 * byte-compatible contracts as the native server (`crates/fingerprintd/src/lib.rs`)
 * so a client works against either. The route handlers themselves live in each
 * module's `*.routes.ts` and are aggregated (behind the per-IP rate limits) by
 * `routes/index.ts`; this file is the composition root that wires CORS and
 * mounts that aggregate over the injected {@link Deps}.
 */

import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { EdgeConfig } from './config'
import type { NewDeviceVelocityStore } from './lib/do/velocity-do'
import { SIGNATURE_HEADER, SIGNATURE_TIMESTAMP_HEADER } from './lib/signature'
import type { CandidateSource, NonceStore } from './lib/state'
import type { CheckinStore } from './modules/checkin'
import type { EdgeEngine } from './modules/fingerprint'
import { routes } from './routes'

/** Everything the routes need, injected so tests supply fakes. */
export interface Deps {
  engine: EdgeEngine
  nonces: NonceStore
  candidates: CandidateSource
  config: EdgeConfig
  checkin: CheckinStore
  /** Cross-session new-device velocity, backed by the `VELOCITY` Durable Object. */
  velocity: NewDeviceVelocityStore
  /** Per-IP limiter for `POST /identify` and `POST /checkin/assess`, backed by
   *  the `RATE_LIMIT` binding. */
  rateLimiter: RateLimiter
  /** Per-IP limiter for `GET /challenge`, backed by the `CHALLENGE_RATE_LIMIT`
   *  binding — a separate bucket so a challenge flood cannot drain identify. */
  challengeRateLimiter: RateLimiter
}

/** The slice of the Cloudflare `RateLimit` binding the edge uses. */
export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>
}

/** Build the edge Hono app over the injected {@link Deps}. */
export function createApp(deps: Deps): Hono {
  const app = new Hono()

  // Browser CORS for the playground. Off unless origins are configured
  // (`FP_CORS_ORIGINS`); when on, expose the signature headers so the browser
  // client can read them, and let the middleware answer preflight `OPTIONS`.
  const { corsOrigins } = deps.config
  if (corsOrigins.length > 0) {
    const allowAny = corsOrigins.includes('*')
    app.use(
      '*',
      cors({
        origin: allowAny ? '*' : corsOrigins,
        allowMethods: ['GET', 'POST', 'OPTIONS'],
        allowHeaders: ['Content-Type'],
        exposeHeaders: [SIGNATURE_TIMESTAMP_HEADER, SIGNATURE_HEADER],
        maxAge: 86400,
      }),
    )
  }

  // Mount the aggregate router (`GET /health` + the domain sub-routers).
  app.route('/', routes(deps))

  return app
}
