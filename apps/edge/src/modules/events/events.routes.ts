/**
 * Events route, the server-side read of a past identify (native
 * `get_event`):
 *   - `GET /events/:request_id` — `FP_API_KEY`-gated; returns the stored
 *     identify response body verbatim.
 *
 * Fail-closed like erasure: no API key configured ⇒ `404` (as if unrouted);
 * missing/wrong `Authorization: Bearer` ⇒ `401`; unknown or expired id ⇒ `404`.
 */

import { Hono } from 'hono'
import type { EdgeConfig } from '../../config'
import { bearerAuthorized } from '../../lib/auth'
import { jsonResponse } from '../../lib/http'
import type { EventLog } from '../../lib/state'

/** The events route's slice of the injected deps. */
export interface EventsDeps {
  events: EventLog
  config: EdgeConfig
}

/** Build the events sub-router over the injected {@link EventsDeps}. */
export function eventsRoutes(deps: EventsDeps): Hono {
  const app = new Hono()

  app.get('/events/:request_id', async (c) => {
    const { apiKey } = deps.config
    if (!apiKey) return c.body(null, 404)
    if (!bearerAuthorized(c.req.header('authorization'), apiKey)) {
      return c.body(null, 401)
    }
    const event = await deps.events.get(c.req.param('request_id'), Date.now())
    if (!event) return c.body(null, 404)
    return jsonResponse(event.body)
  })

  return app
}
