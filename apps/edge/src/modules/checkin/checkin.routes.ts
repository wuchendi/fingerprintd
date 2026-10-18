/**
 * Check-in domain route: the anti-farming decision layer.
 *   - `POST /checkin/assess` — score a business `account_id` on a past identify
 *     (named by `request_id`) into an allow/challenge/deny gate.
 *
 * Server-to-server and `FP_API_KEY`-gated like the events API: no key
 * configured ⇒ `404`; missing/wrong bearer ⇒ `401`. The device id, signals and
 * client IP all come from the stored identify event (the caller is the
 * customer backend, so its own `cf-connecting-ip` is never read); an unknown
 * or expired `request_id` is a `404`. The check-in is recorded (once per
 * `request_id`) BEFORE the aggregates are read so it is reflected. A
 * `request_id` already assessed for a different `account_id` is a `409` and
 * nothing is scored; the same account replaying it is re-scored from the
 * aggregates, which already count it once.
 * Dependencies are injected ({@link CheckinDeps}) so the router is
 * unit-testable without the Workers runtime.
 */

import { zValidator } from '@hono/zod-validator'
import { Hono } from 'hono'
import * as z from 'zod'
import type { EdgeConfig } from '../../config'
import type { Aggregates } from '../../config/risk-config'
import { defaultProfiles } from '../../config/risk-config'
import { bearerAuthorized } from '../../lib/auth'
import { requireJson } from '../../lib/http'
import type { EventLog } from '../../lib/state'
import type { IdentifyResponse } from '../../lib/types'
import type { AssessRequest } from './assess-types'
import type { CheckinStore } from './checkin-state'
import type { AggregateResult } from './checkin-store'
import { assess } from './risk-engine'

/** The check-in routes' slice of the injected deps. */
export interface CheckinDeps {
  checkin: CheckinStore
  events: EventLog
  config: EdgeConfig
}

/** `POST /checkin/assess` request body, closed: any unknown key is a `400`. */
const assessSchema = z
  .object({
    account_id: z.string().min(1),
    action: z.literal('daily_checkin'),
    request_id: z.string(),
  })
  .strict() satisfies z.ZodType<AssessRequest>

/** Build the check-in domain sub-router over the injected {@link CheckinDeps}. */
export function checkinRoutes(deps: CheckinDeps): Hono {
  const app = new Hono()

  app.post(
    '/checkin/assess',
    async (c, next) => {
      const { apiKey } = deps.config
      if (!apiKey) return c.body(null, 404)
      if (!bearerAuthorized(c.req.header('authorization'), apiKey)) {
        return c.body(null, 401)
      }
      await next()
    },
    requireJson,
    zValidator('json', assessSchema, (result) => {
      if (!result.success) return new Response(null, { status: 400 })
    }),
    async (c) => {
      const req = c.req.valid('json')
      const ts = Date.now()
      const event = await deps.events.get(req.request_id, ts)
      if (!event) return c.body(null, 404)

      const identify = JSON.parse(event.body) as IdentifyResponse
      const ip = event.ip ?? ''
      const recorded = await deps.checkin.record({
        request_id: req.request_id,
        account_id: req.account_id,
        visitor_id: identify.visitor_id,
        ip,
        ts,
      })
      if (!recorded.inserted && recorded.account_id !== req.account_id) {
        return c.body(null, 409)
      }
      const agg = await deps.checkin.getAggregates(
        req.account_id,
        identify.visitor_id,
        ip,
        ts,
      )
      const result = assess(
        {
          action: req.action,
          visitor_id: identify.visitor_id,
          signals: identify.signals,
        },
        toAggregates(agg),
        defaultProfiles[req.action],
      )
      return c.json(result)
    },
  )

  return app
}

/**
 * Reconcile the check-in store's nested {@link AggregateResult} to the risk
 * engine's flat {@link Aggregates}: the single window/metric each threshold is
 * defined against (fan-out on 24h, IP sharing on 1h, the churn `rate` and timing
 * `regularity` scalars). `account_device_count` and `batch_clustering` are not
 * thresholded today but carried so the shape is complete (batch as the larger of
 * the device/IP burst).
 */
function toAggregates(r: AggregateResult): Aggregates {
  return {
    device_account_fanout: r.device_account_fanout.h24,
    account_device_count: r.account_device_count.d7,
    account_new_device_rate: r.account_new_device_rate.rate,
    ip_account_count: r.ip_account_count.h1,
    checkin_interval_regularity: r.checkin_interval_regularity.regularity,
    batch_clustering: Math.max(
      r.batch_clustering.device,
      r.batch_clustering.ip,
    ),
  }
}
