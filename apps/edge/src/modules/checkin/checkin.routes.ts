/**
 * Check-in domain route: the anti-farming decision layer, split out of the
 * monolithic `app.ts` into its own Hono sub-router.
 *   - `POST /checkin/assess` — score a business `accountId` + a pre-obtained
 *     fingerprintd verdict into an allow/challenge/deny gate.
 *
 * Independent of `/identify` — the caller passes through an already-obtained
 * identify body. `ip`/`ts` are observed edge-side (never from the body); the
 * event is recorded BEFORE the aggregates are read so this check-in is
 * reflected. Dependencies are injected ({@link CheckinDeps}) so the router is
 * unit-testable without the Workers runtime.
 */

import { zValidator } from '@hono/zod-validator'
import { Hono } from 'hono'
import * as z from 'zod'
import type { Aggregates } from '../../config/risk-config'
import { defaultProfiles } from '../../config/risk-config'
import type { AssessRequest } from '../../lib/types'
import type { CheckinStore } from './checkin-state'
import type { AggregateResult } from './checkin-store'
import { assess } from './risk-engine'

/** The check-in routes' slice of the injected deps. */
export interface CheckinDeps {
  checkin: CheckinStore
}

/** The edge header carrying the connecting IP, injected by Cloudflare. Observed
 *  edge-side and never client-supplied. */
const CF_CONNECTING_IP = 'cf-connecting-ip'

/**
 * `POST /checkin/assess` request body. `.strict()` at the top level REJECTS any
 * unknown key — a body carrying edge-observed `ip`/`ts` is a `400`, since those
 * are observed edge-side and never client-supplied. `identify` is `.loose()` so
 * the full pass-through `IdentifyResponse` (confidence, decision, …) is accepted
 * while only the load-bearing `visitorId` / `signals` are validated.
 */
const assessSchema = z
  .object({
    accountId: z.string().min(1),
    action: z.literal('daily_checkin'),
    identify: z
      .object({
        visitorId: z.string().min(1),
        signals: z.object({
          ua_tls_consistent: z.boolean(),
          ip_risk: z.enum(['low', 'medium', 'high']),
        }),
      })
      .loose(),
  })
  .strict()

/** Build the check-in domain sub-router over the injected {@link CheckinDeps}. */
export function checkinRoutes(deps: CheckinDeps): Hono {
  const app = new Hono()

  // Check-in anti-farming decision layer: score a business `accountId` + the
  // fingerprintd verdict into an allow/challenge/deny gate. Independent of
  // `/identify` — the caller passes through an already-obtained identify body.
  // `ip`/`ts` are observed edge-side (never from the body); the event is
  // recorded BEFORE the aggregates are read so this check-in is reflected.
  app.post('/checkin/assess', zValidator('json', assessSchema), async (c) => {
    const req = c.req.valid('json')
    const { accountId, identify } = req

    const ip = c.req.raw.headers.get(CF_CONNECTING_IP)?.trim() ?? ''
    const ts = Date.now()

    await deps.checkin.record({
      accountId,
      visitorId: identify.visitorId,
      ip,
      ts,
    })
    const agg = await deps.checkin.getAggregates(
      accountId,
      identify.visitorId,
      ip,
      ts,
    )
    const result = assess(
      req as unknown as AssessRequest,
      toAggregates(agg),
      defaultProfiles[req.action],
    )
    return c.json(result)
  })

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
