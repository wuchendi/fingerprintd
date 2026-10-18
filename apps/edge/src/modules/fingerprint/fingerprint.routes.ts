/**
 * Fingerprint domain routes (architecture §5), the Contract v1 surface the
 * native server also serves (`crates/fingerprintd/src/lib.rs`):
 *   - `GET  /challenge`        — mint a one-time nonce.
 *   - `POST /identify`         — validate, burn the nonce, check `ts`, then
 *                                recall → score → persist → signals, and
 *                                store the event when `FP_API_KEY` is set.
 *   - `DELETE /visitor/:id`    — admin-gated GDPR erasure.
 *
 * The dependencies are injected ({@link FingerprintDeps}) so the router is
 * unit-testable without the Workers runtime.
 */

import { zValidator } from '@hono/zod-validator'
import { Hono } from 'hono'
import * as z from 'zod'
import type { EdgeConfig } from '../../config'
import { asnIpRisk } from '../../lib/asn-ip-risk'
import { bearerAuthorized } from '../../lib/auth'
import type { NewDeviceVelocityStore } from '../../lib/do/velocity-do'
import { jsonResponse, requireJson } from '../../lib/http'
import type { CandidateSource, EventLog, NonceStore } from '../../lib/state'
import { randomId } from '../../lib/state'
import type {
  Band,
  ChallengeResponse,
  IdentifyRequest,
  IdentifyResponse,
  PassiveVerdict,
} from '../../lib/types'
import type { EdgeEngine } from './engine'

/** The fingerprint routes' slice of the injected deps. */
export interface FingerprintDeps {
  engine: EdgeEngine
  nonces: NonceStore
  candidates: CandidateSource
  /** Identify events, written only when `config.apiKey` is set. */
  events: EventLog
  config: EdgeConfig
  /** Cross-session new-device velocity, backed by the `VELOCITY` Durable Object. */
  velocity: NewDeviceVelocityStore
}

/** The connecting client IP. Set by Cloudflare in front of a Worker, where a
 *  client cannot forge it. */
const CF_CONNECTING_IP = 'cf-connecting-ip'

/** Trailing window of the per-IP new-device velocity (native `WINDOW`). */
const VELOCITY_WINDOW_MS = 3600 * 1000

const integrityLabel = z.enum(['ok', 'noise', 'unavailable'])

/**
 * `POST /identify` request body, closed at every level like the native
 * `deny_unknown_fields`. `components` is checked against the closed component
 * schema by the WASM engine before the nonce is consumed.
 */
const identifySchema = z
  .object({
    nonce: z.string(),
    ts: z.number().int(),
    components: z.record(z.string(), z.unknown()),
    user_agent: z.string().optional(),
    botd: z
      .object({ bot: z.boolean(), kind: z.string().nullable().optional() })
      .strict()
      .optional(),
    integrity: z
      .object({
        canvas: integrityLabel.optional(),
        webgl: integrityLabel.optional(),
        audio: integrityLabel.optional(),
        rect: integrityLabel.optional(),
      })
      .strict()
      .optional(),
  })
  .strict() satisfies z.ZodType<IdentifyRequest>

/** Build the fingerprint domain sub-router over the injected {@link FingerprintDeps}. */
export function fingerprintRoutes(deps: FingerprintDeps): Hono {
  const app = new Hono()

  app.get('/challenge', async () => {
    const { nonce, ttlSecs } = await deps.nonces.issue()
    const body: ChallengeResponse = { nonce, expires_in: ttlSecs }
    return jsonResponse(JSON.stringify(body))
  })

  app.post(
    '/identify',
    requireJson,
    zValidator('json', identifySchema, (result) => {
      if (!result.success) return badRequest()
    }),
    async (c) => {
      const req = c.req.valid('json')

      // The closed component schema: an unknown key or wrongly-typed value
      // throws. Checked before the nonce is consumed, so a malformed body never
      // burns it.
      let blockingKeys: string[]
      try {
        blockingKeys = deps.engine.blockingKeys(req.components)
      } catch {
        return badRequest()
      }

      if ((await deps.nonces.consume(req.nonce)) !== 'valid') {
        return unauthorized()
      }
      const now = Date.now()
      // Timestamp window (architecture §4.1): bounds how long a captured
      // payload stays replayable.
      if (Math.abs(now - req.ts) > deps.config.tsSkewMs) {
        return unauthorized()
      }

      const candidates = await deps.candidates.recall(blockingKeys)
      const outcome = deps.engine.score(req.components, candidates)
      const visitor_id = await deps.candidates.persist(outcome, now)

      const clientIp = c.req.header(CF_CONNECTING_IP)?.trim() || undefined
      const passive = passiveSignals(c.req.raw, clientIp, req.user_agent, deps)
      const integrity = deps.engine.clientIntegrity(
        req.integrity,
        deps.config.integrityPenaltyEnabled,
      )

      // Per-IP new-device velocity: a fresh device from an IP that has minted
      // many lately loses confidence (inside the engine on native).
      let velocity: Band = 'low'
      let base = outcome.confidence
      if (outcome.decision === 'new_device' && clientIp) {
        const n = await deps.velocity.newDeviceVelocityIp(
          clientIp,
          visitor_id,
          VELOCITY_WINDOW_MS,
        )
        velocity = deps.engine.velocityBand(n)
        base = clamp(base - deps.engine.velocityPenalty(velocity))
      }
      // Fuse the passive + integrity adjustments (fuzzy-matching §6). The
      // visitor_id and decision are unchanged.
      const confidence = clamp(
        base + passive.confidence_adjustment + integrity.confidence_adjustment,
      )

      const response: IdentifyResponse = {
        request_id: randomId(),
        visitor_id,
        confidence,
        decision: outcome.decision,
        is_new_device: outcome.is_new_device,
        collision_risk: outcome.collision_risk,
        signals: {
          ua_tls_consistent: passive.ua_tls_consistent,
          ip_risk: passive.ip_risk,
          client_integrity: integrity.client_integrity,
          persona_coherence: deps.engine.personaCoherence(
            req.user_agent,
            req.components.fonts,
          ),
          new_device_velocity: velocity,
          automation: deps.engine.automation(req.botd),
          template_jump: outcome.template_jump,
        },
      }

      // Serialize once: the stored event is byte-for-byte the body sent.
      const json = JSON.stringify(response)
      if (deps.config.apiKey) {
        await deps.events.put(
          {
            request_id: response.request_id,
            visitor_id,
            ip: clientIp ?? null,
            body: json,
          },
          now + deps.config.eventTtlMs,
        )
      }
      return jsonResponse(json)
    },
  )

  // GDPR erasure: remove every trace of a visitor. Fail-closed and
  // admin-gated — never exposed without an explicit key, never leaks existence.
  //   - no admin key configured ⇒ endpoint DISABLED ⇒ 404 (as if unrouted).
  //   - missing/wrong `Authorization: Bearer <key>` ⇒ 401 (constant-time compare).
  //   - authorized ⇒ erase the template, index rows and identify events +
  //     tombstone, then 204, idempotent even for an unknown id.
  app.delete('/visitor/:id', async (c) => {
    const { adminKey } = deps.config
    if (!adminKey) return c.body(null, 404)

    if (!bearerAuthorized(c.req.header('authorization'), adminKey)) {
      return c.body(null, 401)
    }

    await deps.candidates.erase(c.req.param('id'))
    return c.body(null, 204)
  })

  return app
}

/**
 * The passive-signal verdict for a request, from Cloudflare's own enrichment:
 * the JA4 of the TLS handshake (`request.cf.botManagement.ja4`), the connecting
 * IP, and the client-claimed UA it is cross-checked against. Off Cloudflare
 * (`request.cf` absent) the JA4 is missing and the verdict degrades to neutral.
 *
 * The Cloudflare ASN reputation can only RAISE the IP band to `high` (a curated
 * hosting/datacenter ASN whose IP is outside the engine's CIDR table).
 */
function passiveSignals(
  raw: Request,
  clientIp: string | undefined,
  claimedUa: string | undefined,
  deps: FingerprintDeps,
): PassiveVerdict {
  const cf = (
    raw as {
      cf?: {
        asn?: number
        asOrganization?: string
        botManagement?: { ja4?: string }
      }
    }
  ).cf
  const ja4 = cf?.botManagement?.ja4?.trim() || undefined
  const verdict = deps.engine.passiveSignals(ja4, clientIp, claimedUa)
  if (asnIpRisk(cf?.asn, cf?.asOrganization) === 'high') {
    return { ...verdict, ip_risk: 'high' }
  }
  return verdict
}

/** Clamp a confidence into `[0, 1]` (fuzzy-matching §6). */
function clamp(value: number): number {
  return Math.min(1, Math.max(0, value))
}

/** Bare `400` for a malformed or schema-violating body. */
function badRequest(): Response {
  return new Response(null, { status: 400 })
}

/** Uniform `401` for a bad nonce or an out-of-window `ts`. */
function unauthorized(): Response {
  return new Response(null, { status: 401 })
}
