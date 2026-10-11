/**
 * Fingerprint domain routes (architecture §5): the three byte-compatible
 * endpoints the native server exposes (`crates/fingerprintd/src/lib.rs`), split
 * out of the monolithic `app.ts` into their own Hono sub-router.
 *   - `GET  /challenge`  — mint a one-time nonce + collection plan.
 *   - `POST /identify`   — burn the nonce, then score via the WASM engine.
 *   - `DELETE /visitor/:id` — admin-gated GDPR erasure.
 *
 * The dependencies are injected ({@link FingerprintDeps}) so the router is
 * unit-testable without the Workers runtime. The orchestration — derive blocking
 * keys → recall candidates → score → persist — and the signed `x-fp-*` headers
 * are byte-identical to the pre-split handler, so cross-stack parity is
 * unaffected.
 */

import { zValidator } from '@hono/zod-validator'
import { Hono } from 'hono'
import * as z from 'zod'
import type { EdgeConfig } from '../../config'
import { asnIpRisk } from '../../lib/asn-ip-risk'
import type { NewDeviceVelocityStore } from '../../lib/do/velocity-do'
import {
  SIGNATURE_HEADER,
  SIGNATURE_TIMESTAMP_HEADER,
} from '../../lib/signature'
import type { CandidateSource, NonceStore } from '../../lib/state'
import type {
  ChallengeResponse,
  IdentifyResponse,
  PassiveVerdict,
  ProbeDescriptor,
  ScoreOutcome,
} from '../../lib/types'
import type { EdgeEngine } from './engine'

/** The fingerprint routes' slice of the injected deps. */
export interface FingerprintDeps {
  engine: EdgeEngine
  nonces: NonceStore
  candidates: CandidateSource
  config: EdgeConfig
  /** Cross-session new-device velocity, backed by the `VELOCITY` Durable Object.
   *  Absent (binding unbound / test) ⇒ the velocity path degrades to the neutral
   *  `'low'` band, exactly like the pre-DO stateless edge. */
  velocity?: NewDeviceVelocityStore
}

/** Stable probe identifiers advertised in `GET /challenge` (matches the server). */
const STABLE_PROBES = ['userAgent', 'languages', 'timezone', 'platform']
/** Active challenge targets seeded with the nonce. */
const CHALLENGE_TARGETS = ['canvas', 'audio']
/** The fixed nonce-probe transform advertised under probe enforcement. */
const PROBE_DESCRIPTOR: ProbeDescriptor = {
  alg: 'HMAC-SHA256',
  input: 'nonce',
  encoding: 'hex',
}

/** Trusted edge headers carrying the passive signals, injected by Cloudflare —
 *  the SAME names the native adapter reads (`crates/fingerprintd/src/signals.rs`).
 *  Trusted only behind a trusted edge; a client-supplied copy is never trusted. */
const JA4_HEADER = 'cf-bot-management-ja4'
const CF_CONNECTING_IP = 'cf-connecting-ip'
/** Client-reported UA key spellings, in native precedence order
 *  (`crates/fingerprintd/src/lib.rs` `claimed_ua`). First string value wins. */
const CLAIMED_UA_KEYS = ['userAgent', 'user_agent', 'ua']

/** Cross-session new-device velocity thresholds, mirroring `fp_core::fuzzy::velocity`
 *  (WINDOW 3600s; per-IP MEDIUM 5 / HIGH 20; per-JA4-class MEDIUM 100 / HIGH 400 —
 *  orders of magnitude higher because a JA4 class is shared by every real client
 *  of a browser family). Kept in lockstep with the native constants. */
const VELOCITY_WINDOW_MS = 3600 * 1000
const VELOCITY_IP_MEDIUM = 5
const VELOCITY_IP_HIGH = 20
const VELOCITY_JA4_MEDIUM = 100
const VELOCITY_JA4_HIGH = 400
/** The neutral, cold-start velocity bands — the fail-open / non-new-device result. */
const NEUTRAL_VELOCITY = {
  new_device_velocity: 'low',
  new_device_velocity_ja4: 'low',
} as const

/**
 * `POST /identify` request body (architecture §5). `stable_components` is an arbitrary
 * component object (nested keys unrestricted); `probe`/`ts` are optional depth
 * checks; `integrity` carries the optional client-integrity probe verdicts
 * (free-form object, top-level so it never enters matching). The schema is `.strict()` — any UNKNOWN top-level key (e.g. a stray
 * `challenge_response`) is REJECTED with a `400`, mirroring the native
 * `deny_unknown_fields`. This removes the former forward-compat
 * tolerance: a client must send exactly these fields.
 */
const identifySchema = z
  .object({
    nonce: z.string(),
    stable_components: z.record(z.string(), z.unknown()),
    probe: z.string().optional(),
    ts: z.number().optional(),
    integrity: z.record(z.string(), z.unknown()).optional(),
  })
  .strict()

/** Build the fingerprint domain sub-router over the injected {@link FingerprintDeps}. */
export function fingerprintRoutes(deps: FingerprintDeps): Hono {
  const app = new Hono()

  app.get('/challenge', async () => {
    const { nonce, ttlSecs } = await deps.nonces.issue()
    // Advertise the probe transform only when probe enforcement is on, so a
    // probe-capable client knows to compute it.
    const verify = deps.config.probeKey ? PROBE_DESCRIPTOR : undefined
    const body: ChallengeResponse = {
      nonce,
      expires_in: ttlSecs,
      collect: {
        stable: STABLE_PROBES,
        challenge: { seed: nonce, targets: CHALLENGE_TARGETS, verify },
      },
    }
    return jsonResponse(body)
  })

  app.post('/identify', zValidator('json', identifySchema), async (c) => {
    const req = c.req.valid('json')

    // Primary anti-replay lock: consume the one-time nonce first.
    if ((await deps.nonces.consume(req.nonce)) !== 'valid') {
      return unauthorized()
    }

    // Depth check on top of the nonce: require a correct probe when a probe
    // key is configured. A missing or forged probe is rejected before scoring.
    if (deps.config.probeKey) {
      if (!req.probe || !deps.engine.verifyProbe(req.nonce, req.probe)) {
        return unauthorized()
      }
    }

    const now = Date.now()

    // Timestamp window: when enabled, require the client `ts` within the
    // configured skew of server time. Fail-closed: missing/out-of-window ⇒ 401.
    if (deps.config.enforceTsWindow) {
      if (
        req.ts === undefined ||
        !inWindow(req.ts, now, deps.config.tsSkewMs)
      ) {
        return unauthorized()
      }
    }

    // Host I/O orchestration: derive blocking keys → recall the candidate block
    // → score → persist the verdict. The engine is pure; the host owns state, so
    // it writes back per the decision (drift a match, mint a new device, leave a
    // review untouched) — mirroring `fp_core`'s `identify`.
    const components = req.stable_components
    const blockingKeys = deps.engine.blockingKeys(components)
    const candidates = await deps.candidates.recall(blockingKeys)
    const outcome = deps.engine.score(components, candidates)
    await deps.candidates.persist(outcome, components, blockingKeys, now)

    // Cross-check the client-reported UA against the unforgeable edge-observed
    // TLS stack / IP and fuse the passive adjustment into confidence, exactly as
    // native (`crates/fingerprintd/src/lib.rs`). The verdict comes from the shared
    // WASM compute; the host only wires the trusted inputs and clamps.
    const verdict = edgeSignals(c.req.raw, components, deps)
    // Client-side known-answer integrity probes (shared WASM compute, exactly as
    // native): surfaced always, fused only behind the opt-in penalty flag.
    const integrity = deps.engine.clientIntegrity(
      req.integrity,
      deps.config.integrityPenaltyEnabled,
    )
    const confidence = clamp(
      outcome.confidence +
        verdict.confidence_adjustment +
        integrity.confidence_adjustment,
    )
    // UA-claimed OS family vs the collected fonts (surfaced-only, shared WASM).
    const persona = deps.engine.personaCoherence(
      claimedUa(components),
      components.fonts,
    )

    // Cross-session new-device velocity, computed from the VELOCITY Durable
    // Object on a fresh device (native parity: `fp_core::fuzzy` records/bands only
    // on a NewDevice verdict, keyed on the edge-observed IP + JA4 class).
    const velocity = await edgeVelocity(c.req.raw, outcome, deps)

    const response: IdentifyResponse = {
      visitorId: outcome.visitor_id,
      confidence,
      is_new_device: outcome.is_new_device,
      decision: outcome.decision,
      collision_risk: outcome.collision_risk,
      signals: {
        ua_tls_consistent: verdict.ua_tls_consistent,
        ip_risk: verdict.ip_risk,
        client_integrity: integrity.client_integrity,
        persona_coherence: persona,
        new_device_velocity: velocity.new_device_velocity,
        new_device_velocity_ja4: velocity.new_device_velocity_ja4,
      },
    }

    return signedJson(response, deps.config, deps.engine, now)
  })

  // GDPR erasure: remove every trace of a visitor. Fail-closed and
  // admin-gated — never exposed without an explicit key, never leaks existence.
  //   - no admin key configured ⇒ endpoint DISABLED ⇒ 404 (as if unrouted).
  //   - missing/wrong `Authorization: Bearer <key>` ⇒ 401 (constant-time compare).
  //   - authorized ⇒ erase then 204, idempotent even for an unknown id.
  app.delete('/visitor/:id', async (c) => {
    const { adminKey } = deps.config
    if (!adminKey) return c.body(null, 404)

    const bearer = bearerToken(c.req.header('authorization'))
    if (bearer === undefined || !constantTimeEqual(bearer, adminKey)) {
      return c.body(null, 401)
    }

    await deps.candidates.erase(c.req.param('id'))
    return c.body(null, 204)
  })

  return app
}

/** Extract the token from an `Authorization: Bearer <token>` header, or
 *  `undefined` when the header is absent or not a bearer credential. */
function bearerToken(header: string | undefined): string | undefined {
  if (header === undefined) return undefined
  const match = /^Bearer (.+)$/.exec(header)
  return match ? match[1] : undefined
}

/**
 * Constant-time string equality for the admin credential check: unequal lengths
 * fail fast, but equal-length inputs are compared by XOR-accumulating every
 * char code so the loop never short-circuits on the first mismatch — a timing
 * side channel must not leak how many leading characters matched.
 */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return diff === 0
}

/** Whether a client `ts` sits within `±skewMs` of `now` (both Unix ms). */
function inWindow(clientTs: number, now: number, skewMs: number): boolean {
  return Math.abs(now - clientTs) <= skewMs
}

/**
 * Compute the passive-signal verdict for a request via the shared WASM compute.
 *
 * The trust boundary (architecture §4.2): edge-injected JA4/IP are read ONLY behind a
 * trusted edge. When `trustEdgeHeaders` is off we pass `undefined` for all three
 * inputs — an untrusted origin ignores any client-supplied copy — so the WASM
 * returns the degraded neutral verdict (`ua_tls_consistent: true`, `ip_risk:
 * "low"`, adjustment `0`). Fail-closed. Absent JA4 behind a trusted edge degrades
 * the same way, mirroring native (`crates/fingerprintd/src/lib.rs`).
 */
function edgeSignals(
  raw: Request,
  components: Record<string, unknown>,
  deps: FingerprintDeps,
): PassiveVerdict {
  if (!deps.config.trustEdgeHeaders) {
    return deps.engine.passiveSignals(undefined, undefined, undefined)
  }
  const ja4 = (raw.headers.get(JA4_HEADER) ?? cfJa4(raw))?.trim() || undefined
  const clientIp = raw.headers.get(CF_CONNECTING_IP)?.trim() || undefined
  const verdict = deps.engine.passiveSignals(
    ja4,
    clientIp,
    claimedUa(components),
  )
  // Fuse the Cloudflare ASN reputation band: it can only RAISE the WASM band to
  // `high` (a curated hosting/datacenter ASN whose IP is outside fp-core's CIDR
  // table), never lower a `medium`/`high` band. `max(wasmBand, asnBand)` with
  // `high` the top — read ONLY here on the trusted path, so an untrusted origin
  // never touches `cf`.
  const { asn, asOrganization } = cfAsn(raw)
  if (asnIpRisk(asn, asOrganization) === 'high') {
    return { ...verdict, ip_risk: 'high' }
  }
  return verdict
}

/** The Cloudflare-computed JA4 fallback from `request.cf.botManagement` when the
 *  header is absent. The property is not in the base workers-types, so read it
 *  defensively. */
function cfJa4(raw: Request): string | undefined {
  const cf = (raw as { cf?: { botManagement?: { ja4?: string } } }).cf
  return cf?.botManagement?.ja4
}

/** The Cloudflare-computed ASN enrichment from `request.cf` — the AS number and
 *  AS organization of the connecting IP's network. Not in the base workers-types,
 *  and absent locally (miniflare / tests) or off a non-CF edge, so read it
 *  defensively and default to `{}`. */
function cfAsn(raw: Request): { asn?: number; asOrganization?: string } {
  const cf = (raw as { cf?: { asn?: number; asOrganization?: string } }).cf
  return cf ? { asn: cf.asn, asOrganization: cf.asOrganization } : {}
}

/** The client-reported UA under suspicion, taken from the body's stable
 *  components by native key precedence — the value the TLS stack cross-checks. */
function claimedUa(components: Record<string, unknown>): string | undefined {
  for (const key of CLAIMED_UA_KEYS) {
    const value = components[key]
    if (typeof value === 'string') return value
  }
  // The real SDK emits no top-level UA (FingerprintJS has no such component);
  // its UA rides under the BotD signals. Mirrors native `claimed_ua`.
  const botd = components.botd as
    | { signals?: { userAgent?: { value?: unknown } } }
    | undefined
  const fromBotd = botd?.signals?.userAgent?.value
  return typeof fromBotd === 'string' ? fromBotd : undefined
}

/**
 * Cross-session new-device velocity bands for one request, computed from the
 * VELOCITY Durable Object — the edge form of `fp_core::fuzzy`'s velocity signal.
 *
 * Only a freshly minted device from a TRUSTED, edge-observed IP / JA4 feeds the
 * signal, mirroring native exactly: the engine records/bands only on a
 * `NewDevice` verdict, and the IP/JA4 are read from trusted headers (both `None`
 * on an untrusted origin). The per-IP band uses the documented MEDIUM/HIGH
 * thresholds; the per-JA4-class band uses the far-higher JA4 thresholds and is
 * surface-only (it never moves confidence, matching the native fusion choice).
 *
 * FAIL-OPEN (load-bearing): if the binding is unbound or the DO throws, the
 * whole path degrades to the neutral `'low'` bands — the pre-DO stateless
 * behaviour — and NEVER blocks or errors the request.
 */
async function edgeVelocity(
  raw: Request,
  outcome: ScoreOutcome,
  deps: FingerprintDeps,
): Promise<{ new_device_velocity: string; new_device_velocity_ja4: string }> {
  if (
    outcome.decision !== 'new_device' ||
    !deps.config.trustEdgeHeaders ||
    !deps.velocity
  ) {
    return { ...NEUTRAL_VELOCITY }
  }
  const store = deps.velocity
  try {
    const result = { ...NEUTRAL_VELOCITY } as {
      new_device_velocity: string
      new_device_velocity_ja4: string
    }
    const ip = raw.headers.get(CF_CONNECTING_IP)?.trim() || undefined
    if (ip) {
      const n = await store.newDeviceVelocityIp(
        ip,
        outcome.visitor_id,
        VELOCITY_WINDOW_MS,
      )
      result.new_device_velocity = classifyBand(
        n,
        VELOCITY_IP_MEDIUM,
        VELOCITY_IP_HIGH,
      )
    }
    const ja4 = (raw.headers.get(JA4_HEADER) ?? cfJa4(raw))?.trim() || undefined
    const cls = ja4 ? ja4Class(ja4) : undefined
    if (cls) {
      const n = await store.newDeviceVelocityJa4(
        cls,
        outcome.visitor_id,
        VELOCITY_WINDOW_MS,
      )
      result.new_device_velocity_ja4 = classifyBand(
        n,
        VELOCITY_JA4_MEDIUM,
        VELOCITY_JA4_HIGH,
      )
    }
    return result
  } catch {
    // Degrade to neutral on any DO/binding failure — never fail the request.
    return { ...NEUTRAL_VELOCITY }
  }
}

/** Band a new-device `count` against explicit `medium`/`high` thresholds
 *  (`fp_core::fuzzy::velocity::VelocityBand::classify_with`). */
function classifyBand(count: number, medium: number, high: number): string {
  if (count >= high) return 'high'
  if (count >= medium) return 'medium'
  return 'low'
}

/**
 * Derive the coarse, low-cardinality JA4 **class** key — the structural
 * `(protocol, tls_version, sni, alpn)` shape without the cipher/extension counts
 * — replicating `fp_core::signals::ja4_class` (which reuses `parse_ja4_shape`).
 * Returns `undefined` when the `JA4_a` prefix is missing / too short / has
 * non-numeric count fields, so a malformed JA4 records no class event.
 */
function ja4Class(ja4: string): string | undefined {
  const a = ja4.split('_')[0] ?? ja4
  // Layout: protocol(0..1) tls_version(1..3) sni(3..4) ciphers(4..6)
  // extensions(6..8) alpn(8..10). The alpn field needs length ≥ 10.
  if (a.length < 10) return undefined
  // The count fields must parse as integers (parse_ja4_shape returns None
  // otherwise), even though the class itself omits them.
  if (!/^\d\d$/.test(a.slice(4, 6)) || !/^\d\d$/.test(a.slice(6, 8))) {
    return undefined
  }
  return a.slice(0, 1) + a.slice(1, 3) + a.slice(3, 4) + a.slice(8, 10)
}

/** Clamp a fused confidence into `[0, 1]` (fuzzy-matching §6). */
function clamp(value: number): number {
  return Math.min(1, Math.max(0, value))
}

/** A `200 application/json` response over a stable serialization. */
function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}

/**
 * Serialize the `/identify` body once and, when signing is enabled, attach the
 * `x-fp-timestamp` / `x-fp-signature` headers over those EXACT bytes so what is
 * signed equals what is sent.
 */
function signedJson(
  response: IdentifyResponse,
  config: EdgeConfig,
  engine: EdgeEngine,
  issuedMs: number,
): Response {
  const body = new TextEncoder().encode(JSON.stringify(response))
  const headers = new Headers({ 'content-type': 'application/json' })
  if (config.signingKey) {
    headers.set(SIGNATURE_TIMESTAMP_HEADER, String(issuedMs))
    headers.set(SIGNATURE_HEADER, engine.sign(issuedMs, body))
  }
  return new Response(body, { status: 200, headers })
}

/** Uniform `401` used for every failed anti-replay / verification check. */
function unauthorized(): Response {
  return new Response('unauthorized', { status: 401 })
}
