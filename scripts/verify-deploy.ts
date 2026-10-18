#!/usr/bin/env bun
/**
 * verify-deploy.ts — end-to-end smoke of a deployed fingerprintd edge Worker.
 *
 * Exercises the public HTTP contract against a running Worker:
 *
 *   1. `GET /health` -> 200.
 *   2. `GET /challenge` -> 200 with exactly `{nonce, expires_in}`.
 *   3. `POST /identify` with a per-run random fingerprint -> 200 `new_device`,
 *      exactly the response keys (top level and `signals`), `request_id` and
 *      `visitor_id` as 32 lowercase hex.
 *   4. Re-identify the same fingerprint with a fresh nonce -> `match`, same
 *      `visitor_id`, different `request_id`.
 *   5. Rejects: reused nonce -> 401, `ts` 10 minutes old -> 401, unknown
 *      top-level key -> 400, unknown `components` key -> 400; a 400 does not
 *      consume the nonce (the same nonce then identifies -> 200).
 *   6. `GET /events/{request_id}` (needs FP_API_KEY): 200 with the exact
 *      identify body, wrong / missing key -> 401, unknown id -> 404. Without
 *      the key the route is disabled and must not answer 200.
 *   7. `POST /checkin/assess` (needs FP_API_KEY): 200 with a `decision`,
 *      unknown request_id -> 404, missing key -> 401, unknown body key -> 400.
 *   8. `DELETE /visitor/{visitor_id}` (needs FP_ADMIN_KEY): 204, the visitor's
 *      events are gone (when FP_API_KEY is set), and re-identifying the same
 *      fingerprint yields `new_device` under a different visitor id.
 *
 * Runtime-agnostic: uses only global `fetch` and Web Crypto, so it runs
 * identically under `bun` and `node` (>= 23).
 *
 *   bun  scripts/verify-deploy.ts
 *   node scripts/verify-deploy.ts
 *
 * Env (key values are never printed):
 *   BASE          Worker origin (default: the cdlab.workers.dev deployment)
 *   FP_API_KEY    server-to-server API key; unset ⇒ events/check-in checks skipped
 *   FP_ADMIN_KEY  admin key; unset ⇒ erase checks skipped
 *
 * Exit code is 0 only when every executed check passes.
 */

const BASE = (
  process.env.BASE ?? 'https://fingerprintd-edge.cdlab.workers.dev'
).replace(/\/$/, '')
const API_KEY = process.env.FP_API_KEY ?? ''
const ADMIN_KEY = process.env.FP_ADMIN_KEY ?? ''

const IDENTIFY_KEYS = [
  'collision_risk',
  'confidence',
  'decision',
  'is_new_device',
  'request_id',
  'signals',
  'visitor_id',
]
const SIGNAL_KEYS = [
  'automation',
  'client_integrity',
  'ip_risk',
  'new_device_velocity',
  'persona_coherence',
  'template_jump',
  'ua_tls_consistent',
]
const HEX32 = /^[0-9a-f]{32}$/

function randomHex(bytes: number): string {
  return [...crypto.getRandomValues(new Uint8Array(bytes))]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

const USER_AGENT =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'

/**
 * A closed-schema fingerprint unique to this run (random canvas hash and
 * fonts), so a live deployment always sees it first as a new device.
 */
const COMPONENTS = {
  webgl: 'ANGLE (Intel, Mesa Intel(R) UHD Graphics 620, OpenGL 4.6)',
  platform: 'Linux x86_64',
  timezone: 'UTC',
  languages: 'en-US',
  audio: '124.04347527516074',
  canvas: randomHex(32),
  cpu_cores: 8,
  device_memory: 8,
  screen: '1920x1080',
  fonts: ['Arial', 'DejaVu Sans', `verify-${randomHex(8)}`],
  math: 'verify-deploy',
}

let passed = 0
let failed = 0
let skipped = 0

function check(name: string, cond: boolean, extra = ''): void {
  const tag = cond ? 'PASS' : 'FAIL'
  cond ? passed++ : failed++
  console.log(`  [${tag}] ${name}${extra ? `  ${extra}` : ''}`)
}

function skip(name: string, why: string): void {
  skipped++
  console.log(`  [SKIP] ${name}  (${why})`)
}

interface Reply {
  /** HTTP status; 0 when the request itself failed (network error). */
  status: number
  body: any
  error?: string
}

/** One HTTP call; network errors become status 0 instead of throwing. */
async function call(
  method: string,
  path: string,
  opts: { json?: unknown; bearer?: string } = {},
): Promise<Reply> {
  const headers: Record<string, string> = {}
  if (opts.json !== undefined) headers['content-type'] = 'application/json'
  if (opts.bearer !== undefined) headers.authorization = `Bearer ${opts.bearer}`
  try {
    const res = await fetch(`${BASE}${path}`, {
      method,
      headers,
      body: opts.json === undefined ? undefined : JSON.stringify(opts.json),
    })
    const text = await res.text()
    let body: unknown = null
    try {
      body = text ? JSON.parse(text) : null
    } catch {
      body = text
    }
    return { status: res.status, body }
  } catch (err) {
    return { status: 0, body: null, error: (err as Error).message }
  }
}

function got(r: Reply): string {
  return r.error ? `got ${r.status} (${r.error})` : `got ${r.status}`
}

function sameKeys(obj: unknown, keys: string[]): boolean {
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
    return false
  }
  return JSON.stringify(Object.keys(obj).sort()) === JSON.stringify(keys)
}

/** Structural JSON equality, insensitive to object key order. */
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true
  if (typeof a !== 'object' || typeof b !== 'object' || !a || !b) return false
  if (Array.isArray(a) !== Array.isArray(b)) return false
  const ka = Object.keys(a)
  const kb = Object.keys(b)
  if (ka.length !== kb.length) return false
  return ka.every((k) =>
    deepEqual(
      (a as Record<string, unknown>)[k],
      (b as Record<string, unknown>)[k],
    ),
  )
}

async function mintNonce(): Promise<string> {
  const r = await call('GET', '/challenge')
  return typeof r.body?.nonce === 'string' ? r.body.nonce : ''
}

function identifyBody(nonce: string, patch: Record<string, unknown> = {}) {
  return {
    nonce,
    ts: Date.now(),
    components: COMPONENTS,
    user_agent: USER_AGENT,
    botd: { bot: false },
    ...patch,
  }
}

async function identify(
  nonce: string,
  patch: Record<string, unknown> = {},
): Promise<Reply> {
  return call('POST', '/identify', { json: identifyBody(nonce, patch) })
}

async function main(): Promise<number> {
  console.log(`BASE=${BASE}`)

  console.log('\n== liveness + challenge ==')
  const health = await call('GET', '/health')
  check('GET /health -> 200', health.status === 200, got(health))

  const chal = await call('GET', '/challenge')
  check('GET /challenge -> 200', chal.status === 200, got(chal))
  check(
    'challenge has exactly {nonce, expires_in}',
    sameKeys(chal.body, ['expires_in', 'nonce']) &&
      typeof chal.body.nonce === 'string' &&
      typeof chal.body.expires_in === 'number',
    got(chal),
  )
  if (chal.status !== 200 || typeof chal.body?.nonce !== 'string') {
    console.log('  (abort) no nonce from /challenge — cannot continue')
    return 1
  }

  console.log('\n== identify ==')
  const first = await identify(chal.body.nonce)
  check('POST /identify -> 200', first.status === 200, got(first))
  const id1 = first.body ?? {}
  check(
    'identify body has exactly the response keys',
    sameKeys(id1, IDENTIFY_KEYS),
  )
  check(
    'signals has exactly the signal keys',
    sameKeys(id1.signals, SIGNAL_KEYS),
  )
  check('request_id is 32 lowercase hex', HEX32.test(String(id1.request_id)))
  check('visitor_id is 32 lowercase hex', HEX32.test(String(id1.visitor_id)))
  check(
    'first sighting -> new_device',
    id1.decision === 'new_device' && id1.is_new_device === true,
    `decision=${id1.decision}`,
  )

  const second = await identify(await mintNonce())
  const id2 = second.body ?? {}
  check('re-identify -> 200', second.status === 200, got(second))
  check(
    're-identify -> match',
    id2.decision === 'match',
    `decision=${id2.decision}`,
  )
  check('re-identify keeps visitor_id', id2.visitor_id === id1.visitor_id)
  check('re-identify has a new request_id', id2.request_id !== id1.request_id)

  console.log('\n== identify rejects ==')
  const reused = await identify(chal.body.nonce)
  check('reused nonce -> 401', reused.status === 401, got(reused))

  const stale = await identify(await mintNonce(), { ts: Date.now() - 600_000 })
  check('ts 10 minutes old -> 401', stale.status === 401, got(stale))

  const unknownTop = await identify(await mintNonce(), { extra: true })
  check(
    'unknown top-level key -> 400',
    unknownTop.status === 400,
    got(unknownTop),
  )

  const keptNonce = await mintNonce()
  const unknownComp = await identify(keptNonce, {
    components: { ...COMPONENTS, not_a_component: 'x' },
  })
  check(
    'unknown components key -> 400',
    unknownComp.status === 400,
    got(unknownComp),
  )
  const afterBad = await identify(keptNonce)
  check(
    'a 400 does not consume the nonce',
    afterBad.status === 200,
    got(afterBad),
  )

  console.log('\n== events ==')
  const eventPath = `/events/${id1.request_id}`
  if (API_KEY) {
    const ev = await call('GET', eventPath, { bearer: API_KEY })
    check('GET /events/{id} -> 200', ev.status === 200, got(ev))
    check('event equals the identify response', deepEqual(ev.body, id1))
    const wrong = await call('GET', eventPath, { bearer: `${API_KEY}x` })
    check('wrong key -> 401', wrong.status === 401, got(wrong))
    const none = await call('GET', eventPath)
    check('no Authorization -> 401', none.status === 401, got(none))
    const unknown = await call('GET', `/events/${randomHex(16)}`, {
      bearer: API_KEY,
    })
    check('unknown request_id -> 404', unknown.status === 404, got(unknown))
  } else {
    const ev = await call('GET', eventPath)
    check(
      'events disabled without FP_API_KEY -> not 200',
      ev.status !== 200,
      got(ev),
    )
    skip('events accept path', 'FP_API_KEY not set')
  }

  console.log('\n== check-in ==')
  if (API_KEY) {
    const assess = {
      account_id: `verify-${randomHex(8)}`,
      action: 'daily_checkin',
      request_id: id1.request_id,
    }
    const ok = await call('POST', '/checkin/assess', {
      json: assess,
      bearer: API_KEY,
    })
    check('POST /checkin/assess -> 200', ok.status === 200, got(ok))
    check('assess has a decision', typeof ok.body?.decision === 'string')
    const unknown = await call('POST', '/checkin/assess', {
      json: { ...assess, request_id: randomHex(16) },
      bearer: API_KEY,
    })
    check('unknown request_id -> 404', unknown.status === 404, got(unknown))
    const noKey = await call('POST', '/checkin/assess', { json: assess })
    check('missing key -> 401', noKey.status === 401, got(noKey))
    const extra = await call('POST', '/checkin/assess', {
      json: { ...assess, extra: true },
      bearer: API_KEY,
    })
    check('unknown body key -> 400', extra.status === 400, got(extra))
  } else {
    skip('check-in', 'FP_API_KEY not set')
  }

  console.log('\n== erase ==')
  if (ADMIN_KEY) {
    const del = await call('DELETE', `/visitor/${id1.visitor_id}`, {
      bearer: ADMIN_KEY,
    })
    check('DELETE /visitor/{id} -> 204', del.status === 204, got(del))
    if (API_KEY) {
      const ev = await call('GET', eventPath, { bearer: API_KEY })
      check('erased visitor events -> 404', ev.status === 404, got(ev))
    } else {
      skip('erased visitor events -> 404', 'FP_API_KEY not set')
    }
    const again = await identify(await mintNonce())
    check('identify after erase -> 200', again.status === 200, got(again))
    check(
      'identify after erase -> new_device',
      again.body?.decision === 'new_device',
      `decision=${again.body?.decision}`,
    )
    check(
      'erased visitor_id is not re-minted',
      HEX32.test(String(again.body?.visitor_id)) &&
        again.body.visitor_id !== id1.visitor_id,
    )
  } else {
    skip('erase', 'FP_ADMIN_KEY not set')
  }

  return failed === 0 ? 0 : 1
}

void main().then((code) => {
  console.log(
    `\n${code === 0 ? 'OK' : 'FAILED'} — ${passed} passed, ${failed} failed, ${skipped} skipped`,
  )
  process.exit(code)
})
