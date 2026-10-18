import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { count } from 'drizzle-orm'
import { beforeAll, describe, expect, it } from 'vitest'
import type { Deps } from '../src/app'
import { createApp } from '../src/app'
import type { Env } from '../src/config'
import { resolveConfig } from '../src/config'
import { checkinEvents } from '../src/db/schema'
import type { IdentifyResponse, Signals } from '../src/lib/types'
import type { CheckinStore } from '../src/modules/checkin'
import { CheckinEventStore } from '../src/modules/checkin'
import type {
  AssessRequest,
  AssessResponse,
} from '../src/modules/checkin/assess-types'
import type {
  AggregateResult,
  CheckinEvent,
} from '../src/modules/checkin/checkin-store'
import { EventStore } from '../src/modules/events'
import {
  EdgeEngine,
  initEngineRuntime,
} from '../src/modules/fingerprint/engine'
import {
  EmptyCheckinStore,
  fakeStores,
  memoryDb,
  zeroAggregateResult,
} from './helpers/fakes'

// `/checkin/assess` lives in the merged edge app, so a test drives the FULL
// edge `Deps` with injected event + check-in stores. The WASM engine is loaded
// once from the vendored bytes.
beforeAll(() => {
  const wasmPath = fileURLToPath(
    new URL('../wasm/fp_wasm_bg.wasm', import.meta.url).href,
  )
  initEngineRuntime(readFileSync(wasmPath))
})

const API_KEY = 'api-secret'
const AUTH = `Bearer ${API_KEY}`

/** Build the full edge deps with the API key set and an injected check-in
 *  store (empty by default). */
function makeDeps(
  checkin: CheckinStore = new EmptyCheckinStore(),
  env: Env = { FP_API_KEY: API_KEY },
): Deps {
  const config = resolveConfig({ FP_SALT_SECRET: 'test-salt', ...env })
  return {
    engine: new EdgeEngine(config.saltSecret),
    config,
    ...fakeStores(config.nonceTtlSecs),
    checkin,
  }
}

const CLEAN: Signals = {
  ua_tls_consistent: true,
  ip_risk: 'low',
  client_integrity: 'unavailable',
  persona_coherence: 'unknown',
  new_device_velocity: 'low',
  automation: 'unknown',
  template_jump: false,
}

/** Store an identify event for `request_id` the way `/identify` does. */
async function storeIdentify(
  deps: Deps,
  request_id = 'req-1',
  visitor_id = 'vis-1',
  ip: string | null = '198.51.100.20',
): Promise<void> {
  const body: IdentifyResponse = {
    request_id,
    visitor_id,
    confidence: 0.9,
    decision: 'match',
    is_new_device: false,
    collision_risk: false,
    signals: CLEAN,
  }
  await deps.events.put(
    { request_id, visitor_id, ip, body: JSON.stringify(body) },
    Date.now() + 60_000,
  )
}

/** A well-formed assess request body; override per case. */
function buildBody(overrides: Partial<AssessRequest> = {}): AssessRequest {
  return {
    account_id: 'acct-1',
    action: 'daily_checkin',
    request_id: 'req-1',
    ...overrides,
  }
}

/** POST a JSON body to `/checkin/assess` from the customer backend's IP. */
function post(
  deps: Deps,
  body: unknown,
  headers: Record<string, string> = { authorization: AUTH },
): Promise<Response> {
  return Promise.resolve(
    createApp(deps).request('https://edge.test/checkin/assess', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'cf-connecting-ip': '203.0.113.7',
        ...headers,
      },
      body: JSON.stringify(body),
    }),
  )
}

/** A check-in store that records what it is handed and returns `agg`; set
 *  `recorded` to an account id to report the request_id as already recorded
 *  for it. */
function spyStore(
  agg: AggregateResult = zeroAggregateResult(),
): CheckinStore & {
  calls: string[]
  seen: CheckinEvent[]
  recorded: string | undefined
} {
  const calls: string[] = []
  const seen: CheckinEvent[] = []
  return {
    calls,
    seen,
    recorded: undefined,
    record(event) {
      calls.push('record')
      seen.push(event)
      // Simulates a prior check-in of this request_id when `recorded` is set.
      if (this.recorded === undefined) {
        return Promise.resolve({ inserted: true, account_id: event.account_id })
      }
      return Promise.resolve({ inserted: false, account_id: this.recorded })
    },
    getAggregates() {
      calls.push('getAggregates')
      return Promise.resolve(agg)
    },
  }
}

describe('POST /checkin/assess auth', () => {
  it('returns 404 when no API key is configured (endpoint disabled)', async () => {
    const deps = makeDeps(undefined, {})
    await storeIdentify(deps)
    expect((await post(deps, buildBody())).status).toBe(404)
  })

  it('returns 401 on a missing or wrong bearer credential', async () => {
    const deps = makeDeps()
    await storeIdentify(deps)
    expect((await post(deps, buildBody(), {})).status).toBe(401)
    expect(
      (await post(deps, buildBody(), { authorization: 'Bearer nope' })).status,
    ).toBe(401)
    expect(
      (await post(deps, buildBody(), { authorization: API_KEY })).status,
    ).toBe(401)
  })
})

describe('POST /checkin/assess', () => {
  it('scores a clean check-in as allow/human, all keys snake_case', async () => {
    const deps = makeDeps()
    await storeIdentify(deps)
    const res = await post(deps, buildBody())
    expect(res.status).toBe(200)
    const json = (await res.json()) as AssessResponse
    expect(Object.keys(json).sort()).toEqual([
      'decision',
      'reasons',
      'risk',
      'verdict',
      'visitor_id',
    ])
    expect(json).toEqual({
      decision: 'allow',
      verdict: 'human',
      risk: 0,
      reasons: [],
      visitor_id: 'vis-1',
    })
  })

  it('returns 404 for an unknown or expired request_id', async () => {
    const deps = makeDeps()
    expect((await post(deps, buildBody())).status).toBe(404)
    await deps.events.put(
      { request_id: 'old', visitor_id: 'v', ip: null, body: '{}' },
      Date.now() - 1,
    )
    expect((await post(deps, buildBody({ request_id: 'old' }))).status).toBe(
      404,
    )
  })

  it('records the stored event BEFORE it scores, with the identify-time IP', async () => {
    const store = spyStore()
    const deps = makeDeps(store)
    await storeIdentify(deps)
    expect((await post(deps, buildBody())).status).toBe(200)
    expect(store.calls).toEqual(['record', 'getAggregates'])
    // The IP is the client's at identify, not the assess caller's (203.0.113.7).
    expect(store.seen[0]).toMatchObject({
      request_id: 'req-1',
      account_id: 'acct-1',
      visitor_id: 'vis-1',
      ip: '198.51.100.20',
    })
  })

  it('records an empty IP when the identify saw none', async () => {
    const store = spyStore()
    const deps = makeDeps(store)
    await storeIdentify(deps, 'req-1', 'vis-1', null)
    expect((await post(deps, buildBody())).status).toBe(200)
    expect(store.seen[0]?.ip).toBe('')
  })

  it('takes the device id, signals and IP from a real identify', async () => {
    const store = spyStore()
    const deps = makeDeps(store)
    const app = createApp(deps)
    const challenge = await app.request('https://edge.test/challenge')
    const { nonce } = (await challenge.json()) as { nonce: string }
    const identifyRes = await app.request('https://edge.test/identify', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'cf-connecting-ip': '198.51.100.44',
      },
      body: JSON.stringify({
        nonce,
        ts: Date.now(),
        components: { platform: 'Linux x86_64', cpu_cores: 8 },
      }),
    })
    const identify = (await identifyRes.json()) as IdentifyResponse

    const res = await post(deps, buildBody({ request_id: identify.request_id }))
    expect(res.status).toBe(200)
    expect(((await res.json()) as AssessResponse).visitor_id).toBe(
      identify.visitor_id,
    )
    expect(store.seen[0]).toMatchObject({
      visitor_id: identify.visitor_id,
      ip: '198.51.100.44',
    })
  })

  it('rejects a replay of a request_id under another account with 409', async () => {
    const db = await memoryDb()
    const deps = {
      ...makeDeps(new CheckinEventStore(db)),
      events: new EventStore(db),
    }
    await storeIdentify(deps)
    expect((await post(deps, buildBody())).status).toBe(200)
    const replay = await post(deps, buildBody({ account_id: 'acct-2' }))
    expect(replay.status).toBe(409)
    const rows = await db
      .select({ account_id: checkinEvents.account_id })
      .from(checkinEvents)
    expect(rows).toEqual([{ account_id: 'acct-1' }])
  })

  it('does not score a cross-account replay', async () => {
    const store = spyStore()
    store.recorded = 'acct-other'
    const deps = makeDeps(store)
    await storeIdentify(deps)
    expect((await post(deps, buildBody())).status).toBe(409)
    expect(store.calls).toEqual(['record'])
  })

  it('re-assesses a same-account replay idempotently', async () => {
    const db = await memoryDb()
    const deps = {
      ...makeDeps(new CheckinEventStore(db)),
      events: new EventStore(db),
    }
    await storeIdentify(deps)
    const first = await post(deps, buildBody())
    const again = await post(deps, buildBody())
    expect(first.status).toBe(200)
    expect(again.status).toBe(200)
    expect(((await again.json()) as AssessResponse).decision).toBe(
      ((await first.json()) as AssessResponse).decision,
    )
    const [row] = await db.select({ n: count() }).from(checkinEvents)
    expect(row?.n).toBe(1)
  })

  it('passes mapped aggregates through to the verdict (deny on a device farm)', async () => {
    const deps = makeDeps(
      spyStore({
        ...zeroAggregateResult(),
        device_account_fanout: { h24: 50, d7: 80 },
        account_new_device_rate: { rate: 0.9, sampled: 20 },
      }),
    )
    await storeIdentify(deps)
    const json = (await (
      await post(deps, buildBody())
    ).json()) as AssessResponse
    // DEVICE_FARM (0.6) + FP_RESET (0.4) => risk clamps to 1 => deny/farming.
    expect(json.decision).toBe('deny')
    expect(json.verdict).toBe('farming')
    expect(json.reasons.map((r) => r.code)).toEqual(['DEVICE_FARM', 'FP_RESET'])
  })

  it('rejects a non-JSON content type with 415', async () => {
    const deps = makeDeps()
    const res = await createApp(deps).request(
      'https://edge.test/checkin/assess',
      {
        method: 'POST',
        headers: { 'content-type': 'text/plain', authorization: AUTH },
        body: JSON.stringify(buildBody()),
      },
    )
    expect(res.status).toBe(415)
  })

  describe('rejects a malformed body with 400', () => {
    const { account_id: _a, ...noAccount } = buildBody()
    const { request_id: _r, ...noRequest } = buildBody()
    const cases: [string, unknown][] = [
      ['missing account_id', noAccount],
      ['empty account_id', buildBody({ account_id: '' })],
      ['missing request_id', noRequest],
      ['wrong action', { ...buildBody(), action: 'weekly_checkin' }],
      ['unknown top-level field', { ...buildBody(), extra: true }],
      ['a client-supplied ip', { ...buildBody(), ip: '10.0.0.1' }],
      ['a passed-through identify', { ...buildBody(), identify: {} }],
    ]
    for (const [name, body] of cases) {
      it(name, async () => {
        const deps = makeDeps()
        await storeIdentify(deps)
        expect((await post(deps, body)).status).toBe(400)
      })
    }

    it('invalid JSON', async () => {
      const res = await createApp(makeDeps()).request(
        'https://edge.test/checkin/assess',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: AUTH },
          body: '{ not json',
        },
      )
      expect(res.status).toBe(400)
    })
  })
})
