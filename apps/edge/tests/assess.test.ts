import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { beforeAll, describe, expect, it } from 'vitest'
import type { Deps } from '../src/app'
import { createApp } from '../src/app'
import { resolveConfig } from '../src/config'
import type {
  AssessRequest,
  AssessResponse,
  IdentifyResponse,
} from '../src/lib/types'
import type { CheckinStore } from '../src/modules/checkin/checkin-state'
import type {
  AggregateResult,
  CheckinEvent,
} from '../src/modules/checkin/checkin-store'
import {
  EdgeEngine,
  initEngineRuntime,
} from '../src/modules/fingerprint/engine'
import {
  EmptyCheckinStore,
  fakeStores,
  zeroAggregateResult,
} from './helpers/fakes'

// `/checkin/assess` lives in the merged edge app, so a test drives the FULL
// edge `Deps` (engine, nonces, candidates, config) with an injected check-in
// store — the assess path only touches `deps.checkin`, but the app still needs
// the rest wired. The WASM engine is loaded once from the vendored bytes.
beforeAll(() => {
  const wasmPath = fileURLToPath(
    new URL('../wasm/fp_wasm_bg.wasm', import.meta.url).href,
  )
  initEngineRuntime(readFileSync(wasmPath))
})

/** Build the full edge deps with an injected check-in store (empty by default). */
function makeDeps(checkin: CheckinStore = new EmptyCheckinStore()): Deps {
  const config = resolveConfig({ FP_SALT_SECRET: 'test-salt' })
  return {
    engine: new EdgeEngine(config),
    config,
    ...fakeStores(config.nonceTtlSecs),
    checkin,
  }
}

/** A clean pass-through identify verdict; override per case. */
function buildIdentify(
  overrides: Partial<IdentifyResponse> = {},
): IdentifyResponse {
  return {
    visitorId: 'vis-1',
    confidence: 0.9,
    is_new_device: false,
    decision: 'match',
    collision_risk: false,
    signals: { ua_tls_consistent: true, ip_risk: 'low' },
    ...overrides,
  }
}

/** A well-formed assess request body; override per case. */
function buildBody(overrides: Partial<AssessRequest> = {}): AssessRequest {
  return {
    accountId: 'acct-1',
    action: 'daily_checkin',
    identify: buildIdentify(),
    ...overrides,
  }
}

/** POST a JSON body to `/checkin/assess`, carrying an edge IP header. */
function post(
  app: ReturnType<typeof createApp>,
  body: unknown,
): Promise<Response> {
  return Promise.resolve(
    app.request('https://edge.test/checkin/assess', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'cf-connecting-ip': '203.0.113.7',
      },
      body: JSON.stringify(body),
    }),
  )
}

/** Parse a JSON response body as the typed {@link AssessResponse}. */
function asAssess(res: Response): Promise<AssessResponse> {
  return res.json() as Promise<AssessResponse>
}

describe('POST /checkin/assess', () => {
  it('scores a clean request as allow/human (empty-store fallback)', async () => {
    const app = createApp(makeDeps())
    const res = await post(app, buildBody())
    expect(res.status).toBe(200)
    const json = await asAssess(res)
    expect(json).toMatchObject({
      decision: 'allow',
      verdict: 'human',
      risk: 0,
      visitorId: 'vis-1',
    })
    expect(json.reasons).toEqual([])
  })

  it('does not throw and allows when D1/DO are unbound', async () => {
    // EmptyCheckinStore: record is a no-op, aggregates zero.
    const app = createApp(makeDeps())
    const res = await post(app, buildBody())
    expect(res.status).toBe(200)
    expect((await asAssess(res)).decision).toBe('allow')
  })

  it('records the event BEFORE it scores (aggregate ordering)', async () => {
    const calls: string[] = []
    const seen: CheckinEvent[] = []
    const spyStore: CheckinStore = {
      record(event) {
        calls.push('record')
        seen.push(event)
        return Promise.resolve()
      },
      getAggregates() {
        calls.push('getAggregates')
        return Promise.resolve(zeroAggregateResult())
      },
    }
    const app = createApp(makeDeps(spyStore))
    const res = await post(app, buildBody())
    expect(res.status).toBe(200)
    expect(calls).toEqual(['record', 'getAggregates'])
    // The recorded event uses edge-observed ip, never a body field.
    expect(seen[0]).toMatchObject({
      accountId: 'acct-1',
      visitorId: 'vis-1',
      ip: '203.0.113.7',
    })
  })

  it('passes mapped aggregates through to the verdict (deny on a device farm)', async () => {
    const farmed: AggregateResult = {
      ...zeroAggregateResult(),
      device_account_fanout: { h24: 50, d7: 80 },
      account_new_device_rate: { rate: 0.9, sampled: 20 },
    }
    const store: CheckinStore = {
      record: () => Promise.resolve(),
      getAggregates: () => Promise.resolve(farmed),
    }
    const app = createApp(makeDeps(store))
    const res = await post(app, buildBody())
    expect(res.status).toBe(200)
    const json = await asAssess(res)
    // DEVICE_FARM (0.6) + FP_RESET (0.4) => risk clamps to 1 => deny/farming.
    expect(json.decision).toBe('deny')
    expect(json.verdict).toBe('farming')
    expect(json.reasons.map((r) => r.code)).toEqual(['DEVICE_FARM', 'FP_RESET'])
  })

  describe('rejects a malformed body with 400', () => {
    it('missing accountId', async () => {
      const app = createApp(makeDeps())
      const { accountId: _drop, ...rest } = buildBody()
      const res = await post(app, rest)
      expect(res.status).toBe(400)
    })

    it('wrong action', async () => {
      const app = createApp(makeDeps())
      const res = await post(app, { ...buildBody(), action: 'weekly_checkin' })
      expect(res.status).toBe(400)
    })

    it('unknown top-level field', async () => {
      const app = createApp(makeDeps())
      const res = await post(app, { ...buildBody(), extra: true })
      expect(res.status).toBe(400)
    })

    it('body carrying edge-observed ip', async () => {
      const app = createApp(makeDeps())
      const res = await post(app, { ...buildBody(), ip: '10.0.0.1' })
      expect(res.status).toBe(400)
    })

    it('body carrying edge-observed ts', async () => {
      const app = createApp(makeDeps())
      const res = await post(app, { ...buildBody(), ts: 123 })
      expect(res.status).toBe(400)
    })

    it('identify missing signals', async () => {
      const app = createApp(makeDeps())
      const { signals: _drop, ...identify } = buildIdentify()
      const res = await post(app, { ...buildBody(), identify })
      expect(res.status).toBe(400)
    })

    it('invalid JSON', async () => {
      const app = createApp(makeDeps())
      const res = await app.request('https://edge.test/checkin/assess', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{ not json',
      })
      expect(res.status).toBe(400)
    })
  })
})
