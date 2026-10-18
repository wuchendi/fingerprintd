/**
 * End-to-end integration coverage for `POST /checkin/assess`.
 *
 * Drives the full event lookup -> handler -> store -> engine -> response path
 * over the real Hono app from `createApp`: each case stores an identify event
 * carrying the scenario's signals, then assesses it by `request_id`, with a
 * fake {@link CheckinStore} that returns
 * controlled {@link AggregateResult} values (the store's own D1 query logic has
 * dedicated coverage in `checkin-store.test.ts`). Each representative
 * business scenario asserts the decision/verdict BAND the merged
 * engine actually produces — expectations are computed here from the committed
 * `defaultProfiles` weights/bands, never from loose prose, so this test tracks
 * the real config rather than a copy of it.
 */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { beforeAll, describe, expect, it } from 'vitest'
import type { Deps } from '../src/app'
import { createApp } from '../src/app'
import { resolveConfig } from '../src/config'
import type { ReasonCode, ThresholdProfile } from '../src/config/risk-config'
import { defaultProfiles } from '../src/config/risk-config'
import type { IdentifyResponse, Signals } from '../src/lib/types'
import type { AssessResponse } from '../src/modules/checkin/assess-types'
import type { CheckinStore } from '../src/modules/checkin/checkin-state'
import type { AggregateResult } from '../src/modules/checkin/checkin-store'
import {
  EdgeEngine,
  initEngineRuntime,
} from '../src/modules/fingerprint/engine'
import { fakeStores, zeroAggregateResult } from './helpers/fakes'

// The assess path lives in the merged edge app, so a test builds the FULL edge
// `Deps` with an injected check-in store and the API key set. The WASM engine
// loads once from the vendored bytes (the assess route never touches it, but
// `Deps` requires it).
beforeAll(() => {
  const wasmPath = fileURLToPath(
    new URL('../wasm/fp_wasm_bg.wasm', import.meta.url).href,
  )
  initEngineRuntime(readFileSync(wasmPath))
})

/** Build the full edge deps with an injected check-in store. */
function makeDeps(checkin: CheckinStore): Deps {
  const config = resolveConfig({
    FP_SALT_SECRET: 'test-salt',
    FP_API_KEY: 'api-secret',
  })
  return {
    engine: new EdgeEngine(config.saltSecret),
    config,
    ...fakeStores(config.nonceTtlSecs),
    checkin,
  }
}

/** The committed profile the endpoint scores `daily_checkin` against. */
const cfg: ThresholdProfile = defaultProfiles.daily_checkin

/** Sum the committed weights of the fired codes and band them exactly as the
 *  engine does (`risk>=deny`, `>=challenge`, else allow), so every expectation
 *  below is derived from `defaultProfiles`, not hard-coded. */
function expected(codes: ReasonCode[]): {
  risk: number
  decision: AssessResponse['decision']
  verdict: AssessResponse['verdict']
} {
  const risk = Math.min(
    1,
    codes.reduce((sum, code) => sum + cfg.weights[code], 0),
  )
  if (risk >= cfg.bands.deny)
    return { risk, decision: 'deny', verdict: 'farming' }
  if (risk >= cfg.bands.challenge)
    return { risk, decision: 'challenge', verdict: 'suspicious' }
  return { risk, decision: 'allow', verdict: 'human' }
}

/** The scenario's identify: a stored event with these hard signals. */
interface Scenario {
  visitor_id: string
  signals?: Pick<Signals, 'ua_tls_consistent' | 'ip_risk'>
}

/** A fake store returning fixed aggregates — the handler still records first,
 *  then reads these back, exercising the real reconcile + scoring path. */
function storeReturning(agg: AggregateResult): CheckinStore {
  return {
    record: (event) =>
      Promise.resolve({ inserted: true, account_id: event.account_id }),
    getAggregates: () => Promise.resolve(agg),
  }
}

/** Store the scenario's identify event, assess it through the app, parse
 *  the verdict. */
async function assess(
  agg: AggregateResult,
  scenario: Scenario,
): Promise<AssessResponse> {
  const deps = makeDeps(storeReturning(agg))
  const identify: IdentifyResponse = {
    request_id: 'req-int',
    visitor_id: scenario.visitor_id,
    confidence: 0.9,
    decision: 'match',
    is_new_device: false,
    collision_risk: false,
    signals: {
      ua_tls_consistent: true,
      ip_risk: 'low',
      client_integrity: 'unavailable',
      persona_coherence: 'unknown',
      new_device_velocity: 'low',
      automation: 'unknown',
      template_jump: false,
      ...scenario.signals,
    },
  }
  await deps.events.put(
    {
      request_id: 'req-int',
      visitor_id: scenario.visitor_id,
      ip: '203.0.113.9',
      body: JSON.stringify(identify),
    },
    Date.now() + 60_000,
  )
  const res = await createApp(deps).request(
    'https://edge.test/checkin/assess',
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer api-secret',
      },
      body: JSON.stringify({
        account_id: 'acct-int',
        action: 'daily_checkin',
        request_id: 'req-int',
      }),
    },
  )
  expect(res.status).toBe(200)
  return res.json() as Promise<AssessResponse>
}

/** Aggregate bundle nudged above the relevant committed thresholds. */
const HIGH_FANOUT: AggregateResult = {
  ...zeroAggregateResult(),
  // toAggregates() reads .h24; must exceed thresholds.device_account_fanout (5).
  device_account_fanout: { h24: 50, d7: 80 },
}
const HIGH_NEW_DEVICE_RATE: AggregateResult = {
  ...zeroAggregateResult(),
  // .rate must exceed thresholds.account_new_device_rate (0.5).
  account_new_device_rate: { rate: 0.9, sampled: 20 },
}
const HIGH_IP_COUNT: AggregateResult = {
  ...zeroAggregateResult(),
  // .h1 must exceed thresholds.ip_account_count (10).
  ip_account_count: { h1: 25, h24: 40 },
}

/** Assert a verdict matches the config-derived band + reason set. Reason codes
 *  are order-insensitive (sorted) since the two-stage engine order is an
 *  internal detail; every reason must still be a well-formed {code, detail}. */
function expectVerdict(
  json: AssessResponse,
  codes: ReasonCode[],
  visitor_id: string,
): void {
  const exp = expected(codes)
  expect(json.decision).toBe(exp.decision)
  expect(json.verdict).toBe(exp.verdict)
  expect(json.risk).toBeCloseTo(exp.risk, 10)
  expect(json.visitor_id).toBe(visitor_id)
  expect([...json.reasons.map((r) => r.code)].sort()).toEqual([...codes].sort())
  for (const reason of json.reasons) {
    expect(typeof reason.code).toBe('string')
    expect(reason.code.length).toBeGreaterThan(0)
    expect(typeof reason.detail).toBe('string')
    expect(reason.detail.length).toBeGreaterThan(0)
  }
}

describe('POST /checkin/assess — integration (handler -> store -> engine)', () => {
  it('clean human -> allow/human, no reasons', async () => {
    const body: Scenario = { visitor_id: 'vis-clean' }
    const json = await assess(zeroAggregateResult(), body)
    expectVerdict(json, [], 'vis-clean')
  })

  it('scripted (UA/TLS mismatch + datacenter IP) -> deny/farming', async () => {
    const body: Scenario = {
      visitor_id: 'vis-scripted',
      signals: { ua_tls_consistent: false, ip_risk: 'high' },
    }
    // 0.5 + 0.3 = 0.8 >= deny(0.7).
    const json = await assess(zeroAggregateResult(), body)
    expectVerdict(json, ['UA_TLS_MISMATCH', 'DATACENTER_IP'], 'vis-scripted')
  })

  it('device farm, isolated (high fan-out only) -> challenge/suspicious', async () => {
    const body: Scenario = { visitor_id: 'vis-farm' }
    // 0.6: a single strong signal is challenged, not denied.
    const json = await assess(HIGH_FANOUT, body)
    expect(json.decision).toBe('challenge')
    expectVerdict(json, ['DEVICE_FARM'], 'vis-farm')
  })

  it('device farm on datacenter egress (fan-out + high IP) -> deny/farming', async () => {
    const body: Scenario = {
      visitor_id: 'vis-farm-dc',
      signals: { ua_tls_consistent: true, ip_risk: 'high' },
    }
    // 0.6 + 0.3 = 0.9 >= deny(0.7) — how a real device farm reaches deny.
    const json = await assess(HIGH_FANOUT, body)
    expectVerdict(json, ['DEVICE_FARM', 'DATACENTER_IP'], 'vis-farm-dc')
  })

  it('fingerprint reset (high new-device rate only) -> challenge/suspicious', async () => {
    const body: Scenario = { visitor_id: 'vis-reset' }
    // 0.4 >= challenge(0.35), < deny(0.7).
    const json = await assess(HIGH_NEW_DEVICE_RATE, body)
    expect(json.decision).toBe('challenge')
    expectVerdict(json, ['FP_RESET'], 'vis-reset')
  })

  it('shared-egress benign (high IP count only) -> allow, never deny', async () => {
    const body: Scenario = { visitor_id: 'vis-nat' }
    // 0.3 < challenge(0.35): conservative on corp/campus NAT.
    const json = await assess(HIGH_IP_COUNT, body)
    // KEY PROPERTY: a benign shared egress must not be denied.
    expect(json.decision).not.toBe('deny')
    expect(json.decision).toBe('allow')
    expectVerdict(json, ['IP_BATCH'], 'vis-nat')
  })
})
