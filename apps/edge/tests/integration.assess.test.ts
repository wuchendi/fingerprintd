/**
 * End-to-end integration coverage for `POST /checkin/assess`.
 *
 * Drives the full handler -> store -> engine -> response path over the real
 * Hono app from `createApp`, injecting a fake {@link CheckinStore} that returns
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
import type {
  AssessRequest,
  AssessResponse,
  IdentifyResponse,
} from '../src/lib/types'
import type { CheckinStore } from '../src/modules/checkin/checkin-state'
import type { AggregateResult } from '../src/modules/checkin/checkin-store'
import {
  EdgeEngine,
  initEngineRuntime,
} from '../src/modules/fingerprint/engine'
import { fakeStores, zeroAggregateResult } from './helpers/fakes'

// The assess path lives in the merged edge app, so a test builds the FULL edge
// `Deps` with an injected check-in store. The WASM engine loads once from the
// vendored bytes (the assess route never touches it, but `Deps` requires it).
beforeAll(() => {
  const wasmPath = fileURLToPath(
    new URL('../wasm/fp_wasm_bg.wasm', import.meta.url).href,
  )
  initEngineRuntime(readFileSync(wasmPath))
})

/** Build the full edge deps with an injected check-in store. */
function makeDeps(checkin: CheckinStore): Deps {
  const config = resolveConfig({ FP_SALT_SECRET: 'test-salt' })
  return {
    engine: new EdgeEngine(config),
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

/** A clean pass-through identify verdict; override signals per case. */
function buildIdentify(
  overrides: Partial<IdentifyResponse> = {},
): IdentifyResponse {
  return {
    visitorId: 'vis-int',
    confidence: 0.9,
    is_new_device: false,
    decision: 'match',
    collision_risk: false,
    signals: { ua_tls_consistent: true, ip_risk: 'low' },
    ...overrides,
  }
}

/** A well-formed assess request; override `identify` per case. */
function buildBody(overrides: Partial<AssessRequest> = {}): AssessRequest {
  return {
    accountId: 'acct-int',
    action: 'daily_checkin',
    identify: buildIdentify(),
    ...overrides,
  }
}

/** A fake store returning fixed aggregates — the handler still records first,
 *  then reads these back, exercising the real reconcile + scoring path. */
function storeReturning(agg: AggregateResult): CheckinStore {
  return {
    record: () => Promise.resolve(),
    getAggregates: () => Promise.resolve(agg),
  }
}

/** POST a body through the app with an edge IP header, parse the verdict. */
async function assess(
  agg: AggregateResult,
  body: AssessRequest,
): Promise<AssessResponse> {
  const app = createApp(makeDeps(storeReturning(agg)))
  const res = await app.request('https://edge.test/checkin/assess', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'cf-connecting-ip': '203.0.113.9',
    },
    body: JSON.stringify(body),
  })
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
  visitorId: string,
): void {
  const exp = expected(codes)
  expect(json.decision).toBe(exp.decision)
  expect(json.verdict).toBe(exp.verdict)
  expect(json.risk).toBeCloseTo(exp.risk, 10)
  expect(json.visitorId).toBe(visitorId)
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
    const body = buildBody({
      identify: buildIdentify({ visitorId: 'vis-clean' }),
    })
    const json = await assess(zeroAggregateResult(), body)
    expectVerdict(json, [], 'vis-clean')
  })

  it('scripted (UA/TLS mismatch + datacenter IP) -> deny/farming', async () => {
    const body = buildBody({
      identify: buildIdentify({
        visitorId: 'vis-scripted',
        signals: { ua_tls_consistent: false, ip_risk: 'high' },
      }),
    })
    // 0.5 + 0.3 = 0.8 >= deny(0.7).
    const json = await assess(zeroAggregateResult(), body)
    expectVerdict(json, ['UA_TLS_MISMATCH', 'DATACENTER_IP'], 'vis-scripted')
  })

  it('device farm, isolated (high fan-out only) -> challenge/suspicious', async () => {
    const body = buildBody({
      identify: buildIdentify({ visitorId: 'vis-farm' }),
    })
    // 0.6: a single strong signal is challenged, not denied.
    const json = await assess(HIGH_FANOUT, body)
    expect(json.decision).toBe('challenge')
    expectVerdict(json, ['DEVICE_FARM'], 'vis-farm')
  })

  it('device farm on datacenter egress (fan-out + high IP) -> deny/farming', async () => {
    const body = buildBody({
      identify: buildIdentify({
        visitorId: 'vis-farm-dc',
        signals: { ua_tls_consistent: true, ip_risk: 'high' },
      }),
    })
    // 0.6 + 0.3 = 0.9 >= deny(0.7) — how a real device farm reaches deny.
    const json = await assess(HIGH_FANOUT, body)
    expectVerdict(json, ['DEVICE_FARM', 'DATACENTER_IP'], 'vis-farm-dc')
  })

  it('fingerprint reset (high new-device rate only) -> challenge/suspicious', async () => {
    const body = buildBody({
      identify: buildIdentify({ visitorId: 'vis-reset' }),
    })
    // 0.4 >= challenge(0.35), < deny(0.7).
    const json = await assess(HIGH_NEW_DEVICE_RATE, body)
    expect(json.decision).toBe('challenge')
    expectVerdict(json, ['FP_RESET'], 'vis-reset')
  })

  it('shared-egress benign (high IP count only) -> allow, never deny', async () => {
    const body = buildBody({
      identify: buildIdentify({ visitorId: 'vis-nat' }),
    })
    // 0.3 < challenge(0.35): conservative on corp/campus NAT.
    const json = await assess(HIGH_IP_COUNT, body)
    // KEY PROPERTY: a benign shared egress must not be denied.
    expect(json.decision).not.toBe('deny')
    expect(json.decision).toBe('allow')
    expectVerdict(json, ['IP_BATCH'], 'vis-nat')
  })
})
