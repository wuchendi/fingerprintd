import { describe, expect, it } from 'vitest'
import type { Aggregates, ThresholdProfile } from '../src/config/risk-config'
import { defaultProfiles } from '../src/config/risk-config'
import type { AssessInput } from '../src/modules/checkin/assess-types'
import { assess } from '../src/modules/checkin/risk-engine'

const profile = defaultProfiles.daily_checkin

/** An input with clean signals; override `signals` per case. */
function buildReq(signals: Partial<AssessInput['signals']> = {}): AssessInput {
  return {
    action: 'daily_checkin',
    visitor_id: 'vis-1',
    signals: { ua_tls_consistent: true, ip_risk: 'low', ...signals },
  }
}

/** Aggregates with every value safely below its threshold; override per case. */
function buildAgg(overrides: Partial<Aggregates> = {}): Aggregates {
  return {
    device_account_fanout: 0,
    account_device_count: 0,
    account_new_device_rate: 0,
    ip_account_count: 0,
    checkin_interval_regularity: 0,
    batch_clustering: 0,
    ...overrides,
  }
}

const codes = (r: ReturnType<typeof assess>): string[] =>
  r.reasons.map((x) => x.code)

describe('assess()', () => {
  it('clean human → allow/human with empty reasons', () => {
    const res = assess(buildReq(), buildAgg(), profile)
    expect(res.decision).toBe('allow')
    expect(res.verdict).toBe('human')
    expect(res.risk).toBeLessThan(0.35)
    expect(res.reasons).toEqual([])
    expect(res.visitor_id).toBe('vis-1')
  })

  it('UA/TLS mismatch + datacenter IP → both reasons present, banded', () => {
    const res = assess(
      buildReq({ ua_tls_consistent: false, ip_risk: 'high' }),
      buildAgg(),
      profile,
    )
    // 0.5 + 0.3 = 0.8 → deny.
    expect(res.risk).toBeCloseTo(0.8)
    expect(res.decision).toBe('deny')
    expect(codes(res)).toEqual(['UA_TLS_MISMATCH', 'DATACENTER_IP'])
  })

  it('high device_account_fanout fires DEVICE_FARM (0.6, alone → challenge)', () => {
    const res = assess(
      buildReq(),
      buildAgg({ device_account_fanout: 50 }),
      profile,
    )
    // A single DEVICE_FARM weight (0.6) lands in the challenge band, not deny.
    expect(res.risk).toBeCloseTo(0.6)
    expect(res.decision).toBe('challenge')
    expect(codes(res)).toEqual(['DEVICE_FARM'])
  })

  it('device farm + datacenter IP → farming/deny with risk ≥ 0.7', () => {
    const res = assess(
      buildReq({ ip_risk: 'high' }),
      buildAgg({ device_account_fanout: 50 }),
      profile,
    )
    // 0.6 + 0.3 = 0.9 → deny/farming.
    expect(res.risk).toBeGreaterThanOrEqual(0.7)
    expect(res.decision).toBe('deny')
    expect(res.verdict).toBe('farming')
    expect(codes(res)).toContain('DEVICE_FARM')
  })

  it('high account_new_device_rate → FP_RESET fires', () => {
    const res = assess(
      buildReq(),
      buildAgg({ account_new_device_rate: 0.9 }),
      profile,
    )
    expect(codes(res)).toEqual(['FP_RESET'])
  })

  it('high ip_account_count → IP_BATCH fires', () => {
    const res = assess(buildReq(), buildAgg({ ip_account_count: 100 }), profile)
    expect(codes(res)).toEqual(['IP_BATCH'])
  })

  it('high checkin_interval_regularity → SCRIPTED_TIMING fires', () => {
    const res = assess(
      buildReq(),
      buildAgg({ checkin_interval_regularity: 0.95 }),
      profile,
    )
    expect(codes(res)).toEqual(['SCRIPTED_TIMING'])
  })

  it('each reason code fires only on its own trigger', () => {
    // Aggregate values exactly AT the threshold must not fire (strict `>`).
    const atThreshold = assess(
      buildReq(),
      buildAgg({
        device_account_fanout: profile.thresholds.device_account_fanout,
        account_new_device_rate: profile.thresholds.account_new_device_rate,
        ip_account_count: profile.thresholds.ip_account_count,
        checkin_interval_regularity:
          profile.thresholds.checkin_interval_regularity,
      }),
      profile,
    )
    expect(atThreshold.reasons).toEqual([])
    // Non-scoring aggregates (account_device_count, batch_clustering) never fire.
    const noise = assess(
      buildReq(),
      buildAgg({ account_device_count: 9999, batch_clustering: 9999 }),
      profile,
    )
    expect(noise.reasons).toEqual([])
  })

  it('banding boundary: risk exactly 0.7 → deny', () => {
    // FP_RESET (0.4) + IP_BATCH (0.3) = 0.7 exactly.
    const res = assess(
      buildReq(),
      buildAgg({ account_new_device_rate: 0.9, ip_account_count: 100 }),
      profile,
    )
    expect(res.risk).toBeCloseTo(0.7)
    expect(res.decision).toBe('deny')
    expect(res.verdict).toBe('farming')
  })

  it('banding boundary: risk exactly 0.35 → challenge', () => {
    // Custom profile: a single 0.35-weight trigger lands on the challenge cutoff.
    const cfg: ThresholdProfile = {
      ...profile,
      weights: { ...profile.weights, DATACENTER_IP: 0.35 },
    }
    const res = assess(buildReq({ ip_risk: 'high' }), buildAgg(), cfg)
    expect(res.risk).toBeCloseTo(0.35)
    expect(res.decision).toBe('challenge')
    expect(res.verdict).toBe('suspicious')
  })

  it('risk is clamped to [0,1] when all triggers fire', () => {
    const res = assess(
      buildReq({ ua_tls_consistent: false, ip_risk: 'high' }),
      buildAgg({
        device_account_fanout: 50,
        account_new_device_rate: 0.9,
        ip_account_count: 100,
        checkin_interval_regularity: 0.95,
      }),
      profile,
    )
    // Raw sum 0.5+0.3+0.6+0.4+0.3+0.3 = 2.4 → clamped.
    expect(res.risk).toBe(1)
    expect(res.decision).toBe('deny')
  })

  it('defaults the profile from the input action when cfg is omitted', () => {
    const res = assess(buildReq(), buildAgg())
    expect(res.decision).toBe('allow')
  })
})
