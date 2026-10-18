/**
 * Rule-engine configuration for the check-in risk layer. Weights and thresholds
 * are data, not code: {@link assess} reads them
 * from a {@link ThresholdProfile} selected by `action`, so tuning never touches
 * the scoring path. Defaults live in {@link defaultProfiles}.
 */

import type { AssessRequest } from '../modules/checkin/assess-types'

/**
 * Aggregate signals the rule engine consumes — the account/device/IP/time
 * relationship state fingerprintd deliberately does not own. Field names match
 * the storage layer's aggregate keys (`AggregateResult`), which the route
 * reduces to one scalar each.
 */
export interface Aggregates {
  /** Distinct accounts seen on this device (visitor_id → distinct account_id). */
  device_account_fanout: number
  /** Distinct devices seen on this account (account_id → distinct visitor_id). */
  account_device_count: number
  /** Rate of never-before-seen devices for this account over the last N. */
  account_new_device_rate: number
  /** Distinct accounts seen from this IP (ip → distinct account_id). */
  ip_account_count: number
  /** Regularity of this account/device's check-in intervals (scripted timing). */
  checkin_interval_regularity: number
  /** Minute-bucket burst clustering by device|IP. */
  batch_clustering: number
}

/** Stable reason codes emitted by {@link assess}. */
export type ReasonCode =
  | 'UA_TLS_MISMATCH'
  | 'DATACENTER_IP'
  | 'DEVICE_FARM'
  | 'FP_RESET'
  | 'IP_BATCH'
  | 'SCRIPTED_TIMING'

/**
 * Per-action weights, aggregate thresholds and decision bands. All numbers the
 * scoring path uses come from here — nothing is hard-coded in {@link assess}.
 */
export interface ThresholdProfile {
  /** Risk weight added when each trigger fires, keyed by reason code. */
  weights: Record<ReasonCode, number>
  /** Aggregate values are triggers only when they exceed these thresholds. */
  thresholds: {
    device_account_fanout: number
    account_new_device_rate: number
    ip_account_count: number
    checkin_interval_regularity: number
  }
  /** Risk banding cutoffs: `risk >= deny` → deny, `>= challenge` → challenge. */
  bands: {
    deny: number
    challenge: number
  }
}

/**
 * Default `daily_checkin` profile — the weights and thresholds. Conservative
 * `deny` band; prefer `challenge` on shared-egress false positives.
 */
export const defaultProfiles: Record<
  AssessRequest['action'],
  ThresholdProfile
> = {
  daily_checkin: {
    weights: {
      UA_TLS_MISMATCH: 0.5,
      DATACENTER_IP: 0.3,
      DEVICE_FARM: 0.6,
      FP_RESET: 0.4,
      IP_BATCH: 0.3,
      SCRIPTED_TIMING: 0.3,
    },
    thresholds: {
      device_account_fanout: 5,
      account_new_device_rate: 0.5,
      ip_account_count: 10,
      checkin_interval_regularity: 0.8,
    },
    bands: {
      deny: 0.7,
      challenge: 0.35,
    },
  },
}
