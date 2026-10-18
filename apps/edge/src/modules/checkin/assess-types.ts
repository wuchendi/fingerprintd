/**
 * Wire and engine types for `POST /checkin/assess`.
 *
 * The caller names a past identify by its `request_id`; the edge looks the
 * stored event up and reads its `visitor_id`, `signals` and identify-time IP,
 * so nothing about the device is taken from the caller.
 */

import type { Signals } from '../../lib/types'

/**
 * `POST /checkin/assess` request body. Closed: an unknown key is a `400`.
 */
export interface AssessRequest {
  /** Business identity being assessed. */
  account_id: string
  /** Scenario tag selecting a threshold profile. */
  action: 'daily_checkin'
  /** The `request_id` of the identify this check-in is assessed on. */
  request_id: string
}

/** What the risk engine scores: the scenario plus the stored identify's
 *  device id and signals. */
export interface AssessInput {
  action: AssessRequest['action']
  visitor_id: string
  signals: Pick<Signals, 'ua_tls_consistent' | 'ip_risk'>
}

/** A single reason contributing to an {@link AssessResponse} decision. */
export interface AssessReason {
  /** Stable machine code for the reason, e.g. `DEVICE_FARM`. */
  code: string
  /** Human-readable explanation for logs/debugging. */
  detail: string
}

/** `POST /checkin/assess` success body. */
export interface AssessResponse {
  /** Gate action the caller should take. */
  decision: 'allow' | 'challenge' | 'deny'
  /** Interpreted risk label. */
  verdict: 'human' | 'suspicious' | 'farming'
  /** Continuous risk score in `[0.0, 1.0]`. */
  risk: number
  /** Ordered reasons that produced the decision. */
  reasons: AssessReason[]
  /** The device identifier of the stored identify event. */
  visitor_id: string
}
