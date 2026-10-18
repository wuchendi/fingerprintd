/**
 * Check-in module barrel — the domain's public surface: the check-in store
 * (interface + database-backed implementation), the pure risk-scoring
 * `assess`, and the Hono sub-router.
 * Consumers (the composition root in `index.ts`, `app.ts`, tests) import from
 * here rather than reaching into the module's files.
 */

export type { CheckinDeps } from './checkin.routes'
export { checkinRoutes } from './checkin.routes'
export type { CheckinStore } from './checkin-state'
export type {
  AggregateResult,
  CheckinEvent,
  RecordResult,
} from './checkin-store'
export {
  CheckinEventStore,
  INTERVAL_SAMPLE,
  NEW_DEVICE_SAMPLE,
} from './checkin-store'
export { assess } from './risk-engine'
