/**
 * Host state interface for the check-in route.
 *
 * Mirrors `lib/state.ts`: the `/checkin/assess` handler depends on an async
 * {@link CheckinStore} interface, never on the concrete database wrapper, so
 * the router stays unit-testable without the Workers runtime. `index.ts`
 * injects the database-backed `CheckinEventStore`; Node tests inject fakes.
 */

import type {
  AggregateResult,
  CheckinEvent,
  RecordResult,
} from './checkin-store'

/**
 * The append + aggregate surface the handler consumes. `CheckinEventStore`
 * implements it over the database. Only these two methods are needed on the
 * assess path (the retention purge lives on the concrete class and is driven
 * by the cron).
 */
export interface CheckinStore {
  /** Append one check-in observation; a second one for the same
   *  `request_id` records nothing and reports the account it was first
   *  recorded for. */
  record(event: CheckinEvent): Promise<RecordResult>
  /** Windowed aggregates for the `(account, device, ip)` triple as of
   *  `now` (Unix ms). */
  getAggregates(
    account_id: string,
    visitor_id: string,
    ip: string,
    now: number,
  ): Promise<AggregateResult>
}
