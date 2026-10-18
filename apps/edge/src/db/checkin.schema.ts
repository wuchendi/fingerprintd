import {
  index,
  integer,
  sqliteTable,
  text,
  uniqueIndex,
} from 'drizzle-orm/sqlite-core'

// Check-in event log — the relationship-graph state fingerprintd deliberately
// lacks. One append-only row per assessed identify event, carrying the three
// graph dimensions plus the edge-observed timestamp;
// all farming signals are windowed `COUNT(DISTINCT ...)` aggregates over it
// (see `src/modules/checkin/checkin-store.ts`). Hot atomic velocity counters
// that would otherwise scan this table per request live in a Durable Object
// instead (`src/lib/do/velocity-do.ts`).

/**
 * Append-only check-in event: `(account_id, visitor_id, ip)` observed at `ts`
 * (Unix ms, edge-stamped). `request_id` is the identify event the check-in was
 * assessed on; its unique index records at most one check-in per identify, so
 * one identify cannot be replayed to inflate the aggregates. The three
 * composite indexes each front a windowed aggregate — recall filters on the
 * leading column and the `ts >= now - window` range on the trailing one:
 *   - `(visitor_id, ts)` → `device_account_fanout`, `batch_clustering` (device).
 *   - `(account_id, ts)` → `account_device_count`, `account_new_device_rate`,
 *     `checkin_interval_regularity`.
 *   - `(ip, ts)`         → `ip_account_count`, `batch_clustering` (ip).
 */
export const checkinEvents = sqliteTable(
  'checkin_events',
  {
    request_id: text('request_id').notNull(),
    account_id: text('account_id').notNull(),
    visitor_id: text('visitor_id').notNull(),
    ip: text('ip').notNull(),
    ts: integer('ts').notNull(),
  },
  (t) => [
    uniqueIndex('idx_checkin_events_request_id').on(t.request_id),
    index('idx_checkin_events_visitor_ts').on(t.visitor_id, t.ts),
    index('idx_checkin_events_account_ts').on(t.account_id, t.ts),
    index('idx_checkin_events_ip_ts').on(t.ip, t.ts),
  ],
)
