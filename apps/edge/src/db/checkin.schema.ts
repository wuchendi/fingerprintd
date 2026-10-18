import { index, integer, sqliteTable, text } from 'drizzle-orm/sqlite-core'

// Check-in event log — the relationship-graph state fingerprintd deliberately
// lacks. One append-only row per assessed check-in,
// carrying only the three graph dimensions plus the edge-observed timestamp;
// all farming signals are windowed `COUNT(DISTINCT ...)` aggregates over it
// (see `src/modules/checkin/checkin-store.ts`). Hot atomic velocity counters
// that would otherwise scan this table per request live in a Durable Object
// instead (`src/lib/do/velocity-do.ts`).

/**
 * Append-only check-in event: `(accountId, visitorId, ip)` observed at `ts`
 * (Unix ms, edge-stamped — never client-reported). No natural primary key: a
 * device may legitimately check the same account in twice, so rows are kept
 * distinct by the implicit SQLite `rowid`. The three composite indexes each
 * front a windowed aggregate — recall filters on the leading column and the
 * `ts >= now - window` range on the trailing one:
 *   - `(visitor_id, ts)` → `device_account_fanout`, `batch_clustering` (device).
 *   - `(account_id, ts)` → `account_device_count`, `account_new_device_rate`,
 *     `checkin_interval_regularity`.
 *   - `(ip, ts)`         → `ip_account_count`, `batch_clustering` (ip).
 */
export const checkinEvents = sqliteTable(
  'checkin_events',
  {
    accountId: text('account_id').notNull(),
    visitorId: text('visitor_id').notNull(),
    ip: text('ip').notNull(),
    ts: integer('ts').notNull(),
  },
  (t) => [
    index('idx_checkin_events_visitor_ts').on(t.visitorId, t.ts),
    index('idx_checkin_events_account_ts').on(t.accountId, t.ts),
    index('idx_checkin_events_ip_ts').on(t.ip, t.ts),
  ],
)
