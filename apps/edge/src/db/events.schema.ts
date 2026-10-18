import { index, integer, sqliteTable, text } from 'drizzle-orm/sqlite-core'

/**
 * Identify events, served back by `GET /events/{request_id}` and looked up by
 * `POST /checkin/assess`. `body` is the exact serialized identify response;
 * `ip` is the edge-observed client IP of that identify (null when absent).
 * Rows live until `expires_at` (Unix ms): the `expires_at` index serves the
 * scheduled purge and the `visitor_id` index serves erasure.
 */
export const events = sqliteTable(
  'events',
  {
    request_id: text('request_id').primaryKey(),
    visitor_id: text('visitor_id').notNull(),
    ip: text('ip'),
    body: text('body').notNull(),
    expires_at: integer('expires_at').notNull(),
  },
  (t) => [
    index('idx_events_visitor_id').on(t.visitor_id),
    index('idx_events_expires_at').on(t.expires_at),
  ],
)
