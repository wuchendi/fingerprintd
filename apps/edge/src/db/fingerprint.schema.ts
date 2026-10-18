import {
  index,
  integer,
  primaryKey,
  sqliteTable,
  text,
} from 'drizzle-orm/sqlite-core'

// Edge fingerprint state schema (libSQL or D1): the externalized form of
// `fingerprintd`'s record store + blocking index (DESIGN.md fuzzy-matching
// §3/§4/§11), plus the erasure tombstones. Only the salted stored form of a
// device is persisted — never raw component values. The one-time nonce needs
// atomic check-and-burn, so it lives in a Durable Object, not here.

/**
 * Fingerprint library: `visitor_id -> template`. `stored` is the JSON of the
 * WASM engine's salted stored form (salted hashes / numerics only), handed back
 * to the scorer verbatim on recall. A confirmed match rewrites it with the
 * drifted template (fuzzy-matching §7); a review never touches it.
 */
export const templates = sqliteTable('templates', {
  visitor_id: text('visitor_id').primaryKey(),
  stored: text('stored').notNull(),
  firstSeen: integer('first_seen').notNull(),
  lastSeen: integer('last_seen').notNull(),
  observationCount: integer('observation_count').notNull(),
})

/**
 * The `key -> set<visitor_id>` blocking inverted index (fuzzy-matching §4).
 * The composite primary key makes re-indexing idempotent; the `key` index
 * serves recall and the `visitor_id` index serves erasure / purge.
 */
export const blockingIndex = sqliteTable(
  'blocking_index',
  {
    key: text('key').notNull(),
    visitor_id: text('visitor_id').notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.key, t.visitor_id] }),
    index('idx_blocking_index_key').on(t.key),
    index('idx_blocking_index_visitor_id').on(t.visitor_id),
  ],
)

/**
 * Erasure tombstones: a visitor id erased by `DELETE /visitor/{id}` is never
 * minted or written again. Bounded by the scheduled trim, oldest first
 * (`erased_at` index).
 */
export const erasedVisitors = sqliteTable(
  'erased_visitors',
  {
    visitor_id: text('visitor_id').primaryKey(),
    erasedAt: integer('erased_at').notNull(),
  },
  (t) => [index('idx_erased_visitors_erased_at').on(t.erasedAt)],
)
