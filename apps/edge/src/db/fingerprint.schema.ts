import {
  index,
  integer,
  primaryKey,
  sqliteTable,
  text,
} from 'drizzle-orm/sqlite-core'

// Edge fingerprint state schema (libSQL or D1) — the externalized half of
// `fingerprintd`'s in-memory store (DESIGN.md fuzzy-matching §3/§4/§11). Mirrors
// the native `FingerprintRecord` + `BlockingIndex`. The one-time nonce is the
// exception: it needs atomic check-and-burn, so it lives in a Durable Object,
// not here.

/**
 * Fingerprint library: `visitorId -> template` (fuzzy-matching §3/§11). `components`
 * holds the RAW component object the host recalls and hands to the WASM scorer,
 * which re-salts it deterministically (the salt secret is a Worker Secret, not
 * stored). Drift (fuzzy-matching §7) upserts this row on a confirmed match; a
 * review-band hit never touches it (anti-poisoning).
 */
export const templates = sqliteTable('templates', {
  visitorId: text('visitor_id').primaryKey(),
  components: text('components').notNull(),
  firstSeen: integer('first_seen').notNull(),
  lastSeen: integer('last_seen').notNull(),
  observationCount: integer('observation_count').notNull(),
})

/**
 * The `key -> set<visitorId>` blocking inverted index (fuzzy-matching §4). Stage-one
 * recall unions the visitors sharing any of a probe's blocking keys. The
 * composite primary key makes re-indexing a known `(key, visitor)` idempotent;
 * `idx_blocking_index_key` serves the `WHERE key IN (...)` recall.
 */
export const blockingIndex = sqliteTable(
  'blocking_index',
  {
    key: text('key').notNull(),
    visitorId: text('visitor_id').notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.key, t.visitorId] }),
    index('idx_blocking_index_key').on(t.key),
  ],
)
