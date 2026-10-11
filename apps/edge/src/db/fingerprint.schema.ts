import {
  index,
  integer,
  primaryKey,
  sqliteTable,
  text,
} from 'drizzle-orm/sqlite-core'

// Edge D1 state schema — the externalized half of `fingerprintd_core`'s in-memory store
// (DESIGN.md fuzzy-matching §3/§4/§9/§11). Mirrors the native
// `FingerprintRecord` + `BlockingIndex`. The one-time nonce is the exception:
// it needs atomic check-and-burn (D1's eventual replication cannot give it), so
// it lives in a Durable Object, not here.

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

/**
 * Per-value frequency material for the `u_i` rarity estimate (fuzzy-matching §9), keyed
 * by salted value hash so no plaintext component value is stored. Provisioned
 * here; unpopulated on the edge (the WASM `score` approximates `u_i` over the
 * recalled block — the parity refinement).
 */
export const valueFrequency = sqliteTable('value_frequency', {
  valueHash: text('value_hash').primaryKey(),
  count: integer('count').notNull(),
})
