/**
 * Edge Worker configuration, resolved from the runtime environment.
 *
 * The defaults mirror the native server's `Config::default`
 * (`crates/fingerprintd/src/config.rs`): probe enforcement OFF, response signing
 * OFF, timestamp window OFF, nonce TTL 30s, ±30s skew, so a client works
 * against either unchanged. `FP_SALT_SECRET` has no default: an unset salt
 * throws instead of deriving blocking keys from a public placeholder.
 *
 * `FP_SALT_SECRET`, `FP_PROBE_KEY`, `FP_SIGNING_KEY`, `FP_ADMIN_KEY`, and
 * `LIBSQL_AUTH_TOKEN` are Worker Secrets; the rest are `[vars]`. Secrets are
 * never embedded.
 */

/** Cloudflare Worker environment bindings: string-typed config vars plus the
 *  state bindings. Typed optional so a missing binding is checked at startup
 *  (`src/index.ts` throws) rather than assumed; Node tests inject fakes. */
export interface Env {
  /** Nonce Durable Object namespace. Required: unbound ⇒ startup throws. */
  NONCE?: DurableObjectNamespace
  /** Database driver: `"libsql"` (default when unset/empty) or `"d1"`. */
  DB_TYPE?: string
  /** libSQL server URL (e.g. Turso). Required when `DB_TYPE` is `libsql`. */
  LIBSQL_URL?: string
  /** libSQL auth token (Worker Secret). Omit for an unauthenticated server. */
  LIBSQL_AUTH_TOKEN?: string
  /** D1 binding holding the fingerprint library + blocking index + check-in
   *  event log. Required when `DB_TYPE` is `d1`. */
  DB?: D1Database
  /** Velocity Durable Object namespace for the cross-session new-device
   *  velocity counters. Required: unbound ⇒ startup throws. */
  VELOCITY?: DurableObjectNamespace
  /** Per-IP rate limiter for `POST /identify` and `POST /checkin/assess`.
   *  Required: unbound ⇒ startup throws. */
  RATE_LIMIT?: RateLimit
  /** Per-IP rate limiter for `GET /challenge`, separate from `RATE_LIMIT`.
   *  Required: unbound ⇒ startup throws. */
  CHALLENGE_RATE_LIMIT?: RateLimit
  /** Check-in retention window in seconds: events older than this are purged by
   *  the scheduled cron. `0`/unset ⇒ check-in retention disabled. */
  CHECKIN_RETENTION_SECS?: string
  /** Seeds the deterministic salt + MinHash family so blocking keys are stable
   *  across isolates (Worker Secret). Required: unset/blank ⇒ startup throws. */
  FP_SALT_SECRET?: string
  /** Pre-shared nonce-probe key (Worker Secret). Empty/unset ⇒ probe OFF. */
  FP_PROBE_KEY?: string
  /** Response-signing key (Worker Secret). Empty/unset ⇒ signing OFF. */
  FP_SIGNING_KEY?: string
  /** `"1"`/`"true"` enables the request timestamp window. Default OFF. */
  FP_ENFORCE_TS_WINDOW?: string
  /** Allowed clock skew in seconds when the timestamp window is on. Default 30. */
  FP_TS_SKEW_SECS?: string
  /** Nonce lifetime in seconds. Default 30. */
  FP_NONCE_TTL_SECS?: string
  /** `"1"`/`"true"` trusts edge-injected passive-signal headers. Default OFF. */
  FP_TRUST_EDGE_HEADERS?: string
  FP_INTEGRITY_PENALTY_ENABLED?: string
  /** Admin key gating `DELETE /visitor/{id}` GDPR erasure (Worker Secret).
   *  Empty/unset ⇒ the erasure endpoint is DISABLED (returns 404, fail-closed). */
  FP_ADMIN_KEY?: string
  /** D1 retention window in seconds: templates whose `last_seen` is older than
   *  this are purged by the scheduled cron. `0`/unset ⇒ retention disabled. */
  FP_RETENTION_SECS?: string
  /** Comma-separated allowed CORS origins for the browser playground, e.g.
   *  `https://fingerprintd.pages.dev`. `*` allows any origin.
   *  Empty/unset ⇒ no CORS headers (same-origin / server-to-server only). */
  FP_CORS_ORIGINS?: string
}

/** Resolved, typed configuration for one Worker isolate. */
export interface EdgeConfig {
  /** Salt/MinHash seed passed to the WASM engine. Always non-empty. */
  saltSecret: string
  /** Nonce-probe key; `undefined` ⇒ probe verification is skipped (OFF). */
  probeKey?: string
  /** Response-signing key; `undefined` ⇒ responses are not signed (OFF). */
  signingKey?: string
  /** Whether to enforce the request timestamp window. */
  enforceTsWindow: boolean
  /** Allowed skew in milliseconds when the window is on. */
  tsSkewMs: number
  /** Nonce lifetime in seconds, advertised as `expires_in`. */
  nonceTtlSecs: number
  /** Whether edge-injected passive-signal headers are trusted. */
  trustEdgeHeaders: boolean
  /** Whether a `noise` client-integrity verdict may lower confidence. Off by
   *  default: the band is surfaced-only until its false-positive rate is known. */
  integrityPenaltyEnabled: boolean
  /** Admin key for `DELETE /visitor/{id}` erasure; `undefined` ⇒ endpoint
   *  DISABLED (fail-closed 404). Compared constant-time against the bearer. */
  adminKey?: string
  /** D1 retention window in milliseconds; `0` ⇒ retention disabled (no purge). */
  retentionMs: number
  /** Check-in retention window in milliseconds; `0` ⇒ disabled (no purge). */
  checkinRetentionMs: number
  /** Allowed CORS origins for the browser playground; `['*']` allows any.
   *  Empty ⇒ CORS disabled (no `Access-Control-*` headers emitted). */
  corsOrigins: string[]
}

/** Read a boolean flag var: `"1"`, `"true"`, `"yes"` (case-insensitive) ⇒ true. */
function flag(value: string | undefined): boolean {
  if (value === undefined) return false
  const v = value.trim().toLowerCase()
  return v === '1' || v === 'true' || v === 'yes'
}

/** Read a non-negative integer var, falling back to `fallback` on absent/invalid. */
function intVar(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback
  const n = Number.parseInt(value, 10)
  return Number.isFinite(n) && n >= 0 ? n : fallback
}

/** Read a secret trimmed; empty/whitespace counts as unset so it disables its
 *  feature. */
function secret(value: string | undefined): string | undefined {
  if (value === undefined) return undefined
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : undefined
}

/** Parse a comma-separated origin list, trimming blanks. Empty ⇒ CORS off. */
function originList(value: string | undefined): string[] {
  if (value === undefined) return []
  return value
    .split(',')
    .map((o) => o.trim())
    .filter((o) => o.length > 0)
}

/** Resolve the typed {@link EdgeConfig} from raw environment bindings. */
export function resolveConfig(env: Env): EdgeConfig {
  const saltSecret = secret(env.FP_SALT_SECRET)
  if (!saltSecret) {
    throw new Error(
      'FP_SALT_SECRET is required (set it with `wrangler secret put FP_SALT_SECRET`, or in .dev.vars for local dev)',
    )
  }
  return {
    saltSecret,
    probeKey: secret(env.FP_PROBE_KEY),
    signingKey: secret(env.FP_SIGNING_KEY),
    enforceTsWindow: flag(env.FP_ENFORCE_TS_WINDOW),
    tsSkewMs: intVar(env.FP_TS_SKEW_SECS, 30) * 1000,
    nonceTtlSecs: intVar(env.FP_NONCE_TTL_SECS, 30),
    trustEdgeHeaders: flag(env.FP_TRUST_EDGE_HEADERS),
    integrityPenaltyEnabled: flag(env.FP_INTEGRITY_PENALTY_ENABLED),
    adminKey: secret(env.FP_ADMIN_KEY),
    retentionMs: intVar(env.FP_RETENTION_SECS, 0) * 1000,
    checkinRetentionMs: intVar(env.CHECKIN_RETENTION_SECS, 0) * 1000,
    corsOrigins: originList(env.FP_CORS_ORIGINS),
  }
}
