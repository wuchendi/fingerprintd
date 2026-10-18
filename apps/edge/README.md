# @cdlab/fingerprintd-edge

Cloudflare Worker deployment of fingerprintd: a **TypeScript host** (Hono) that
owns I/O, routing and state, calling **Rust compiled to WASM**
(`crates/fp-wasm` → `crates/fp-core`) for the pure compute — blocking keys,
scoring, and the passive / integrity / persona / automation / velocity signals.
It serves the same Contract v1 as the native Axum server (`crates/fingerprintd`),
so a client works against either. `POST /checkin/assess` is edge-only.

## HTTP API

All JSON is snake_case. Every error is a bare status with an empty body.

### `GET /health`

`200`, empty body.

### `GET /challenge`

Mints a one-time nonce in the `NONCE` Durable Object.

```json
{ "nonce": "…", "expires_in": 30 }
```

Exactly these two keys; `expires_in` is `FP_NONCE_TTL_SECS`. Per-IP rate limited
by `CHALLENGE_RATE_LIMIT` (`429` when exceeded).

### `POST /identify`

```jsonc
{
  "nonce": "…",                 // from GET /challenge, single use
  "ts": 1760000000000,          // Unix ms, required, within ±FP_TS_SKEW_SECS
  "components": { … },          // closed component schema keys only
  "user_agent": "…",            // optional
  "botd": { "bot": false, "kind": null },                       // optional
  "integrity": { "canvas": "ok", "webgl": "noise", "audio": "unavailable", "rect": "ok" } // optional, each key optional
}
```

The body is closed at every level: an unknown key (top level, inside
`components`, `botd` or `integrity`) or a wrongly-typed value is a `400`. The
body is validated **before** the nonce is consumed, so a malformed request never
burns it.

```json
{
  "request_id": "32 lowercase hex",
  "visitor_id": "32 lowercase hex",
  "confidence": 0.97,
  "decision": "match" | "review" | "new_device",
  "is_new_device": false,
  "collision_risk": false,
  "signals": {
    "ua_tls_consistent": true,
    "ip_risk": "low" | "medium" | "high",
    "client_integrity": "ok" | "noise" | "unavailable",
    "persona_coherence": "consistent" | "mismatch" | "unknown",
    "new_device_velocity": "low" | "medium" | "high",
    "automation": "detected" | "not_detected" | "unknown",
    "template_jump": false
  }
}
```

Exactly these keys. `request_id` and every minted `visitor_id` are random
128-bit ids (`crypto.getRandomValues`). When `FP_API_KEY` is set, the response
is stored byte-for-byte as an event readable through `GET /events/{request_id}`.
Per-IP rate limited by `RATE_LIMIT` (`429` when exceeded).

### `GET /events/{request_id}`

`Authorization: Bearer <FP_API_KEY>`. Returns `200` with the exact identify
body until the event expires (`FP_EVENT_TTL_SECS`).

### `DELETE /visitor/{visitor_id}`

`Authorization: Bearer <FP_ADMIN_KEY>`. GDPR erasure: deletes the template, its
blocking-index rows and every identify event of the visitor, and tombstones the
id so it is never minted or written again. `204`, idempotent (an unknown id is
also `204`, so existence never leaks).

### `POST /checkin/assess`

`Authorization: Bearer <FP_API_KEY>`. Server-to-server: the customer backend
names a past identify by its `request_id`; the device id, signals and client IP
all come from the stored event, never from the caller.

```jsonc
// request (closed body)
{ "account_id": "acct-1", "action": "daily_checkin", "request_id": "…" }
// 200
{
  "decision": "allow" | "challenge" | "deny",
  "verdict": "human" | "suspicious" | "farming",
  "risk": 0.0,
  "reasons": [{ "code": "DEVICE_FARM", "detail": "…" }],
  "visitor_id": "…"
}
```

The check-in is recorded once per `request_id` in `checkin_events`, then scored
by the pure `assess()` engine (`modules/checkin/risk-engine.ts`; weights,
thresholds and bands in `config/risk-config.ts`) over windowed
account/device/IP/time aggregates — device fan-out, account device count,
new-device rate, IP sharing, timing regularity. Shares the `RATE_LIMIT` bucket
with `POST /identify`. The [playground](../web/README.md) demos the
identify → assess flow.

### Status matrix

| Status | When |
| --- | --- |
| `400` | unknown key or wrongly-typed value anywhere in the body; malformed JSON |
| `401` | `/identify`: bad, expired or reused nonce, or `ts` outside the window. Key-gated routes: missing or wrong bearer |
| `404` | `/events`, `/checkin/assess`: `FP_API_KEY` unset (route disabled), or unknown/expired `request_id`. `/visitor`: `FP_ADMIN_KEY` unset (route disabled) |
| `409` | `/checkin/assess`: the `request_id` was already assessed for a different `account_id` (nothing is scored or recorded) |
| `415` | `POST` body not `application/json` (or a `+json` type) |
| `429` | per-IP rate limit exceeded |

## Configuration

Resolved in `src/config/index.ts`. `FP_SALT_SECRET`, the database configuration
and all four bindings are required — a missing one throws on the first request
instead of running degraded. Secrets are read at runtime and never embedded.

| Name | Kind | Role | Default |
| --- | --- | --- | --- |
| `FP_SALT_SECRET` | secret | seeds the deterministic salt + MinHash family; **required** | — |
| `FP_API_KEY` | secret | bearer for `GET /events` and `POST /checkin/assess`; unset ⇒ both disabled and no events stored | off |
| `FP_ADMIN_KEY` | secret | bearer for `DELETE /visitor/{id}`; unset ⇒ disabled | off |
| `FP_EVENT_TTL_SECS` | var | lifetime of a stored identify event | 3600 |
| `FP_TS_SKEW_SECS` | var | allowed clock skew of the request `ts` (always enforced) | 30 |
| `FP_NONCE_TTL_SECS` | var | nonce lifetime, advertised as `expires_in` | 30 |
| `FP_INTEGRITY_PENALTY_ENABLED` | var | `"1"`/`"true"`/`"yes"` lets a `noise` client-integrity verdict lower confidence (always surfaced) | off |
| `FP_RETENTION_SECS` | var | purge templates not seen for this long; `0` ⇒ off | 0 (`wrangler.jsonc`: 2592000) |
| `CHECKIN_RETENTION_SECS` | var | purge check-in events older than this; `0` ⇒ off | 0 |
| `FP_CORS_ORIGINS` | var | comma-separated browser CORS origins (`*` = any); unset ⇒ no CORS headers | off |
| `DB_TYPE` | var | database driver: `libsql` or `d1` | `libsql` |
| `LIBSQL_URL` | var/secret | libSQL server URL (e.g. Turso); required for `libsql` | — |
| `LIBSQL_AUTH_TOKEN` | secret | libSQL auth token; omit for an unauthenticated server | — |
| `NONCE` | Durable Object | one-time nonce store (atomic check-and-burn + TTL alarm) | — |
| `VELOCITY` | Durable Object | per-IP distinct new-device counter | — |
| `RATE_LIMIT` | rate limit | per-IP limit on `POST /identify` + `POST /checkin/assess` | 60 / 60s |
| `CHALLENGE_RATE_LIMIT` | rate limit | per-IP limit on `GET /challenge`, its own bucket | 120 / 60s |
| `DB` | D1 | the database; required for `d1` | — |

Locally, copy `.dev.vars.example` → `.dev.vars` (gitignored); `wrangler dev`
loads it into the same `env.*` bindings. Remotely, set each secret with
`wrangler secret put <NAME>`; `[vars]` in `wrangler.jsonc` hold only non-secret
values and `keep_vars` keeps dashboard-set vars across deploys.

`FP_SALT_SECRET` MUST be stable and identical across every isolate — rotating it
re-partitions the blocking index and orphans every stored template (all devices
re-mint). Treat it as a long-lived deployment identity.

## Storage

One database, libSQL by default or D1 with `DB_TYPE=d1`, defined by the Drizzle
schema in `src/db/` and created by the single drizzle-kit migration
`drizzle/0000_*.sql`:

- `templates` — each visitor's **salted stored form** only; raw component values
  are never persisted.
- `blocking_index` — the `key → visitor_id` inverted index recall walks.
- `erased_visitors` — erasure tombstones; a tombstoned id is never minted and a
  match is never written back to it. Trimmed to the newest 100 000.
- `events` — identify responses with an `expires_at` (`FP_EVENT_TTL_SECS`),
  read by `/events` and `/checkin/assess`.
- `checkin_events` — the append-only check-in log, unique per `request_id`.

The daily cron (`03:00 UTC`, `scheduled` in `src/index.ts`) deletes expired
events, templates past `FP_RETENTION_SECS`, check-in events past
`CHECKIN_RETENTION_SECS`, and trims the tombstones.

The D1 block is commented out in `wrangler.jsonc`; `bun run cf:d1config` writes a
gitignored `wrangler.d1.jsonc` with it enabled. To deploy on D1, uncomment the
block and set `DB_TYPE` to `"d1"`.

## Signals

- **JA4** comes from Cloudflare's own enrichment, `request.cf.botManagement.ja4`;
  the client cannot supply it. Off Cloudflare (no `request.cf`) it is absent and
  the UA↔TLS verdict degrades to neutral.
- **Client IP** is `cf-connecting-ip`, set by Cloudflare in front of the Worker.
- **ASN fuse** — `request.cf.asn` / `asOrganization` is classified against a
  curated hosting/datacenter/VPN ASN set (`src/lib/asn-ip-risk.ts`, illustrative —
  swap for a real reputation feed). A listed ASN raises `ip_risk` to `high`; it
  never lowers the WASM band.
- **New-device velocity** — every `new_device` from an IP records its minted
  visitor id in that IP's `VELOCITY` Durable Object (1h rolling window, at most
  64 live members). The distinct count is banded by the engine like native, and
  the band's penalty (non-zero at `high`) is subtracted from confidence. A match,
  a review or a request without `cf-connecting-ip` stays `low`.

## Known limitations

- **Concurrent first sightings.** There is no per-device lock: two concurrent
  first identifies of the same device may each mint a visitor id. This is a
  demo trade-off. A match is never written back for a visitor erased in the
  meantime (every write-back statement requires the template to still exist).
- **Cold-start scoring store.** The edge rebuilds the scoring store per request
  from the recalled candidates, so the agreement weights `m_i` stay at their
  cold-start priors and the rarity `u_i` is estimated over the recalled
  candidate block only. Edge and native confidence can therefore drift apart
  after many confirmed matches; identity and decision are computed by the same
  engine.
- **Bounded recall.** Recall visits the exact key first, then the rarest keys,
  taking at most 256 visitors per key (most recently seen first) and 1024 in
  total. A very hot block can still miss a true match.

## Layout

```
src/
  index.ts                  Worker entry — imports the .wasm, builds engine + state per
                            isolate, runs the retention cron, re-exports the DOs
  app.ts                    composition root: CORS + the aggregate router over injected deps
  routes/index.ts           GET /health, per-IP rate limits, mounts the domain routers
  config/index.ts           typed config + bindings resolved from env
  config/risk-config.ts     check-in weights / thresholds / bands per action
  db/                       Drizzle schema (fingerprint, events, checkin) + DB_TYPE client
  modules/fingerprint/      engine wrapper, recall/persist/erase store, challenge/identify/erase routes
  modules/events/           event store + GET /events/:request_id
  modules/checkin/          check-in store, risk engine, POST /checkin/assess
  lib/                      wire types, bearer auth, HTTP helpers, state contracts, ASN classifier
  lib/do/                   NonceDurableObject, VelocityDurableObject + host adapters
drizzle/                    the single drizzle-kit migration
scripts/d1-config.ts        writes wrangler.d1.jsonc (D1 block enabled)
wasm/                       `wasm-pack --target web` build of crates/fp-wasm (not committed)
tests/
  *.test.ts                 Node: routes over the real WASM, stores on libSQL, config, risk engine
  *.workers.test.ts         miniflare: Durable Objects, the Worker on D1, cross-stack parity
```

## Develop & verify

```bash
bash scripts/build-wasm.sh   # from the repo root: builds apps/edge/wasm
bun install
bunx biome check .  # lint (Biome)
bun run typecheck   # tsc --noEmit
bun run test        # vitest: node project + workers project (miniflare, DB_TYPE=d1)
bun run deploy:dry  # wrangler deploy --dry-run (bundles the Worker + .wasm + bindings)
bun run dev         # wrangler dev --local (loads .dev.vars; no account)
```

`tests/parity.workers.test.ts` drives the native parity vectors
(`crates/fingerprintd/tests/fixtures/parity.json`, asserted natively by
`crates/fingerprintd/tests/parity.rs`) through the full edge stack and asserts
the same decision, `is_new_device`, `collision_risk`, `template_jump`, symbolic
visitor labels and confidence (to the fixture tolerance).

The full cross-stack gate (Rust, WASM, TypeScript) is `bash scripts/check.sh`
from the repo root.

Apply migrations with:

```bash
LIBSQL_URL=… LIBSQL_AUTH_TOKEN=… bun run db:migrate   # libSQL (drizzle-kit migrate)
bun run cf:localdb                                     # local D1
bun run cf:remotedb                                    # remote D1 (needs an account)
```

`bun run db:gen` regenerates `drizzle/` from the schema and needs no env.

## Deploy

### Local (no account)

```bash
cp .dev.vars.example .dev.vars   # then edit, incl. LIBSQL_URL
bun run db:migrate               # e.g. against `turso dev --port 8081`
bun run dev                      # wrangler dev --local
```

### Cloudflare

SQLite-backed Durable Objects + D1 are on the Workers free plan.

1. **Database.** libSQL (default): `wrangler secret put LIBSQL_URL` and
   `wrangler secret put LIBSQL_AUTH_TOKEN`. D1: `wrangler d1 create fingerprintd`,
   put the id into the `d1_databases` block, uncomment it and set `DB_TYPE` to
   `"d1"`.
2. **Migrations:** `bun run db:migrate` (libSQL) or `bun run cf:remotedb` (D1).
3. **Secrets:**

   ```bash
   wrangler secret put FP_SALT_SECRET   # required — stable, high-entropy
   wrangler secret put FP_API_KEY       # optional — events API + check-in
   wrangler secret put FP_ADMIN_KEY     # optional — erasure
   ```

4. **Deploy:** `bun run deploy` (`wrangler deploy --minify`). Validate offline
   first with `bun run deploy:dry`.

`scripts/deploy-cf.sh [edge|web|all]` runs the same flow locally (`DRY_RUN=1`
for build-only, `RUN_MIGRATIONS=1` to migrate first).

### CI deploy

`.github/workflows/deploy-edge.yml` (manual `workflow_dispatch`) builds the WASM,
optionally applies migrations (libSQL when the `LIBSQL_URL` secret is set, else
D1), syncs the non-empty `FP_SALT_SECRET` / `FP_ADMIN_KEY` / `FP_API_KEY` /
`LIBSQL_URL` / `LIBSQL_AUTH_TOKEN` GitHub secrets to the Worker, then deploys.
It needs the `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID` repository secrets.

### Smoke test

`scripts/verify-deploy.ts` exercises the public contract against a running
Worker — health, challenge, identify → match, the 400/401 rejects (and that a
400 does not consume the nonce), events, check-in and erasure:

```bash
BASE=https://<worker-origin> FP_API_KEY=… FP_ADMIN_KEY=… bun scripts/verify-deploy.ts
```

`BASE` defaults to the `cdlab.workers.dev` deployment; without `FP_API_KEY` the
events/check-in checks are skipped, without `FP_ADMIN_KEY` the erasure checks.
