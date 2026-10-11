# @cdlab/fingerprintd-edge

Cloudflare Worker deployment of the fingerprintd challenge/identify flow:
a **TypeScript host** that owns I/O and routing, calling **Rust compiled to WASM**
(`crates/fp-wasm` → `crates/fp-core`) for the pure compute. It is the second
deployment target for the same engine as the native Axum server
(`crates/fingerprintd`) — a client works against **either** unchanged.

## Status — integrated + parity-verified against the native server

The request surface, the WASM engine, the externalized state, **and** a
cross-stack parity proof now run:

| Concern | Status | Notes |
| --- | --- | --- |
| Router `/health` `/challenge` `/identify` | ✅ real, byte-compatible with the server | |
| WASM compute (blocking keys, scoring, probe, signing) | ✅ real (`FpEngine`) | |
| One-time nonce | ✅ Durable Object (`NonceDurableObject`) | atomic check-and-burn + TTL alarm |
| Fingerprint library + blocking index | ✅ D1 (`templates`, `blocking_index`) | recall → score → drift write-back |
| Worker Secrets (salt / probe / signing) | ✅ read at runtime; local via `.dev.vars` | never embedded — see "Deploy" |
| Parity (Worker == native fp-core) | ✅ shared-fixture suite, both stacks | see "Parity" below |
| `value_frequency` (global `u_i`) | 🟡 schema provisioned; block-local `u_i` used | bounded divergence — see "Parity" |
| Passive signals (JA4/IP) | 🟡 neutral degraded default | matches the server's default (no trusted edge) |

The orchestration in `src/app.ts` (a Hono app) — derive blocking keys → recall
candidates → score → persist per the verdict — is the **real edge host flow**,
mirroring `fingerprintd_core`'s `identify`. `POST /identify` bodies are validated with Zod.
State is injected (`NonceStore` / `CandidateSource`), so the app is unchanged
whether it runs on the Durable Object + D1 (Worker) or the in-isolate stubs (Node
unit tests, or a bare `wrangler dev` with no bindings).

## Parity (Worker == native)

The edge Worker and the native Axum server (`crates/fingerprintd`) are two
deployments of ONE engine (`crates/fp-core`, exposed to JS via `crates/fp-wasm`).
A single committed fixture, `tests/fixtures/parity.json`, drives **both** stacks
and asserts the SAME `expect` block field-by-field:

- `crates/fingerprintd/tests/parity.rs` runs the vectors through the native
  `FuzzyStore::identify`.
- `tests/parity.workers.test.ts` runs the SAME vectors through the full edge
  stack — WASM engine + nonce Durable Object + D1 — in real workerd/miniflare.

Both are seeded from the fixture's `salt_secret` (native production uses a random
per-process salt; the edge pins it as a Worker Secret so keys are stable across
isolates), and both assert `visitorId`, `decision`, `is_new_device`,
`collision_risk`, and `confidence` (to a `1e-12` tolerance). Regenerate the
`expect` values with `cargo test -p fingerprintd --test parity -- --nocapture`,
which prints the outcomes the native engine computed.

Two keyed-hash vectors additionally pin the secret-gated paths byte-for-byte
across stacks — the probe key (`ad83…37d0`) and the signing key (`11e7…1792`),
each asserted in a native `fp-wasm` test and its JS counterpart.

### Confidence exactness boundary (the block-local `u_i`)

`confidence` matches **exactly** whenever a probe's recalled candidate block is
the whole stored population (a single device, or a set that all recall together)
— which the parity fixtures are built to hold. The one place the two stacks can
diverge is the Fellegi–Sunter rarity term `u_i`: the native scorer reads a
**global** `value_hash → count` frequency table, while the WASM `score`
estimates `u_i` over just the recalled block. They coincide until the store holds
a device that a scoring probe does NOT recall (a heterogeneous population with
partial recall), after which `u_i` — and only `confidence`, never the identity or
decision — can differ slightly. Closing that gap means populating `value_frequency`
(migration `0001` provisions it) via a WASM-exposed salted hasher and feeding the
global snapshot into `score`; it is a pure addition, not a migration, and remains
a deliberate future refinement. Identity and decision parity hold regardless.

The template-merge edge case is likewise bounded: drift merges raw components per
key (present overwrites, absent retained); native additionally drops null/invalid
values from its stored form, but the WASM re-derivation drops them again at score
time, so the **scoring input matches** even where the stored blob differs.

## Layout

```
src/
  index.ts                Worker entry — imports the .wasm, builds engine + state
                          per isolate, re-exports the nonce + velocity DOs
  app.ts                  composition root: Hono app (dependency-injected,
                          unit-testable) wiring CORS + the aggregate router
  routes/index.ts         route aggregation — bare GET /health + mounts the two
                          domain sub-routers
  config/index.ts         resolve typed config + state bindings from env (schema/loader)
  config/risk-config.ts   per-action check-in weights / thresholds / bands (defaultProfiles)
  db/schema.ts            Drizzle schema barrel (re-exports both domains)
  db/fingerprint.schema.ts  templates / blocking_index / value_frequency
  db/checkin.schema.ts    checkin_events
  db/client.ts            Drizzle D1 client factory
  drizzle/                drizzle-kit-generated D1 migrations (one set for the whole DB)
  modules/fingerprint/
    engine.ts             typed wrapper around the FpEngine WASM class + one-time init
    fingerprint-store-d1.ts  D1 recall + drift persistence via Drizzle (templates + index)
    fingerprint.routes.ts    GET /challenge, POST /identify (Zod), DELETE /visitor/:id
    index.ts              module barrel (public surface)
  modules/checkin/
    checkin-state.ts      CheckinStore contract + empty (unbound) fallback
    checkin-store-d1.ts   D1 append + windowed account/device/IP/time aggregates
    risk-engine.ts        pure check-in risk scoring (assess -> verdict)
    checkin.routes.ts     POST /checkin/assess (Zod)
    index.ts              module barrel (public surface)
  lib/types.ts            wire types, kept in sync with the server + browser SDK
  lib/signature.ts        response-signature header names
  lib/asn-ip-risk.ts      edge-only ASN → ip_risk band classifier
  lib/state.ts            NonceStore / CandidateSource contracts + in-isolate stubs
  lib/do/nonce-do.ts      NonceDurableObject (atomic burn) + DurableNonceStore adapter
  lib/do/velocity-do.ts   VelocityDurableObject (hot counters; not on the MVP assess path)
drizzle.config.ts         drizzle-kit config (schema -> src/db/schema.ts, out -> ./drizzle)
wasm/                     vendored `wasm-pack --target web` build of crates/fp-wasm
tests/
  app.test.ts             Node: Hono app contract + secret-gated paths over the WASM
  state.workers.test.ts   miniflare: nonce DO + D1 recall/drift + e2e
  parity.workers.test.ts  miniflare: cross-stack parity vs the native reference
  fixtures/parity.json    shared parity vectors (also driven by crates/fingerprintd)
```

## Configuration

With **no** environment set the Worker mirrors a default `fingerprintd`: probe
enforcement off, response signing off, timestamp window off, 30s nonce TTL. All
secrets are read at runtime — never embedded.

| Binding | Role | Default |
| --- | --- | --- |
| `FP_SALT_SECRET` (secret) | seeds the deterministic salt + MinHash family | dev placeholder |
| `FP_PROBE_KEY` (secret) | nonce-probe key; unset ⇒ probe check off | off |
| `FP_SIGNING_KEY` (secret) | response-signing key; unset ⇒ signing off | off |
| `FP_ENFORCE_TS_WINDOW` (var) | `"1"`/`"true"` enables the timestamp window | off |
| `FP_TS_SKEW_SECS` (var) | allowed clock skew when the window is on | 30 |
| `FP_NONCE_TTL_SECS` (var) | nonce lifetime, advertised as `expires_in` | 30 |
| `FP_TRUST_EDGE_HEADERS` (var) | trust edge-injected passive-signal headers | off |
| `FP_INTEGRITY_PENALTY_ENABLED` (var) | let a `noise` client-integrity verdict lower confidence (the band is always surfaced) | off |
| `FP_CORS_ORIGINS` (var) | comma-separated browser CORS origins (`*` = any); unset ⇒ CORS off | off |
| `NONCE` (Durable Object) | one-time nonce store; unbound ⇒ in-isolate stub | — |
| `DB` (D1) | single database — fingerprint library + blocking index + check-in event log; unbound ⇒ empty stub | — |
| `VELOCITY` (Durable Object) | hot velocity counters (check-in); not on the MVP assess path | — |
| `CHECKIN_RETENTION_SECS` (var) | purge check-in events older than this; `0` ⇒ off | 0 |

The three `FP_*` **secrets** are read at runtime and never embedded in the
artifact. Provide them per environment:

- **Local (`wrangler dev`):** copy `.dev.vars.example` → `.dev.vars` (gitignored)
  and fill in values. `wrangler dev` loads them into the same `env.FP_*` bindings.
- **Remote:** set each with `wrangler secret put FP_SALT_SECRET` (etc.) — never
  commit them. `[vars]` in `wrangler.jsonc` are for the non-secret flags only.

The `NONCE` / `DB` bindings are wired in `wrangler.jsonc`; a bare `wrangler dev`
without them falls back to the stubs (single-isolate nonce, every probe new).

`FP_SALT_SECRET` MUST be stable and identical across every isolate — it seeds the
deterministic salt + MinHash family, so rotating it re-partitions the blocking
index and orphans every stored template (all devices re-mint). Treat it as a
long-lived deployment identity, not a routinely rotated credential.

### Edge-only IP reputation (Cloudflare ASN)

The surfaced `signals.ip_risk` band fuses one edge-only source on top of the
shared WASM verdict: Cloudflare's per-request ASN enrichment (`request.cf.asn` /
`asOrganization`). A curated hosting/datacenter/VPN ASN set (`src/lib/asn-ip-risk.ts`,
illustrative — swap for a real reputation feed) classifies the connecting
network, and the two bands combine as `max(wasmBand, asnBand)` with `high` at the
top: the ASN can only **raise** the band to `high`, never lower a `medium`/`high`
WASM band. This catches a datacenter IP that sits outside fp-core's coarse
`StaticIpIntel` CIDR table but belongs to a known hosting ASN. It is read **only**
behind `FP_TRUST_EDGE_HEADERS` (same trust boundary as JA4/IP) — an untrusted
origin never touches `cf` — and it is TS-only in `apps/edge`: `ip_risk` is a
surfaced signal, not an identity input, so the cross-stack parity bytes are
unchanged.

## Check-in risk (`POST /checkin/assess`)

A config-gated layer on the same Worker that turns a fingerprintd verdict into a
check-in anti-farming decision. It does **not** proxy `/identify` — the caller
obtains the `IdentifyResponse` first and passes it through:

```
Req: { accountId, action: "daily_checkin", identify: <IdentifyResponse> }
     ip / ts are edge-observed (cf-connecting-ip + server clock), never in the body
200: { decision: "allow"|"challenge"|"deny",
       verdict:  "human"|"suspicious"|"farming",
       risk: 0.0..1.0, reasons: [{ code, detail }], visitorId }
400: unknown top-level field (strict body) / bad shape
```

It records the event in the check-in event log (the shared `DB`), derives
windowed account/device/IP/time aggregates (device fan-out, account device count,
new-device rate, IP sharing, timing regularity), and scores them with
fingerprintd's hard signals through the pure `assess()` engine
(`modules/checkin/risk-engine.ts`; weights/thresholds in `config/risk-config.ts`).
Unbound (`DB` absent) it falls back to zero aggregates, so every request
scores on the fingerprintd signals alone. The [playground](../web/README.md)
demos the full identify → assess flow.

## Develop & verify

```bash
bun install
bun run lint        # biome check .
bun run typecheck   # tsc --noEmit
bun run test        # vitest run — two projects:
                    #   node    — router contract over the vendored WASM
                    #   workers — state layer (nonce DO + D1) + cross-stack parity
                    #             in real miniflare
bun run deploy:dry  # wrangler deploy --dry-run (bundles the Worker + .wasm + bindings)
bun run dev         # wrangler dev --local (loads .dev.vars; local workerd, no account)
```

For a full cross-stack check, pair the Worker `test` with the native reference so
both halves of the parity fixture are exercised:

```bash
bun run test                                       # edge half (workers project)
cargo test -p fingerprintd --test parity           # native half (from repo root)
```

The `workers` test project (`*.workers.test.ts`) runs under
`@cloudflare/vitest-pool-workers`, so the Durable Object burn, the D1
recall/persist round-trips, **and** the parity vectors execute against the actual
workerd runtime with the `wrangler.jsonc` bindings live — a fresh local D1 with
the `drizzle/` migrations applied. No Cloudflare account is needed; miniflare
provides D1/DO locally.

Apply migrations to a real (or persistent local) D1 with:

```bash
wrangler d1 migrations apply fingerprintd --local   # local sqlite
wrangler d1 migrations apply fingerprintd            # remote (needs an account)
```

### Rebuilding the vendored WASM

`wasm/` is a committed `wasm-pack` artifact. Rebuild it after changing
`crates/fp-core` or `crates/fp-wasm`:

```bash
# `--out-dir` is relative to the CRATE dir — use an absolute path so it lands in
# the vendor dir, not `crates/fp-wasm/apps/edge/wasm`.
wasm-pack build --target web --out-dir "$PWD/apps/edge/wasm" crates/fp-wasm
rm -f apps/edge/wasm/.gitignore apps/edge/wasm/package.json  # keep only the glue + .wasm
```

The server-side `FpEngine` takes its keys at runtime, so no build-time key
injection is needed here (unlike the browser probe in `packages/client`).

## Deploy

### Local (no account)

```bash
cp .dev.vars.example .dev.vars                       # then edit in real dev values
wrangler d1 migrations apply fingerprintd --local    # seed the local sqlite schema
bun run dev                                          # wrangler dev --local
```

`wrangler dev --local` runs the full stack — Worker + WASM + Durable Object + D1 —
in local workerd/miniflare, loading `.dev.vars` as the secrets. No account needed.

### Real Cloudflare (account holder)

SQLite-backed Durable Objects + D1 are on the Workers free plan, so a test
deploy needs no paid plan.

1. **Create D1** and copy the id it prints into `wrangler.jsonc`
   (`d1_databases[0].database_id` — already set to a real D1; replace it for a
   fresh account):

   ```bash
   wrangler d1 create fingerprintd
   ```

2. **Apply migrations** to the remote database (the drizzle-kit output in
   `apps/edge/drizzle/`):

   ```bash
   bun run cf:remotedb   # wrangler d1 migrations apply fingerprintd --remote
   ```

3. **Set the secrets** (prompted for each value; nothing is committed):

   ```bash
   wrangler secret put FP_SALT_SECRET     # required — stable, high-entropy
   wrangler secret put FP_PROBE_KEY       # optional — enables the nonce probe
   wrangler secret put FP_SIGNING_KEY     # optional — enables response signing
   ```

   If `FP_PROBE_KEY` is set, rebuild the vendored WASM (`apps/edge/wasm` +
   `packages/client/wasm`) with the SAME key
   (`FP_PROBE_KEY=… wasm-pack build --target web crates/fp-wasm`, then re-vendor)
   so the probe verifies — the committed WASM is dev-keyed.

4. **Deploy.** The Durable Object migration in `wrangler.jsonc`
   (`migrations[].new_sqlite_classes`) provisions the nonce class on first publish:

   ```bash
   bun run deploy   # wrangler deploy --minify
   ```

Validate the config offline first with `bun run deploy:dry` (bundles the Worker +
`.wasm` and resolves the bindings without publishing).

### CI deploy

`.github/workflows/deploy-edge.yml` runs the same flow from the Actions tab
(manual `workflow_dispatch`, with an optional "apply remote D1 migrations"
toggle). It needs the `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID` repository
secrets and syncs the optional `FP_SALT_SECRET` / `FP_PROBE_KEY` /
`FP_SIGNING_KEY` Worker secrets from matching GitHub secrets (unset ones skipped).

## Environment limit

There is **no Cloudflare account** in this environment and Durable Objects + D1
are paid, so only **local** execution is wired and verified here: `wrangler dev
--local`, `wrangler deploy --dry-run`, and the miniflare-backed `workers` test
project (state + parity). The Durable Object and D1 bindings are fully declared
in `wrangler.jsonc` and the `database_id` is a local placeholder; the real remote
deploy above — creating the D1, applying migrations, setting the secrets, and
`wrangler deploy` — is deferred to a human with an account.
