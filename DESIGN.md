# fingerprintd — Design

**English** · [中文](DESIGN.zh-CN.md)

> Server-side device fingerprinting for **anti-fraud / anti-automation**. Judgment
> is server-authoritative: the client only collects; the server issues a one-time
> challenge, fuzzy-matches, fuses passive signals, and records a `visitor_id` +
> `confidence` that the customer backend fetches server-to-server by
> `request_id`.

This is the authoritative design spec; the implementation follows it. It has two
parts — **[Architecture](#architecture)** (the challenge protocol, trust
boundary, and HTTP contract) and **[Fuzzy matching](#fuzzy-matching)** (the
two-stage engine that turns collected components into a `visitor_id`). Section
numbers are stable anchors that source doc-comments cite as `architecture §N` /
`fuzzy-matching §N`.

## Contents

**Architecture**

1. [Background](#1-background)
2. [Goals and threat model](#2-goals-and-threat-model)
3. [Success metrics](#3-success-metrics)
4. [One-time challenge + server-side fusion](#4-architecture-one-time-challenge--server-side-fusion)
5. [HTTP interface (Contract v1)](#5-http-interface-contract-v1)
6. [Data model](#6-data-model)
7. [Privacy and compliance](#7-privacy-and-compliance)
8. [Deployment targets](#8-deployment-targets)
9. [Defense-in-depth controls](#9-defense-in-depth-controls)

**Fuzzy matching**

1. [Problem statement](#1-problem-statement)
2. [Component classification](#2-component-classification-the-closed-schema)
3. [Storage representation](#3-storage-representation-the-salted-stored-form)
4. [Stage one: candidate generation](#4-stage-one-candidate-generation-blocking)
5. [Stage two: probabilistic scoring](#5-stage-two-probabilistic-scoring-fellegisunter)
6. [Confidence output](#6-confidence-output)
7. [Drift and poisoning defense](#7-drift-template-adaptation-and-poisoning-defense)
8. [Edge cases](#8-edge-cases)
9. [Parameter estimation and cold start](#9-parameter-estimation-and-cold-start)
10. [Offline evaluation](#10-offline-evaluation)
11. [Data structures and performance](#11-data-structures-and-performance)
12. [Open questions](#12-open-questions)

---

# Architecture

## 1. Background

Pure client-side fingerprinting (as in the open-source FingerprintJS) has
structural flaws:

- **Forgeable** — the id is computed on the client from client-controlled values.
- **No replay protection** — a static id is captured once and resubmitted freely.
- **Imprecise** — an exact client hash *avalanches*: any one component changing
  makes the same device look new, while same-model devices collide.
- **Weak against adversaries** — privacy browsers / anti-fingerprint extensions
  actively add noise.

| Problem | Root cause | Direction |
|---|---|---|
| Forgeable | trusts client-reported values | cross-check with **passive signals the client cannot self-report** |
| No replay protection | id is static | **one-time nonce** + a mandatory timestamp window |
| Imprecise | exact client hash + avalanche | **server-side fuzzy matching + multi-source fusion** |

Judgment moves entirely server-side; the client only collects — the path
FingerprintJS Pro / DataDome / Akamai all take.

---

## 2. Goals and threat model

At high-risk actions (login, signup, checkout, coupon redemption) each request
yields a stable `visitor_id` and a `confidence` for the risk engine: is this a new
device, is it linked to a known device, and do the self-reported browser features
agree with the network layer (bot detection)?

### Threat model

| Adversary | Capability | System goal |
|---|---|---|
| **Script** | curl / scripts, no JS | must reject (no nonce / no collection / TLS mismatch) |
| **Automation** | headless browser, runs JS, forges UA/JS values | catch via passive signals + consistency |
| **Advanced** | curl-impersonate / uTLS forging JA3/JA4 + full stack, anti-detect browsers | **lower confidence + cross-verify**, not absolute blocking |

No absolute defense is claimed. An advanced adversary can forge any single
signal; the value is in **raising forgery cost** and **multi-signal consistency
detection**, not in being unbeatable.

### Goals

- **G1** — the server issues a one-time nonce and enforces a timestamp window; a captured request cannot be replayed.
- **G2** — fuse client components + passive network signals into `visitor_id` + `confidence`.
- **G3** — fuzzy matching replaces the exact hash, removing avalanche; stability over uniqueness.
- **G4** — P99 decision latency ≤ 50ms (excluding client collection); ≥ 2k RPS per instance.
- **G5** — the authoritative result never depends on the browser: the customer backend reads it server-to-server by `request_id`.

### Non-goals

- No full client SDK UI/telemetry framework — only a minimal collect + submit SDK.
- No unbreakable client tamper-proofing: every client-reported value (components, `user_agent`, `botd`, `integrity`) is hookable and is treated as evidence, never as a lock.
- No cross-site tracking / ad attribution.
- No device-association graph (account ↔ device clustering) in the core; the edge check-in assessment (§8) is a reference consumer layered on top.

---

## 3. Success metrics

| Metric | Definition | Target |
|---|---|---|
| Stability rate | same device re-resolved to one `visitor_id` across visits over two weeks | ≥ 95% |
| Collision rate | distinct devices resolved to one `visitor_id` | ≤ 1% |
| Script/automation detection | scripted / forged requests flagged low-confidence | ≥ 90% |
| Decision P99 | submit → `visitor_id` returned | ≤ 50ms |
| Replay rejection | expired / reused nonce, or `ts` outside the window, refused | 100% |

> The stability/collision targets are gated behind an **offline evaluation against
> a labelled corpus** — see [fuzzy-matching §10](#10-offline-evaluation). They must
> not be reported from synthetic fixtures.

---

## 4. Architecture: one-time challenge + server-side fusion

### 4.1 Freshness vs. identity (the core split)

Matching requires that the same device produces the **same** stable output each
time. So evidence is split into two lanes that never mix:

- **`components`** — the closed component schema
  ([fuzzy-matching §2](#2-component-classification-the-closed-schema)), no nonce
  mixed in. Converted to the salted stored form, it drives identity matching.
- **freshness** — the server-issued `nonce` and the client `ts`. They prove the
  request is live and **never** participate in identity matching.

**Replay protection** rests on two checks, both always enforced:

1. **One-time nonce.** `GET /challenge` mints a random nonce with a short TTL
   (`FP_NONCE_TTL_SECS`, default 30 s, advertised as `expires_in`). `POST
   /identify` consumes it: the first consumption of a live nonce succeeds and
   burns it; an unknown, expired, or reused nonce is rejected with `401`.
2. **Timestamp window.** `ts` (Unix milliseconds) is required and must lie within
   `±FP_TS_SKEW_SECS` (default 30 s) of server time, else `401`. It bounds how
   long a captured payload stays usable on top of the nonce.

The request body is validated before the nonce is consumed, so a malformed
request (`400` / `415`) never burns a nonce. The nonce is checked before the
timestamp, so a request outside the window still burns its nonce.

### 4.2 Passive signals and the trust boundary

TLS JA3/JA4 is **not** a high-entropy per-device identifier and **not**
unforgeable:

- Low entropy — millions of same-model Chrome instances share one JA4, so it
  cannot be a `visitor_id` source.
- Forgeable — curl-impersonate / uTLS can construct any ClientHello.

Its real value is **consistency cross-checking**, weighted into `confidence`, never
into `visitor_id`:

- **UA ↔ TLS.** The request's top-level `user_agent` is classified (browser /
  automation / unknown) and compared with the stack the JA4 reveals (a curated
  set of real-browser JA4 shapes plus cipher/extension-count floors). A
  contradiction in either direction is a `Mismatch` (confidence −0.5,
  `ua_tls_consistent: false`); agreement is `Consistent` (+0.05); a missing or
  unclassifiable JA4 is `Degraded` — neutral, never a penalty, and
  `ua_tls_consistent` stays `true`.
- **IP reputation** — a coarse band (`low` / `medium` / `high`) from the client IP,
  surfaced as `signals.ip_risk`; it does not move `confidence`. The built-in
  classifier is a small static datacenter CIDR table (an illustrative stand-in
  for a real reputation feed); private, loopback and link-local addresses read
  `low`.

**Deployment constraint (hard).** Connection-layer signals can only be captured by
the party terminating the client's TLS connection, so the edge in front of the
service must supply them. Each host reads them from a source the client cannot
write:

- **Native server.** The real client IP comes from `cf-connecting-ip` and the JA4
  from `cf-bot-management-ja4`, both injected by Cloudflare. They are read **only**
  when `trust_edge_headers` (`FP_TRUST_EDGE_HEADERS`) is `true`; the default is
  `false` (fail-closed) and every client-supplied copy is ignored, so passive
  signals degrade to neutral and IP velocity is not computed. Enable it only when
  the origin sits behind Cloudflare and an origin IP allowlist rejects direct
  connections — the setting is topology-dependent, and enabling it on a
  directly-reachable origin lets a client inject a browser-looking JA4.
- **Edge Worker.** The JA4 is Cloudflare's own enrichment,
  `request.cf.botManagement.ja4`, and the client IP is `cf-connecting-ip`, set by
  Cloudflare in front of the Worker; no request header can supply the JA4. Without
  Bot Management (or off Cloudflare) the JA4 is absent and the verdict degrades.
  The edge additionally classifies `request.cf.asn` / `asOrganization` against a
  curated hosting/datacenter/VPN ASN set; a listed ASN raises `ip_risk` to `high`
  and never lowers it.

### 4.3 Fuzzy matching and candidate generation

Matching is **not** a hash lookup and cannot linearly scan the whole library. Two
stages: (1) blocking / LSH recall compresses the library to a bounded candidate
set; (2) weighted probabilistic scoring (Fellegi–Sunter) ranks them and decides.
Full spec: the [Fuzzy matching](#fuzzy-matching) part below.

### 4.4 Client collection: pure-TypeScript SDK over FingerprintJS / BotD

The client only collects; judgment is server-side (§4). The SDK
([`packages/client`](packages/client/README.md), npm `@cdlab/fingerprintd`) is
pure TypeScript and reuses existing MIT libraries:

| Library | License | How reused | Boundary |
|---|---|---|---|
| **FingerprintJS** (OSS) | MIT | npm dependency; its raw `components` are adapted to the closed schema | its client-side `visitorId` hash is discarded |
| **BotD** (OSS) | MIT | npm dependency; its verdict is sent as `botd: { bot, kind? }` | client-reported, surfaced only |

One `collect()` produces `{ components, user_agent?, botd?, integrity? }`:

- **`components`** — the adapter unwraps FingerprintJS's `{value, duration}`
  wrappers, maps its component names onto the closed schema keys
  ([fuzzy-matching §2](#2-component-classification-the-closed-schema)), normalizes
  each value to its kind (object/array category values are digested), and drops
  every unmapped component. It emits only schema keys.
- **`user_agent`** — the browser UA as a top-level field. It is not a component;
  the server uses it only for the UA↔TLS cross-check (§4.2) and the persona check
  (§5).
- **`botd`** — the BotD verdict, surfaced as `signals.automation`
  (`detected` / `not_detected` / `unknown`); it never moves `confidence`, the
  decision, or the `visitor_id`.
- **`integrity`** — four known-answer integrity probes (`canvas`, `webgl`,
  `audio`, `rect`), see `client_integrity` in §5.

`run()` fetches the challenge, collects, stamps `ts` right before the POST, and
submits. The browser-side result is display-only (§5, *Trust chain*).

---

## 5. HTTP interface (Contract v1)

Both deployment targets (§8) serve the same contract. All JSON is `snake_case`;
every error is a bare status with an empty body. Request bodies are closed at
every level: an unknown key (top level, inside `components`, `botd`, or
`integrity`), a wrong type, a missing required field, or malformed JSON is `400`;
a non-JSON content type is `415`.

### GET /challenge

```
200: {
  nonce: string,      // one-time, server-issued
  expires_in: number  // seconds (FP_NONCE_TTL_SECS, default 30)
}
```

### POST /identify

```
Req: {
  nonce: string,                // from GET /challenge, single use
  ts: number,                   // client Unix ms, required, within ±FP_TS_SKEW_SECS
  components: { ... },          // closed schema keys only (fuzzy-matching §2)
  user_agent?: string,          // client-reported UA, top-level
  botd?: { bot: boolean, kind?: string },
  integrity?: {                 // each key optional
    canvas?: "ok" | "noise" | "unavailable",
    webgl?: ..., audio?: ..., rect?: ...
  }
}
200: {
  request_id: string,           // random 128-bit, 32 lowercase hex
  visitor_id: string,           // random 128-bit, 32 lowercase hex
  confidence: 0.0..1.0,         // DECISION confidence, not identity trust — see §6
  decision: "match" | "review" | "new_device",
  is_new_device: boolean,
  collision_risk: boolean,
  signals: {                    // for the risk engine; raw passive signals are never echoed
    ua_tls_consistent: boolean,
    ip_risk: "low" | "medium" | "high",
    client_integrity: "ok" | "noise" | "unavailable",
    persona_coherence: "consistent" | "mismatch" | "unknown",
    new_device_velocity: "low" | "medium" | "high",
    automation: "detected" | "not_detected" | "unknown",
    template_jump: boolean
  }
}
400: unknown key / wrong type / malformed JSON
401: unknown, expired or reused nonce, or ts outside the window
```

Passive signals (JA4/IP) come from the connection (§4.2) and are **never**
accepted from the body. None of the signals moves the `visitor_id` or the
decision.

**`visitor_id`.** A random 128-bit id, 32 lowercase hex characters, minted by the
host when the verdict is `new_device` (native: OS RNG; edge:
`crypto.getRandomValues`). It is never derived from the components. A minted id
is re-drawn if it names a live or an erased visitor, so an erased visitor never
gets its id back. `request_id` is minted the same way for every successful
identify.

**`new_device_velocity`** is an IP-keyed **cross-session** signal. When the
verdict is `new_device` and a trusted client IP is known (§4.2), the minted
`visitor_id` is recorded against that IP and the number of **distinct**
`visitor_id`s minted for it within a trailing 1-hour window is banded: `medium`
at ≥ 5, `high` at ≥ 20 (tuning placeholders). A `high` band subtracts 0.3 from
`confidence` on both stacks; the id and decision are unchanged. A match, a
review, or a request without a trusted client IP reads `low`. This catches the
fresh-seed-per-launch farm that no single request reveals.

**`client_integrity`** fuses the SDK's four **known-answer integrity probes**: the
collector asks the browser questions an unmodified Chromium answers exactly (a
lossless canvas `toDataURL` → `getImageData` round-trip of opaque pixels, a flat
WebGL clear, a `ConstantSourceNode` rendered offline, a `getBoundingClientRect` at
1/64-px-representable offsets) and reports `ok` / `noise` / `unavailable` per
probe. A fingerprint-noising (anti-detect) browser answers them wrongly. The
verdicts ride top-level in the request — never inside `components` — so they
cannot enter the `visitor_id`; any `noise` wins, else any `ok`, else
`unavailable` (absent field or missing APIs — always neutral). The band is
**surfaced-only by default**: legitimate privacy tooling (Brave farbling, canvas
blockers) trips the same probes, so the `noise` downgrade (−0.3) is opt-in
(`integrity_penalty_enabled` / `FP_INTEGRITY_PENALTY_ENABLED`).

**`persona_coherence`** cross-checks the UA-claimed OS family (from the top-level
`user_agent`) against the collected `fonts` set: a Windows (`Windows NT`) or macOS
(`Macintosh`) UA whose font set contains **none** of that OS's core fonts (a tiny
curated list drawn from what FingerprintJS probes — Calibri, Segoe UI Light, MS UI
Gothic, Marlett, Microsoft Uighur / Helvetica Neue, Menlo, Gill Sans) reads
`mismatch` — a borrowed persona, e.g. a cloaking browser presenting Windows from a
Linux container. Other OS families, a missing `user_agent`, or a missing `fonts`
component read `unknown`. Surfaced-only. Honest limit: an operator who installs
the Windows font set (or a binary that spoofs font metrics) passes it; it raises
cost, nothing more.

**`automation`** is the client-side BotD verdict (`bot: true` ⇒ `detected`,
`false` ⇒ `not_detected`, absent ⇒ `unknown`). Surfaced-only.

**`template_jump`** is `true` when the best candidate cleared the match threshold
but the probe changed too many high-stability components of its template; the
verdict is downgraded to `review` and the template is not updated
([fuzzy-matching §7](#7-drift-template-adaptation-and-poisoning-defense)).

### GET /events/{request_id}

Server-to-server read of a past identify result.

```
Authorization: Bearer <FP_API_KEY>
200: the exact /identify response body stored under request_id
401: missing or wrong bearer
404: FP_API_KEY unset (route disabled), or unknown / expired request_id
```

When `FP_API_KEY` is set, every successful `/identify` stores its response body
byte-for-byte under its `request_id` for `FP_EVENT_TTL_SECS` (default 3600 s);
with no key nothing is stored. The native store is in memory and bounded by
`FP_EVENT_MAX` (default 100 000; past it the oldest event is evicted); the edge
stores events in its `events` table.

**Trust chain.** The `/identify` response the browser receives is
**display-only**: anything running in the page can rewrite it. The browser
forwards only the `request_id` to the customer backend, which fetches the
authoritative result server-to-server via `GET /events/{request_id}` (or, on the
edge, passes the `request_id` to `POST /checkin/assess`). `FP_API_KEY` is a
server-side secret and must never ship to the browser.

### DELETE /visitor/{id}

GDPR right-to-be-forgotten (§7).

```
Authorization: Bearer <FP_ADMIN_KEY>
204: erased (idempotent — also 204 for an unknown id, so existence never leaks)
401: missing or wrong bearer
404: FP_ADMIN_KEY unset (route disabled)
```

Erasure removes the visitor's template, its blocking-index memberships, and every
stored identify event of that visitor (`GET /events/{request_id}` then answers `404`
for them), and tombstones the id so it is never minted or written again (native:
an in-memory tombstone set of up to 100 000 ids; edge: the `erased_visitors`
table, trimmed to the newest 100 000).

### POST /checkin/assess (edge only)

A reference risk consumer for daily check-in anti-farming, served only by the edge
Worker.

```
Authorization: Bearer <FP_API_KEY>
Req: { account_id: string, action: "daily_checkin", request_id: string }
200: {
  decision: "allow" | "challenge" | "deny",
  verdict: "human" | "suspicious" | "farming",
  risk: number,
  reasons: [{ code: string, detail: string }],
  visitor_id: string
}
401: missing or wrong bearer
404: FP_API_KEY unset (route disabled), or unknown / expired request_id
409: the request_id was already assessed for a different account_id
```

The device id, signals and client IP all come from the stored identify event
(server-side lookup), never from the caller. The check-in is recorded once per
`request_id`; a same-account retry is idempotent (`200`); a `409` scores and
records nothing.

### Load limits and status summary

The native server runs every route under a global concurrency cap
(`FP_MAX_CONCURRENT_REQUESTS`, default 1024; further requests wait for a slot)
and a per-request deadline (`FP_REQUEST_TIMEOUT_SECS`, default 10 s, including
time spent waiting) answered with `408`. The edge applies per-IP rate limits
keyed on `cf-connecting-ip`: `RATE_LIMIT` (60 / 60 s) on `POST /identify` and
`POST /checkin/assess`, `CHALLENGE_RATE_LIMIT` (120 / 60 s) on `GET /challenge`,
answered with `429`.

| Status | When |
|---|---|
| `400` | unknown key or wrongly-typed value anywhere in the body; malformed JSON |
| `401` | `/identify`: bad, expired or reused nonce, or `ts` outside the window. Key-gated routes: missing or wrong bearer |
| `404` | `/events`, `/checkin/assess`: `FP_API_KEY` unset, or unknown/expired `request_id`. `/visitor`: `FP_ADMIN_KEY` unset |
| `408` | native: request not answered within `FP_REQUEST_TIMEOUT_SECS` |
| `409` | edge `/checkin/assess`: `request_id` already assessed for a different `account_id` |
| `415` | `POST` body not JSON |
| `429` | edge: per-IP rate limit exceeded |

---

## 6. Data model

Hosts persist only the salted stored form of a device, never raw component values
(§7, [fuzzy-matching §3](#3-storage-representation-the-salted-stored-form)).

**Native server** — everything is in memory, process-local, and bounded:

- **nonces** — live nonces with their expiry, single-use, reaped on expiry; at
  most `FP_NONCE_MAX_LIVE` (default 1 000 000), past which the oldest is evicted.
- **fuzzy store** — the record library (`visitor_id` → current stored template,
  first-observation snapshot, per-component freshness, first/last seen,
  observation count, blocking keys), the blocking index, the per-component
  frequency table (`u_i`), the agreement table (`m_i`), the per-IP velocity
  table, and the erasure tombstones. Bounds: `FP_FUZZY_MAX_RECORDS`,
  `FP_FUZZY_RECORD_TTL_SECS`, `FP_FUZZY_MAX_BLOCK`,
  `FP_FUZZY_MAX_FREQUENCY_VALUES`, `FP_FUZZY_MAX_AGREEMENT_COMPONENTS`
  ([fuzzy-matching §11](#11-data-structures-and-performance)).
- **events** — `request_id` → identify response body, TTL `FP_EVENT_TTL_SECS`,
  cap `FP_EVENT_MAX`, indexed by `visitor_id` for erasure.

**Edge Worker** — two Durable Objects plus one SQL database selected by `DB_TYPE`:
`libsql` (default; `LIBSQL_URL` + optional `LIBSQL_AUTH_TOKEN`) or `d1` (the `DB`
binding):

- `NONCE` Durable Object — one-time nonces (atomic check-and-burn + TTL alarm).
- `VELOCITY` Durable Object — per-IP distinct new-device ids (1-hour window, at
  most 64 live members).
- `templates` — `visitor_id`, the salted stored form (`stored`), `first_seen`,
  `last_seen`, `observation_count`.
- `blocking_index` — `(key, visitor_id)` rows of the inverted index.
- `erased_visitors` — erasure tombstones.
- `events` — `request_id`, `visitor_id`, client `ip`, response `body`,
  `expires_at`.
- `checkin_events` — the append-only check-in log, unique per `request_id`.

**`confidence` semantics.** `confidence` is **decision confidence**, not
identity-trust: a first-ever unseen device resolves as `new_device` with high
decision confidence (the engine is sure it is new). A risk consumer must read
`is_new_device` / `decision` for identity trust and must not treat a high-confidence
`new_device` as a high-trust identity.

---

## 7. Privacy and compliance

Storing derived fingerprints is higher-sensitivity than a pure client scheme, so:

- **Legal basis** — under GDPR/CCPA/PIPL device fingerprints are typically personal
  data; anti-fraud usually rests on legitimate interest, which requires a DPIA
  record.
- **Data minimization** — hosts persist only the salted stored form: category
  values as `SHA-256(salt ‖ value)`, set values as per-element
  `SHA-256(salt ‖ element)`, numeric values (`cpu_cores`, `device_memory`) as
  integers. The salt is per instance — 16 random bytes on the native server, the
  first 16 bytes of `SHA-256(FP_SALT_SECRET)` on the edge
  ([fuzzy-matching §3](#3-storage-representation-the-salted-stored-form)). The
  `user_agent`, `botd` and `integrity` inputs are never persisted; stored events
  hold the identify response (and, on the edge, the client IP).
- **Retention** — native: `FP_RETENTION_SECS` (default `0` = off) runs a
  background sweep purging records by `last_seen`; `FP_FUZZY_RECORD_TTL_SECS`
  evicts lazily on identify. Edge: a daily cron (03:00 UTC) deletes expired events,
  templates past `FP_RETENTION_SECS` (the shipped `wrangler.jsonc` sets 30 days),
  check-in events past `CHECKIN_RETENTION_SECS`, and trims the tombstones. Events
  expire after `FP_EVENT_TTL_SECS` on both.
- **Erasure** — `DELETE /visitor/{id}` (§5) removes the template, index rows and
  events, and tombstones the id. The aggregate frequency table is left untouched:
  it holds value counts with no per-visitor linkage.
- **Strict input** — the closed request schema rejects unmodeled fields with `400`.
- **Purpose limitation** — anti-fraud only; using it for advertising/tracking
  changes the legal basis and is out of scope.
- **Transparency** — disclose device fingerprinting in the privacy policy.

---

## 8. Deployment targets

One engine ([`crates/fp-core`](crates/fp-core), the published `fingerprintd`
crate), two hosts. A client works against either unchanged; a shared parity fixture
(`crates/fingerprintd/tests/fixtures/parity.json`) is asserted on both.

| Concern | Native server (`crates/fingerprintd`, package `fingerprintd-server`, binary `fingerprintd`) | Edge Worker (`apps/edge`, demo) |
|---|---|---|
| Runtime | Axum / Tokio, long-lived process, graceful shutdown on SIGTERM / Ctrl-C | Cloudflare Worker (Hono host, per-request) |
| Nonce store | in memory, single-use + TTL, bounded | `NONCE` Durable Object |
| Fingerprint library | in-memory fuzzy store, bounded/evicting | libSQL (default) or D1: `templates` + `blocking_index` |
| Events | in-memory, TTL + cap | `events` table |
| Compute | native `fingerprintd` | `fingerprintd` compiled to WASM (`crates/fp-wasm`, unpublished) |
| Passive signals | Cloudflare headers behind `trust_edge_headers` (§4.2) | `request.cf` + `cf-connecting-ip`, plus the ASN fuse |
| Configuration | defaults ← `fingerprintd.toml` ← `FP_*` env | Worker vars / secrets (`FP_SALT_SECRET` required) |

The native store is process-local and its salt is random per process: a restart
loses every template and re-mints devices. See [`apps/edge`](apps/edge/README.md)
for the persisted deployment.

**Edge known limitations.**

- **Concurrent first sightings.** There is no per-device lock: two concurrent first
  identifies of one device may each mint a `visitor_id`. (The native store
  re-decides under its write lock, so concurrent first sightings yield one
  visitor.)
- **Cold-start scoring store.** The edge rebuilds the scoring store per request
  from the recalled candidates, so `m_i` stays at its cold-start priors and `u_i`
  is estimated over the recalled block only. Native and edge `confidence` can
  drift apart after many confirmed matches; identity and decision are computed by
  the same engine.
- **Bounded recall.** Recall visits the exact key first, then the rarest keys,
  taking at most 256 visitors per key (most recently seen first) and 1024 in
  total. A very hot block can miss a true match.
- **No first-observation snapshot.** `templates` keeps only the current drifted
  template.

**Downstream consumers.** `visitor_id` + `confidence` + `signals` are inputs *for a
risk engine*, not a verdict on their own — the core holds no account state and no
behavioural history (Non-goals, §2). A caller that needs an allow/challenge/deny
decision layers that on top. The edge ships a reference example, `POST
/checkin/assess` (§5): it joins a stored identify event with windowed
account/device/IP/time aggregates (device fan-out, account device count,
new-device rate, IP sharing, timing regularity) to score daily check-in
anti-farming. The [playground](apps/web/README.md) demos identify → assess.

---

## 9. Defense-in-depth controls

| Control | Setting | Default |
|---|---|---|
| One-time nonce | `FP_NONCE_TTL_SECS` | 30 s |
| Timestamp window (always enforced) | `FP_TS_SKEW_SECS` | ±30 s |
| Trust Cloudflare passive-signal headers (native) | `trust_edge_headers` / `FP_TRUST_EDGE_HEADERS` | `false` (fail-closed) |
| Integrity `noise` confidence penalty | `integrity_penalty_enabled` / `FP_INTEGRITY_PENALTY_ENABLED` | `false` (opt-in; always surfaced) |
| Events API + check-in | `api_key` / `FP_API_KEY` | unset ⇒ `404` |
| Erasure | `admin_key` / `FP_ADMIN_KEY` | unset ⇒ `404` |
| Retention sweep | `retention_secs` / `FP_RETENTION_SECS` | `0` (off); edge config ships 30 days |
| Request deadline (native) | `FP_REQUEST_TIMEOUT_SECS` | 10 s ⇒ `408` |
| Concurrency cap (native) | `FP_MAX_CONCURRENT_REQUESTS` | 1024 |
| Per-IP rate limits (edge) | `RATE_LIMIT` / `CHALLENGE_RATE_LIMIT` | 60 / 60 s, 120 / 60 s ⇒ `429` |
| Bounded stores (native) | `FP_NONCE_MAX_LIVE`, `FP_EVENT_MAX`, `FP_FUZZY_MAX_*` | see §6 |

Key-gated routes are fail-closed: an unset or empty key disables the route, and the
bearer is compared in constant time. Keys are redacted from debug output. The
template-jump guard and review-without-update rule
([fuzzy-matching §7](#7-drift-template-adaptation-and-poisoning-defense)) defend
the library against poisoning. Client-side evidence is depth, never a lock.

---

# Fuzzy matching

> The stage-two matching engine behind
> [architecture §4.3](#43-fuzzy-matching-and-candidate-generation).
> Targets ([architecture §3](#3-success-metrics)): stability ≥ 95%,
> collision ≤ 1%, decision P99 ≤ 50ms, ≥ 2k RPS per instance.

## 1. Problem statement

Input: the component set of one observation, `probe = {c_1, …, c_n}`.
Output: the matched `visitor_id` (same device) or a new-device verdict, plus a
`confidence`.

Three constraints pull against each other:

- **De-avalanche** — one component changing (a browser auto-upgrade, a new font, an
  external monitor) must not mint a new `visitor_id`.
- **Anti-collision** — two distinct devices of the same model + browser version must
  not resolve to one `visitor_id`.
- **High throughput** — a million-record library cannot be linearly scanned per
  request.

Two core decisions:

1. **Two stages** — candidate generation (§4) → probabilistic scoring (§5).
2. **Scoring uses the Fellegi–Sunter (FS) probabilistic record-linkage model** (§5)
   rather than a hand-tuned weighted average — FS's two parameters `m_i / u_i`
   model *stability* and *distinctiveness* separately, aligning naturally with the
   two failure modes above.

---

## 2. Component classification (the closed schema)

Each component is characterized on two orthogonal axes — the source of every weight:

- **Stability** — probability the component is unchanged across visits of the same
  device (→ FS `m_i`; cold-start prior high `0.95`, medium `0.80`, low `0.50`).
- **Distinctiveness** — probability two distinct devices share the value (→ FS `u_i`;
  rarer = lower `u`).

The schema is closed: these 18 keys (`COMPONENT_KEYS` in
`crates/fp-core/src/fuzzy/component.rs`) are the only accepted `components` keys;
any other key is a `400`. A `null` or absent key means "not collected".

| Key | Kind | Stability | `u_i` prior | Notes |
|---|---|---|---|---|
| `webgl` | category | high | 0.05 | GPU vendor/renderer |
| `webgl_extensions` | category | medium | 0.05 | digest of supported extensions |
| `platform` | category | high | 0.3 | `navigator.platform` |
| `timezone` | category | high | 0.2 | IANA name |
| `languages` | category | high | 0.3 | comma-joined |
| `audio` | category | high | 0.05 | audio-stack render fingerprint |
| `canvas` | category | low | 0.02 | flips on driver/browser upgrade; noised per session by privacy / anti-detect browsers |
| `cpu_cores` | numeric | high | 0.3 | |
| `device_memory` | numeric | high | 0.4 | GiB |
| `screen` | category | medium | 0.1 | `"WxH"`, longer side first; an external display changes it |
| `fonts` | set | medium | 0.05 | incremental change → Jaccard / MinHash |
| `plugins` | set | medium | 0.3 | plugin names |
| `font_preferences` | category | medium | 0.1 | |
| `screen_frame` | category | medium | 0.2 | taskbar/dock insets |
| `math` | category | medium | 0.5 | |
| `touch_support` | category | medium | 0.5 | |
| `dom_blockers` | category | medium | 0.5 | content-blocker detection |
| `user_agent_data` | category | medium | 0.05 | UA Client Hints digest |

The `u_i` priors are tuning placeholders (judgement, not measured).

> Key insight: the browser version string is not a component. The UA travels only
> as the top-level `user_agent` (UA↔TLS and persona checks), so browser
> auto-upgrades cannot avalanche identity through it; components that do move
> across upgrades (`canvas`, the medium tier) carry a lower `m_i`, so a mismatch
> costs a bounded penalty.

---

## 3. Storage representation (the salted stored form)

To satisfy data minimization ([architecture §7](#7-privacy-and-compliance)), raw
values are never stored while matching is preserved. Every host persists only the
**salted stored form** (`StoredComponents`): a JSON object keyed by component
name, absent components omitted.

- **Category** — `{"category": "<64 hex>"}`, the salted hash `SHA-256(salt ‖ value)`.
  Supports equality comparison + frequency counting (for `u_i`).
- **Set** (`fonts`, `plugins`) — `{"set": ["<64 hex>", …]}`, the sorted
  **per-element** salted hashes. Per-element hashing **preserves Jaccard**, so set
  similarity + MinHash still work.
- **Numeric** (`cpu_cores`, `device_memory`) — `{"numeric": <i64>}`, the JSON
  number rounded to the nearest integer.

Deserialization rejects an unknown component name, a value of the wrong kind, or a
malformed hash. The salt is a 16-byte per-instance secret: random on the native
server, derived as the first 16 bytes of `SHA-256(FP_SALT_SECRET)` on the edge so
every isolate derives identical hashes and blocking keys. Per `visitor_id` the
native library also keeps the first-observation snapshot, per-component
freshness, `first_seen`, `last_seen`, and `observation_count` (§7, §11).

---

## 4. Stage one: candidate generation (blocking)

Goal: from a million-record library, get a bounded candidate set in near O(1)
**without missing the true match** (recall first).

A single exact key cannot be used — any one component changing misses. Use
**multiple independent blocking keys, unioned** for recall redundancy (each a
SHA-256 over the salted stored values; a composite key is emitted only when all of
its members are present):

- `K0` — every present scalar (category + numeric) component, name and value: the
  exact-match key, fragile by design
- `K1 = H(webgl ‖ platform ‖ timezone)` — one high-stability subset
- `K2 = H(audio ‖ cpu_cores ‖ device_memory)` — a disjoint high-stability subset
- `K3` — MinHash-LSH band keys over the `fonts` set (16 permutations, 8 bands × 2
  rows), tolerating incremental font change

Recall = 1 − P(all keys miss). Each key uses a different component subset, so when
one component changes another key still hits. Candidate set = ∪(the
`visitor_id`s each key hits).

**Index** — one `blocking_key → set<visitor_id>` inverted index holds the scalar
keys and the MinHash band keys alike.

**Hot-block inflation** — a popular config (default-Safari iPhone) makes one block
huge (low information). Mitigation:

- cap block size (native `FP_FUZZY_MAX_BLOCK`, default 1024); over the cap the key
  carries little information and cannot narrow candidates — stage-two scoring (§5)
  must disambiguate;
- over-cap drops are counted and logged (no silent truncation), so "looks covered
  but isn't" cannot happen;
- the edge bounds recall per request instead: exact key first, then the rarest
  keys, at most 256 visitors per key and 1024 in total.

---

## 5. Stage two: probabilistic scoring (Fellegi–Sunter)

For each candidate `cand` vs `probe`, compare component-wise and accumulate the
log-likelihood ratio.

### 5.1 Per-component agreement `agree_i`

- Category — hash equal → agree, else disagree.
- Set — Jaccard `J = |A∩B| / |A∪B|`; `J ≥ τ` → full agreement (`τ = 0.5`), else the
  agreement fraction is `J` (see 5.3).
- Numeric — equal integers → agree, else disagree.

### 5.2 The two parameters

- `m_i = P(agree_i | same device)` — models stability; starts at the §2 tier prior
  and is refined from **confirmed matches** (§9).
- `u_i = P(agree_i | different device)` — models distinctiveness; estimated from the
  **frequency** of the probe's value among that component's sightings (§9). A rare
  value → very low `u_i` → equality is strong evidence; a common Chrome/Windows
  value → high `u_i` → equality barely counts.

### 5.3 Per-component weight

```
u_i ← min(u_i, m_i)                                      // a value more common than stable is no evidence
agree:      w_i = log2( m_i / u_i )                      // positive; rarer = larger
disagree:   w_i = log2( (1 - m_i) / (1 - u_i) )          // negative; more stable = more negative
partial (set, J < τ): w_i = J · log2(m_i/u_i) + (1-J) · log2((1-m_i)/(1-u_i))
missing (either side lacks it): w_i = 0                  // not compared, not scored (see §8)
```

Total: `score(cand) = Σ_i w_i`, in bits.

**Why the model is right:**

- **De-avalanche** — a low-`m_i` component (canvas) disagreeing gives
  `(1-m_i)/(1-u_i)` near 1, so its `log` is small → it barely penalizes.
- **Anti-collision** — two same-model devices disagree on high-stability components
  whose `m_i` is high → each disagreement carries a large negative, pulling the
  total below threshold → judged distinct.
- **Low-entropy auto-fade** — a common value's `u_i` is high (capped at `m_i`) →
  agreement barely adds, so "both in the same zone" never forces a match.

### 5.4 Decision

Take the top candidate `best`; two thresholds `T_hi = 12` bits > `T_lo = 8` bits:

- `score(best) ≥ T_hi` → **same device** (`match`); return its `visitor_id`, apply
  drift (§7) — unless the template-jump guard (§7) downgrades it to `review`.
- `T_lo ≤ score(best) < T_hi` → **suspected** (`review`); return the `visitor_id`
  with lowered confidence; nothing is written.
- `score(best) < T_lo` (or no candidate) → **new device** (`new_device`); the host
  mints a fresh `visitor_id`.
- **A match whose runner-up also scores ≥ `T_hi` within 2 bits** → collision risk;
  take the top and set `collision_risk`.

---

## 6. Confidence output

`confidence ∈ [0,1]`, rule-weighted (no learned model). The engine computes a base
value from the decision, the score margins and completeness:

- **Match** — `0.5 + 0.5 · min(σ((s − T_hi)/4), σ((s − s₂)/4))`: how far
  `score(best)` clears `T_hi` and its gap to the runner-up `s₂` (σ is the logistic
  function; no runner-up counts as a full gap).
- **Review** — `0.25 + 0.25 · (s − T_lo)/(T_hi − T_lo)`.
- **New device** — `0.5 + 0.5 · (1 − σ((s − T_lo)/4))`: confident it is new when the
  best score sits well below `T_lo`.
- **Completeness** — the base is scaled by `0.5 + 0.5 · min(compared / 8, 1)`, where
  `compared` is the number of components scored against the best candidate; more
  missing → lower confidence (§8).

The host then fuses, clamping to `[0, 1]` after each step:

- **New-device velocity** — `−0.3` when the band is `high`
  ([architecture §5](#5-http-interface-contract-v1)).
- **Passive-signal consistency** — UA/JA4 consistent → `+0.05`; mismatch → `−0.5`
  (the anti-forgery core, [architecture §4.2](#42-passive-signals-and-the-trust-boundary));
  degraded → `0`.
- **Client integrity** — `−0.3` on `noise`, only when `integrity_penalty_enabled`.

---

## 7. Drift (template adaptation) and poisoning defense

Without drift, stored components go stale and matching degrades after a few
browser upgrades. Rules:

- **Only on a confirmed `match`** is the template updated: every component present in
  the probe overwrites the template's value and freshness, `last_seen` and
  `observation_count` advance, and the blocking memberships are re-derived from the
  merged template. On the edge the merged stored form is written back to
  `templates`.
- **A `review` writes nothing** — neither the template nor any estimation material.
- **Template-jump guard.** A best candidate that clears `T_hi` but whose probe
  changes **more than 2** high-stability components (`webgl`, `platform`,
  `timezone`, `languages`, `audio`, `cpu_cores`, `device_memory`; only components
  present on both sides count) of the matched template is downgraded to `review`
  with `signals.template_jump: true`, so the template is not updated. This bounds
  how far one observation can move a template and stops an attacker walking one
  device's template onto another.
- **Immutable origin.** The native record keeps the stored values of the
  observation that created it (`first_observation`); drift never overwrites it, so a
  template's origin stays auditable however far it drifts.

---

## 8. Edge cases

- **Privacy browser blocks canvas (null/empty)** — a missing component scores `w_i = 0`
  and does not participate. Never treat "null canvas" as a matchable value — otherwise
  all privacy users agree on that component → mass collision. More missing → lower
  confidence.
- **Brave-style per-session canvas randomization** — the component changes every visit
  of the same device; canvas sits in the low tier (`m_i` prior 0.5), so its
  disagreement weighs little and the match falls back to fonts/audio/webgl.
- **Corporate golden image / identical VMs** — genuinely distinct devices with
  identical fingerprints; fuzzy matching cannot resolve them and will collide. Must
  fall back to IP + account behavior; this is a **known capability boundary**, not
  solved by this engine.

---

## 9. Parameter estimation and cold start

- `u_i` — per-component value frequency, updated incrementally in the store. Counts
  are keyed by `(component, value hash)` with a **per-component** denominator (a set
  counts as a whole via an order-independent digest), and they count **devices, not
  visits** (a revisit only counts changed values). The estimate is
  `(hits + 10 · u_prior) / (total + 10)`, clamped to `[1e-4, 0.9999]`: the
  per-component prior (§2) holds a cold or tiny library (the edge scores over the
  recalled block only) near the prior, and observed frequency takes over as
  sightings accumulate. The weight caps `u_i` at `m_i` (§5.3).
- `m_i` — learned online from confirmed matches: on each `match`, before drift, every
  component present on both sides records one same-device observation (agree iff its
  similarity clears `τ`). The estimate is `(agree + 20 · prior) / (total + 20)`,
  clamped to `[1e-4, 0.9999]`; with no observations it is the §2 prior **exactly**.
  The edge keeps no agreement material, so its `m_i` stays at the priors
  ([architecture §8](#8-deployment-targets)).
- Cold-library phase: everything reads as a new device; the blocking index and
  frequency stats accumulate over time.

---

## 10. Offline evaluation

Proving the architecture §3 targets requires a labelled evaluation set first:

- **Ground truth** — use login state / long-lived cookies to label "multiple visits of
  one device."
- **Stability rate** — fraction of same-device revisits resolved to one `visitor_id`
  (sweep `T_hi`).
- **Collision rate** — fraction of distinct devices resolved to one `visitor_id`.
- Grid-search `T_lo / T_hi / τ` and the component priors; plot the
  stability–collision trade-off curve to set thresholds.
- After launch, continuously re-feed review/collision_risk samples for manual review
  to refine `m_i/u_i` and thresholds.

> The repository ships a synthetic fixture and a replay harness
> (`cargo run -p fingerprintd-server --example eval`) that exercise the scoring
> wiring **directionally** — a smoke test, not evidence for the numeric targets. The
> rates it prints must not be reported as production stability/collision figures.

---

## 11. Data structures and performance

| Use | Structure | Native | Edge |
|---|---|---|---|
| Blocking inverted index | `key → set<visitor_id>` | in memory, per-block cap `FP_FUZZY_MAX_BLOCK` (1024) | `blocking_index` table |
| MinHash-LSH | band keys in the blocking index | 16 permutations, 8 bands × 2 rows | same (seeded from `FP_SALT_SECRET`) |
| Fingerprint library | `visitor_id → record` | current template + first observation + freshness + timestamps + keys; cap `FP_FUZZY_MAX_RECORDS` (1 000 000), oldest `last_seen` evicted; optional TTL | `templates` table (current template + timestamps) |
| Frequency stats | `(component, value hash) → count` + per-component total | cap `FP_FUZZY_MAX_FREQUENCY_VALUES` (1 000 000) | rebuilt per request from recalled templates |
| Agreement stats | `component → (agree, total)` | cap `FP_FUZZY_MAX_AGREEMENT_COMPONENTS` (1024) | none (priors) |
| Velocity | `ip → {visitor_id → last seen}` | 1-hour window, ≤ 64 ids per IP, ≤ 1 000 000 IPs | `VELOCITY` Durable Object |
| Tombstones | erased `visitor_id`s | FIFO, 100 000 | `erased_visitors`, trimmed to 100 000 |

Every cap-driven eviction or drop is counted, never silent. Performance: stage one is
O(candidates); stage two is O(candidates × constant components). On the native
server all matching state sits behind one read-write lock: recall and scoring run
under a shared read guard, and the write-back takes the exclusive guard; if the
state changed in between, the verdict is re-decided against the write-guarded state
before anything is persisted, so concurrent first sightings of one device yield one
visitor and an identify racing an erasure never resurrects the erased id. Matching
runs on a blocking thread pool, off the async workers.

---

## 12. Open questions

1. MinHash band count / τ for set components — needs real-data measurement.
2. How many confirmed same-device revisits `m_i` needs to converge, and the
   pseudo-count weights (`10` for `u_i`, `20` for `m_i`).
3. The block-size cap and the fallback for over-cap cohorts (force high-entropy agreement?).
4. Time-decay window for frequency stats (down-weight stale values?).
5. Whether to stratify parameter estimation by device cohort (mobile vs desktop `m/u` differ).
6. Detecting a cohort with an always-changing canvas and masking that component for it.
7. Persisting frequency and agreement material on the edge so its `confidence` converges with native.
