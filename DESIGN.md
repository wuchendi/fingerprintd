# fingerprintd — Design

**English** · [中文](DESIGN.zh-CN.md)

> Server-side device fingerprinting for **anti-fraud / anti-automation**. Judgment
> is server-authoritative: the client only collects; the server issues a one-time
> challenge, fuzzy-matches, fuses passive signals, and returns
> `visitorId` + `confidence`.

This is the authoritative design spec; the implementation follows it. It has two
parts — **[Architecture](#architecture)** (the challenge-response protocol, trust
boundary, and HTTP contract) and **[Fuzzy matching](#fuzzy-matching)** (the
two-stage engine that turns raw components into a `visitorId`). Section numbers
are stable anchors that source doc-comments cite as `architecture §N` /
`fuzzy-matching §N`.

## Contents

**Architecture**

1. [Background](#1-background)
2. [Goals and threat model](#2-goals-and-threat-model)
3. [Success metrics](#3-success-metrics)
4. [Challenge-response + server-side fusion](#4-architecture-challenge-response--server-side-fusion)
5. [HTTP interface](#5-http-interface)
6. [Data model](#6-data-model)
7. [Privacy and compliance](#7-privacy-and-compliance)
8. [Deployment targets](#8-deployment-targets)
9. [Defense-in-depth controls](#9-defense-in-depth-controls-config-gated-off-by-default)

**Fuzzy matching**

1. [Problem statement](#1-problem-statement)
2. [Component classification](#2-component-classification-the-modeling-premise)
3. [Storage representation](#3-storage-representation)
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
| No replay protection | id is static | **one-time challenge** bound to a freshness proof |
| Imprecise | exact client hash + avalanche | **server-side fuzzy matching + multi-source fusion** |

Judgment moves entirely server-side; the client only collects — the path
FingerprintJS Pro / DataDome / Akamai all take.

---

## 2. Goals and threat model

At high-risk actions (login, signup, checkout, coupon redemption) each request
yields a stable `visitorId` and a `confidence` for the risk engine: is this a new
device, is it linked to a known device, and do the self-reported browser features
agree with the network layer (bot detection)?

### Threat model

| Adversary | Capability | System goal |
|---|---|---|
| **L1 script** | curl / scripts, no JS | must reject (no collection / TLS mismatch) |
| **L2 automation** | headless browser, runs JS, forges UA/JS values | catch via passive signals + consistency |
| **L3 advanced** | curl-impersonate / uTLS forging JA3/JA4 + full stack | **lower confidence + cross-verify**, not absolute blocking |

No absolute defense is claimed. An L3 adversary can forge any single signal; the
value is in **raising forgery cost** and **multi-signal consistency detection**,
not in being unbeatable.

### Goals

- **G1** — server issues a one-time challenge; the result is bound to freshness, so replay is invalid.
- **G2** — fuse client components + passive network signals into `visitorId` + `confidence`.
- **G3** — fuzzy matching replaces the exact hash, removing avalanche; stability over uniqueness.
- **G4** — P99 decision latency ≤ 50ms (excluding client collection); ≥ 2k RPS per instance.

### Non-goals

- No full client SDK UI/telemetry framework — only a minimal collect + challenge shell.
- No unbreakable tamper-proofing (the WASM shell raises hook cost, it is not decisive).
- No cross-site tracking / ad attribution.
- No device-association graph (account ↔ device clustering) in the current version; data is reserved for it.

---

## 3. Success metrics

| Metric | Definition | Target |
|---|---|---|
| Stability rate | same device re-resolved to one `visitorId` across visits over two weeks | ≥ 95% |
| Collision rate | distinct devices resolved to one `visitorId` | ≤ 1% |
| L1/L2 detection | scripted / forged requests flagged low-confidence | ≥ 90% |
| Decision P99 | submit → `visitorId` returned | ≤ 50ms |
| Replay rejection | expired / reused nonce refused | 100% |

> The stability/collision targets are gated behind an **offline evaluation against
> a labelled corpus** — see [fuzzy-matching §10](#10-offline-evaluation). They must
> not be reported from synthetic fixtures.

---

## 4. Architecture: challenge-response + server-side fusion

### 4.1 Freshness vs. identity (the core split)

Matching requires that the same device produces the **same** stable output each
time. So evidence is split into two lanes that never mix:

- **`stable_components`** — no nonce mixed in; raw values enter the fingerprint
  library and drive identity matching.
- **freshness proof** — depends on the server-issued nonce and proves the
  collection is live; it **never** participates in identity matching.

**Replay protection** rests on two layers, in order of authority:

1. **One-time nonce (primary lock).** The server mints a short-TTL, single-use
   nonce and burns it on consumption. A reused or expired nonce is rejected with
   `401`. This is the decisive guarantee.
2. **Nonce probe (defense in depth, optional).** When a `probe_key` is configured,
   the server advertises a deterministic transform in the challenge; the client
   returns `hex(HMAC-SHA256(key, nonce))`, computed in WASM. This proves the client
   computed live per protocol rather than replaying a fixed value. It is depth on
   top of the one-time nonce, not the primary lock — the key ships in client WASM
   and is extractable, so it raises the bar without being decisive.

> An earlier design mixed the nonce into canvas/audio draw seeds (`challenge_response`).
> It was removed: freshness that depends on "the output differs every time" cannot
> be independently verified by the server, whereas the one-time nonce can. The HMAC
> probe replaces it as the live-collection proof.

### 4.2 Passive signals and the trust boundary

TLS JA3/JA4 is **not** a high-entropy per-device identifier and **not**
unforgeable:

- Low entropy — millions of same-model Chrome instances share one JA3, so it
  cannot be a `visitorId` source.
- Forgeable — curl-impersonate / uTLS can construct any ClientHello.

Its real value is **consistency cross-checking**, weighted into `confidence`, never
into `visitorId`:

- JS claims Chrome/Windows but JA4 is a Python/Go stack → strong anomaly, confidence sharply lowered.
- IP reputation (datacenter / proxy / risk feed) → auxiliary, not decisive.

**Deployment constraint (hard).** Connection-layer signals can only be captured by
the party terminating the client's TLS connection. Behind Cloudflare's proxy the
origin sees the CF↔origin segment, so client-layer signals must be passed through.

- **Current topology** — Cloudflare extracts JA3/JA4 and forwards them via header.
  Availability depends on the account (JA4 headers are bound to Bot Management,
  Enterprise): present → used; **absent → auto-degrade** (connection-layer signals
  are neutralized and de-weighted, the request is **not** blocked; the real client
  IP via `CF-Connecting-IP` still feeds IP reputation).
- **Trust boundary (fail-closed).** Edge-injected passive-signal headers are read
  **only** when the deployment is configured to trust the edge
  (`trust_edge_headers`); otherwise any client-supplied copy is ignored. This
  prevents a client stuffing a forged JA4. A self-managed nginx/envoy edge that
  injects its own trusted JA4 header is a future extension.

### 4.3 Fuzzy matching and candidate generation

Matching is **not** a hash lookup and cannot linearly scan the whole library. Two
stages: (1) blocking / LSH recall compresses the library to tens–hundreds of
candidates; (2) weighted probabilistic scoring (Fellegi–Sunter) ranks them and
decides. Full spec: the [Fuzzy matching](#fuzzy-matching) part below.

### 4.4 Client collection: reuse FingerprintJS / BotD

The client only collects; judgment is server-side (§4). The collector reuses
existing MIT libraries rather than reinventing them:

| Library | License | How reused | Boundary |
|---|---|---|---|
| **FingerprintJS** (OSS) | MIT | npm dependency; take its **raw `components`** as `stable_components` | discard its client-side `visitorId` hash |
| **BotD** (OSS) | MIT | npm dependency; bot signals fold into server `confidence` | client signals are forgeable, secondary input |

The nonce probe (§4.1) is written in-house — FingerprintJS does not compute a
keyed transform over a server nonce. A client-side adapter maps FingerprintJS's
nested `{value, duration}` component shape and key names onto the server's schema
before submission, so real browser probes are matchable. See
[`packages/client`](packages/client/README.md).

---

## 5. HTTP interface

Both deployment targets (§8) serve the same wire contract.

### GET /challenge

```
200: {
  nonce: string,          // one-time, server-issued
  expires_in: 30,         // seconds (nonce_ttl_secs)
  collect: {
    stable: [...],                 // stable component ids to gather
    challenge: {
      seed: string,                // = nonce; seeds the rendered canvas/audio challenge
      targets: [...],              // active-probe targets to render, e.g. ["canvas", "audio"]
      verify?: {                   // advertised only when a probe_key is configured
        alg: "HMAC-SHA256",
        input: "nonce",
        encoding: "hex"
      }
    }
  }
}
```

### POST /identify

```
Req: {
  nonce: string,
  stable_components: { ... },   // raw values, no nonce mixed in
  probe?: string,               // hex(HMAC-SHA256(key, nonce)); required when the server enforces the probe
  ts?: number,                  // client Unix ms; checked only when the timestamp window is enforced
  integrity?: {                 // known-answer client integrity probe verdicts; top-level so they never enter matching
    canvas: "ok" | "noise" | "unavailable", webgl: ..., audio: ..., rect: ...
  }
}
200: {
  visitorId: string,
  confidence: 0.0..1.0,         // DECISION confidence, not identity trust — see §6
  decision: "match" | "review" | "new_device",
  is_new_device: boolean,
  collision_risk: boolean,
  signals: {                    // for the risk engine; raw passive signals are never echoed
    ua_tls_consistent: boolean,
    ip_risk: "low" | "medium" | "high",
    client_integrity: "ok" | "noise" | "unavailable",  // fused client integrity verdict
    persona_coherence: "consistent" | "mismatch" | "unknown",  // UA OS family vs fonts, surfaced-only
    new_device_velocity: "low" | "medium" | "high"  // IP-keyed cross-session new-device rate
  }
}
401: nonce expired / reused, or an enforced probe / timestamp check failed
```

The request body is `deny_unknown_fields` — an unexpected top-level key is rejected
`400` (both stacks). When `response_signing_key` is set, a success additionally
carries `x-fp-timestamp` + `x-fp-signature` (`hex(HMAC-SHA256(key, be64(issuedMs) ++ body))`).

Passive signals (JA4/IP) are obtained server-side from the connection (§4.2) and
are **never** accepted from the client body.

`new_device_velocity` is an IP-keyed **cross-session** signal: how many new devices
one client IP minted inside a trailing window. A high rate is the fresh-seed-per-launch
farm's footprint — invisible to the per-session engine one request at a time — and
downgrades decision confidence without touching the `visitorId`. Its window and
thresholds are tuning placeholders. It is a risk band surfaced alongside `ip_risk`,
never folded into identity. The stateful native server computes the real band; the
stateless edge Worker holds no cross-session store and always reports the neutral
`low`, mirroring how it treats an empty frequency/agreement store as neutral.

`client_integrity` fuses the SDK's four **known-answer integrity probes**: the
collector asks the browser questions an unmodified Chromium answers exactly (a
lossless canvas `toDataURL` → `getImageData` round-trip of opaque pixels, a flat
WebGL clear, a `ConstantSourceNode` rendered offline, a `getBoundingClientRect` at
1/64-px-representable offsets) and reports `ok` / `noise` / `unavailable` per probe.
A fingerprint-noising (anti-detect) browser answers all four wrongly; it is the
first **single-request** signal that observes such a browser, from inside the
collector. The verdicts ride top-level in the request — never inside
`stable_components` — so they cannot enter the `visitorId`; any `noise` wins, else
any `ok`, else `unavailable` (absent field, missing APIs, malformed material —
always neutral). The band is **surfaced-only by default**: legitimate privacy
tooling (Brave farbling, canvas blockers) trips the same probes, so the `noise`
confidence downgrade is opt-in (`integrity_penalty_enabled` /
`FP_INTEGRITY_PENALTY_ENABLED`) until a real-traffic false-positive rate exists.
Both stacks compute it through the shared core (`fingerprintd::signals::ClientIntegrity`).

`persona_coherence` cross-checks the UA-claimed OS family against the collected
`fonts` set: a Windows or macOS UA whose font set contains **none** of that OS's
core fonts (a tiny curated list drawn from what FingerprintJS probes — Calibri,
Segoe UI Light, MS UI Gothic, … / Helvetica Neue, Menlo, Gill Sans) reads
`mismatch` — a borrowed persona, e.g. a cloaking browser presenting Windows from a
Linux container that hides the host's fonts but adds none. Other OS families, a
missing UA or a missing `fonts` array read `unknown`. Surfaced-only: it never moves
`confidence` or the `visitorId`. Honest limit: an operator who installs the Windows
font set (or a binary that spoofs font metrics) passes it; it raises cost, nothing
more. The claimed UA is read from the top-level component spellings and, for the
real SDK payload, from the BotD signal (`botd.signals.userAgent.value`) — the same
fallback that lets the UA↔TLS cross-check (§4.2) see SDK traffic at all.

### DELETE /visitor/{id}

GDPR right-to-be-forgotten (§7). Admin-key gated (`admin_key`): unset ⇒ the route
is disabled. Erasure is idempotent — `204` even when the visitor did not exist.

---

## 6. Data model

- **fingerprints** — `visitorId` → per-component salted hashes, blocking keys,
  first/last-seen, observation count. Raw values are **not** stored (§7); category
  components are salted hashes and set components are per-element hashes (preserving
  Jaccard). See [fuzzy-matching §3](#3-storage-representation).
- **nonce** — `nonce` → `{issued_at, used}`, TTL = `expires_in`, burned on use.
- **frequency** — per-value counts for the `u_i` rarity estimate
  ([fuzzy-matching §9](#9-parameter-estimation-and-cold-start)).

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
- **Data minimization** — only salted hashes are stored, never raw component values
  (§6 / [fuzzy-matching §3](#3-storage-representation)).
- **Retention** — records past `retention_secs` are swept and deleted; `0` disables
  the sweep.
- **Erasure** — `DELETE /visitor/{id}` (§5) implements right-to-be-forgotten.
- **Strict input** — `deny_unknown_fields` on the request body prevents silently
  accepting unmodeled fields.
- **Purpose limitation** — anti-fraud only; using it for advertising/tracking
  changes the legal basis and is out of scope.
- **Transparency** — disclose device fingerprinting in the privacy policy.

---

## 8. Deployment targets

One engine ([`crates/fp-core`](crates/fp-core)), two hosts. A client works against
either unchanged; the two are held to identical behavior by a shared parity fixture
run on both sides.

| Concern | Native server (`crates/fingerprintd`) | Edge Worker (`apps/edge`) |
|---|---|---|
| Runtime | Axum / Tokio, long-lived process | Cloudflare Worker (V8 isolate, per-request) |
| Nonce store | in-memory, single-use + TTL, bounded + reaped | Durable Object (atomic check-and-burn + TTL alarm) |
| Fingerprint library | in-memory inverted index + frequency table, bounded/evicting | D1 (SQLite): `templates` + `blocking_index` |
| Compute | native `fingerprintd` | `fingerprintd` compiled to WASM (`crates/fp-wasm`) |
| Passive signals | full JA4/IP fusion (§4.2) | neutral by default; JA4/IP behind a trusted edge |
| Secrets | config / env | Worker Secrets |

The native store is process-local: a restart re-mints devices, so a durable backend
(the D1/Durable Object seam, or an external store behind the `NonceStore` /
`FingerprintStore` / `CandidateSource` traits) is required for a production
single-instance-stable `visitorId`. See [`apps/edge`](apps/edge/README.md) for the
persisted deployment.

**Downstream consumers.** `visitorId` + `confidence` + `signals` are inputs *for a
risk engine*, not a verdict on their own — fingerprintd deliberately holds no
account state and no behavioural history (Non-goal, §2). A caller that needs an
allow/challenge/deny decision layers that on top. The edge Worker ships the
reference example as a config-gated `POST /checkin/assess` route
([`apps/edge`](apps/edge/README.md)): it joins `/identify` output with
account/device/IP/time aggregation to score daily check-in anti-farming, leaving
the fingerprint core unchanged. The [playground](apps/web/README.md) demos it.

---

## 9. Defense-in-depth controls (config-gated, off by default)

All three are fail-closed and activate only once their key is set:

- **Nonce probe** (`probe_key`, §4.1) — verifies the WASM-computed `probe`; wrong/
  missing ⇒ `401`. The same key must be baked into the client WASM build.
- **Response signing** (`response_signing_key`, §5) — signs each `/identify` success
  so the client can detect tampering.
- **Timestamp window** (`enforce_ts_window` + `ts_skew_secs`, §5) — bounds how stale
  a request `ts` may be.

They are depth on top of the one-time nonce and TLS, which remain primary. Embedded
client secrets are extractable and must not be promoted to decisive controls.

---

# Fuzzy matching

> The stage-two matching engine behind
> [architecture §4.3](#43-fuzzy-matching-and-candidate-generation).
> Targets ([architecture §3](#3-success-metrics)): stability ≥ 95%,
> collision ≤ 1%, decision P99 ≤ 50ms, ≥ 2k RPS per instance.

## 1. Problem statement

Input: the stable-component set of one observation, `probe = {c_1, …, c_n}`.
Output: the matched `visitorId` (same device) or a new-device verdict, plus a
`confidence`.

Three constraints pull against each other:

- **De-avalanche** — one component changing (a browser auto-upgrade, a new font, an
  external monitor) must not mint a new `visitorId`.
- **Anti-collision** — two distinct devices of the same model + browser version must
  not resolve to one `visitorId`.
- **High throughput** — a million-record library cannot be linearly scanned per
  request.

Two core decisions:

1. **Two stages** — candidate generation (§4) → probabilistic scoring (§5).
2. **Scoring uses the Fellegi–Sunter (FS) probabilistic record-linkage model** (§5)
   rather than a hand-tuned weighted average — FS's two parameters `m_i / u_i`
   model *stability* and *distinctiveness* separately, aligning naturally with the
   two failure modes above.

---

## 2. Component classification (the modeling premise)

Each component is characterized on two orthogonal axes — the source of every weight:

- **Stability** — probability the component is unchanged across visits of the same
  device (→ FS `m_i`).
- **Distinctiveness** — probability two distinct devices share the value (→ FS `u_i`;
  rarer = lower `u`).

| Component | Type | Stability | Distinctiveness | Notes |
|---|---|---|---|---|
| WebGL vendor+renderer | category | high | medium | GPU hardware, rarely changes |
| Canvas hash | category | low | high | flips wholesale on driver/browser upgrade; noised per session by privacy / anti-detect browsers |
| Audio fingerprint | category | high | med-high | audio stack, stable |
| Font list | set | medium | high | incremental change → Jaccard/MinHash |
| Timezone / language / platform | category | high | low | low entropy, insufficient alone |
| Screen resolution | category (`"WxH"`, longer side first) | medium | med-low | external display changes it |
| CPU cores / device memory | numeric | high | low | |
| Browser version / UA | version | **low** | medium | **the avalanche source**, auto-upgrades every few weeks |
| Plugins / mimeTypes | set | medium | medium | |

> Key insight: UA/browser version changes frequently — an exact hash keeps minting
> "new devices," which is exactly FingerprintJS's avalanche. Under FS its `m_i` is
> low, so a mismatch barely penalizes; it fades automatically.

---

## 3. Storage representation

To satisfy data minimization ([architecture §7](#7-privacy-and-compliance)), raw
values are never stored while matching is preserved:

- **Category components** — store salted hashes `H(salt || value)`. Still supports
  equality comparison + frequency counting (for `u_i`).
- **Set components (fonts, …)** — store the **per-element hashed** set
  `{H(f) for f in fonts}`. Per-element hashing **preserves Jaccard**, so set
  similarity + MinHash still work.
- **Numeric components** — store the value or a bucketed value.
- Per `visitorId` also store: each component's latest value, `first_seen`,
  `last_seen`, `observation_count`, and per-component freshness for drift (§7).

---

## 4. Stage one: candidate generation (blocking)

Goal: from a million-record library, get tens–hundreds of candidates in near O(1)
**without missing the true match** (recall first).

A single exact key cannot be used — any one component changing misses. Use
**multiple independent blocking keys, unioned** for recall redundancy:

- `K1 = H(webgl_renderer || platform || timezone)` — one high-stability subset
- `K2 = H(audio_hash || cpu_cores || device_memory)` — a disjoint high-stability subset
- `K3 = MinHash-LSH(font set)` band buckets — tolerates incremental font change
- (optional) `K4 = Simhash(all-component tokens)` Hamming neighbor buckets

Recall = 1 − P(all keys miss). Each key uses a disjoint stable-component subset, so
when one component happens to change another key still hits. Candidate set = ∪(the
`visitorId`s each key hits).

**Index** — `blocking_key → set<visitorId>` inverted index. MinHash-LSH:
`band signature → bucket → visitorId`.

**Hot-block inflation** — a popular config (default-Safari iPhone) makes one block
huge (low information). Mitigation:

- cap block size; over the cap the key carries little information and cannot narrow
  candidates — stage-two scoring (§5) must disambiguate;
- over-cap drops **must be logged** (no silent truncation), so "looks covered but
  isn't" cannot happen.

---

## 5. Stage two: probabilistic scoring (Fellegi–Sunter)

For each candidate `cand` vs `probe`, compare component-wise and accumulate the
log-likelihood ratio.

### 5.1 Per-component agreement `agree_i`

- Category — hash equal → agree, else disagree.
- Set — Jaccard `J = |A∩B| / |A∪B|`; `J ≥ τ` → agree (τ ≈ 0.8), else linearly
  interpolated (see 5.3).
- Numeric — equal or same bucket → agree.
- Version — same major → agree; adjacent major → partial (see 5.3); else disagree.

### 5.2 The two parameters

- `m_i = P(agree_i | same device)` — estimated from **high-confidence match revisits**;
  models stability.
- `u_i = P(agree_i | different device)` — estimated from the **library frequency** of
  that component's value; models distinctiveness. A rare value → very low `u_i` →
  equality is strong evidence; a common Chrome/Windows value → high `u_i` → equality
  barely counts.

### 5.3 Per-component weight

```
agree:      w_i = log2( m_i / u_i )                      // positive; rarer = larger
disagree:   w_i = log2( (1 - m_i) / (1 - u_i) )          // negative; more stable = more negative
partial (set/version): w_i = J · log2(m_i/u_i) + (1-J) · log2((1-m_i)/(1-u_i))
missing (either side lacks it): w_i = 0                  // not compared, not scored (see §8)
```

Total: `score(cand) = Σ_i w_i`.

**Why the model is right:**

- **De-avalanche** — UA `m_i` is low → `(1-m_i)/(1-u_i)` ≈ 1, `log` ≈ 0 → a UA
  mismatch barely penalizes.
- **Anti-collision** — two same-model devices disagree on high-entropy components
  (canvas/fonts) whose `m_i` is high → the disagreement carries a large negative,
  pulling the total below threshold → judged distinct.
- **Low-entropy auto-fade** — timezone/language `u_i` is high → agreement barely
  adds, so "both in the same zone" never forces a match.

### 5.4 Decision

Take the top candidate `best`; two thresholds `T_hi > T_lo`:

- `score(best) ≥ T_hi` → **same device**; return its `visitorId`, apply drift (§7).
- `T_lo ≤ score(best) < T_hi` → **suspected**; return the `visitorId` with lowered
  confidence and a `review` flag.
- `score(best) < T_lo` → **new device**; mint a fresh `visitorId`.
- **≥ 2 candidates ≥ T_hi with a small gap** → collision risk; take the top and raise
  a `collision_risk` flag.

---

## 6. Confidence output

`confidence ∈ [0,1]`, fused from three parts (rule-weighted; no learned model in the
current version):

- **Match margin** — how far `score(best)` clears `T_hi` + the gap to the runner-up
  (larger gap → more certain).
- **Passive-signal consistency** — JA4/UA consistent → boost; inconsistent → sharp
  cut (the anti-forgery core, [architecture §4.2](#42-passive-signals-and-the-trust-boundary)).
- **Component completeness** — how many components participated; more missing → lower
  confidence (§8).

---

## 7. Drift (template adaptation) and poisoning defense

Without drift, stored components (UA, …) go stale and matching degrades after a few
browser upgrades. Rules:

- **Only on a high-confidence match (≥ T_hi)** refresh that `visitorId`'s latest
  component values and `last_seen`.
- **Template-poisoning defense** — an attacker might slowly morph A's fingerprint into
  B via repeated low-confidence matches. So:
  - low-confidence / review hits **do not** trigger an update;
  - the original observation history is retained; updates overwrite only the
    "latest value" layer, never the history;
  - the per-update change magnitude is bounded; an abnormal jump is flagged.

---

## 8. Edge cases

- **Privacy browser blocks canvas (null/empty)** — a missing component scores `w_i = 0`
  and does not participate. Never treat "null canvas" as a matchable value — otherwise
  all privacy users agree on that component → mass collision. More missing → lower
  confidence.
- **Brave-style per-session canvas randomization** — the component changes every visit
  of the same device → `m_i → 0`, so FS ignores it automatically, falling back to
  fonts/audio/webgl. Advanced: detect a cohort with an always-changing canvas and mask
  that component for it (future).
- **Corporate golden image / identical VMs** — genuinely distinct devices with
  identical fingerprints; fuzzy matching cannot resolve them and will collide. Must
  fall back to IP + account behavior; this is a **known capability boundary**, not
  solved by this engine.

---

## 9. Parameter estimation and cold start

- `u_i` — maintain per-component-value frequency counts, updated incrementally in the
  store.
- `m_i` — needs "same-device revisit" labels. Cold start uses **priors** (per the §2
  classification: high-stability = 0.95, medium = 0.80, low = 0.50); after launch,
  **EM iteration** over high-confidence-match revisits converges it. This is an
  iterative process, not one-shot.
- Cold-library phase: everything reads as a new device; the blocking index and
  frequency stats accumulate over time.

---

## 10. Offline evaluation

Proving the §3 targets requires a labelled evaluation set first:

- **Ground truth** — use login state / long-lived cookies to label "multiple visits of
  one device."
- **Stability rate** — fraction of same-device revisits resolved to one `visitorId`
  (sweep `T_hi`).
- **Collision rate** — fraction of distinct devices resolved to one `visitorId`.
- Grid-search `T_lo / T_hi / τ` and the component priors; plot the
  stability–collision trade-off curve to set thresholds.
- After launch, continuously re-feed review/collision_risk samples for manual review
  to refine `m_i/u_i` and thresholds.

> The repository ships a synthetic fixture that exercises the scoring wiring
> **directionally** — it is a smoke test, not evidence for the numeric targets. The
> rates it prints must not be reported as production stability/collision figures.

---

## 11. Data structures and performance

| Use | Structure | Notes |
|---|---|---|
| Blocking inverted index | `key → set<visitorId>` | in-memory / Redis Set / PG GIN |
| MinHash-LSH | `band signature → bucket` | recall for set components |
| Fingerprint library | `visitorId → component hashes + frequency material + timestamps` | KV / D1 / PG |
| Frequency stats | `component value hash → count` | estimates `u_i` |

Performance: stage one is O(candidates); stage two is O(candidates × constant
components). Keeping candidates in the low hundreds satisfies P99 ≤ 50ms. On the
native server the inverted index + scoring stay in memory; the frequency/library
persistence layer flushes asynchronously.

---

## 12. Open questions

1. MinHash band count / τ for set components — needs real-data measurement.
2. How many labelled revisit samples EM needs to converge `m_i`.
3. The block-size cap and the fallback for over-cap cohorts (force high-entropy agreement?).
4. Time-decay window for frequency stats (down-weight stale values?).
5. Whether to stratify parameter estimation by device cohort (mobile vs desktop `m/u` differ).
