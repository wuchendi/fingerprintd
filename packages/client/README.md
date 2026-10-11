# @cdlab/fingerprintd-client

Browser SDK for the [`fingerprintd`](../../crates/fingerprintd) challenge/identify
flow. It **collects** client-observed evidence and submits it; the **server**
judges. The client never derives a `visitorId` or a hash — the identity returned
by the server is authoritative.

## Flow

```
GET  /challenge    -> nonce + collection plan (+ probe transform when enforced)
collect(challenge) -> { stable_components, probe?, ts, integrity }
POST /identify     -> { visitorId, confidence, decision, signals, ... }
```

`run()` wires these together with an injected `Collector`. The evidence fields
stay in their lanes:

- `stable_components` — the "who is this device" matching input.
- `probe` — `hex(HMAC-SHA256(key, nonce))` computed in WASM, the
  nonce-seeded **freshness** proof (NEVER a matching signal). Sent only when
  the challenge advertises `collect.challenge.verify` (i.e. the server has a
  probe key). See [WASM probe](#wasm-probe).
- `ts` — the client clock (Unix ms) at collection (the server timestamp window).
- `integrity` — four known-answer probe verdicts (`canvas` / `webgl` / `audio` /
  `rect`, each `ok` | `noise` | `unavailable`) that catch fingerprint-noising
  browsers (`src/integrity.ts`). Top-level by design — never inside
  `stable_components`, so it cannot enter the `visitorId` match; the server
  surfaces it as a risk signal. `unavailable` is neutral.

## Usage

```ts
import { createCollector, run } from '@cdlab/fingerprintd-client'

const { identity, signatureValid } = await run({
  baseUrl: 'https://fp.example.com',
  // The full collector composes the stable half + WASM probe.
  collect: createCollector(),
  // Optional: verify the response signature (see below).
  signingKey: /* Uint8Array */ undefined,
})
```

`createCollector()` uses the real FingerprintJS + BotD stack and the WASM probe.
Every backend is injectable (`{ fingerprint, probe, now, integrity }`) for tests. A trivial
`stubCollector` is also exported for wiring smoke-tests; it gathers **no real
fingerprint**.

> The server still advertises `collect.challenge.targets` (`['canvas','audio']`)
> and `collect.challenge.seed`, but the client no longer consumes them: the
> active-challenge collector was removed because neither backend read its output.
> The `probe` field is the live freshness control.

## WASM probe

The nonce probe is computed by the [`fp-wasm`](../../crates/fp-wasm) crate,
compiled to WebAssembly and **vendored** under [`wasm/`](./wasm). `createCollector`
calls its `probe(nonce)` export; in the browser the module loads its co-located
`fp_wasm_bg.wasm` sibling, and `bun run build` copies that `.wasm` into `dist/`
next to the bundle.

The transform is byte-for-byte identical to the server verifier
(`crates/fingerprintd/src/probe.rs`). `test/probe.test.ts` proves this by
instantiating the vendored WASM headlessly (reading the `.wasm` bytes — a
`--target web` build otherwise fetches by URL, which Node cannot do) and
asserting the **shared parity vector** in
`crates/fp-wasm/tests/vectors/probe.json`:

```
probe("fixed-nonce-000") === "ad83144894f917b94072c2f7b3246af66d3bc5a450562ccf3671ed64d33137d0"
```

> **The vendored `wasm/fp_wasm_bg.wasm` is a DEV build keyed with the vector's
> `test-probe-secret`**, so the parity test can run without a browser. A real
> deployment must rebuild it with the server's key (see below).

## Environment limit — no real browser here

This package was built in an environment with **no headless browser**. Canvas /
audio / WebGL cannot be exercised for real and there is **no real in-browser
e2e**. Tests are **unit/mock only**:

- jsdom + **mocked** `fetch`, canvas, and audio backends (deterministic fakes),
- the **WASM parity vector** above (a real WASM instantiation, but a fixed
  key+nonce vector — not a real device fingerprint).

They cover the wire contract, the collector wiring, and the probe/signature
crypto — they do **not** validate real fingerprints. Real in-browser
certification is **deferred to a human**.

### Running real in-browser certification

1. Build & serve the bundle: `bun run build`, then serve `dist/` (so both
   `index.js` and its sibling `fp_wasm_bg.wasm` are reachable) over HTTP.
2. Open it in a **real browser** pointed at a running `fingerprintd`.
3. Exercise the flow end-to-end: `GET /challenge` → `collect` → `POST /identify`,
   and confirm the returned `visitorId`/`decision` are stable across reloads and
   distinct across devices.

## Enabling the server probe & response signing

Both are **defense in depth**, off by default:

- **Probe:** set `probe_key` in the `fingerprintd` config. Enforcement
  activates whenever `probe_key` is `Some` (non-empty) — there is **no separate
  `require_probe` flag** (`crates/fingerprintd/src/config.rs`, `probe.rs`). The
  server then advertises `collect.challenge.verify` and rejects a missing/wrong
  `probe` with `401`. The **same key must be embedded in the WASM build**:

  ```sh
  FP_PROBE_KEY=<your probe_key> wasm-pack build --target web crates/fp-wasm
  # then copy fp_wasm.js / fp_wasm.d.ts / fp_wasm_bg.wasm(.d.ts) into packages/client/wasm/
  ```

- **Response signature:** set `response_signing_key` in the config. Each
  `/identify` success then carries `x-fp-timestamp` and `x-fp-signature`
  (`hex(HMAC-SHA256(key, be64(issuedMs) ++ body))`, `signing.rs`). Pass the same
  key to the client as `run({ signingKey })` to have `run()` verify it.

> **Embedded-secret depth caveat:** an attacker can extract the probe/signing key
> from the shipped WASM/JS. This raises the bar against blind replay/forgery but
> is **not a decisive control** — the one-time nonce and TLS remain the primary
> guarantees. Rotate keys accordingly.

## Scripts

```
bun run lint       # biome check .
bun run typecheck  # tsc --noEmit
bun run test       # vitest run
bun run build      # tsup (ESM + d.ts, copies the probe wasm into dist/)
```
