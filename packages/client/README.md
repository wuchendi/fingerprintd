# @cdlab/fingerprintd

Pure-TypeScript browser SDK for the [`fingerprintd`](../../crates/fingerprintd)
challenge/identify flow. It **collects** client-observed evidence and submits
it; the **server** judges. The client never derives a visitor id or a hash.

## Usage

```bash
npm i @cdlab/fingerprintd
```

```ts
import { createCollector, run } from '@cdlab/fingerprintd'

const result = await run({
  baseUrl: 'https://fp.example.com',
  collect: createCollector(),
})

// Display-only. Send `result.request_id` to your backend.
console.log(result.visitor_id, result.decision, result.request_id)
```

`createCollector()` runs FingerprintJS + BotD and the integrity probes. Every
backend is injectable (`{ fingerprint: { loadFingerprint, loadBotd, userAgent },
integrity }`) for tests. `getChallenge()` and `identify()` are exported for
callers that drive the two requests themselves.

### Authoritative result

The `/identify` response the browser receives is **display-only** — anything
running in the page can be tampered with. Your backend fetches the
authoritative result server-to-server, keyed by the returned `request_id`:

```http
GET /events/{request_id}
Authorization: Bearer <FP_API_KEY>
```

This endpoint is server-side only; the SDK does not call it and the API key must
never ship to the browser.

## Wire format

```
GET  /challenge  -> { nonce, expires_in }
collect()        -> { components, user_agent?, botd?, integrity? }
POST /identify   -> { request_id, visitor_id, confidence, decision, ... }
```

`run()` fetches the challenge, runs the collector, stamps `ts` right before the
POST and submits. All JSON is snake_case; the server rejects unknown keys at
every level with `400`.

`GET /challenge` → `200`:

```json
{ "nonce": "…", "expires_in": 30 }
```

`POST /identify` body:

```jsonc
{
  "nonce": "…",                 // from /challenge
  "ts": 1792329908414,          // Unix ms, always sent
  "components": { "platform": "Win32", "cpu_cores": 8, "fonts": ["Arial"] },
  "user_agent": "Mozilla/5.0 …", // optional
  "botd": { "bot": false },      // optional; { "bot": true, "kind": "headless_chrome" }
  "integrity": { "canvas": "ok", "webgl": "ok", "audio": "ok", "rect": "ok" } // optional
}
```

`POST /identify` → `200`:

```jsonc
{
  "request_id": "…",
  "visitor_id": "…",
  "confidence": 0.87,
  "decision": "match",          // "match" | "review" | "new_device"
  "is_new_device": false,
  "collision_risk": false,
  "signals": {
    "ua_tls_consistent": true,
    "ip_risk": "low",                   // "low" | "medium" | "high"
    "client_integrity": "ok",           // "ok" | "noise" | "unavailable"
    "persona_coherence": "consistent",  // "consistent" | "mismatch" | "unknown"
    "new_device_velocity": "low",       // "low" | "medium" | "high"
    "automation": "not_detected",       // "detected" | "not_detected" | "unknown"
    "template_jump": false
  }
}
```

`confidence` is decision confidence, not identity trust: key trust off
`is_new_device` / `decision`.

## Component schema

`components` is a closed schema (`COMPONENT_KEYS`, mirroring
`crates/fp-core/src/fuzzy/component.rs`). The adapter maps FingerprintJS output
onto it and drops every other FingerprintJS component.

| Key | FingerprintJS source | Kind |
| --- | --- | --- |
| `webgl` | `webGlBasics` (`vendor\|renderer`) | Category |
| `webgl_extensions` | `webGlExtensions` (digest) | Category |
| `platform` | `platform` | Category |
| `timezone` | `timezone` | Category |
| `languages` | `languages` (joined) | Category |
| `audio` | `audio` | Category |
| `canvas` | `canvas` (digest) | Category |
| `cpu_cores` | `hardwareConcurrency` | Numeric |
| `device_memory` | `deviceMemory` | Numeric |
| `screen` | `screenResolution` (`WxH`) | Category |
| `fonts` | `fonts` | Set |
| `plugins` | `plugins` (names) | Set |
| `font_preferences` | `fontPreferences` | Category |
| `screen_frame` | `screenFrame` | Category |
| `math` | `math` | Category |
| `touch_support` | `touchSupport` | Category |
| `dom_blockers` | `domBlockers` | Category |
| `user_agent_data` | `userAgentData` | Category |

Numeric values are JSON numbers, Sets are string arrays, Categories are a
string, number or boolean (object/array values are digested). `user_agent` is
not a component — it is the top-level `user_agent` field.

## Integrity

`integrity` carries four known-answer probe verdicts (`canvas` / `webgl` /
`audio` / `rect`, each `ok` | `noise` | `unavailable`) that catch
fingerprint-noising browsers (`src/integrity.ts`). It is a top-level field,
outside `components`, so it never enters the visitor match; the server surfaces
it as `signals.client_integrity`. `unavailable` is neutral. Legitimate privacy
tooling (Brave farbling, canvas blockers) trips the same probes, so treat
`noise` as a risk band, not proof of automation.

## Testing

There is no headless browser in this environment, so canvas / audio / WebGL are
not exercised for real. Tests run in jsdom with a mocked `fetch` and injected
fakes, plus real FingerprintJS captures (`tests/fixtures/fjs-raw/`) and a
real-device payload (`tests/fixtures/sdk-payload/`) checked against the
component schema. Real in-browser certification is done by a human against a
running `fingerprintd`.

## Scripts

```
bun run typecheck  # tsc --noEmit
bun run test       # vitest run
bun run build      # tsdown (ESM + d.ts)
```
