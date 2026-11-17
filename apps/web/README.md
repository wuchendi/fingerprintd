# @cdlab/fingerprintd-web

Browser **playground / debug console** for the
[`fingerprintd`](../../crates/fingerprintd) challenge/identify flow. It drives
the collect-only [`@cdlab/fingerprintd`](../../packages/client) SDK against a
server you point it at and visualizes both what the client **sends** and what
the server **judges** — the client never derives an id, the server is
authoritative.

## What it shows

Enter a server base URL → **Run flow** runs `getChallenge → collect → identify`:

- **Identity** — the server verdict: `visitor_id`, `request_id`, `confidence`,
  `decision` (`match` / `review` / `new_device`), `is_new_device`,
  `collision_risk`, and every risk signal (`ua_tls_consistent`, `ip_risk`,
  `client_integrity`, `persona_coherence`, `new_device_velocity`, `automation`,
  `template_jump`). FingerprintJS's own client-side hash is shown next to it for
  contrast — the SDK discards it and never sends it.
- **Server-side check-in** — the `request_id` plus copyable `curl` snippets for
  `POST /checkin/assess` and `GET /events/{request_id}`. Both calls need the
  server API key (`FP_API_KEY`), so your backend makes them; the playground
  never calls them and never holds the key. The browser result is display-only.
- **Collected evidence** — the exact `POST /identify` body, by lane:
  - `components` — the "who is this device" matching input (closed schema).
  - `user_agent` + `botd` — the browser user agent and BotD verdict.
  - `ts` — the client clock when the request was sent.
  - `integrity` — known-answer probe verdicts, a risk signal only.
- **Check-in decision bands** — canned `allow` / `challenge` / `deny`
  assessments, rendered offline.

## Tech Stack

React 19 · TypeScript · Vite · Tailwind CSS v4 · shadcn/ui (base-nova) +
`@base-ui/react` · Zustand · i18next · Biome

## Development

```bash
bun install
# The playground consumes the built SDK — build it once first (its dist/ is
# gitignored), or run the workspace build from the repo root.
bun run --filter @cdlab/fingerprintd build

bun run dev        # dev server (nsl → http://fingerprintd-web.localhost:<port>)
bun run typecheck  # tsc --noEmit
bun run build      # production build to dist/
bun run preview    # serve the production build
```

To skip the nsl proxy: `bun x vite`.

## Deploy

There is no separate deployment: the edge Worker (`fingerprintd`, see
[`apps/edge/README.md`](../edge/README.md#deploy)) serves `dist/` as static
assets on the same origin as the API, with `index.html` as the SPA fallback.
From the repo root:

```bash
bun run deploy   # build SDK + this app, then deploy the Worker
```

CI: `.github/workflows/deploy.yml` (manual `workflow_dispatch`) does the same.

## Notes

- **Server URL.** The server base URL defaults to the page's own origin — the
  deployed Worker serves both. In `bun run dev`, enter the edge dev server's
  URL instead. Any server on another origin must allow this app's origin via
  CORS (the edge Worker: `FP_CORS_ORIGINS`, see
  [`apps/edge/README.md`](../edge/README.md)).
- **Real-browser only.** Canvas/audio/WebGL collection needs a real browser;
  there is no headless in-repo e2e for this app.
