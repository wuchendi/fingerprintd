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

Ships to **Cloudflare Pages** (direct upload, `wrangler.jsonc`, no server code)
as the `fingerprintd` project — `fingerprintd.pages.dev`. SPA history fallback
is handled by `public/_redirects` (`/* /index.html 200`), copied into `dist/`
at build time.

```bash
bun run --filter @cdlab/fingerprintd build   # SDK dist (gitignored)
bun run build                                 # SPA -> ./dist
bun run deploy                                # wrangler pages deploy --branch main
```

`--branch main` marks the upload as a production deployment. If the Pages
project's configured production branch is not `main`, change the flag to match.

CI: `.github/workflows/deploy-web.yml` (manual `workflow_dispatch`) does the
same — install → build SDK → build web → `wrangler pages deploy`. It reuses the
`CLOUDFLARE_ACCOUNT_ID` secret shared with `deploy-edge.yml`; the
`CLOUDFLARE_API_TOKEN` must additionally carry **Cloudflare Pages:Edit**
(the edge token's `Workers Scripts:Edit` alone cannot deploy to Pages).

## Notes

- **Cross-origin.** The playground fetches `/challenge` and `/identify` on the
  server origin you enter, so that server must allow this app's origin via CORS.
  The edge Worker does this via `FP_CORS_ORIGINS` (see
  [`apps/edge/README.md`](../edge/README.md)). Point at another server and it
  must set its own CORS.
- **Real-browser only.** Canvas/audio/WebGL collection needs a real browser;
  there is no headless in-repo e2e for this app.
