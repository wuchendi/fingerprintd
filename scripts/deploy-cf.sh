#!/usr/bin/env bash
# deploy-cf.sh — build locally and deploy the fingerprintd Worker to Cloudflare.
# One Worker serves the API (apps/edge) and the playground (apps/web/dist, as
# static assets). Mirrors .github/workflows/deploy.yml for a local run: it
# rebuilds the vendored WASM from source, installs, builds the playground, and
# deploys.
#
# Usage:
#   scripts/deploy-cf.sh
#
# Env toggles:
#   DRY_RUN=1       build + `wrangler deploy --dry-run`; no upload, no
#                   Cloudflare account needed.
#   RUN_MIGRATIONS=1  apply the database migrations before the edge deploy:
#                   libSQL when LIBSQL_URL (+ LIBSQL_AUTH_TOKEN) is set, else the
#                   remote D1.
#
# Auth (only for a real upload, not DRY_RUN): wrangler needs either a prior
#   `wrangler login` (OAuth) OR CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID in
#   the environment.
#
# Runtime Worker secrets are NOT managed here — set them with
# `wrangler secret put <NAME>` (see README "Deploy"):
#   FP_SALT_SECRET (required — the Worker refuses to start without it),
#   FP_ADMIN_KEY, FP_API_KEY, LIBSQL_URL, LIBSQL_AUTH_TOKEN.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DRY="${DRY_RUN:-}"

# --- Toolchain -------------------------------------------------------------
# shellcheck source=/dev/null
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "error: wasm-pack not found — install it (cargo install wasm-pack)" >&2
  exit 1
fi

if [ -z "$DRY" ] && [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
  echo "note: CLOUDFLARE_API_TOKEN not set — wrangler will use its saved 'wrangler login' session (run DRY_RUN=1 to build without uploading)."
fi

# --- Build the vendored WASM for the edge Worker ---------------------------
echo "==> build WASM from crates/fp-wasm -> apps/edge/wasm"
wasm-pack build --target web --out-dir "$ROOT/apps/edge/wasm" crates/fp-wasm

# Install once (the root `prepare` builds the SDK).
echo "==> install workspace deps (+ SDK prebuild via prepare)"
bun install --frozen-lockfile

if [ -n "${RUN_MIGRATIONS:-}" ] && [ -z "$DRY" ]; then
  if [ -n "${LIBSQL_URL:-}" ]; then
    echo "==> apply libSQL migrations"
    (cd apps/edge && DB_TYPE=libsql bun run db:migrate)
  else
    echo "==> apply remote D1 migrations"
    (cd apps/edge && bun run cf:remotedb)
  fi
fi

echo "==> build SDK + playground (apps/web/dist, served as Worker assets)"
bun run --filter @cdlab/fingerprintd build
(cd apps/web && bun run build)

if [ -n "$DRY" ]; then
  echo "==> dry-run (build only, no upload)"
  (cd apps/edge && bun run deploy:dry)
else
  echo "==> deploy (wrangler deploy --minify)"
  (cd apps/edge && bun run deploy)
fi

echo "==> Done${DRY:+ [dry-run]}"
