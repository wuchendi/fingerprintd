#!/usr/bin/env bash
# deploy-cf.sh — build locally and deploy to Cloudflare (edge Worker / web Pages).
# Mirrors .github/workflows/deploy-edge.yml + deploy-web.yml for a local run: it
# rebuilds the vendored WASM from source, installs, builds, and deploys.
#
# Usage:
#   scripts/deploy-cf.sh [edge|web|all]   # default: all
#
# Env toggles:
#   DRY_RUN=1       build + `wrangler deploy --dry-run` (edge) / build-only (web);
#                   no upload, no Cloudflare account needed.
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

TARGET="${1:-all}"
case "$TARGET" in
  edge | web | all) ;;
  *) echo "usage: $0 [edge|web|all]" >&2; exit 2 ;;
esac

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

deploy_edge() {
  if [ -n "${RUN_MIGRATIONS:-}" ] && [ -z "$DRY" ]; then
    if [ -n "${LIBSQL_URL:-}" ]; then
      echo "==> [edge] apply libSQL migrations"
      (cd apps/edge && DB_TYPE=libsql bun run db:migrate)
    else
      echo "==> [edge] apply remote D1 migrations"
      (cd apps/edge && bun run cf:remotedb)
    fi
  fi
  if [ -n "$DRY" ]; then
    echo "==> [edge] dry-run (build only, no upload)"
    (cd apps/edge && bun run deploy:dry)
  else
    echo "==> [edge] deploy (wrangler deploy --minify)"
    (cd apps/edge && bun run deploy)
  fi
}

deploy_web() {
  echo "==> [web] build SDK + app"
  bun run --filter @cdlab/fingerprintd build
  (cd apps/web && bun run build)
  if [ -n "$DRY" ]; then
    echo "==> [web] dry-run: build only (Cloudflare Pages has no dry-run) — skipping upload"
  else
    echo "==> [web] deploy (wrangler pages deploy)"
    (cd apps/web && bun run deploy)
  fi
}

case "$TARGET" in
  edge) deploy_edge ;;
  web) deploy_web ;;
  all) deploy_edge; deploy_web ;;
esac

echo "==> Done ($TARGET)${DRY:+ [dry-run]}"
