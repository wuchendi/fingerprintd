#!/usr/bin/env bash
# deploy-cf.sh — build locally and deploy to Cloudflare (edge Worker / web Pages).
# Mirrors .github/workflows/deploy-edge.yml + deploy-web.yml for a local run: it
# rebuilds the vendored WASM from source, installs, builds, and deploys.
#
# Usage:
#   [FP_PROBE_KEY=<key>] scripts/deploy-cf.sh [edge|web|all]   # default: all
#
# Env toggles:
#   FP_PROBE_KEY    baked into the WASM at compile time. Unset ⇒ the source dev
#                   default (matches the deploy workflows). For a probe-enforced
#                   deploy set it to the SAME value as the Worker's RUNTIME
#                   FP_PROBE_KEY secret, so the browser and the edge agree.
#   DRY_RUN=1       build + `wrangler deploy --dry-run` (edge) / build-only (web);
#                   no upload, no Cloudflare account needed.
#   RUN_MIGRATIONS=1  apply the remote D1 migrations before the edge deploy.
#
# Auth (only for a real upload, not DRY_RUN): wrangler needs either a prior
#   `wrangler login` (OAuth) OR CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID in
#   the environment.
#
# Runtime Worker secrets (FP_SALT_SECRET / FP_PROBE_KEY / FP_SIGNING_KEY) are NOT
# managed here — set them with `wrangler secret put <NAME>` (see README "Deploy").
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

# --- Compile-time probe key ------------------------------------------------
# Only export when non-empty: an empty FP_PROBE_KEY would bake an empty key
# (option_env! sees Some("")), which differs from the intended source dev
# default (option_env! None).
if [ -n "${FP_PROBE_KEY:-}" ]; then
  export FP_PROBE_KEY
  echo "==> WASM probe key: provided via FP_PROBE_KEY"
else
  unset FP_PROBE_KEY 2>/dev/null || true
  echo "==> WASM probe key: unset (source dev default)"
fi

# --- Build the vendored WASM once into both consumer dirs ------------------
# Both targets use the identical build; a second pass would only waste time.
echo "==> build WASM from crates/fp-wasm -> apps/edge/wasm + packages/client/wasm"
wasm-pack build --target web --out-dir "$ROOT/apps/edge/wasm" crates/fp-wasm
mkdir -p "$ROOT/packages/client/wasm"
cp -R "$ROOT/apps/edge/wasm/." "$ROOT/packages/client/wasm/"

# Install once (the root `prepare` builds the SDK now that the WASM exists).
echo "==> install workspace deps (+ SDK prebuild via prepare)"
bun install --frozen-lockfile

deploy_edge() {
  if [ -n "${RUN_MIGRATIONS:-}" ] && [ -z "$DRY" ]; then
    echo "==> [edge] apply remote D1 migrations"
    (cd apps/edge && bun run cf:remotedb)
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
