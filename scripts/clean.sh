#!/usr/bin/env bash
# clean.sh — remove build artifacts across every stack.
# Guards each removal with an existence check; never touches source.
# Idempotent: safe to run repeatedly.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# --- Rust ------------------------------------------------------------------
# shellcheck source=/dev/null
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
if command -v cargo >/dev/null 2>&1; then
  echo "==> cargo clean"
  cargo clean
else
  echo "==> skip cargo clean (cargo not found)"
fi

# --- TypeScript ------------------------------------------------------------
# Dependencies + build output across every workspace (root, apps/*, packages/*).
shopt -s nullglob
for pattern in \
  node_modules \
  apps/*/node_modules apps/*/dist apps/*/.wrangler apps/edge/wasm \
  packages/*/node_modules packages/*/dist; do
  for dir in $pattern; do
    if [ -d "$ROOT/$dir" ]; then
      echo "==> rm -rf $dir"
      rm -rf "${ROOT:?}/$dir"
    fi
  done
done
shopt -u nullglob

echo "==> Clean complete"
