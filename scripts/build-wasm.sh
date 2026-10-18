#!/usr/bin/env bash
# build-wasm.sh — build the edge Worker's WASM (a BUILD ARTIFACT, not committed)
# from crates/fp-wasm into apps/edge/wasm. The edge Worker bundles it and the
# edge tests read it from disk; it is the only consumer.
#
# Run this after a fresh clone (and after `bun run clean`) before working on
# apps/edge. Idempotent: safe to run repeatedly.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# shellcheck source=/dev/null
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "error: wasm-pack not found — install it (cargo install wasm-pack)" >&2
  exit 1
fi

echo "==> wasm-pack build --target web -> apps/edge/wasm"
wasm-pack build --target web --out-dir "$ROOT/apps/edge/wasm" crates/fp-wasm

echo "==> WASM build complete"
