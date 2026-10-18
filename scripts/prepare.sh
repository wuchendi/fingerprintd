#!/usr/bin/env bash
# prepare.sh — runs during `bun install` (the repo-root `prepare` lifecycle).
#
# 1. Best-effort build of the edge Worker's WASM (apps/edge/wasm, a BUILD
#    ARTIFACT, not committed): only when it is missing AND wasm-pack is
#    available. A missing toolchain or a failed build warns and continues.
# 2. Build the workspace packages (the pure-TS SDK), so a fresh install yields
#    a ready-to-consume @cdlab/fingerprintd.
#
# `bun install` must NEVER hard-fail because of this script. In CI/deploy the
# WASM is materialised before install, so step 1 is skipped there.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -f "$ROOT/apps/edge/wasm/fp_wasm.js" ]; then
  # shellcheck source=/dev/null
  [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
  if ! command -v wasm-pack >/dev/null 2>&1; then
    echo "prepare: edge WASM missing (apps/edge/wasm) and wasm-pack not found — skipping it."
    echo "prepare: install a Rust toolchain + 'cargo install wasm-pack', then run 'bun run build:wasm'."
  else
    echo "prepare: edge WASM missing — building it from crates/fp-wasm (wasm-pack detected), this may take a moment…"
    if ! bash "$ROOT/scripts/build-wasm.sh"; then
      echo "prepare: WARNING — edge WASM build failed; continuing (run 'bun run build:wasm' once the toolchain is fixed)." >&2
    fi
  fi
fi

if ! (cd "$ROOT" && bun run --filter=./packages/* build); then
  echo "prepare: WARNING — SDK build failed; continuing (run 'bun run build')." >&2
fi
exit 0
