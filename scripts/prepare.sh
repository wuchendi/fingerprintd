#!/usr/bin/env bash
# prepare.sh — runs during `bun install` (the repo-root `prepare` lifecycle).
# Builds the workspace packages (the SDK) so a fresh install yields a
# ready-to-consume @cdlab/fingerprintd.
#
# The SDK imports the vendored WASM under packages/client/wasm, which is a BUILD
# ARTIFACT and NOT committed. When it is missing (fresh clone / after clean):
#   - if a Rust toolchain + wasm-pack are available, build it automatically so a
#     single `bun install` sets everything up;
#   - otherwise skip with a hint, so a JS-only install still succeeds.
# Either way `bun install` must NEVER hard-fail: the auto-build is best-effort —
# a failed WASM build warns and skips the SDK prebuild rather than aborting.
#
# Note: this only fires when the WASM dir is ABSENT, so a normal install (WASM
# already built) never recompiles Rust. In CI/deploy the WASM is materialised
# before install, so this path is not taken there.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

build_sdk() { exec bun run --filter=./packages/* build; }

# WASM already vendored — just build the SDK (original prepare behavior).
if [ -f "$ROOT/packages/client/wasm/fp_wasm.js" ]; then
  build_sdk
fi

# WASM absent — auto-build it when the toolchain is available.
# shellcheck source=/dev/null
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "prepare: vendored WASM missing (packages/client/wasm) and wasm-pack not found — skipping SDK prebuild."
  echo "prepare: install a Rust toolchain + 'cargo install wasm-pack', then run 'bun run build:wasm'."
  exit 0
fi

echo "prepare: vendored WASM missing — building it from crates/fp-wasm (wasm-pack detected), this may take a moment…"
if bash "$ROOT/scripts/build-wasm.sh"; then
  build_sdk
else
  echo "prepare: WARNING — WASM build failed; skipping SDK prebuild (install continues)." >&2
  echo "prepare: fix the toolchain, then run 'bun run build:wasm && bun run build'." >&2
  exit 0
fi
