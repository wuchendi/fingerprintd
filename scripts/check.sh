#!/usr/bin/env bash
# check.sh — cross-stack quality gate for fingerprintd.
# Runs, in sequence, failing on the first red:
#   - Rust: cargo fmt --check, clippy -D warnings, nextest --all-features,
#     build --all-targets, cargo deny check
#   - WASM: cargo test -p fp-wasm, then the edge WASM build (apps/edge/wasm)
#   - TypeScript (every workspace, from the repo root): frozen bun install,
#     Biome, typecheck, test, build, and the edge Worker `deploy:dry` bundle
# Idempotent and self-contained; run from anywhere inside the repo.
set -euo pipefail

# Resolve repo root so the script works regardless of the caller's cwd.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# --- Rust gate -------------------------------------------------------------
# shellcheck source=/dev/null
source "$HOME/.cargo/env"
echo "==> Rust gate"
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features
cargo build --all-targets
cargo deny check

# --- WASM gate -------------------------------------------------------------
# Covered by --all-features above; run explicitly to guarantee the edge WASM
# core stays green on its own.
echo "==> WASM gate"
cargo test -p fp-wasm

# --- Edge WASM build -------------------------------------------------------
# The edge Worker bundles, and its tests read, apps/edge/wasm — a build
# artifact, not committed — so build it before the TS gate. The SDK
# (packages/client) is pure TypeScript and needs no WASM.
echo "==> Edge WASM build"
bash "$ROOT/scripts/build-wasm.sh"

# --- TypeScript gate -------------------------------------------------------
echo "==> TypeScript gate"
bun install --frozen-lockfile
bunx @biomejs/biome check .
bun run typecheck
bun run test
bun run build
bun run --filter @cdlab/fingerprintd-edge deploy:dry

echo "==> All gates green"
