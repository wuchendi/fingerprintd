#!/usr/bin/env bash
# run.sh — reproducible CloakBrowser vs stock-Chromium capture (red-team harness).
#
# Builds the browser-side harness page (real SDK collector + integrity
# measurements), then runs it inside two labelled sibling containers:
#   1. cloakhq/cloakbrowser          — the adversary (free binary), N seeds
#   2. mcr.microsoft.com/playwright  — stock Chromium negative control
# One JSON per run lands in scripts/redteam/cloak/out/runs/ (gitignored).
#
# Usage:
#   bash scripts/redteam/cloak/run.sh                 # default seeds + control
#   SEEDS=12345,12345,54321,random,off PERSONA=windows bash scripts/redteam/cloak/run.sh
#   SKIP_STOCK=1 bash scripts/redteam/cloak/run.sh    # adversary only
#   SKIP_CLOAK=1 bash scripts/redteam/cloak/run.sh    # stock engines only (no 2.5 GB image)
#
# Requires: docker (sibling containers on the host daemon), bun. Not part of CI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DIR="$ROOT/scripts/redteam/cloak"
OUT="$DIR/out"
SEEDS="${SEEDS:-12345,12345,54321,random,off}"
PERSONA="${PERSONA:-windows}"
CLOAK_IMAGE="${CLOAK_IMAGE:-cloakhq/cloakbrowser}"
STOCK_IMAGE="${STOCK_IMAGE:-mcr.microsoft.com/playwright:v1.61.1-noble}"
STOCK_PW="${STOCK_PW:-playwright-core@1.61.1}"
STOCK_CHROME="${STOCK_CHROME:-/ms-playwright/chromium-1228/chrome-linux64/chrome}"

# The agent sandbox aliases /work and /root; the host daemon needs host paths.
host_path() {
  case "$1" in
    /work/*) echo "/srv/station/work/${1#/work/}" ;;
    /root/*) echo "/srv/station/root/${1#/root/}" ;;
    *) echo "$1" ;;
  esac
}
HOST_DIR="$(host_path "$DIR")"

mkdir -p "$OUT/runs"
echo "==> building harness page"
bun build "$DIR/page/harness.ts" --target browser --outfile "$OUT/harness.js" >/dev/null

common=(--rm --label ai-agent=true --network traefik
  -v "$HOST_DIR/driver.mjs:/data/driver.mjs:ro"
  -v "$HOST_DIR/out:/data/out")

if [ -z "${SKIP_CLOAK:-}" ]; then
  echo "==> adversary: $CLOAK_IMAGE (persona=$PERSONA seeds=$SEEDS)"
  docker run "${common[@]}" --name "ai-agent-fingerprintd-redteam-cloak-$$" \
    -e CLOAKBROWSER_SUPPRESS_FONT_WARNING=1 \
    "$CLOAK_IMAGE" bash -c \
    'cp /data/driver.mjs /app/js/driver.mjs && node /app/js/driver.mjs --mode cloak --seeds "$0" --persona "$1" --page /data/out/harness.js --out /data/out/runs' \
    "$SEEDS" "$PERSONA" 2>&1 | grep -v "^$" | grep -E "^\[harness\]|Error|error" || true
fi

if [ -z "${SKIP_STOCK:-}" ]; then
  echo "==> control: $STOCK_IMAGE"
  # ESM ignores NODE_PATH: install playwright-core next to the driver copy.
  docker run "${common[@]}" --name "ai-agent-fingerprintd-redteam-stock-$$" \
    -e CHROME_EXE="$STOCK_CHROME" \
    "$STOCK_IMAGE" bash -c \
    'mkdir -p /tmp/w && cd /tmp/w && npm init -y >/dev/null 2>&1 && npm i "$0" --no-audit --no-fund --loglevel=error >/dev/null && cp /data/driver.mjs . && node driver.mjs --mode stock --page /data/out/harness.js --out /data/out/runs' \
    "$STOCK_PW" 2>&1 | grep -E "^\[harness\]|Error|error" || true
fi

echo "==> captures:"
ls -1 "$OUT/runs"
