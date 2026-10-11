# Red-team harness: CloakBrowser vs fingerprintd

Runs the **real** client collector (`packages/client` FingerprintJS + BotD,
adapted to the server schema) plus four known-answer integrity measurements
inside a fingerprint-noising browser (CloakBrowser, free binary) and inside stock
Chromium as the negative control. Each run produces one JSON capture:

```json
{
  "meta": { "label", "mode", "controller", "binary", "persona", "seed", "args", "captured_at" },
  "user_agent": "...",
  "stable_components": { "...exactly what /identify would receive..." },
  "integrity_measurements": { "canvas", "webgl", "audio", "rect" }
}
```

## Run

```bash
bash scripts/redteam/cloak/run.sh                       # default seeds + stock control
SEEDS=12345,12345,54321,random,off PERSONA=windows bash scripts/redteam/cloak/run.sh
SKIP_STOCK=1 bash scripts/redteam/cloak/run.sh          # adversary only
```

Requires Docker (containers are launched as labelled siblings, `--label
ai-agent=true`, with the harness directory mounted read-only except `out/`) and
`bun` for the page bundle. The CloakBrowser image is ~2.5 GB; the stock control
installs `playwright-core` at runtime. Captures land in `out/runs/` (gitignored).
Not part of CI.

## Fixtures

Curated captures are checked in under
`crates/fp-core/tests/fixtures/cloakbrowser/` and drive the engine behaviour
tests in `crates/fp-core/tests/cloakbrowser_fixtures.rs` and the client
integrity-probe tests. File names carry binary, persona and seed so a capture
from a newer binary can be added beside the old one.

## Layout

- `page/harness.ts` — browser entry; exposes `window.__fingerprintdHarness()`.
- the four measurements live in `packages/client/src/integrity.ts` (the SDK owns them; the page imports measure + evaluate).
- `driver.mjs` — runs inside the container; serves the page via `page.route`.
- `run.sh` — host orchestrator.
