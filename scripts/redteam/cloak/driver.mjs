/**
 * In-container driver for the red-team harness. Runs INSIDE the browser
 * container (CloakBrowser image or the stock Playwright image), never on the
 * host — `run.sh` launches it.
 *
 *   node driver.mjs --mode cloak --seeds 12345,12345,54321,random,off \
 *        --persona windows --page /data/out/harness.js --out /data/out/runs
 *   node driver.mjs --mode stock --page /data/out/harness.js --out /data/out/runs
 *
 * The harness page is served through `page.route` on `http://localhost/` (a
 * secure context, no HTTP server needed). One JSON file is written per run.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const args = Object.fromEntries(
  process.argv
    .slice(2)
    .map((a, i, all) => (a.startsWith('--') ? [a.slice(2), all[i + 1]] : null))
    .filter(Boolean),
)
const mode = args.mode ?? 'cloak'
const pageJs = readFileSync(args.page ?? '/data/out/harness.js', 'utf8')
const outDir = args.out ?? '/data/out/runs'
mkdirSync(outDir, { recursive: true })

const HTML =
  '<!doctype html><html><head><meta charset="utf-8"></head>' +
  '<body>fingerprintd red-team harness<script type="module" src="/harness.js"></script></body></html>'

async function capture(browser, meta) {
  const page = await browser.newPage()
  try {
    await page.route('http://localhost/**', (route) => {
      const url = new URL(route.request().url())
      if (url.pathname === '/harness.js') {
        return route.fulfill({
          status: 200,
          contentType: 'text/javascript',
          body: pageJs,
        })
      }
      return route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: HTML,
      })
    })
    await page.goto('http://localhost/')
    await page.waitForFunction(
      () => typeof window.__fingerprintdHarness === 'function',
    )
    const result = await page.evaluate(() => window.__fingerprintdHarness())
    const chromium = /Chrome\/(\d+)/.exec(result.user_agent)?.[1] ?? '0'
    return {
      meta: {
        ...meta,
        chromium_major: Number(chromium),
        captured_at: new Date().toISOString(),
      },
      ...result,
    }
  } finally {
    await page.close()
  }
}

function save(label, record) {
  const file = join(outDir, `${label}.json`)
  writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`)
  console.log(`[harness] ${label} -> ${file}`)
}

if (mode === 'cloak') {
  // The image ships the JS wrapper at /app/js (built from this repo's js/).
  const { launch } = await import('/app/js/dist/index.js')
  const persona = args.persona ?? 'windows'
  const seeds = (args.seeds ?? '12345,12345,54321,random,off').split(',')
  const seen = new Map()
  for (const seed of seeds) {
    const n = (seen.get(seed) ?? 0) + 1
    seen.set(seed, n)
    // Repeated seeds get -a/-b/… so same-seed determinism is visible by name.
    const repeated = seeds.filter((s) => s === seed).length > 1
    const suffix = repeated ? `-${String.fromCharCode(96 + n)}` : ''
    const label = `cloak-${persona}-${seed === 'off' ? 'fingerprint-off' : `seed-${seed}`}${suffix}`
    const launchArgs = ['--no-sandbox']
    if (seed === 'off') launchArgs.push('--fingerprint=off')
    else {
      launchArgs.push(`--fingerprint-platform=${persona}`)
      if (seed !== 'random') launchArgs.push(`--fingerprint=${seed}`)
    }
    // stealthArgs:false → we control every --fingerprint flag; 'random' re-adds
    // a wrapper-style random seed ourselves so the persona flag stays explicit.
    if (seed === 'random')
      launchArgs.push(
        `--fingerprint=${10000 + Math.floor(Math.random() * 90000)}`,
      )
    const browser = await launch({
      headless: true,
      stealthArgs: false,
      args: launchArgs,
    })
    try {
      const record = await capture(browser, {
        label,
        mode,
        controller: 'cloakbrowser-js-wrapper',
        binary: 'cloakbrowser-free',
        persona: seed === 'off' ? 'off' : persona,
        seed,
        args: launchArgs,
      })
      save(label, record)
    } finally {
      await browser.close()
    }
  }
} else {
  const { chromium } = await import('playwright-core')
  const exe = process.env.CHROME_EXE
  const variants = [
    ['stock-headless-shell', {}],
    ['stock-headless-new', { args: ['--headless=new'], executablePath: exe }],
  ]
  for (const [label, opts] of variants) {
    const browser = await chromium.launch({ headless: true, ...opts })
    try {
      const record = await capture(browser, {
        label,
        mode,
        controller: 'playwright-core',
        binary: 'stock-chromium',
        persona: 'native',
        seed: null,
        args: opts.args ?? [],
      })
      save(label, record)
    } finally {
      await browser.close()
    }
  }
}
