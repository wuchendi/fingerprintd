// Writes a copy of wrangler.jsonc with the commented-out `d1_databases` block
// enabled (libSQL is the default, so D1 stays commented in the real config).
// Used by cf:localdb / cf:remotedb:
//   bun scripts/d1-config.ts [outFile]   (cwd apps/edge, default wrangler.d1.jsonc)
import { readFileSync, writeFileSync } from 'node:fs'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

/** Uncomments the `// "d1_databases": [ ... // ],` block; nothing else changes. */
export function enableD1(source: string): string {
  const lines = source.split('\n')
  const start = lines.findIndex((l) => l.trim() === '// "d1_databases": [')
  const end = lines.findIndex((l, i) => i > start && l.trim() === '// ],')
  if (start < 0 || end < 0) {
    throw new Error('wrangler.jsonc: commented "d1_databases" block not found')
  }
  return lines
    .map((line, i) =>
      i < start || i > end ? line : line.replace(/^(\s*)\/\/ /, '$1'),
    )
    .join('\n')
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const out = process.argv[2] ?? 'wrangler.d1.jsonc'
  writeFileSync(out, enableD1(readFileSync('wrangler.jsonc', 'utf8')))
}
