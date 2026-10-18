/**
 * The TS component schema must equal the Rust `COMPONENT_KEYS` the server
 * matches on — same names, same order.
 */

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { COMPONENT_KEYS } from '../../src/schema'

// vitest runs with cwd = packages/client.
const COMPONENT_RS = resolve(
  process.cwd(),
  '../../crates/fp-core/src/fuzzy/component.rs',
)

function rustComponentKeys(): string[] {
  const source = readFileSync(COMPONENT_RS, 'utf8')
  const body = source.match(
    /pub const COMPONENT_KEYS: \[&str; \d+\] = \[([\s\S]*?)\];/,
  )?.[1]
  if (body === undefined) throw new Error('COMPONENT_KEYS not found')
  return [...body.matchAll(/"([^"]*)"/g)].map((m) => m[1] as string)
}

describe('COMPONENT_KEYS', () => {
  it('equals the Rust COMPONENT_KEYS in order', () => {
    const rust = rustComponentKeys()
    expect(rust.length).toBe(18)
    expect([...COMPONENT_KEYS]).toEqual(rust)
  })
})
