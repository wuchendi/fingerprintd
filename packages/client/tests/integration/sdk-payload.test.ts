/**
 * REAL-DEVICE PAYLOADS — `components` exactly as the SDK sent them to
 * `/identify` from a real device (`tests/fixtures/sdk-payload/`), checked
 * against Contract v1.
 *
 * Complements `fjs-contract.test.ts`: those fixtures are raw FingerprintJS
 * output from headless container browsers (no fonts, software GPU); these are
 * the adapted output of real hardware (real fonts, a real GPU string). They are
 * adapted payloads, not raw captures, so they do NOT go through the adapter.
 */

import { readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import type { Components } from '../../src/schema'
import { COMPONENT_KEYS } from '../../src/schema'
import type { IdentifyRequest } from '../../src/types'
import { IDENTIFY_REQUEST_KEYS, schemaViolations } from '../helpers'

const FIXTURE_DIR = resolve(process.cwd(), 'tests/fixtures/sdk-payload')

interface Payload {
  user_agent: string
  components: Record<string, unknown>
}

const fixtures = readdirSync(FIXTURE_DIR)
  .filter((f) => f.endsWith('.json'))
  .map((f) => ({
    file: f,
    payload: JSON.parse(
      readFileSync(resolve(FIXTURE_DIR, f), 'utf8'),
    ) as Payload,
  }))

describe('real-device SDK payloads', () => {
  it('has at least one real-device payload', () => {
    expect(fixtures.length).toBeGreaterThan(0)
  })

  for (const { file, payload } of fixtures) {
    describe(file, () => {
      it('carries only closed-schema components of the right kind', () => {
        expect(Object.keys(payload.components).length).toBeGreaterThan(0)
        expect(schemaViolations(payload.components, COMPONENT_KEYS)).toEqual([])
      })

      it('builds an identify body with only Contract v1 top-level keys', () => {
        const body: IdentifyRequest = {
          nonce: 'n',
          ts: Date.now(),
          components: payload.components as Components,
          user_agent: payload.user_agent,
        }
        const wire = JSON.parse(JSON.stringify(body))
        for (const key of Object.keys(wire)) {
          expect(IDENTIFY_REQUEST_KEYS).toContain(key)
        }
        expect(wire.ts).toBeTypeOf('number')
      })
    })
  }
})
