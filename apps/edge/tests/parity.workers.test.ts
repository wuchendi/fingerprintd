import { env, SELF } from 'cloudflare:test'
import { beforeEach, describe, expect, it } from 'vitest'
import parityFixture from '../../../crates/fingerprintd/tests/fixtures/parity.json'
import type { IdentifyResponse } from '../src/lib/types'

// Edge half of the cross-stack parity proof.
//
// This drives the native parity vectors (`crates/fingerprintd/tests/fixtures/
// parity.json`, asserted natively by `crates/fingerprintd/tests/parity.rs`)
// through the full edge stack — the WASM engine, the nonce Durable Object, and
// the D1 stored-form index — in real workerd/miniflare. Both stacks assert the
// SAME `expect` block: decision, is_new_device, collision_risk, template_jump,
// confidence (to the fixture's tolerance), and the symbolic visitor labels
// (minted ids are random). No `cf-connecting-ip` is sent, so the new-device
// velocity stays `low` and moves nothing.
//
// The determinism hinges on the salt: `vitest.workers.config.ts` binds
// `FP_SALT_SECRET` to the fixture's `salt_secret` (asserted below).

interface Expect {
  decision: IdentifyResponse['decision']
  is_new_device: boolean
  /** Symbolic visitor label: same label ⇒ same id, different ⇒ different. */
  visitor: string
  collision_risk: boolean
  confidence: number
  template_jump: boolean
}

interface ParityFixture {
  salt_secret: string
  confidence_tolerance: number
  components: Record<string, Record<string, unknown>>
  scenarios: Array<{
    name: string
    steps: Array<{ input: string; expect: Expect }>
  }>
}

const fixture = parityFixture as ParityFixture

const HEX32 = /^[0-9a-f]{32}$/

/** Run one `/identify` against the real Worker: fresh nonce, then score. */
async function identify(
  components: Record<string, unknown>,
): Promise<{ status: number; body: IdentifyResponse }> {
  const challenge = await SELF.fetch('https://edge.test/challenge')
  const { nonce } = (await challenge.json()) as { nonce: string }
  const resp = await SELF.fetch('https://edge.test/identify', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ nonce, ts: Date.now(), components }),
  })
  return { status: resp.status, body: (await resp.json()) as IdentifyResponse }
}

// Storage isolation is per test FILE, so empty the store before each scenario
// — matching the fresh store the native test builds per scenario.
beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM blocking_index'),
    env.DB.prepare('DELETE FROM templates'),
    env.DB.prepare('DELETE FROM erased_visitors'),
  ])
})

describe('cross-stack parity (Worker == native)', () => {
  it('runs with the salt the fixture was generated under', () => {
    expect(env.FP_SALT_SECRET).toBe(fixture.salt_secret)
  })

  for (const scenario of fixture.scenarios) {
    it(scenario.name, async () => {
      const labels = new Map<string, string>()

      for (const [i, step] of scenario.steps.entries()) {
        const components = fixture.components[step.input]
        expect(components, `component input ${step.input}`).toBeDefined()
        if (components === undefined) return

        const { status, body } = await identify(components)
        const e = step.expect

        expect(status, `status @ step ${i}`).toBe(200)
        expect(body.decision, `decision @ step ${i}`).toBe(e.decision)
        expect(body.is_new_device, `is_new_device @ step ${i}`).toBe(
          e.is_new_device,
        )
        expect(body.collision_risk, `collision_risk @ step ${i}`).toBe(
          e.collision_risk,
        )
        expect(body.signals.template_jump, `template_jump @ step ${i}`).toBe(
          e.template_jump,
        )
        expect(
          Math.abs(body.confidence - e.confidence),
          `confidence @ step ${i}: got ${body.confidence}, expected ${e.confidence}`,
        ).toBeLessThanOrEqual(fixture.confidence_tolerance)
        expect(body.visitor_id, `visitor_id @ step ${i}`).toMatch(HEX32)

        const seen = labels.get(e.visitor)
        if (seen === undefined) {
          // A new label must resolve to an id no other label holds.
          expect(
            [...labels.values()],
            `visitor '${e.visitor}' distinct @ step ${i}`,
          ).not.toContain(body.visitor_id)
          labels.set(e.visitor, body.visitor_id)
        } else {
          expect(body.visitor_id, `visitor '${e.visitor}' @ step ${i}`).toBe(
            seen,
          )
        }
      }
    })
  }
})
