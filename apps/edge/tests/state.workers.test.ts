import { env, SELF } from 'cloudflare:test'
import { beforeEach, describe, expect, it } from 'vitest'
import { DurableNonceStore } from '../src/lib/do/nonce-do'

// The state layer against the real runtime: the nonce Durable Object burns
// atomically, and the Worker recalls + drifts templates through D1
// (`DB_TYPE=d1`). These run in workerd/miniflare with live bindings — no fakes.
// The store queries themselves are covered on libSQL in the node suite.

/** Empty the D1 tables so each test starts clean (isolated storage also resets,
 *  but this keeps the intent explicit and order-independent). */
beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM blocking_index'),
    env.DB.prepare('DELETE FROM templates'),
  ])
})

describe('nonce Durable Object (atomic burn)', () => {
  it('issues a nonce, admits it once, then rejects the replay', async () => {
    const store = new DurableNonceStore(env.NONCE, 30)
    const { nonce, ttlSecs } = await store.issue()
    expect(typeof nonce).toBe('string')
    expect(ttlSecs).toBe(30)

    // First consume burns it; the replay finds nothing.
    expect(await store.consume(nonce)).toBe('valid')
    expect(await store.consume(nonce)).toBe('unknown')
  })

  it('rejects a never-issued nonce as unknown', async () => {
    const store = new DurableNonceStore(env.NONCE, 30)
    expect(await store.consume('never-issued')).toBe('unknown')
  })

  it('reports an elapsed TTL as expired, still burning the nonce', async () => {
    // ttl 0 ⇒ the record expires immediately; a later consume (a separate DO
    // invocation, so time has advanced) sees it past expiry.
    const store = new DurableNonceStore(env.NONCE, 0)
    const { nonce } = await store.issue()
    expect(await store.consume(nonce)).toBe('expired')
    // Expired nonces are still removed, so a retry is unknown, not re-expired.
    expect(await store.consume(nonce)).toBe('unknown')
  })

  it('fails closed to unknown when the DO returns a non-ok response', async () => {
    // A DO 5xx returns an error string, not a NonceOutcome. Coercing it would
    // let a garbage value masquerade as a decision; consume() must instead fail
    // closed so /identify still rejects with 401. Stub a namespace whose stub
    // fetch resolves to a 500 with an error body.
    const namespace = {
      idFromName: (name: string) => name,
      get: () => ({
        fetch: () =>
          Promise.resolve(new Response('internal error', { status: 500 })),
      }),
    } as unknown as DurableObjectNamespace
    const store = new DurableNonceStore(namespace, 30)
    expect(await store.consume('any-nonce')).not.toBe('valid')
    expect(await store.consume('any-nonce')).toBe('unknown')
  })
})

describe('end-to-end through the Worker (WASM + DO + D1)', () => {
  /** A rich probe the fuzzy engine can score into a confident match. */
  const probe = {
    webgl: 'ANGLE (Intel)',
    platform: 'Linux x86_64',
    timezone: 'Asia/Shanghai',
    audio: '124.04',
    cpu_cores: 8,
    device_memory: 8,
    fonts: ['Arial', 'Helvetica', 'Courier', 'Times', 'Verdana'],
    user_agent: 'Chrome/120',
  }

  async function identify(components: unknown): Promise<{
    status: number
    body: { visitorId: string; is_new_device: boolean; decision: string }
  }> {
    const challenge = await SELF.fetch('https://edge.test/challenge')
    const { nonce } = (await challenge.json()) as { nonce: string }
    const resp = await SELF.fetch('https://edge.test/identify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ nonce, stable_components: components }),
    })
    return { status: resp.status, body: (await resp.json()) as never }
  }

  it('records a device on first sight and re-identifies it on the second', async () => {
    const first = await identify(probe)
    expect(first.status).toBe(200)
    expect(first.body.is_new_device).toBe(true)
    expect(first.body.decision).toBe('new_device')

    // The same device returns: recalled from D1, scored a match, same id.
    const second = await identify(probe)
    expect(second.status).toBe(200)
    expect(second.body.is_new_device).toBe(false)
    expect(second.body.decision).toBe('match')
    expect(second.body.visitorId).toBe(first.body.visitorId)
  })

  it('burns the nonce across the real Durable Object', async () => {
    const challenge = await SELF.fetch('https://edge.test/challenge')
    const { nonce } = (await challenge.json()) as { nonce: string }
    const send = () =>
      SELF.fetch('https://edge.test/identify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ nonce, stable_components: probe }),
      })
    expect((await send()).status).toBe(200)
    // Replaying the same nonce is rejected: the DO already burned it.
    expect((await send()).status).toBe(401)
  })
})
