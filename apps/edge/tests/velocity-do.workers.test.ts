import { env } from 'cloudflare:test'
import { describe, expect, it } from 'vitest'
import { VelocityStore } from '../src/lib/do/velocity-do'

// The new-device velocity counter against the real runtime: the
// VelocityDurableObject maintains a bounded rolling distinct-member window per IP,
// exercised through workerd/miniflare with the wrangler.jsonc `VELOCITY`
// binding live.

const MINUTE = 60 * 1000

/** Sleep `ms` real milliseconds (miniflare advances real time). */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

describe('new-device velocity per IP', () => {
  it('counts distinct new devices and does not double-count a repeat', async () => {
    const store = new VelocityStore(env.VELOCITY)
    // Each new device mints a fresh visitor id, so the distinct ids seen for
    // the IP are the new-device count the engine bands.
    expect(await store.newDeviceVelocityIp('1.2.3.4', 'v1', MINUTE)).toBe(1)
    expect(await store.newDeviceVelocityIp('1.2.3.4', 'v2', MINUTE)).toBe(2)
    expect(await store.newDeviceVelocityIp('1.2.3.4', 'v1', MINUTE)).toBe(2)
    expect(await store.newDeviceVelocityIp('1.2.3.4', 'v3', MINUTE)).toBe(3)
  })

  it('keeps every IP window independent', async () => {
    const store = new VelocityStore(env.VELOCITY)
    await store.newDeviceVelocityIp('10.0.0.1', 'v1', MINUTE)
    await store.newDeviceVelocityIp('10.0.0.1', 'v2', MINUTE)
    // A different IP is a different instance, starting from empty.
    expect(await store.newDeviceVelocityIp('10.0.0.2', 'v1', MINUTE)).toBe(1)
  })

  it('caps the live members per IP at 64', async () => {
    const store = new VelocityStore(env.VELOCITY)
    let distinct = 0
    for (let i = 0; i < 70; i++) {
      distinct = await store.newDeviceVelocityIp('10.0.0.3', `v${i}`, MINUTE)
    }
    expect(distinct).toBe(64)
  }, 30_000)
})

describe('window expiry', () => {
  it('drops members whose window has lapsed', async () => {
    const store = new VelocityStore(env.VELOCITY)
    // Tiny window: the first visitor lapses before the second bump.
    expect(await store.newDeviceVelocityIp('192.0.2.1', 'v1', 5)).toBe(1)
    await sleep(25)
    // v1 has expired and is pruned; only v2 survives ⇒ distinct stays 1.
    expect(await store.newDeviceVelocityIp('192.0.2.1', 'v2', 5)).toBe(1)
  })
})
