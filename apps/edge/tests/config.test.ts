import { describe, expect, it, vi } from 'vitest'
import type { Env } from '../src/config'
import { resolveConfig } from '../src/config'
import worker from '../src/index'

// The Worker entry imports the `.wasm` artifact, which only wrangler can load;
// the binding checks run before the engine is touched, so a stub suffices.
vi.mock('../wasm/fp_wasm_bg.wasm', () => ({ default: {} }))

describe('resolveConfig', () => {
  it('throws when FP_SALT_SECRET is unset', () => {
    expect(() => resolveConfig({})).toThrow('FP_SALT_SECRET is required')
  })

  it('throws when FP_SALT_SECRET is blank', () => {
    expect(() => resolveConfig({ FP_SALT_SECRET: '   ' })).toThrow(
      'FP_SALT_SECRET is required',
    )
  })

  it('trims secrets', () => {
    const config = resolveConfig({
      FP_SALT_SECRET: ' salt ',
      FP_PROBE_KEY: ' key ',
      FP_SIGNING_KEY: '\tsign\n',
      FP_ADMIN_KEY: ' admin ',
    })
    expect(config.saltSecret).toBe('salt')
    expect(config.probeKey).toBe('key')
    expect(config.signingKey).toBe('sign')
    expect(config.adminKey).toBe('admin')
  })

  it('treats a blank optional secret as unset', () => {
    const config = resolveConfig({ FP_SALT_SECRET: 's', FP_PROBE_KEY: '  ' })
    expect(config.probeKey).toBeUndefined()
  })
})

describe('Worker entry bindings', () => {
  const binding = {} as DurableObjectNamespace
  const full: Env = {
    NONCE: binding,
    VELOCITY: binding,
    RATE_LIMIT: { limit: () => Promise.resolve({ success: true }) },
    CHALLENGE_RATE_LIMIT: { limit: () => Promise.resolve({ success: true }) },
    FP_SALT_SECRET: 'salt',
  }
  const fetchWith = (env: Env) =>
    worker.fetch(new Request('https://edge.test/health'), env)

  it('throws when NONCE is unbound', async () => {
    await expect(fetchWith({ ...full, NONCE: undefined })).rejects.toThrow(
      'NONCE Durable Object binding is required',
    )
  })

  it('throws when VELOCITY is unbound', async () => {
    await expect(fetchWith({ ...full, VELOCITY: undefined })).rejects.toThrow(
      'VELOCITY Durable Object binding is required',
    )
  })

  it('throws when RATE_LIMIT is unbound', async () => {
    await expect(fetchWith({ ...full, RATE_LIMIT: undefined })).rejects.toThrow(
      'RATE_LIMIT rate-limit binding is required',
    )
  })

  it('throws when CHALLENGE_RATE_LIMIT is unbound', async () => {
    await expect(
      fetchWith({ ...full, CHALLENGE_RATE_LIMIT: undefined }),
    ).rejects.toThrow('CHALLENGE_RATE_LIMIT rate-limit binding is required')
  })

  it('throws when FP_SALT_SECRET is unset', async () => {
    await expect(
      fetchWith({ ...full, FP_SALT_SECRET: undefined }),
    ).rejects.toThrow('FP_SALT_SECRET is required')
  })

  it('throws when the database is not configured', async () => {
    await expect(fetchWith(full)).rejects.toThrow('LIBSQL_URL')
  })
})
