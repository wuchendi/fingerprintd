import { createClient as createNodeClient } from '@libsql/client'
import { createClient as createWebClient } from '@libsql/client/web'
import { describe, expect, it } from 'vitest'

// The setup module wraps both client factories so every suite fails the way
// D1 would on a statement that binds more than 100 parameters.
function select(n: number) {
  return {
    sql: `SELECT ${Array.from({ length: n }, () => '?').join(', ')}`,
    args: Array.from({ length: n }, (_, i) => i),
  }
}

describe('D1 bound-parameter guard', () => {
  it('rejects 101 parameters on execute', async () => {
    const client = createNodeClient({ url: ':memory:' })
    await expect(client.execute(select(101))).rejects.toThrow(
      /^D1 bound-parameter cap: 101 > 100: SELECT \?/,
    )
    const { sql, args } = select(101)
    await expect(client.execute(sql, args)).rejects.toThrow(
      'D1 bound-parameter cap: 101 > 100',
    )
  })

  it('counts named arguments', async () => {
    const client = createNodeClient({ url: ':memory:' })
    const args = Object.fromEntries(
      Array.from({ length: 101 }, (_, i) => [`p${i}`, i]),
    )
    const sql = `SELECT ${Object.keys(args)
      .map((k) => `:${k}`)
      .join(', ')}`
    await expect(client.execute({ sql, args })).rejects.toThrow(
      'D1 bound-parameter cap: 101 > 100',
    )
  })

  it('rejects 101 parameters inside a batch', async () => {
    const client = createNodeClient({ url: ':memory:' })
    await expect(
      client.batch(['SELECT 1', select(101)], 'write'),
    ).rejects.toThrow('D1 bound-parameter cap: 101 > 100')
    const { sql, args } = select(101)
    await expect(client.batch([[sql, args]])).rejects.toThrow(
      'D1 bound-parameter cap: 101 > 100',
    )
  })

  it('passes 100 parameters through', async () => {
    const client = createNodeClient({ url: ':memory:' })
    const one = await client.execute(select(100))
    expect(one.columns).toHaveLength(100)
    const many = await client.batch(['SELECT 1', select(100)], 'write')
    expect(many).toHaveLength(2)
  })

  it('wraps clients from @libsql/client/web too', async () => {
    // Nothing listens here: a statement under the cap reaches the network and
    // fails there, one over the cap never leaves the guard.
    const client = createWebClient({ url: 'http://127.0.0.1:9' })
    await expect(client.execute(select(101))).rejects.toThrow(
      'D1 bound-parameter cap: 101 > 100',
    )
    await expect(client.batch([select(101)], 'write')).rejects.toThrow(
      'D1 bound-parameter cap: 101 > 100',
    )
    await expect(client.execute(select(100))).rejects.not.toThrow(
      'D1 bound-parameter cap',
    )
    client.close()
  })
})
