import type { Client, InArgs, InStatement } from '@libsql/client'
import { vi } from 'vitest'

// The node suites run on libSQL, which has no bound-parameter cap, while D1
// caps each statement at 100. Wrap both client factories (the tests' node client
// and the production `@libsql/client/web` one) so a statement over the cap
// fails here the way it would on D1.
const D1_MAX_PARAMS = 100

type BatchItem = InStatement | [string, InArgs?]

function countArgs(args: InArgs | undefined): number {
  if (!args) return 0
  return Array.isArray(args) ? args.length : Object.keys(args).length
}

function check(stmt: BatchItem, args?: InArgs): void {
  let sql: string
  let n: number
  if (typeof stmt === 'string') {
    sql = stmt
    n = countArgs(args)
  } else if (Array.isArray(stmt)) {
    sql = stmt[0]
    n = countArgs(stmt[1])
  } else {
    sql = stmt.sql
    n = countArgs(stmt.args)
  }
  if (n > D1_MAX_PARAMS) {
    throw new Error(
      `D1 bound-parameter cap: ${n} > ${D1_MAX_PARAMS}: ${sql.slice(0, 80)}`,
    )
  }
}

function guard(client: Client): Client {
  const execute = client.execute.bind(client)
  const batch = client.batch.bind(client)
  client.execute = (async (stmt: InStatement, args?: InArgs) => {
    check(stmt, args)
    return execute(stmt as string, args)
  }) as Client['execute']
  client.batch = (async (stmts: BatchItem[], mode) => {
    for (const s of stmts) check(s)
    return batch(stmts, mode)
  }) as Client['batch']
  return client
}

async function wrapped(specifier: string) {
  const actual =
    await vi.importActual<typeof import('@libsql/client')>(specifier)
  return {
    ...actual,
    createClient: (config: Parameters<typeof actual.createClient>[0]) =>
      guard(actual.createClient(config)),
  }
}

vi.mock('@libsql/client', () => wrapped('@libsql/client'))
vi.mock('@libsql/client/web', () => wrapped('@libsql/client/web'))
