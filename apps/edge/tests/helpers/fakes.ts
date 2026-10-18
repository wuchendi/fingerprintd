/**
 * In-memory test doubles for the injected {@link Deps} stores, so the Node
 * suites drive the Hono app without the Workers runtime or a Durable Object. Production wires the durable implementations in
 * `src/index.ts`; none of these are reachable from `src/`.
 */

import { createClient } from '@libsql/client'
import { drizzle } from 'drizzle-orm/libsql'
import { migrate } from 'drizzle-orm/libsql/migrator'
import type { Deps, RateLimiter } from '../../src/app'
import type { Db } from '../../src/db/client'
import * as schema from '../../src/db/schema'
import type { NewDeviceVelocityStore } from '../../src/lib/do/velocity-do'
import type {
  Candidate,
  CandidateSource,
  EventLog,
  NonceOutcome,
  NonceStore,
  StoredEvent,
} from '../../src/lib/state'
import { randomId } from '../../src/lib/state'
import type { ScoreOutcome } from '../../src/lib/types'
import type {
  AggregateResult,
  CheckinEvent,
  CheckinStore,
  RecordResult,
} from '../../src/modules/checkin'

/** One-time nonce store over a `Map`: burns on consume, expires by TTL. A
 *  burned nonce is simply gone, so a replay reports `unknown`. */
export class InMemoryNonceStore implements NonceStore {
  /** nonce -> Unix-millisecond expiry. */
  private readonly live = new Map<string, number>()

  constructor(private readonly ttlSecs: number) {}

  issue(): Promise<{ nonce: string; ttlSecs: number }> {
    const nonce = crypto.randomUUID()
    this.live.set(nonce, Date.now() + this.ttlSecs * 1000)
    return Promise.resolve({ nonce, ttlSecs: this.ttlSecs })
  }

  consume(nonce: string): Promise<NonceOutcome> {
    const expiry = this.live.get(nonce)
    if (expiry === undefined) return Promise.resolve('unknown')
    // Burn first: even an expired nonce is removed so it cannot be retried.
    this.live.delete(nonce)
    if (Date.now() > expiry) return Promise.resolve('expired')
    return Promise.resolve('valid')
  }
}

/** Candidate source that recalls nothing and never persists — every probe is
 *  judged a new device under a freshly minted id. */
export class EmptyCandidateSource implements CandidateSource {
  recall(_blockingKeys: string[]): Promise<Candidate[]> {
    return Promise.resolve([])
  }

  persist(outcome: ScoreOutcome): Promise<string> {
    return Promise.resolve(outcome.visitor_id ?? randomId())
  }

  erase(_id: string): Promise<void> {
    return Promise.resolve()
  }
}

/** Identify event log over a `Map`, honouring each event's expiry. */
export class InMemoryEventLog implements EventLog {
  readonly events = new Map<string, { event: StoredEvent; expiresAt: number }>()

  put(event: StoredEvent, expiresAt: number): Promise<void> {
    this.events.set(event.request_id, { event, expiresAt })
    return Promise.resolve()
  }

  get(requestId: string, nowMs: number): Promise<StoredEvent | undefined> {
    const entry = this.events.get(requestId)
    if (entry === undefined || entry.expiresAt <= nowMs) {
      return Promise.resolve(undefined)
    }
    return Promise.resolve(entry.event)
  }
}

/** A fresh all-zero {@link AggregateResult}, so a clean identify scores
 *  allow/human. A new object each call so no test mutates a shared instance. */
export function zeroAggregateResult(): AggregateResult {
  return {
    device_account_fanout: { h24: 0, d7: 0 },
    account_device_count: { d7: 0, d30: 0 },
    account_new_device_rate: { rate: 0, sampled: 0 },
    ip_account_count: { h1: 0, h24: 0 },
    checkin_interval_regularity: { regularity: 0, samples: 0 },
    batch_clustering: { device: 0, ip: 0 },
  }
}

/** Check-in store that drops every event and reports all-zero aggregates. */
export class EmptyCheckinStore implements CheckinStore {
  record(event: CheckinEvent): Promise<RecordResult> {
    return Promise.resolve({ inserted: true, account_id: event.account_id })
  }

  getAggregates(): Promise<AggregateResult> {
    return Promise.resolve(zeroAggregateResult())
  }
}

/** Velocity store that counts nothing, so every band stays `low`. */
export class NoopVelocityStore implements NewDeviceVelocityStore {
  newDeviceVelocityIp(): Promise<number> {
    return Promise.resolve(0)
  }
}

/** A fresh libSQL `:memory:` database migrated from the committed `./drizzle`
 *  set (behind the D1 parameter guard the node setup file installs). */
export async function memoryDb(): Promise<Db> {
  const libsql = drizzle(createClient({ url: ':memory:' }), { schema })
  await migrate(libsql, { migrationsFolder: './drizzle' })
  return libsql as unknown as Db
}

/** Rate limiter returning a fixed verdict and recording every key it saw. */
export class FakeRateLimiter implements RateLimiter {
  readonly keys: string[] = []

  constructor(private readonly allow = true) {}

  limit(options: { key: string }): Promise<{ success: boolean }> {
    this.keys.push(options.key)
    return Promise.resolve({ success: this.allow })
  }
}

/** The fake stores for a {@link Deps}, minus the engine + config the caller
 *  builds from its own environment. */
export function fakeStores(
  nonceTtlSecs: number,
): Omit<Deps, 'engine' | 'config'> {
  return {
    nonces: new InMemoryNonceStore(nonceTtlSecs),
    candidates: new EmptyCandidateSource(),
    events: new InMemoryEventLog(),
    checkin: new EmptyCheckinStore(),
    velocity: new NoopVelocityStore(),
    rateLimiter: new FakeRateLimiter(),
    challengeRateLimiter: new FakeRateLimiter(),
  }
}
