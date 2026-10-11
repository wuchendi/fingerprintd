/**
 * The one-time nonce store as a Durable Object.
 *
 * The native server keeps nonces in an in-process map with atomic check-and-burn
 * (`fingerprintd::nonce`). A Worker isolate cannot: it is ephemeral and unshared, and
 * D1 (or KV) replicates eventually with no atomic compare-and-delete, so a
 * replayed nonce could be accepted twice in the window between read and delete.
 * A Durable Object is the one edge primitive with the needed guarantee — a
 * single-threaded instance whose storage operations are serialized — so the
 * get-then-burn in {@link NonceDurableObject.consume} cannot interleave with a
 * concurrent replay of the same nonce.
 *
 * ONE INSTANCE PER NONCE: the host addresses the DO by `idFromName(nonce)`, so
 * each nonce's lifecycle lives in its own instance holding a single record. An
 * alarm set to the expiry burns an un-consumed nonce so storage does not leak.
 */

import type { NonceOutcome, NonceStore } from '../state'

/** The single storage key each per-nonce instance holds. */
const RECORD_KEY = 'nonce'

/** The stored nonce record: just its absolute expiry (Unix ms). */
interface NonceRecord {
  expiresAt: number
}

/**
 * Durable Object backing one nonce. Exactly one record (`RECORD_KEY`) exists per
 * instance for the nonce that addressed it. The HTTP surface is internal — only
 * {@link DurableNonceStore} calls it — with two routes:
 *   - `POST /issue?ttl=<secs>` — persist the nonce with a TTL and cleanup alarm.
 *   - `POST /consume`          — atomically burn it, returning its {@link NonceOutcome}.
 */
export class NonceDurableObject {
  constructor(private readonly state: DurableObjectState) {}

  fetch(request: Request): Promise<Response> {
    const url = new URL(request.url)
    if (request.method === 'POST' && url.pathname === '/issue') {
      const ttlSecs = Number(url.searchParams.get('ttl'))
      return this.issue(ttlSecs)
    }
    if (request.method === 'POST' && url.pathname === '/consume') {
      return this.consume()
    }
    return Promise.resolve(new Response('not found', { status: 404 }))
  }

  /** Persist the nonce with its expiry and an alarm to reclaim it if unused. */
  private async issue(ttlSecs: number): Promise<Response> {
    const expiresAt = Date.now() + ttlSecs * 1000
    await this.state.storage.put<NonceRecord>(RECORD_KEY, { expiresAt })
    // Reclaim an un-consumed nonce at expiry so per-nonce storage does not leak.
    // Only schedule the alarm when the nonce actually lives into the future: an
    // already-expired (ttl<=0) nonce needs no reclaim — consume() reports it
    // `expired` and removes it. Setting an alarm at a non-future `expiresAt`
    // would fire immediately and race consume(), deleting the record first so
    // the legitimate consume reads `unknown` instead of `expired`.
    if (ttlSecs > 0) {
      await this.state.storage.setAlarm(expiresAt)
    }
    return new Response(null, { status: 204 })
  }

  /**
   * Atomically consume the nonce. The read, burn, and expiry check run in one
   * serialized invocation on this single-threaded instance, so a replay of the
   * same nonce sees an already-empty record and is rejected.
   *
   * `reused` is folded into `unknown` (a burned nonce is simply gone), which
   * still yields the correct rejection; distinguishing them would need a
   * tombstone this one-time store does not keep.
   */
  private async consume(): Promise<Response> {
    const record = await this.state.storage.get<NonceRecord>(RECORD_KEY)
    if (record === undefined) return outcome('unknown')
    // Burn first: even an expired nonce is removed so it cannot be retried, and
    // the pending cleanup alarm is no longer needed.
    await this.state.storage.delete(RECORD_KEY)
    await this.state.storage.deleteAlarm()
    if (Date.now() > record.expiresAt) return outcome('expired')
    return outcome('valid')
  }

  /** Reclaim an un-consumed nonce once its TTL elapses. */
  async alarm(): Promise<void> {
    await this.state.storage.delete(RECORD_KEY)
  }
}

/** A `200 text/plain` response carrying a {@link NonceOutcome}. */
function outcome(value: NonceOutcome): Response {
  return new Response(value, { status: 200 })
}

/**
 * Host adapter presenting the {@link NonceStore} contract over the
 * {@link NonceDurableObject} binding. Each nonce is addressed by
 * `idFromName(nonce)`, so issue and consume route to that nonce's own instance.
 */
export class DurableNonceStore implements NonceStore {
  constructor(
    private readonly namespace: DurableObjectNamespace,
    private readonly ttlSecs: number,
  ) {}

  async issue(): Promise<{ nonce: string; ttlSecs: number }> {
    const nonce = crypto.randomUUID()
    const response = await this.stub(nonce).fetch(
      `https://nonce/issue?ttl=${this.ttlSecs}`,
      { method: 'POST' },
    )
    if (!response.ok) {
      throw new Error(`nonce issue failed: ${response.status}`)
    }
    return { nonce, ttlSecs: this.ttlSecs }
  }

  async consume(nonce: string): Promise<NonceOutcome> {
    const response = await this.stub(nonce).fetch('https://nonce/consume', {
      method: 'POST',
    })
    // Mirror `issue`'s guard: a non-ok (DO 5xx) body is an error string, not a
    // NonceOutcome. Coercing it would let a garbage value flow downstream; fail
    // closed to `unknown` so /identify still rejects with 401.
    if (!response.ok) {
      return 'unknown'
    }
    return (await response.text()) as NonceOutcome
  }

  /** The DO stub owning `nonce`'s lifecycle. */
  private stub(nonce: string): DurableObjectStub {
    return this.namespace.get(this.namespace.idFromName(nonce))
  }
}
