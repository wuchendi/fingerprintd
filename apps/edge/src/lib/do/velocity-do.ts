/**
 * Cross-session new-device velocity counters as a Durable Object.
 *
 * Every `new_device` verdict on `/identify` mints a fresh visitor id; the edge
 * counts how many distinct ones an IP produced inside a rolling window and the
 * WASM engine bands that count like `fingerprintd::fuzzy::velocity`. A
 * Durable Object gives the edge the primitive the database cannot: a
 * single-threaded instance whose storage is serialized, so a distinct-member
 * count is maintained incrementally and read atomically on the hot path.
 *
 * ONE INSTANCE PER KEY: the host addresses the DO by `idFromName(scopeKey)`
 * (`nv:<ip>`), so each key's rolling window lives in its own instance. Each
 * `bump` records the member (the minted visitor id) with an expiry, prunes
 * lapsed members, caps the live set at {@link MAX_IDS_PER_KEY}, and returns the
 * live distinct count. An alarm at the furthest expiry evicts a fully-lapsed
 * instance so storage does not leak.
 */

/** The single storage key each per-key instance holds. */
const RECORD_KEY = 'members'

/** Most live members kept per key (native `MAX_IDS_PER_KEY`): the earliest to
 *  expire are dropped first, so storage stays bounded while the count still
 *  saturates far above the `high` band. */
const MAX_IDS_PER_KEY = 64

/** Live members of one key's window: `memberId -> absolute expiry (Unix ms)`. */
type MemberMap = Record<string, number>

/**
 * Durable Object backing one key's rolling distinct-member window. The HTTP
 * surface is internal — only {@link VelocityStore} calls it — with one route:
 *   - `POST /bump?member=<id>&window=<ms>` — record the member for `window` ms,
 *     prune lapsed members, and return `{ distinct }` (the live count).
 */
export class VelocityDurableObject {
  constructor(private readonly state: DurableObjectState) {}

  fetch(request: Request): Promise<Response> {
    const url = new URL(request.url)
    if (request.method === 'POST' && url.pathname === '/bump') {
      const member = url.searchParams.get('member') ?? ''
      const windowMs = Number(url.searchParams.get('window'))
      return this.bump(member, windowMs)
    }
    return Promise.resolve(new Response('not found', { status: 404 }))
  }

  /**
   * Record `member` as live for `windowMs`, drop any member whose expiry has
   * passed, cap the live set, persist the pruned map, and return the surviving distinct count. The
   * read-prune-write runs in one serialized invocation on this single-threaded
   * instance, so concurrent bumps of the same key cannot lose an update.
   */
  private async bump(member: string, windowMs: number): Promise<Response> {
    const now = Date.now()
    const members = (await this.state.storage.get<MemberMap>(RECORD_KEY)) ?? {}
    for (const [id, expiresAt] of Object.entries(members)) {
      if (expiresAt <= now) delete members[id]
    }
    members[member] = now + windowMs
    const live = Object.entries(members)
    if (live.length > MAX_IDS_PER_KEY) {
      live.sort((a, b) => a[1] - b[1])
      for (const [id] of live.slice(0, live.length - MAX_IDS_PER_KEY)) {
        delete members[id]
      }
    }
    await this.state.storage.put<MemberMap>(RECORD_KEY, members)
    // Reclaim the instance once the last member lapses, so a key that goes
    // quiet does not leak storage. The alarm re-checks on fire (below).
    const furthest = Math.max(...Object.values(members))
    await this.state.storage.setAlarm(furthest)
    return Response.json({ distinct: Object.keys(members).length })
  }

  /**
   * Eviction sweep: drop lapsed members and either delete the record (window
   * fully drained) or re-arm the alarm to the next expiry. Cannot assume all
   * members lapsed — a bump after the alarm was set may have extended the window.
   */
  async alarm(): Promise<void> {
    const now = Date.now()
    const members = (await this.state.storage.get<MemberMap>(RECORD_KEY)) ?? {}
    for (const [id, expiresAt] of Object.entries(members)) {
      if (expiresAt <= now) delete members[id]
    }
    if (Object.keys(members).length === 0) {
      await this.state.storage.delete(RECORD_KEY)
      return
    }
    await this.state.storage.put<MemberMap>(RECORD_KEY, members)
    await this.state.storage.setAlarm(Math.max(...Object.values(members)))
  }
}

/**
 * The cross-session new-device velocity surface the `/identify` path consumes:
 * distinct new devices minted for an IP inside the rolling window.
 * {@link VelocityStore} implements it over the DO; unit tests inject a fake.
 */
export interface NewDeviceVelocityStore {
  /** Record `member` (the minted visitor id) as a new device for `ip` and
   *  return the distinct count within `windowMs`. */
  newDeviceVelocityIp(
    ip: string,
    member: string,
    windowMs: number,
  ): Promise<number>
}

/**
 * Host adapter presenting the new-device velocity counters over the
 * {@link VelocityDurableObject} binding. Each IP is addressed by
 * `idFromName('nv:' + ip)`, its own instance.
 */
export class VelocityStore implements NewDeviceVelocityStore {
  constructor(private readonly namespace: DurableObjectNamespace) {}

  /**
   * Distinct new devices minted for `ip` within `windowMs`. Every `new_device`
   * verdict mints a fresh visitor id, so the distinct-member count equals the
   * native per-IP new-device event count.
   */
  async newDeviceVelocityIp(
    ip: string,
    member: string,
    windowMs: number,
  ): Promise<number> {
    const stub = this.namespace.get(this.namespace.idFromName(`nv:${ip}`))
    const response = await stub.fetch(
      `https://velocity/bump?member=${encodeURIComponent(member)}&window=${windowMs}`,
      { method: 'POST' },
    )
    if (!response.ok) {
      throw new Error(`velocity bump failed: ${response.status}`)
    }
    const body = (await response.json()) as { distinct: number }
    return body.distinct
  }
}
