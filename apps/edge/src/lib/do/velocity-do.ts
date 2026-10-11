/**
 * Hot atomic velocity counters as a Durable Object.
 *
 * The windowed fan-out aggregates (`device_account_fanout`, `ip_account_count`)
 * are load-bearing but expensive: computing them from D1 means a `COUNT(DISTINCT)`
 * scan on every check-in. For the hottest entities — a device farm's shared
 * device, a proxy's shared IP — that scan repeats thousands of times a minute.
 * A Durable Object gives the edge primitive D1 cannot: a single-threaded
 * instance whose storage is serialized, so a distinct-member velocity count can
 * be maintained incrementally and read atomically without touching the table.
 *
 * ONE INSTANCE PER ENTITY: the host addresses the DO by `idFromName(scopeKey)`
 * (e.g. `v:<visitorId>` or `ip:<ip>`), so each entity's rolling window lives in
 * its own instance. Each `bump` records the member (the counterpart id) with an
 * expiry, prunes lapsed members, and returns the live distinct count. An alarm
 * at the furthest expiry evicts a fully-lapsed instance so storage does not leak.
 */

/** The single storage key each per-entity instance holds. */
const RECORD_KEY = 'members'

/** Live members of one entity's window: `memberId -> absolute expiry (Unix ms)`. */
type MemberMap = Record<string, number>

/**
 * Durable Object backing one entity's rolling distinct-member window. The HTTP
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
   * passed, persist the pruned map, and return the surviving distinct count. The
   * read-prune-write runs in one serialized invocation on this single-threaded
   * instance, so concurrent bumps of the same entity cannot lose an update.
   */
  private async bump(member: string, windowMs: number): Promise<Response> {
    const now = Date.now()
    const members = (await this.state.storage.get<MemberMap>(RECORD_KEY)) ?? {}
    for (const [id, expiresAt] of Object.entries(members)) {
      if (expiresAt <= now) delete members[id]
    }
    members[member] = now + windowMs
    await this.state.storage.put<MemberMap>(RECORD_KEY, members)
    // Reclaim the instance once the last member lapses, so an entity that goes
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
 * distinct new devices minted for an IP (or JA4 shape class) inside the rolling
 * window. {@link VelocityStore} implements it over the DO; a unit test injects a
 * fake. Kept structural so the router never depends on the concrete DO class.
 */
export interface NewDeviceVelocityStore {
  /** Distinct new devices minted for `ip` within `windowMs`. */
  newDeviceVelocityIp(
    ip: string,
    visitorId: string,
    windowMs: number,
  ): Promise<number>
  /** Distinct new devices minted for a JA4 shape `class` within `windowMs`. */
  newDeviceVelocityJa4(
    ja4Class: string,
    visitorId: string,
    windowMs: number,
  ): Promise<number>
}

/**
 * Host adapter presenting the hot velocity counters over the
 * {@link VelocityDurableObject} binding. Each entity is addressed by
 * `idFromName(scope + ':' + key)`, so a device's fan-out and an IP's velocity
 * route to independent instances.
 */
export class VelocityStore implements NewDeviceVelocityStore {
  constructor(private readonly namespace: DurableObjectNamespace) {}

  /**
   * Distinct new devices minted for `ip` within `windowMs` — the hot-path,
   * edge-side form of the per-IP new-device velocity (`fingerprintd_core::fuzzy::velocity`).
   * A `NewDevice` verdict always mints a fresh `visitorId`, so the distinct-member
   * count of visitorIds seen for the IP equals fp-core's new-device event count.
   */
  async newDeviceVelocityIp(
    ip: string,
    visitorId: string,
    windowMs: number,
  ): Promise<number> {
    return this.bump(`nv:${ip}`, visitorId, windowMs)
  }

  /**
   * Distinct new devices minted for a JA4 shape `class` within `windowMs` — the
   * secondary per-JA4-class new-device velocity (HARDEN-002). Namespaced `nvja4:`
   * so a class string can never collide with an `nv:` IP key in the shared store.
   */
  async newDeviceVelocityJa4(
    ja4Class: string,
    visitorId: string,
    windowMs: number,
  ): Promise<number> {
    return this.bump(`nvja4:${ja4Class}`, visitorId, windowMs)
  }

  /**
   * Distinct accounts seen on `visitorId` within `windowMs` — the hot-path form
   * of `device_account_fanout`. Bumps `accountId` and returns the live count.
   */
  async deviceAccountFanout(
    visitorId: string,
    accountId: string,
    windowMs: number,
  ): Promise<number> {
    return this.bump(`v:${visitorId}`, accountId, windowMs)
  }

  /**
   * Distinct accounts seen on `ip` within `windowMs` — the hot-path form of
   * `ip_account_count`. Bumps `accountId` and returns the live count.
   */
  async ipAccountVelocity(
    ip: string,
    accountId: string,
    windowMs: number,
  ): Promise<number> {
    return this.bump(`ip:${ip}`, accountId, windowMs)
  }

  /** Route a bump to the entity's own instance and return its distinct count. */
  private async bump(
    scopeKey: string,
    member: string,
    windowMs: number,
  ): Promise<number> {
    const stub = this.namespace.get(this.namespace.idFromName(scopeKey))
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
