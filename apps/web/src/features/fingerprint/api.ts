/**
 * Playground flow runner.
 *
 * Drives the collect-only SDK end-to-end against a fingerprintd server and
 * returns every intermediate the UI visualizes. The three evidence lanes
 * (`stable_components` / `probe` / `ts`) come straight out of the SDK's
 * {@link Collected} — the client never derives an id, the server judges.
 */
import type {
  ChallengeResponse,
  Collected,
  IdentifyRequest,
  IdentifyResponse,
} from '@cdlab/fingerprintd-client'
import {
  createCollector,
  getChallenge,
  identify,
  initProbe,
  verifySignature,
} from '@cdlab/fingerprintd-client'
import wasmUrl from '@cdlab/fingerprintd-client/wasm?url'
import FingerprintJS from '@fingerprintjs/fingerprintjs'

/**
 * Init the WASM probe once with the Vite-resolved asset URL. Passing the URL
 * explicitly is more robust under Vite than the SDK's default `import.meta.url`
 * fetch (which is brittle across a pre-bundled dependency). Idempotent: the
 * SDK's own `initProbe()` inside the collector reuses this singleton.
 */
let probeReady: Promise<void> | null = null
function ensureProbe(): Promise<void> {
  if (probeReady === null) probeReady = initProbe(wasmUrl)
  return probeReady
}

/** Response-signature summary for the UI. */
export interface SignatureInfo {
  /** The server sent both the timestamp and signature headers. */
  signed: boolean
  /** `x-fp-timestamp` — server issue time in Unix ms (string). */
  timestamp?: string
  /** `x-fp-signature` — hex HMAC-SHA256 of the response. */
  signature?: string
  /** Verification result; set only when a signing key was supplied AND signed. */
  valid?: boolean
}

/**
 * The client-side FingerprintJS verdict the SDK deliberately DISCARDS (§4.4).
 * Surfaced here only so the playground can contrast a naive "trust the browser
 * hash" fingerprint against the server-authoritative visitorId.
 */
export interface OriginalFingerprint {
  /** FingerprintJS's own `visitorId` hash — never sent to the server. */
  visitorId: string
}

/** Everything a single flow run produces. */
export interface FlowResult {
  challenge: ChallengeResponse
  collected: Collected
  identity: IdentifyResponse
  signature: SignatureInfo
  /** The discarded client-side FingerprintJS verdict, kept for comparison. */
  original?: OriginalFingerprint
}

/** A single reason contributing to a check-in {@link AssessResponse}. */
export interface AssessReason {
  /** Stable machine code, e.g. `NEW_DEVICE`. */
  code: string
  /** Human-readable explanation. */
  detail: string
}

/**
 * `POST /checkin/assess` response — the anti-farming decision layered on top of
 * a fingerprintd `IdentifyResponse` for a given business `accountId`.
 */
export interface AssessResponse {
  /** Gate action to take. */
  decision: 'allow' | 'challenge' | 'deny'
  /** Interpreted risk label. */
  verdict: 'human' | 'suspicious' | 'farming'
  /** Continuous risk score in `[0.0, 1.0]`. */
  risk: number
  /** Ordered reasons that produced the decision. */
  reasons: AssessReason[]
  /** Echoed fingerprintd visitorId the decision was keyed on. */
  visitorId: string
}

/**
 * `POST {baseUrl}/checkin/assess` — score a check-in for farming, reusing the
 * `IdentifyResponse` already obtained from `/identify` (the two are independent
 * routes; identify is never re-run). `ip`/`ts` are observed server-side and are
 * deliberately not sent. Throws on transport/HTTP errors.
 */
export async function assessCheckin(
  baseUrl: string,
  accountId: string,
  identity: IdentifyResponse,
): Promise<AssessResponse> {
  const url = `${baseUrl.replace(/\/+$/, '')}/checkin/assess`
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({
      accountId,
      action: 'daily_checkin',
      identify: identity,
    }),
  })
  if (!response.ok) {
    throw new Error(`POST /checkin/assess failed: ${response.status}`)
  }
  return (await response.json()) as AssessResponse
}

/**
 * Run `getChallenge -> collect -> identify`, verifying the response signature
 * when `signingKey` is a non-empty UTF-8 key. Throws on transport/HTTP errors.
 */
export async function runFlow(
  baseUrl: string,
  signingKey: string,
): Promise<FlowResult> {
  await ensureProbe()

  const challenge = await getChallenge(baseUrl)

  // Capture FingerprintJS's own visitorId as a side effect of the SDK's stable
  // collection: the injected loader wraps the real agent so we observe the hash
  // the SDK throws away, without a second FingerprintJS pass or altering what is
  // sent to the server (only `stable_components` still ships).
  let original: OriginalFingerprint | undefined
  const collector = createCollector({
    fingerprint: {
      loadFingerprint: async () => {
        const agent = await FingerprintJS.load()
        return {
          get: async () => {
            const res = await agent.get()
            original = { visitorId: res.visitorId }
            return res
          },
        }
      },
    },
  })
  const collected = await collector(challenge)

  const request: IdentifyRequest = {
    nonce: challenge.nonce,
    stable_components: collected.stable_components,
  }
  if (collected.ts !== undefined) request.ts = collected.ts
  if (collected.probe !== undefined) request.probe = collected.probe
  if (collected.integrity !== undefined) request.integrity = collected.integrity

  const { result, bodyBytes, timestamp, signature } = await identify(
    baseUrl,
    request,
  )

  const signed = timestamp !== undefined && signature !== undefined
  const info: SignatureInfo = { signed, timestamp, signature }
  if (signed && signingKey.trim() !== '') {
    const key = new TextEncoder().encode(signingKey)
    info.valid = await verifySignature(
      key,
      Number(timestamp),
      bodyBytes,
      signature as string,
    )
  }

  return { challenge, collected, identity: result, signature: info, original }
}
