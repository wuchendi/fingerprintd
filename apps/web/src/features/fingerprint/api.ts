/**
 * Playground flow runner.
 *
 * Drives the collect-only SDK end-to-end against a fingerprintd server and
 * returns every intermediate the UI visualizes, including the exact identify
 * body sent. The client never derives an id; the server judges, and the
 * `/identify` response is display-only — the authoritative result is fetched
 * server-to-server by `request_id`.
 */
import type {
  ChallengeResponse,
  IdentifyRequest,
  IdentifyResponse,
} from '@cdlab/fingerprintd'
import { createCollector, getChallenge, identify } from '@cdlab/fingerprintd'
import FingerprintJS from '@fingerprintjs/fingerprintjs'

/**
 * The client-side FingerprintJS verdict the SDK deliberately DISCARDS.
 * Surfaced here only so the playground can contrast a naive "trust the browser
 * hash" fingerprint against the server-authoritative `visitor_id`.
 */
export interface OriginalFingerprint {
  /** FingerprintJS's own `visitorId` hash — never sent to the server. */
  visitorId: string
}

/** Everything a single flow run produces. */
export interface FlowResult {
  challenge: ChallengeResponse
  /** The exact `POST /identify` body sent. */
  request: IdentifyRequest
  identity: IdentifyResponse
  /** The discarded client-side FingerprintJS verdict, kept for comparison. */
  original?: OriginalFingerprint
}

/** A single reason contributing to a check-in {@link AssessResponse}. */
export interface AssessReason {
  /** Stable machine code, e.g. `FP_RESET`. */
  code: string
  /** Human-readable explanation. */
  detail: string
}

/**
 * `POST /checkin/assess` response — the anti-farming decision for a business
 * account, keyed on an identify event's `request_id`. Server-to-server only.
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
  /** The fingerprintd visitor the decision was keyed on. */
  visitor_id: string
}

/** Run `getChallenge -> collect -> identify`. Throws on transport/HTTP errors. */
export async function runFlow(baseUrl: string): Promise<FlowResult> {
  const challenge = await getChallenge(baseUrl)

  // Capture FingerprintJS's own visitorId as a side effect of the SDK's
  // collection: the injected loader wraps the real agent so we observe the hash
  // the SDK throws away, without a second FingerprintJS pass or altering what is
  // sent to the server.
  let original: OriginalFingerprint | undefined
  const collect = createCollector({
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
  const collected = await collect()

  const request: IdentifyRequest = {
    nonce: challenge.nonce,
    ts: Date.now(),
    components: collected.components,
  }
  if (collected.user_agent !== undefined) {
    request.user_agent = collected.user_agent
  }
  if (collected.botd !== undefined) request.botd = collected.botd
  if (collected.integrity !== undefined) request.integrity = collected.integrity

  const identity = await identify(baseUrl, request)

  return { challenge, request, identity, original }
}
