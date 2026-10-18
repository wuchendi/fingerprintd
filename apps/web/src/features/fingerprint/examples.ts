import type { AssessResponse } from './api'

/**
 * Representative `POST /checkin/assess` outcomes across the three decision bands.
 * The assessment is a server-to-server call the browser never makes (and the
 * farming case needs a real device farm), so these canned examples let the
 * playground demonstrate the full anti-farming range offline. The reason
 * `code`s mirror the ones the edge risk engine emits.
 */
export interface CheckinExample {
  /** i18n key for the scenario caption shown above the card. */
  readonly captionKey: string
  readonly assess: AssessResponse
}

export const checkinExamples: readonly CheckinExample[] = [
  {
    captionKey: 'Returning human — allowed',
    assess: {
      decision: 'allow',
      verdict: 'human',
      risk: 0.05,
      reasons: [],
      visitor_id: 'vis-1a2b3c4d-returning',
    },
  },
  {
    captionKey: 'Device churn — challenged',
    assess: {
      decision: 'challenge',
      verdict: 'suspicious',
      risk: 0.4,
      reasons: [
        {
          code: 'FP_RESET',
          detail: 'Account shows a high rate of never-before-seen devices',
        },
      ],
      visitor_id: 'vis-7c8d9e0f-churn',
    },
  },
  {
    captionKey: 'Device farm — denied',
    assess: {
      decision: 'deny',
      verdict: 'farming',
      risk: 1,
      reasons: [
        {
          code: 'UA_TLS_MISMATCH',
          detail: 'User-Agent and edge-observed TLS fingerprint disagree',
        },
        {
          code: 'DATACENTER_IP',
          detail: 'Request originates from a high-risk (datacenter/proxy) IP',
        },
        {
          code: 'FP_RESET',
          detail: 'Account shows a high rate of never-before-seen devices',
        },
      ],
      visitor_id: 'vis-e5f6a7b8-farm',
    },
  },
]
