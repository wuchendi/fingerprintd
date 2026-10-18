import { create } from 'zustand'
import type { FlowResult } from './api'
import { runFlow } from './api'

type FlowStatus = 'idle' | 'running' | 'done' | 'error'

interface FingerprintState {
  baseUrl: string
  accountId: string
  status: FlowStatus
  error?: string
  result?: FlowResult
  setBaseUrl: (value: string) => void
  setAccountId: (value: string) => void
  run: () => Promise<void>
  reset: () => void
}

export const useFingerprintStore = create<FingerprintState>((set, get) => ({
  baseUrl: 'https://fingerprintd-edge.cdlab.workers.dev',
  accountId: 'user-123',
  status: 'idle',

  setBaseUrl: (value) => set({ baseUrl: value }),
  setAccountId: (value) => set({ accountId: value }),

  run: async () => {
    const trimmed = get().baseUrl.trim()
    if (trimmed === '') {
      set({ status: 'error', error: 'Enter a server base URL first.' })
      return
    }
    set({ status: 'running', error: undefined })
    try {
      const result = await runFlow(trimmed)
      set({ status: 'done', result })
    } catch (err) {
      set({
        status: 'error',
        error: err instanceof Error ? err.message : String(err),
      })
    }
  },

  reset: () => set({ status: 'idle', error: undefined, result: undefined }),
}))
