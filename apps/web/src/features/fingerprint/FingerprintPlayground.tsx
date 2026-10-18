import { useTranslation } from 'react-i18next'
import { CheckinExamples } from './components/CheckinExamples'
import { CheckinFlowCard } from './components/CheckinFlowCard'
import { EmptyPipeline } from './components/EmptyPipeline'
import { EvidenceLanes } from './components/EvidenceLanes'
import { Hero } from './components/Hero'
import { IdentityCard } from './components/IdentityCard'
import { RunPanel } from './components/RunPanel'
import { useFingerprintStore } from './store'

export function FingerprintPlayground() {
  const { t } = useTranslation()
  const baseUrl = useFingerprintStore((s) => s.baseUrl)
  const accountId = useFingerprintStore((s) => s.accountId)
  const status = useFingerprintStore((s) => s.status)
  const error = useFingerprintStore((s) => s.error)
  const result = useFingerprintStore((s) => s.result)

  return (
    <>
      <Hero />
      <div className="mx-auto grid max-w-5xl grid-cols-1 gap-6 px-4 py-8 md:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <div className="min-w-0 space-y-6">
          <RunPanel />
          {error && (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
              <span className="font-semibold">{t('Flow failed')}: </span>
              {error}
            </div>
          )}
          {result && (
            <IdentityCard
              identity={result.identity}
              original={result.original}
            />
          )}
          {result && (
            <CheckinFlowCard
              baseUrl={baseUrl}
              accountId={accountId}
              requestId={result.identity.request_id}
            />
          )}
        </div>

        <div className="min-w-0 space-y-6">
          {result ? (
            <EvidenceLanes
              challenge={result.challenge}
              request={result.request}
            />
          ) : (
            status !== 'running' && <EmptyPipeline />
          )}
        </div>
      </div>

      <CheckinExamples />
    </>
  )
}
