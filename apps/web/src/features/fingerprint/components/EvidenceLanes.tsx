import type { ChallengeResponse, Collected } from '@cdlab/fingerprintd-client'
import { useTranslation } from 'react-i18next'
import { Badge } from '@/shared/components/ui/badge'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/shared/components/ui/card'
import { JsonBlock } from './JsonBlock'

function Lane({
  title,
  description,
  present,
  children,
}: {
  title: string
  description: string
  present: boolean
  children: React.ReactNode
}) {
  const { t } = useTranslation()
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div>
          <p className="font-mono text-sm font-semibold">{title}</p>
          <p className="text-xs text-muted-foreground">{description}</p>
        </div>
        {!present && <Badge variant="outline">{t('not sent')}</Badge>}
      </div>
      {present && children}
    </div>
  )
}

export function EvidenceLanes({
  challenge,
  collected,
}: {
  challenge: ChallengeResponse
  collected: Collected
}) {
  const { t } = useTranslation()

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('Collected evidence')}</CardTitle>
        <CardDescription className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-xs">
          <span>
            {t('nonce')}: {challenge.nonce}
          </span>
          <span>
            {t('expires in')}: {challenge.expires_in} {t('seconds')}
          </span>
          <span>
            {t('targets')}: [{challenge.collect.challenge.targets.join(', ')}]
          </span>
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <Lane
          title="stable_components"
          description={t('the "who is this device" matching input')}
          present
        >
          <JsonBlock value={collected.stable_components} />
        </Lane>

        <Lane
          title="probe"
          description={t('hex(HMAC-SHA256(key, nonce)) computed in WASM')}
          present={collected.probe !== undefined}
        >
          <p className="break-all rounded-md border border-border bg-muted/40 p-3 font-mono text-xs">
            {collected.probe}
          </p>
        </Lane>

        <Lane
          title="ts"
          description={t('client clock at collection')}
          present={collected.ts !== undefined}
        >
          <p className="rounded-md border border-border bg-muted/40 p-3 font-mono text-xs">
            {collected.ts}
            {collected.ts !== undefined &&
              ` (${new Date(collected.ts).toISOString()})`}
          </p>
        </Lane>

        <Lane
          title="integrity"
          description={t(
            'known-answer probe verdicts (canvas / webgl / audio / rect) — a risk signal, never matching input',
          )}
          present={collected.integrity !== undefined}
        >
          <JsonBlock value={collected.integrity} />
        </Lane>
      </CardContent>
    </Card>
  )
}
