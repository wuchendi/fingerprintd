import type { ChallengeResponse, IdentifyRequest } from '@cdlab/fingerprintd'
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
  request,
}: {
  challenge: ChallengeResponse
  request: IdentifyRequest
}) {
  const { t } = useTranslation()
  const client =
    request.user_agent !== undefined || request.botd !== undefined
      ? { user_agent: request.user_agent, botd: request.botd }
      : undefined

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
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <Lane
          title="components"
          description={t('the "who is this device" matching input')}
          present
        >
          <JsonBlock value={request.components} />
        </Lane>

        <Lane
          title="user_agent + botd"
          description={t('browser user agent and client-side BotD verdict')}
          present={client !== undefined}
        >
          <JsonBlock value={client} />
        </Lane>

        <Lane
          title="ts"
          description={t('client clock when the request was sent')}
          present
        >
          <p className="rounded-md border border-border bg-muted/40 p-3 font-mono text-xs">
            {request.ts} ({new Date(request.ts).toISOString()})
          </p>
        </Lane>

        <Lane
          title="integrity"
          description={t(
            'known-answer probe verdicts (canvas / webgl / audio / rect) — a risk signal, never matching input',
          )}
          present={request.integrity !== undefined}
        >
          <JsonBlock value={request.integrity} />
        </Lane>
      </CardContent>
    </Card>
  )
}
