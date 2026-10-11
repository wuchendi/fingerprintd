import type { IdentifyResponse } from '@cdlab/fingerprintd'
import { useTranslation } from 'react-i18next'
import {
  Card,
  CardAction,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/shared/components/ui/card'
import { cn } from '@/shared/lib/utils'
import type { OriginalFingerprint } from '../api'
import { RidgeMeter } from './RidgeMeter'

const verdictAccent: Record<IdentifyResponse['decision'], string> = {
  match: 'text-match',
  review: 'text-review',
  new_device: 'text-newdev',
}

function Signal({
  label,
  value,
  tone,
}: {
  label: string
  value: React.ReactNode
  tone?: 'default' | 'muted'
}) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-border/60 py-2 text-sm last:border-0">
      <span className="text-muted-foreground">{label}</span>
      <span
        className={cn(
          'font-medium',
          tone === 'muted' && 'text-muted-foreground',
        )}
      >
        {value}
      </span>
    </div>
  )
}

export function IdentityCard({
  identity,
  original,
}: {
  identity: IdentifyResponse
  original?: OriginalFingerprint
}) {
  const { t } = useTranslation()

  return (
    <Card>
      <CardHeader className="border-b">
        <CardTitle>{t('Identity')}</CardTitle>
        {/* The meter is the readout; the verdict names it. */}
        <CardAction
          className={cn(
            'flex items-center gap-2 text-sm font-semibold',
            verdictAccent[identity.decision],
          )}
        >
          <span className="size-2 rounded-full bg-current" />
          {t(identity.decision)}
        </CardAction>
      </CardHeader>

      <CardContent className="space-y-5">
        <div className="flex justify-center pt-1">
          <RidgeMeter
            value={identity.confidence}
            decision={identity.decision}
            label={t('Confidence')}
          />
        </div>

        <div className="space-y-1.5">
          <span className="text-[0.7rem] uppercase tracking-[0.14em] text-muted-foreground">
            visitorId
          </span>
          <p className="break-all rounded-md border border-border bg-muted/40 px-3 py-2 font-mono text-sm">
            {identity.visitorId}
          </p>
        </div>

        {original && (
          <div className="space-y-1.5">
            <span className="flex items-center gap-2 text-[0.7rem] uppercase tracking-[0.14em] text-muted-foreground">
              {t('Original fingerprint (client-side)')}
            </span>
            <p className="break-all rounded-md border border-dashed border-border bg-muted/20 px-3 py-2 font-mono text-sm text-muted-foreground">
              {original.visitorId}
            </p>
            <p className="text-xs text-muted-foreground">
              {t(
                'FingerprintJS computes this hash in the browser. The SDK discards it — the server judges identity from raw evidence instead.',
              )}
            </p>
          </div>
        )}

        <div>
          <Signal
            label={t('New device')}
            value={identity.is_new_device ? t('Yes') : t('No')}
            tone={identity.is_new_device ? 'default' : 'muted'}
          />
          <Signal
            label={t('Collision risk')}
            value={identity.collision_risk ? t('Yes') : t('No')}
            tone={identity.collision_risk ? 'default' : 'muted'}
          />
          <Signal
            label={t('UA / TLS consistent')}
            value={identity.signals.ua_tls_consistent ? t('Yes') : t('No')}
            tone={identity.signals.ua_tls_consistent ? 'muted' : 'default'}
          />
          <Signal
            label={t('IP risk')}
            value={
              <span className="font-mono">{identity.signals.ip_risk}</span>
            }
          />
          <Signal
            label={t('Client integrity')}
            value={
              <span className="font-mono">
                {identity.signals.client_integrity ?? 'unavailable'}
              </span>
            }
            tone={
              identity.signals.client_integrity === 'noise'
                ? 'default'
                : 'muted'
            }
          />
          <Signal
            label={t('Persona coherence')}
            value={
              <span className="font-mono">
                {identity.signals.persona_coherence ?? 'unknown'}
              </span>
            }
            tone={
              identity.signals.persona_coherence === 'mismatch'
                ? 'default'
                : 'muted'
            }
          />
        </div>
      </CardContent>
    </Card>
  )
}
