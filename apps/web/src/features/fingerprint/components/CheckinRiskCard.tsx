import { useTranslation } from 'react-i18next'
import { Badge } from '@/shared/components/ui/badge'
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/shared/components/ui/card'
import { cn } from '@/shared/lib/utils'
import type { AssessResponse } from '../api'

/**
 * Decision → semantic color, reusing the app's verdict tokens: allow = match
 * (verdant), challenge = review (amber), deny = destructive (red).
 */
const decisionAccent: Record<AssessResponse['decision'], string> = {
  allow: 'text-match',
  challenge: 'text-review',
  deny: 'text-destructive',
}

const riskFill: Record<AssessResponse['decision'], string> = {
  allow: 'bg-match',
  challenge: 'bg-review',
  deny: 'bg-destructive',
}

export function CheckinRiskCard({ checkin }: { checkin: AssessResponse }) {
  const { t } = useTranslation()
  const pct = Math.round(Math.max(0, Math.min(1, checkin.risk)) * 100)

  return (
    <Card>
      <CardHeader className="border-b">
        <CardTitle>{t('Check-in risk')}</CardTitle>
        <CardDescription>
          {t('Anti-farming decision for this account on daily_checkin.')}
        </CardDescription>
        <CardAction
          className={cn(
            'flex items-center gap-2 text-sm font-semibold uppercase tracking-wide',
            decisionAccent[checkin.decision],
          )}
        >
          <span className="size-2 rounded-full bg-current" />
          {t(checkin.decision)}
        </CardAction>
      </CardHeader>

      <CardContent className="space-y-5">
        <div className="flex items-center justify-between gap-4 text-sm">
          <span className="text-muted-foreground">{t('Verdict')}</span>
          <span className="font-medium">{t(checkin.verdict)}</span>
        </div>

        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">{t('Risk')}</span>
            <span className="font-mono font-medium">{pct}%</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
            <div
              className={cn('h-full rounded-full', riskFill[checkin.decision])}
              style={{ width: `${pct}%` }}
            />
          </div>
        </div>

        <div className="space-y-1.5">
          <span className="text-[0.7rem] uppercase tracking-[0.14em] text-muted-foreground">
            visitor_id
          </span>
          <p className="break-all rounded-md border border-border bg-muted/40 px-3 py-2 font-mono text-sm">
            {checkin.visitor_id}
          </p>
        </div>

        <div className="space-y-2">
          <span className="text-[0.7rem] uppercase tracking-[0.14em] text-muted-foreground">
            {t('Reasons')}
          </span>
          {checkin.reasons.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('No reasons.')}</p>
          ) : (
            <ul className="space-y-2">
              {checkin.reasons.map((reason) => (
                <li
                  key={reason.code}
                  className="space-y-1 rounded-md border border-border bg-muted/20 px-3 py-2"
                >
                  <Badge variant="outline" className="font-mono">
                    {reason.code}
                  </Badge>
                  <p className="text-sm text-muted-foreground">
                    {reason.detail}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
