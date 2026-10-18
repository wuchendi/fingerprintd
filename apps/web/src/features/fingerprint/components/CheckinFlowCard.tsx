import { useTranslation } from 'react-i18next'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/shared/components/ui/card'
import { CopyButton } from '@/shared/components/ui/copy-button'

function Snippet({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-1.5">
      <span className="text-[0.7rem] uppercase tracking-[0.14em] text-muted-foreground">
        {label}
      </span>
      <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3">
        <pre className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-xs leading-relaxed">
          {value}
        </pre>
        <CopyButton value={value} size="sm" className="shrink-0" />
      </div>
    </div>
  )
}

/**
 * The server-side half of a check-in: the browser only hands the `request_id`
 * to its backend, which looks the event up and scores the check-in with its
 * own API key. Renders copyable snippets for that call; nothing here is sent
 * from the browser.
 */
export function CheckinFlowCard({
  baseUrl,
  accountId,
  requestId,
}: {
  baseUrl: string
  accountId: string
  requestId: string
}) {
  const { t } = useTranslation()
  const origin = baseUrl.trim().replace(/\/+$/, '')
  const body = JSON.stringify({
    account_id: accountId.trim(),
    action: 'daily_checkin',
    request_id: requestId,
  })
  const assess = `curl -X POST ${origin}/checkin/assess -H 'Authorization: Bearer $FP_API_KEY' -H 'content-type: application/json' -d '${body}'`
  const lookup = `curl ${origin}/events/${requestId} -H 'Authorization: Bearer $FP_API_KEY'`

  return (
    <Card>
      <CardHeader className="border-b">
        <CardTitle>{t('Server-side check-in')}</CardTitle>
        <CardDescription>
          {t(
            'Send the request_id to your backend. Your backend looks the result up by request_id with its API key and scores the check-in.',
          )}
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-5">
        <div className="space-y-1.5">
          <span className="text-[0.7rem] uppercase tracking-[0.14em] text-muted-foreground">
            request_id
          </span>
          <div className="flex items-center gap-2 rounded-md border border-border bg-muted/40 px-3 py-1">
            <p className="min-w-0 flex-1 break-all font-mono text-sm">
              {requestId}
            </p>
            <CopyButton value={requestId} size="sm" className="shrink-0" />
          </div>
        </div>

        <Snippet label={t('Score the check-in (server-side)')} value={assess} />
        <Snippet
          label={t('Fetch the identify event (server-side)')}
          value={lookup}
        />

        <p className="rounded-md border border-review/40 bg-review/10 p-3 text-xs leading-relaxed text-muted-foreground">
          {t(
            'The result shown in the browser is display-only. Keep FP_API_KEY on your server — never ship it to the browser.',
          )}
        </p>
      </CardContent>
    </Card>
  )
}
