import { Play, RotateCcw } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/shared/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/shared/components/ui/card'
import { Input } from '@/shared/components/ui/input'
import { Label } from '@/shared/components/ui/label'
import { useFingerprintStore } from '../store'

export function RunPanel() {
  const { t } = useTranslation()
  const baseUrl = useFingerprintStore((s) => s.baseUrl)
  const accountId = useFingerprintStore((s) => s.accountId)
  const status = useFingerprintStore((s) => s.status)
  const setBaseUrl = useFingerprintStore((s) => s.setBaseUrl)
  const setAccountId = useFingerprintStore((s) => s.setAccountId)
  const run = useFingerprintStore((s) => s.run)
  const reset = useFingerprintStore((s) => s.reset)

  const running = status === 'running'

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('Challenge / identify playground')}</CardTitle>
        <CardDescription>
          {t(
            'Run the collect-only client flow against a fingerprintd server and inspect what it sends and what the server judges.',
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="baseUrl">{t('Server base URL')}</Label>
          <Input
            id="baseUrl"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="https://fp.example.com"
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="accountId">{t('Account ID')}</Label>
          <Input
            id="accountId"
            value={accountId}
            onChange={(e) => setAccountId(e.target.value)}
            placeholder="user-123"
            autoComplete="off"
            spellCheck={false}
          />
          <p className="text-xs text-muted-foreground">
            {t(
              'Business account your backend scores for check-in farming, used in the server-side check-in snippet.',
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button onClick={() => run()} disabled={running}>
            <Play />
            {running ? t('Running…') : t('Run flow')}
          </Button>
          <Button variant="outline" onClick={() => reset()} disabled={running}>
            <RotateCcw />
            {t('Reset')}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
