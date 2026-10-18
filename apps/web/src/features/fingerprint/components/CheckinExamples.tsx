import { useTranslation } from 'react-i18next'
import { checkinExamples } from '../examples'
import { CheckinRiskCard } from './CheckinRiskCard'

/**
 * A static gallery of the three check-in decision bands (allow / challenge /
 * deny). Educational and offline: `/checkin/assess` is a server-to-server call,
 * and a single browser can never reproduce the farming case anyway.
 */
export function CheckinExamples() {
  const { t } = useTranslation()

  return (
    <section className="mx-auto max-w-5xl px-4 pb-12">
      <p className="mb-3 flex items-center gap-2 font-mono text-xs uppercase tracking-[0.2em] text-primary">
        <span className="h-px w-6 bg-primary/60" />
        {t('Check-in decision bands')}
      </p>
      <h2 className="font-heading text-2xl font-semibold tracking-tight">
        {t('What the anti-farming layer decides')}
      </h2>
      <p className="mt-2 max-w-xl text-sm leading-relaxed text-muted-foreground">
        {t(
          'Representative outcomes across the three decision bands — no live device farm required.',
        )}
      </p>

      <div className="mt-6 grid grid-cols-1 gap-6 md:grid-cols-3">
        {checkinExamples.map((example) => (
          <div key={example.assess.visitor_id} className="min-w-0 space-y-2">
            <span className="text-[0.7rem] uppercase tracking-[0.14em] text-muted-foreground">
              {t(example.captionKey)}
            </span>
            <CheckinRiskCard checkin={example.assess} />
          </div>
        ))}
      </div>
    </section>
  )
}
