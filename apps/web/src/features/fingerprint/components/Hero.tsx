import { useTranslation } from 'react-i18next'

/**
 * The thesis: this tool lifts a device's latent print and reads the verdict.
 * Kept tight — it's a console, not a landing page.
 */
export function Hero() {
  const { t } = useTranslation()

  return (
    <section className="ridge-field border-b border-border/70">
      <div className="mx-auto max-w-5xl px-4 py-10 md:py-14">
        <p className="mb-3 flex items-center gap-2 font-mono text-xs uppercase tracking-[0.2em] text-primary">
          <span className="h-px w-6 bg-primary/60" />
          {t('challenge → identify')}
        </p>
        <h1 className="max-w-2xl font-heading text-3xl font-semibold leading-[1.1] tracking-tight md:text-[2.6rem]">
          {t('Lift a device fingerprint,')}{' '}
          <span className="text-primary">{t('read the verdict.')}</span>
        </h1>
        <p className="mt-4 max-w-xl text-sm leading-relaxed text-muted-foreground md:text-base">
          {t(
            'Point the collect-only client at a fingerprintd server. It collects device components, sends them with a one-time nonce and a timestamp, and the server returns a match / review / new-device call with a request_id your backend looks up.',
          )}
        </p>
      </div>
    </section>
  )
}
