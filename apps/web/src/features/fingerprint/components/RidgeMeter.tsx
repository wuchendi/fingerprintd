import type { IdentifyResponse } from '@cdlab/fingerprintd'
import { cn } from '@/shared/lib/utils'

const verdictColor: Record<IdentifyResponse['decision'], string> = {
  match: 'text-match',
  review: 'text-review',
  new_device: 'text-newdev',
}

const RINGS = 15

/**
 * The signature element: confidence drawn as a lifted fingerprint. Concentric
 * ridge loops fill from the core outward up to the confidence fraction, inked
 * in the verdict color; the remaining ridges stay faint, as if undeveloped.
 */
export function RidgeMeter({
  value,
  decision,
  label,
}: {
  value: number
  decision: IdentifyResponse['decision']
  label: string
}) {
  const pct = Math.round(value * 100)
  const filled = Math.round(value * RINGS)

  const rings = Array.from({ length: RINGS }, (_, i) => {
    const t = i / (RINGS - 1)
    const rx = 12 + t * 80
    const ry = rx * 1.14
    // Loop core drifts upward and tilts as ridges widen — a real print, not a target.
    const cy = 100 - i * 0.7
    const rot = -7 + i * 0.5
    const inked = i < filled
    return { i, rx, ry, cy, rot, inked }
  })

  return (
    <div className={cn('relative', verdictColor[decision])}>
      <svg
        viewBox="0 0 200 210"
        role="img"
        aria-label={`${label}: ${pct}%`}
        className="w-full max-w-[220px]"
      >
        <title>{`${label}: ${pct}%`}</title>
        {rings.map((r) => (
          <ellipse
            key={r.i}
            cx={100}
            cy={r.cy}
            rx={r.rx}
            ry={r.ry}
            transform={`rotate(${r.rot} 100 ${r.cy})`}
            fill="none"
            pathLength={100}
            strokeDasharray="85 15"
            strokeDashoffset={68}
            strokeLinecap="round"
            strokeWidth={r.inked ? 2.4 : 1.4}
            className={
              r.inked
                ? 'stroke-current transition-all duration-500'
                : 'stroke-muted-foreground/25 transition-all duration-500'
            }
            style={{ opacity: r.inked ? 0.55 + (r.i / RINGS) * 0.45 : 1 }}
          />
        ))}
        {/* Core delta marker */}
        <circle cx={100} cy={99} r={3} className="fill-current" />
      </svg>

      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-3xl font-semibold tabular-nums text-foreground">
          {pct}
          <span className="text-lg text-muted-foreground">%</span>
        </span>
        <span className="text-[0.65rem] font-medium uppercase tracking-[0.18em] text-current">
          {label}
        </span>
      </div>
    </div>
  )
}
