import { SEVERITY_ORDER, SEVERITY_COLORS } from '../api'
import type { Summary } from '../api'

export function SeverityCards({ summary }: { summary: Summary | null }) {
  const bySev = summary?.by_severity ?? {}
  return (
    <div className="cards">
      {SEVERITY_ORDER.map((s) => {
        const n = bySev[s] ?? 0
        return (
          <div className="sev" key={s} style={n ? undefined : { opacity: 0.35 }}>
            <div className="n" style={{ color: SEVERITY_COLORS[s] }}>
              {n}
            </div>
            <div className="l">{s}</div>
          </div>
        )
      })}
    </div>
  )
}
