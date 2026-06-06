import { SEVERITY_ORDER, SEVERITY_COLORS } from '../api'
import type { HistoryItem } from '../api'

export function HistoryTable({ items }: { items: HistoryItem[] }) {
  if (items.length === 0) {
    return <div className="empty">Hali skan qilinmagan.</div>
  }
  return (
    <table>
      <thead>
        <tr>
          <th>Nishon</th>
          <th>Sana</th>
          <th>Topilmalar</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {items.map((s) => {
          const sev = s.summary?.by_severity ?? {}
          return (
            <tr key={s.name}>
              <td className="tgt">{s.target}</td>
              <td>{s.generated_at}</td>
              <td>
                <b>{s.summary?.total ?? 0}</b>{' '}
                {SEVERITY_ORDER.filter((x) => sev[x]).map((x) => (
                  <span className="mini" key={x} style={{ background: SEVERITY_COLORS[x] }}>
                    {x[0]} {sev[x]}
                  </span>
                ))}
              </td>
              <td>
                <a className="btn-link" href={s.report_url} target="_blank" rel="noopener">
                  Ochish
                </a>
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}
