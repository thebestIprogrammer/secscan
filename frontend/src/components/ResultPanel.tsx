import type { Scan } from '../api'
import { SeverityCards } from './SeverityCards'

export function ResultPanel({ scan }: { scan: Scan }) {
  if (scan.status !== 'done' || !scan.report_url) return null
  return (
    <div className="card">
      <h2>Natija</h2>
      <SeverityCards summary={scan.summary} />
      <div className="toolbar">
        <a className="btn-link" href={scan.report_url} target="_blank" rel="noopener">
          To'liq hisobotni yangi oynada ochish
        </a>
        {scan.json_url && (
          <a className="btn-link" href={scan.json_url} target="_blank" rel="noopener">
            JSON
          </a>
        )}
      </div>
      <iframe className="report" src={scan.report_url} title="hisobot" />
    </div>
  )
}
