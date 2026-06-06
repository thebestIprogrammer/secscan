import { useEffect, useRef } from 'react'
import type { Scan } from '../api'

export function StatusPanel({ scan }: { scan: Scan }) {
  const logRef = useRef<HTMLPreElement>(null)

  // Yangi log qatori kelganda pastga avtomatik aylantirish.
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [scan.log])

  return (
    <div className="card">
      <h2>Holat</h2>
      <div style={{ marginBottom: 12, fontSize: 14 }}>
        {scan.status === 'running' && (
          <>
            <span className="spinner" /> Skanlanmoqda...
          </>
        )}
        {scan.status === 'done' && 'Skan yakunlandi.'}
        {scan.status === 'error' && <span className="err">XATO: {scan.error}</span>}
      </div>
      <pre className="log" ref={logRef}>
        {scan.log.join('\n')}
      </pre>
    </div>
  )
}
