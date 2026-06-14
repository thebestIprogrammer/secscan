import { useEffect, useRef, useState } from 'react'
import { api } from './api'
import type { HistoryItem, Meta, Scan, TargetItem } from './api'
import { ScanForm } from './components/ScanForm'
import { StatusPanel } from './components/StatusPanel'
import { ResultPanel } from './components/ResultPanel'
import { HistoryTable } from './components/HistoryTable'

export default function App() {
  const [meta, setMeta] = useState<Meta | null>(null)
  const [targets, setTargets] = useState<TargetItem[]>([])
  const [scan, setScan] = useState<Scan | null>(null)
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pollRef = useRef<number | null>(null)

  useEffect(() => {
    api.meta().then(setMeta).catch((e) => setError(msg(e)))
    api.targets().then((r) => setTargets(r.targets)).catch(() => {})
    loadHistory()
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  function loadHistory() {
    api.history().then(setHistory).catch(() => {
      /* tarixni o'qib bo'lmasa, jim qolamiz */
    })
  }

  async function onScan(target: string, type: string, tools: string[], mode: string) {
    setError('')
    setBusy(true)
    try {
      const s = await api.createScan({ target, type, tools, mode })
      setScan(s)
      startPolling(s.id)
    } catch (e) {
      setError(msg(e))
      setBusy(false)
    }
  }

  function startPolling(id: string) {
    if (pollRef.current) clearInterval(pollRef.current)
    pollRef.current = window.setInterval(async () => {
      try {
        const s = await api.getScan(id)
        setScan(s)
        if (s.status !== 'running') {
          if (pollRef.current) clearInterval(pollRef.current)
          pollRef.current = null
          setBusy(false)
          loadHistory()
        }
      } catch {
        /* keyingi urinishda davom etamiz */
      }
    }, 1000)
  }

  return (
    <>
      <header className="app">
        <h1>🛡️ SecScan</h1>
        <span className="sub">Xavfsizlik skaneri — Trivy + Gitleaks + Semgrep</span>
        {meta && <span className="ver">v{meta.version}</span>}
      </header>
      <main>
        {error && <div className="banner-err">{error}</div>}

        <div className="card">
          <h2>Yangi skan</h2>
          <ScanForm meta={meta} targets={targets} busy={busy} onScan={onScan} />
        </div>

        {scan && <StatusPanel scan={scan} />}
        {scan && <ResultPanel scan={scan} />}

        <div className="card">
          <h2>Oldingi skanlar</h2>
          <HistoryTable items={history} />
        </div>
      </main>
    </>
  )
}

function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}
