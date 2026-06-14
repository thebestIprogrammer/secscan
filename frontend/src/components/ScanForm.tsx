import { useEffect, useState } from 'react'
import type { Meta, TargetItem } from '../api'

const CAT_ORDER = ['sca', 'sbom', 'secret', 'sast', 'misconfig', 'dast']
const CAT_LABELS: Record<string, string> = {
  sca: "Bog'liqlik / CVE",
  sbom: 'SBOM',
  secret: 'Maxfiy kalit',
  sast: 'Kod zaifligi',
  misconfig: 'Xato sozlama / IaC',
  dast: 'DAST (web)',
}

interface Props {
  meta: Meta | null
  targets: TargetItem[]
  busy: boolean
  onScan: (target: string, type: string, tools: string[], mode: string) => void
}

export function ScanForm({ meta, targets, busy, onScan }: Props) {
  const [type, setType] = useState('fs')
  const [mode, setMode] = useState('online')
  const [target, setTarget] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())

  useEffect(() => {
    if (meta) setSelected(new Set(meta.tools.filter((t) => t.default_on).map((t) => t.key)))
  }, [meta])

  const isImage = type === 'image'
  const isUrl = type === 'url'
  const offline = mode === 'offline'

  const toolsForType = (meta?.tools ?? []).filter((t) => t.target_types.includes(type))
  const byCat: Record<string, typeof toolsForType> = {}
  toolsForType.forEach((t) => {
    ;(byCat[t.category] ||= []).push(t)
  })

  function toggleTool(k: string) {
    setSelected((prev) => {
      const n = new Set(prev)
      n.has(k) ? n.delete(k) : n.add(k)
      return n
    })
  }

  function submit() {
    const t = target.trim()
    if (!t) {
      alert(isImage ? 'Image nomini kiriting.' : isUrl ? 'URL kiriting.' : 'Papka yo\'lini kiriting.')
      return
    }
    // Offline'da internet talab qiladigan toollarni yubormaymiz
    const chosen = toolsForType
      .filter((x) => selected.has(x.key) && !(offline && x.offline_support === 'no'))
      .map((x) => x.key)
    if (chosen.length === 0) {
      alert('Kamida bitta (bu rejimda ishlaydigan) tool tanlang.')
      return
    }
    onScan(t, type, chosen, mode)
  }

  const fieldLabel = isImage ? 'Docker image nomi' : isUrl ? 'Web manzil (URL)' : 'Loyiha papkasi yo\'li'
  const placeholder = isImage
    ? 'masalan: nginx:1.21'
    : isUrl
      ? 'masalan: https://example.com'
      : meta?.in_container
        ? 'Papka yo\'lini bu yerga tashlang — masalan: D:\\projects\\my-app'
        : 'masalan: ./samples/vulnerable-app'

  return (
    <>
      {/* Tur va Rejim — segmented toggle'lar */}
      <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap', marginBottom: 16 }}>
        <div>
          <div className="cat-label">Nishon turi</div>
          <div className="seg">
            <button type="button" className={type === 'fs' ? 'active' : ''} onClick={() => setType('fs')}>
              📁 Papka
            </button>
            <button type="button" className={isImage ? 'active' : ''} onClick={() => setType('image')}>
              🐳 Image
            </button>
            <button type="button" className={isUrl ? 'active' : ''} onClick={() => setType('url')}>
              🌐 URL
            </button>
          </div>
        </div>
        <div>
          <div className="cat-label">Rejim</div>
          <div className="seg">
            <button type="button" className={!offline ? 'active' : ''} onClick={() => setMode('online')}>
              Onlayn
            </button>
            <button type="button" className={offline ? 'active' : ''} onClick={() => setMode('offline')}>
              Offline
            </button>
          </div>
        </div>
      </div>

      {/* Nishon maydoni */}
      <div className="field-label">{fieldLabel}</div>
      <div className="path-input">
        <span className="ic">{isImage ? '🐳' : isUrl ? '🌐' : '📁'}</span>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !busy) submit()
          }}
          placeholder={placeholder}
        />
      </div>

      {/* fs uchun: topilgan loyihalardan tezkor tanlash */}
      {type === 'fs' && targets.length > 0 && (
        <div className="quickpick">
          <span>yoki ro'yxatdan tanlang:</span>
          <select
            value={targets.some((t) => t.path === target) ? target : ''}
            onChange={(e) => e.target.value && setTarget(e.target.value)}
          >
            <option value="">— topilgan loyihalar ({targets.length}) —</option>
            {targets.map((t) => (
              <option key={t.path} value={t.path}>
                {t.label}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Toollar — toifaga guruhlangan */}
      <div className="field-label" style={{ marginTop: 18 }}>Toollar</div>
      {CAT_ORDER.filter((c) => byCat[c]).map((cat) => (
        <div key={cat} style={{ marginBottom: 10 }}>
          <div className="cat-label">{CAT_LABELS[cat] ?? cat}</div>
          <div className="checks">
            {byCat[cat].map((t) => {
              const skip = offline && t.offline_support === 'no'
              return (
                <label key={t.key} style={skip ? { opacity: 0.45 } : undefined}>
                  <input
                    type="checkbox"
                    checked={selected.has(t.key)}
                    onChange={() => toggleTool(t.key)}
                  />
                  {t.title}
                  {skip ? ' — internet kerak' : ''}
                </label>
              )
            })}
          </div>
        </div>
      ))}

      <button
        className="primary"
        onClick={submit}
        disabled={busy}
        style={{ width: '100%', marginTop: 14 }}
      >
        {busy ? 'Skanlanmoqda...' : 'Skanlash'}
      </button>

      <div className="hint">
        {offline
          ? 'Offline rejim: bazalar yangilanmaydi (keshdan), internet talab qiladigan toollar o\'tkazib yuboriladi. Avval bir marta onlayn skan qilib keshni isiting.'
          : isImage
            ? 'Image lokal (host daemon) da mavjud bo\'lishi kerak.'
            : isUrl
              ? 'DAST: ishlab turgan web-ilova manzili.'
              : meta?.in_container
                ? 'Istalgan host papkasi yo\'lini tashlang — SCAN_DIR shart emas.'
                : 'Eslatma: papka yo\'li server ishlagan joyga nisbatan beriladi.'}
      </div>
    </>
  )
}
