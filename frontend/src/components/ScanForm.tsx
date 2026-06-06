import { useEffect, useState } from 'react'
import type { Meta, TargetItem } from '../api'

const CAT_ORDER = ['sca', 'secret', 'sast', 'misconfig', 'dast']
const CAT_LABELS: Record<string, string> = {
  sca: "Bog'liqlik / CVE",
  secret: 'Maxfiy kalit',
  sast: 'Kod zaifligi',
  misconfig: 'Xato sozlama / IaC',
  dast: 'DAST (web)',
}

interface Props {
  meta: Meta | null
  targets: TargetItem[]
  busy: boolean
  onScan: (target: string, type: string, tools: string[]) => void
}

export function ScanForm({ meta, targets, busy, onScan }: Props) {
  const [type, setType] = useState('fs')
  const [target, setTarget] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())

  // Meta kelganda: standart yoqilgan toollarni belgilaymiz.
  useEffect(() => {
    if (meta) setSelected(new Set(meta.tools.filter((t) => t.default_on).map((t) => t.key)))
  }, [meta])

  const isImage = type === 'image'
  const isUrl = type === 'url'

  // Joriy nishon turini qo'llaydigan toollar, toifa bo'yicha guruhlangan.
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
    const chosen = toolsForType.filter((x) => selected.has(x.key)).map((x) => x.key)
    if (chosen.length === 0) {
      alert('Kamida bitta tool tanlang.')
      return
    }
    onScan(t, type, chosen)
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
      {/* Tur — segmented toggle */}
      <div className="seg" style={{ marginBottom: 16 }}>
        <button type="button" className={type === 'fs' ? 'active' : ''} onClick={() => setType('fs')}>
          📁 Papka / kod
        </button>
        <button type="button" className={isImage ? 'active' : ''} onClick={() => setType('image')}>
          🐳 Docker image
        </button>
        <button type="button" className={isUrl ? 'active' : ''} onClick={() => setType('url')}>
          🌐 URL (DAST)
        </button>
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

      {/* Toollar — toifaga guruhlangan checkbox'lar */}
      <div className="field-label" style={{ marginTop: 18 }}>
        Toollar ({toolsForType.filter((t) => selected.has(t.key)).length}/{toolsForType.length})
      </div>
      {CAT_ORDER.filter((c) => byCat[c]).map((cat) => (
        <div key={cat} style={{ marginBottom: 10 }}>
          <div className="cat-label">{CAT_LABELS[cat] ?? cat}</div>
          <div className="checks">
            {byCat[cat].map((t) => (
              <label key={t.key}>
                <input
                  type="checkbox"
                  checked={selected.has(t.key)}
                  onChange={() => toggleTool(t.key)}
                />
                {t.title}
              </label>
            ))}
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
        {isImage
          ? 'Image lokal (host daemon) da mavjud bo\'lishi kerak.'
          : isUrl
            ? 'DAST: ishlab turgan web-ilova manzili. URL skaner konteyneridan ochiq bo\'lishi kerak.'
            : meta?.in_container
              ? 'Istalgan host papkasi yo\'lini tashlang — SCAN_DIR shart emas.'
              : 'Eslatma: papka yo\'li server ishlagan joyga nisbatan beriladi.'}
      </div>
    </>
  )
}
