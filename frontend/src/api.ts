// REST API mijozi va umumiy tiplar.

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'] as const
export type Severity = (typeof SEVERITY_ORDER)[number]

export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#7b1fa2',
  HIGH: '#c62828',
  MEDIUM: '#ef6c00',
  LOW: '#f9a825',
  INFO: '#0277bd',
  UNKNOWN: '#607d8b',
}

export interface Summary {
  total: number
  by_severity: Record<string, number>
  by_category: Record<string, number>
  by_scanner: Record<string, number>
}

export interface Scan {
  id: string
  status: 'running' | 'done' | 'error'
  target: string
  type: string
  tools: string[]
  log: string[]
  summary: Summary | null
  report_url: string | null
  json_url: string | null
  error: string | null
}

export interface HistoryItem {
  name: string
  target: string
  target_type: string
  generated_at: string
  summary: Summary
  report_url: string
  json_url: string
}

export interface ToolInfo {
  key: string
  title: string
  category: string
  target_types: string[]
  default_on: boolean
}

export interface Meta {
  version: string
  tools: ToolInfo[]
  default_target: string
  in_container: boolean
}

export interface TargetItem {
  path: string
  label: string
}

async function http<T>(url: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(url, opts)
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail || detail
    } catch {
      /* ignore */
    }
    throw new Error(detail)
  }
  return (await res.json()) as T
}

export const api = {
  meta: () => http<Meta>('/api/meta'),
  targets: () => http<{ root: string; targets: TargetItem[] }>('/api/targets'),
  createScan: (body: { target: string; type: string; tools: string[] }) =>
    http<Scan>('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  getScan: (id: string) => http<Scan>(`/api/scans/${id}`),
  history: () => http<HistoryItem[]>('/api/scans'),
}
