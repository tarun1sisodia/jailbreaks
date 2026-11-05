import type { Finding, RawFinding, Scan, Severity } from '../types'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
export const PHASES = ['Recon', 'Auth', 'Injection', 'Authz', 'Logic', 'Infra']

export function capitalize(value: string): string {
  return value ? value.charAt(0).toUpperCase() + value.slice(1) : '—'
}

export function profileLabel(profile: string): string {
  const labels: Record<string, string> = { owasp: 'OWASP', api: 'API', authz: 'Authz' }
  return labels[profile.toLowerCase()] || capitalize(profile)
}

export function hostOf(value: string): string {
  try {
    const url = new URL(value)
    return url.host + (url.pathname !== '/' ? url.pathname.replace(/\/$/, '') : '')
  } catch {
    return value || '—'
  }
}

export function pathOf(value: string): string {
  if (!value) return '—'
  try {
    const url = new URL(value)
    return `${url.pathname || '/'}${url.search}`
  } catch {
    return value
  }
}

export function duration(seconds?: number): string {
  if (seconds === undefined || seconds === null || !Number.isFinite(seconds)) return '—'
  const rounded = Math.max(0, Math.floor(seconds))
  const hours = Math.floor(rounded / 3600)
  const minutes = Math.floor((rounded % 3600) / 60)
  const secs = rounded % 60
  return hours > 0
    ? `${hours}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`
    : `${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`
}

export function scanDuration(scan: Scan, now = Date.now()): string {
  if ((scan.status === 'running' || scan.status === 'queued') && scan.started_at) {
    return duration(now / 1000 - scan.started_at)
  }
  return duration(scan.duration_seconds)
}

export function relativeTime(timestamp?: number): string {
  if (!timestamp) return '—'
  const difference = Math.max(0, Math.floor(Date.now() / 1000 - timestamp))
  if (difference < 60) return 'Just now'
  if (difference < 3600) return `${Math.floor(difference / 60)}m ago`
  if (difference < 86400) return `${Math.floor(difference / 3600)}h ago`
  if (difference < 604800) return `${Math.floor(difference / 86400)}d ago`
  return new Date(timestamp * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

export function validHttpUrl(value: string): boolean {
  try {
    const url = new URL(value.trim())
    return (url.protocol === 'http:' || url.protocol === 'https:') && Boolean(url.hostname) && !url.username && !url.password
  } catch {
    return false
  }
}

export function validApiBase(value: string): boolean {
  if (/^\/(?!\/)[^?#\s]*$/.test(value)) return true
  try {
    const url = new URL(value)
    return url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  } catch {
    return false
  }
}

export function normalizeFinding(raw: RawFinding, index: number): Finding {
  const rawSeverity = (raw.severity || 'info').toLowerCase() as Severity
  const severity = SEVERITIES.includes(rawSeverity) ? rawSeverity : 'info'
  const rawScore = raw.cvss_score ?? raw.extra?.cvss?.score
  const score = typeof rawScore === 'number' && Number.isFinite(rawScore) ? rawScore : null
  const phase = typeof raw.phase === 'number' ? PHASES[raw.phase - 1] || String(raw.phase) : (raw.phase || '')
  const remediation = typeof raw.remediation === 'string'
    ? raw.remediation
    : [raw.remediation?.summary, ...(raw.remediation?.steps || [])].filter(Boolean).join('\n')
  const evidence = typeof raw.evidence === 'string' ? raw.evidence : ''
  const poc = raw.poc || raw.extra?.poc || (typeof raw.evidence === 'object' && raw.evidence
    ? { request: raw.evidence.request ? { body_text: raw.evidence.request } : undefined, response: raw.evidence.response ? { body_text: raw.evidence.response } : undefined, curl: raw.evidence.curl }
    : undefined)
  const url = raw.url || raw.endpoint || ''
  return {
    id: raw.id || `finding-${index}`,
    title: raw.title || 'Untitled finding',
    severity,
    category: raw.category || '',
    url,
    endpoint: pathOf(raw.endpoint || url),
    method: raw.method || '',
    parameter: raw.param || raw.parameter || '',
    phase,
    score,
    vector: raw.cvss_vector || raw.extra?.cvss?.vector || '',
    cwe: raw.cwe || raw.extra?.taxonomy?.cwe || '',
    owasp: raw.owasp || raw.extra?.taxonomy?.owasp || '',
    description: raw.description || '',
    evidence,
    remediation: remediation || '',
    poc,
  }
}

export function severityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  findings.forEach((finding) => { counts[finding.severity] += 1 })
  return counts
}

export function safeExternalUrl(value: string): string | undefined {
  try {
    const parsed = new URL(value)
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? parsed.href : undefined
  } catch {
    return undefined
  }
}
