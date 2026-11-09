export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'aborted' | 'error' | 'unknown'
export type ProfileId = 'quick' | 'owasp' | 'full' | 'api' | 'recon' | 'auth' | 'injection' | 'authz' | 'business' | 'config' | 'exploit'
export type EngineId = 'webprobe' | 'kagesec' | 'openosint' | 'argus' | 'all'
export interface EngineInfo {
  name: string
  description: string
  url_scan: boolean
  available: boolean
  binary: string | null
  version: string | null
}
export type Engines = Record<string, EngineInfo>
export type Theme = 'system' | 'dark' | 'light'

export interface Settings {
  apiBase: string
  apiKey: string
  defaultProfile: ProfileId
  rateLimit: number
  aimd: boolean
  redact: boolean
  theme: Theme
  reduceMotion: boolean
}

export interface Health {
  status: string
  version: string
  total_checks: number
  profiles: string[]
}

export interface Scan {
  scan_id: string
  url: string
  profile: string
  engine?: string
  status: ScanStatus
  created_at: number
  started_at?: number
  ended_at?: number
  duration_seconds?: number
  findings_count?: number
  severity_summary?: Partial<Record<Severity, number>>
  error?: string
  exit_code?: number
  example?: boolean
}

export interface ScanRequest {
  url: string
  repo?: string
  profile: string
  engine?: EngineId
  rate_limit: number
  aimd: boolean
  redact: boolean
  cookie?: string
  secondary_cookie?: string
  admin_cookie?: string
  webhook_callback?: string | null
}

export interface ScanStarted {
  scan_id: string
  target: string
  status: string
}

export type Profiles = Record<string, { count: number; checks: string[] }>

export interface PocMessage {
  method?: string
  url?: string
  status?: number
  headers?: Record<string, string>
  body_text?: string
}
export interface Poc {
  request?: PocMessage
  response?: PocMessage | null
  curl?: string
}

export interface RawFinding {
  id?: string
  category?: string
  severity?: string
  title?: string
  url?: string
  endpoint?: string
  evidence?: string | { request?: string; response?: string; curl?: string }
  remediation?: string | { summary?: string; steps?: string[] }
  description?: string
  phase?: number | string
  param?: string
  parameter?: string
  method?: string
  payload?: string
  cvss_score?: number
  cvss_vector?: string
  cwe?: string
  owasp?: string
  poc?: Poc
  extra?: {
    cvss?: { score?: number; vector?: string }
    taxonomy?: { cwe?: string; owasp?: string }
    poc?: Poc
    [key: string]: unknown
  }
}

export interface Report {
  metadata?: {
    target?: string
    profile?: string
    engine?: string
    engines?: string[]
    version?: string
    duration_seconds?: number
  }
  total_findings?: number
  findings: RawFinding[]
}

export interface Finding {
  id: string
  title: string
  severity: Severity
  category: string
  url: string
  endpoint: string
  method: string
  parameter: string
  phase: string
  score: number | null
  vector: string
  cwe: string
  owasp: string
  description: string
  evidence: string
  remediation: string
  poc?: Poc
}
