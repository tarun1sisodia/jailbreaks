import type { Engines, Health, Profiles, Report, Scan, ScanRequest, ScanStarted } from '../types'

export class ApiError extends Error {
  status?: number
  constructor(message: string, status?: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

// Locked-down client: every call goes to the same-origin Workers proxy
// (BASE = '/api' on the Workers site). The browser never holds, sends or
// stores a credential. The proxy adds the backend auth header server-side
// from Workers Secrets, routes by engine (webprobe -> Render, other engines -> box6),
// and wakes box6 on demand. Direct calls to Render/box6 without a key
// still return 401 — that is the backends' own auth, unchanged.
const BASE = '/api'

async function request(path: string, init?: RequestInit): Promise<Response> {
  let response: Response
  try {
    response = await fetch(`${BASE}${path}`, { ...init, headers: { Accept: 'application/json', ...init?.headers }, cache: 'no-store' })
  } catch {
    throw new ApiError('Backend unreachable. Check the connection and try again.')
  }
  if (!response.ok) {
    let message = `Request failed (${response.status}).`
    try {
      const body = await response.json() as { detail?: string }
      if (typeof body.detail === 'string') message = body.detail
    } catch { /* Keep the status-based message. */ }
    throw new ApiError(message, response.status)
  }
  return response
}

export const api = {
  async health(): Promise<Health> {
    return (await request('/health')).json()
  },
  async scans(): Promise<Scan[]> {
    return (await request('/scans?limit=1000')).json()
  },
  async profiles(): Promise<Profiles> {
    return (await request('/profiles')).json()
  },
  async engines(): Promise<Engines> {
    return (await request('/engines')).json()
  },
  async scan(id: string): Promise<Scan> {
    return (await request(`/scan/${encodeURIComponent(id)}`)).json()
  },
  async start(payload: ScanRequest): Promise<ScanStarted> {
    return (await request('/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
    })).json()
  },
  async abort(id: string): Promise<void> {
    await request(`/scan/${encodeURIComponent(id)}/abort`, { method: 'POST' })
  },
  async report(id: string): Promise<Report> {
    const response = await request(`/scan/${encodeURIComponent(id)}/report?format=json`)
    if (response.status === 202) throw new ApiError('Report is not ready yet.', 202)
    return response.json()
  },
  async log(id: string): Promise<string> {
    const response = await request(`/scan/${encodeURIComponent(id)}/report?format=log`, { headers: { Accept: 'text/plain' } })
    return response.text()
  },
  async download(id: string, format: 'json' | 'md' | 'sarif'): Promise<void> {
    const response = await request(`/scan/${encodeURIComponent(id)}/report?format=${format}`)
    if (response.status === 202) throw new ApiError('Report is not ready yet.', 202)
    saveBlob(await response.blob(), `webprobe-${id}.${format}`)
  },
}

export function saveBlob(blob: Blob, name: string): void {
  const objectUrl = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = objectUrl
  link.download = name
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000)
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong. Try again.'
}
