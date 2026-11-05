import type { Health, Profiles, Report, Scan, ScanRequest, ScanStarted } from '../types'

export class ApiError extends Error {
  status?: number
  constructor(message: string, status?: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

function endpoint(base: string, path: string): string {
  return `${base.replace(/\/+$/, '')}${path}`
}

async function request(base: string, path: string, init?: RequestInit): Promise<Response> {
  let response: Response
  try {
    response = await fetch(endpoint(base, path), { ...init, headers: { Accept: 'application/json', ...init?.headers }, cache: 'no-store' })
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
  async health(base: string): Promise<Health> {
    return (await request(base, '/health')).json()
  },
  async scans(base: string): Promise<Scan[]> {
    return (await request(base, '/scans?limit=1000')).json()
  },
  async profiles(base: string): Promise<Profiles> {
    return (await request(base, '/profiles')).json()
  },
  async scan(base: string, id: string): Promise<Scan> {
    return (await request(base, `/scan/${encodeURIComponent(id)}`)).json()
  },
  async start(base: string, payload: ScanRequest): Promise<ScanStarted> {
    return (await request(base, '/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
    })).json()
  },
  async abort(base: string, id: string): Promise<void> {
    await request(base, `/scan/${encodeURIComponent(id)}/abort`, { method: 'POST' })
  },
  async report(base: string, id: string): Promise<Report> {
    const response = await request(base, `/scan/${encodeURIComponent(id)}/report?format=json`)
    if (response.status === 202) throw new ApiError('Report is not ready yet.', 202)
    return response.json()
  },
  async log(base: string, id: string): Promise<string> {
    const response = await request(base, `/scan/${encodeURIComponent(id)}/report?format=log`, { headers: { Accept: 'text/plain' } })
    return response.text()
  },
  async download(base: string, id: string, format: 'json' | 'md' | 'sarif'): Promise<void> {
    const response = await request(base, `/scan/${encodeURIComponent(id)}/report?format=${format}`)
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
