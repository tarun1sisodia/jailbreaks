import { afterEach, describe, expect, it, vi } from 'vitest'
import worker, { buildFallbackRequest, mergeScanLists } from '../worker.js'

const env = {
  RENDER_API_URL: 'https://render.example/api',
  RENDER_API_KEY: 'render-key',
  BOX6_API_URL: 'https://box6.example/api',
  BOX6_API_KEY: 'box6-key',
  WAKE_URL: 'https://render.example/api/wake/box6',
  WAKE_SECRET: 'wake-secret',
  ALLOWED_ORIGINS: 'https://jailbreaks.example',
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('Workers proxy scan history', () => {
  it('merges Render and mirrored box6 scans, newest first, without duplicates', () => {
    const merged = mergeScanLists(
      [
        { scan_id: 'render-1', created_at: 10, status: 'completed' },
        { scan_id: 'shared', created_at: 30, status: 'running' },
      ],
      [
        { scan_id: 'box6-1', created_at: 20, status: 'queued' },
        { scan_id: 'shared', created_at: 30, status: 'completed' },
      ],
    )
    expect(merged.map((scan) => scan.scan_id)).toEqual(['shared', 'box6-1', 'render-1'])
    expect(merged[0].status).toBe('running')
  })

  it('keeps the list empty when upstreams return errors', () => {
    expect(mergeScanLists({ detail: 'failed' }, null)).toEqual([])
  })

  it('marks a WebProbe fallback with the engine the caller requested', () => {
    const request = buildFallbackRequest(
      { url: 'https://example.com', profile: 'quick', engine: 'all', repo: 'https://github.com/org/repo' },
      'all',
    )
    expect(request.engine).toBe('webprobe')
    expect(request.requested_engine).toBe('all')
    expect(request.fallback).toBe(true)
    expect(request.repo).toBeUndefined()
    expect(request.fallback_note).toContain('WebProbe only')
  })

  it('sends fallback metadata to Render when box6 cannot wake', async () => {
    const calls = []
    vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
      calls.push({ url: String(url), init })
      if (String(url).includes('/health')) return new Response('', { status: 503 })
      if (String(url).includes('/wake/box6')) return json({ ready: false, state: 'suspended' })
      if (String(url).endsWith('/scan')) return json({ scan_id: 'render-1', target: 'https://example.com', engine: 'webprobe', status: 'queued' }, 202)
      return json({ detail: 'not found' }, 404)
    }))

    const response = await worker.fetch(new Request('https://jailbreaks.example/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://example.com', profile: 'quick', engine: 'all' }),
    }), env, { waitUntil() {} })
    const body = await response.json()
    expect(body.fallback).toBe(true)
    expect(body.requested_engine).toBe('all')
    expect(body.engine_used).toBe('webprobe')

    const renderScan = calls.find((call) => call.url === 'https://render.example/api/scan')
    expect(renderScan).toBeTruthy()
    const sent = JSON.parse(renderScan.init.body)
    expect(sent.engine).toBe('webprobe')
    expect(sent.requested_engine).toBe('all')
    expect(sent.fallback).toBe(true)
    expect(sent.repo).toBeUndefined()
  })

  it('explains that a mirrored scan is asleep instead of reporting it missing', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('/scan/box6-1')) return json({ detail: 'Scan is stored on box6', remote: 'box6' }, 404)
      if (String(url).includes('/health')) return new Response('', { status: 503 })
      return json({ detail: 'not found' }, 404)
    }))

    const response = await worker.fetch(new Request('https://jailbreaks.example/api/scan/box6-1'), env, { waitUntil() {} })
    expect(response.status).toBe(503)
    const body = await response.json()
    expect(body.detail).toContain('asleep')
  })

  it('merges mirrored box6 scans into the history response', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('/remote-scans')) {
        return json([{ scan_id: 'box6-1', created_at: 20, status: 'completed', url: 'https://example.com' }])
      }
      if (String(url).includes('/scans?')) {
        return json([{ scan_id: 'render-1', created_at: 10, status: 'completed', url: 'https://example.org' }])
      }
      return json({ detail: 'not found' }, 404)
    }))

    const response = await worker.fetch(new Request('https://jailbreaks.example/api/scans'), env, { waitUntil() {} })
    const scans = await response.json()
    expect(scans.map((scan) => scan.scan_id)).toEqual(['box6-1', 'render-1'])
  })
})
