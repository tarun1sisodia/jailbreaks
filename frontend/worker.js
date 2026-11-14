// SECURITY NOTICE (2026-11-10): Any secrets previously committed to this file have been REVOKED by the developer and are NO LONGER VALID. Do not use them.
// WebProbe Workers proxy — the ONLY place the browser's scans go.
//
// The frontend calls this Worker same-origin (/api/*) with NO credential.
// This Worker holds the backend keys in Workers Secrets (env, never in
// code or git) and adds the backend auth header server-side.
//
// Required Secrets / Environment Variables:
//   RENDER_API_URL   e.g. https://jailbreaks-46uf.onrender.com/api
//   RENDER_API_KEY   the Render-only backend key
//   BOX6_API_URL     e.g. https://8000-<id>.instabox.tech/api  (box6 public port)
//   BOX6_API_KEY     the box6-only backend key
//   WAKE_URL         e.g. https://jailbreaks-46uf.onrender.com/api/wake/box6
//   WAKE_SECRET      shared secret this Worker sends to the wake endpoint
//   ALLOWED_ORIGINS  comma list, default Workers origin + localhost:5173
//   BOX6_PORT_TOKEN  [OPTIONAL] legacy token if private port used; omitted for public port
//
// Routing by engine:
//   webprobe                         -> Render (always on)
//   kagesec / openosint / argus / all -> box6 (all engines, wake on demand)
//   argus forwards `repo` (git URL or path), never a target URL.
//
// Box6 sleeps after 30 min idle; there is NO keepalive timer anywhere.
// If box6 is asleep, the proxy asks the Render wake endpoint to resume it.
// A wake takes up to ~90s, longer than a Worker subrequest should wait, so
// the first attempt returns a clear 202 "waking, retry in ~60s" response
// and the user retries once. If wake still fails, URL engines fall back to
// Render WebProbe-only with an explicit fallback flag in the response —
// a fallback scan is never reported as a full-engine scan. Argus has no
// Render equivalent, so it returns 503 instead of a silent fallback.
//
// The proxy deliberately does NOT poll box6 on /health or /scans: polling
// would keep the box awake. It contacts box6 only when a scan, status,
// report or abort actually needs it. Box6 scan metadata is mirrored to
// Render (/scans/mirror) so /scans can list those runs without touching box6.

const DEFAULT_ORIGINS = 'https://jailbreaks.coccoder999.workers.dev,http://localhost:5173'
const BOX6_ENGINES = {
  kagesec: { name: 'KageSec', description: 'DAST + CVE templates', url_scan: true, available: true, binary: 'kagesec', version: null, source: 'box6', wake_on_demand: true },
  openosint: { name: 'OpenOSINT', description: 'Passive recon intel', url_scan: true, available: true, binary: 'openosint', version: null, source: 'box6', wake_on_demand: true },
  argus: { name: 'Argus', description: 'SAST / SCA / secrets over code', url_scan: false, available: true, binary: 'argus', version: null, source: 'box6', wake_on_demand: true },
}
const URL_ENGINES = new Set(['webprobe', 'kagesec', 'openosint', 'all'])

// URLs are safe defaults. Credentials are intentionally NOT defaulted:
// RENDER_API_KEY, BOX6_API_KEY and WAKE_SECRET must be supplied as
// Workers Secrets (`wrangler secret put <NAME>`) or via the Cloudflare
// dashboard. A missing credential fails closed with HTTP 503.
const DEFAULTS = {
  RENDER_API_URL: 'https://jailbreaks-46uf.onrender.com/api',
  BOX6_API_URL: 'https://8000-agq3oekm7yaprv7dohu23wsj2y.instabox.tech/api',
  WAKE_URL: 'https://jailbreaks-46uf.onrender.com/api/wake/box6',
  ALLOWED_ORIGINS: 'https://jailbreaks.coccoder999.workers.dev,http://localhost:5173',
}

function resolveEnv(raw) {
  const e = raw || {}
  return {
    RENDER_API_URL: e.RENDER_API_URL || DEFAULTS.RENDER_API_URL,
    RENDER_API_KEY: e.RENDER_API_KEY || '',
    BOX6_API_URL: e.BOX6_API_URL || DEFAULTS.BOX6_API_URL,
    BOX6_API_KEY: e.BOX6_API_KEY || '',
    WAKE_URL: e.WAKE_URL || DEFAULTS.WAKE_URL,
    WAKE_SECRET: e.WAKE_SECRET || '',
    ALLOWED_ORIGINS: e.ALLOWED_ORIGINS || DEFAULTS.ALLOWED_ORIGINS,
    BOX6_PORT_TOKEN: e.BOX6_PORT_TOKEN || '',
    ASSETS: e.ASSETS,
  }
}

function requireSecrets(env, names) {
  const missing = names.filter((name) => !env[name])
  if (!missing.length) return null
  return {
    detail: `Worker is missing required secret(s): ${missing.join(', ')}. ` +
            'Set them with `wrangler secret put <NAME>`; do not commit them.',
  }
}

function allowedOrigins(env) {
  return (env.ALLOWED_ORIGINS || DEFAULT_ORIGINS).split(',').map((s) => s.trim()).filter(Boolean)
}

function corsHeaders(env, request) {
  const origin = request.headers.get('Origin') || ''
  const allowed = allowedOrigins(env)
  const headers = { Vary: 'Origin' }
  if (allowed.includes(origin)) headers['Access-Control-Allow-Origin'] = origin
  return headers
}

function jsonResponse(env, request, body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(env, request) },
  })
}

function box6Url(env, path) {
  const base = (env.BOX6_API_URL || '').replace(/\/+$/, '')
  if (!base) return ''
  const sep = path.includes('?') ? '&' : '?'
  const token = env.BOX6_PORT_TOKEN ? `${sep}_token=${encodeURIComponent(env.BOX6_PORT_TOKEN)}` : ''
  return `${base}${path}${token}`
}

// Explicitly mark a WebProbe-only fallback. The backend persists these fields
// with the scan and copies them into report metadata, so the notice survives
// navigation and a later page refresh.
export function buildFallbackRequest(body, engine) {
  return {
    ...body,
    engine: 'webprobe',
    repo: undefined,
    requested_engine: engine,
    fallback: true,
    fallback_note: 'Full engines were asleep, ran WebProbe only.',
  }
}

// Merge local Render scans with mirrored box6 metadata without contacting
// box6. Render is the durable history index; box6 remains the report source.
export function mergeScanLists(renderScans, remoteScans) {
  const seen = new Set()
  const merged = []
  for (const item of [
    ...(Array.isArray(renderScans) ? renderScans : []),
    ...(Array.isArray(remoteScans) ? remoteScans : []),
  ]) {
    if (!item || typeof item !== 'object' || !item.scan_id || seen.has(item.scan_id)) continue
    seen.add(item.scan_id)
    merged.push(item)
  }
  return merged.sort((a, b) => (Number(b.created_at) || 0) - (Number(a.created_at) || 0))
}

async function fetchWithTimeout(url, init, ms) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), ms)
  try {
    return await fetch(url, { ...init, signal: controller.signal })
  } finally {
    clearTimeout(timer)
  }
}

async function upstreamJson(url, init, ms = 15000) {
  if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
    return {
      status: 502,
      body: { detail: `Backend URL is not configured or invalid (${url || 'empty'})` },
      headers: new Headers(),
    }
  }
  try {
    const res = await fetchWithTimeout(url, init, ms)
    const text = await res.text()
    let body = null
    try { body = text ? JSON.parse(text) : null } catch { body = text }
    return { status: res.status, body, headers: res.headers }
  } catch (err) {
    const isTimeout = err && (err.name === 'AbortError' || err.message?.includes('aborted'))
    return {
      status: isTimeout ? 504 : 502,
      body: { detail: isTimeout ? `Upstream timeout after ${ms}ms` : `Upstream connection failed: ${err?.message || err}` },
      headers: new Headers(),
    }
  }
}

async function box6Healthy(env) {
  if (!env.BOX6_API_URL || !env.BOX6_API_KEY) return false
  const target = box6Url(env, '/health')
  if (!target) return false
  try {
    const res = await fetchWithTimeout(target, { headers: { Accept: 'application/json' } }, 4000)
    return res.ok
  } catch {
    return false
  }
}

// Ask Render to resume box6 and wait for it. Returns { ready, state }.
// The Render endpoint itself polls up to ~90s; this call is capped shorter
// so the Worker does not hang — a timeout here means "still waking".
async function wakeBox6(env) {
  if (!env.WAKE_URL || !env.WAKE_SECRET) return { ready: false, state: 'wake_not_configured' }
  try {
    const res = await fetchWithTimeout(env.WAKE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Wake-Secret': env.WAKE_SECRET },
      body: JSON.stringify({}),
    }, 30000)
    const body = await res.json().catch(() => ({}))
    return { ready: !!body.ready, state: body.state || `http_${res.status}` }
  } catch {
    return { ready: false, state: 'wake_timeout' }
  }
}

// Store box6 scan metadata on Render so GET /api/scans can show full-engine
// scans without polling box6. Status/report reads still go to box6; Render's
// mirrored records are deliberately not registered as local scans.
async function mirrorRemoteScan(env, scan) {
  const renderUrl = (env.RENDER_API_URL || '').replace(/\/+$/, '')
  if (!renderUrl || !env.RENDER_API_KEY || !scan || !scan.scan_id) return
  const record = {
    scan_id: scan.scan_id,
    target: scan.target || scan.url || '',
    url: scan.url || scan.target || '',
    profile: scan.profile || 'full',
    engine: scan.engine || 'all',
    status: scan.status || 'queued',
    created_at: scan.created_at || Math.floor(Date.now() / 1000),
    started_at: scan.started_at,
    ended_at: scan.ended_at,
    duration_seconds: scan.duration_seconds || 0,
    findings_count: scan.findings_count || 0,
    severity_summary: scan.severity_summary || {},
    engine_used: scan.engine_used,
    requested_engine: scan.requested_engine,
    note: scan.note,
    fallback: !!scan.fallback,
  }
  await upstreamJson(`${renderUrl}/scans/mirror`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': env.RENDER_API_KEY },
    body: JSON.stringify(record),
  }, 5000)
}

async function forwardScan(env, body) {
  const engine = body.engine || 'webprobe'
  const renderUrl = (env.RENDER_API_URL || '').replace(/\/+$/, '')
  const renderKey = env.RENDER_API_KEY || ''

  // WebProbe always goes to Render: always on, no wake needed.
  if (engine === 'webprobe') {
    if (!renderUrl) {
      return { status: 503, body: { detail: 'RENDER_API_URL is not configured' }, engineUsed: 'webprobe' }
    }
    if (!renderKey) {
      return { status: 503, body: { detail: 'RENDER_API_KEY is not configured' }, engineUsed: 'webprobe' }
    }
    const res = await upstreamJson(`${renderUrl}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': renderKey },
      body: JSON.stringify(body),
    }, 20000)
    return { status: res.status, body: res.body, engineUsed: 'webprobe' }
  }

  // Other engines need box6.
  if (!env.BOX6_API_KEY) {
    return { status: 503, body: { detail: 'BOX6_API_KEY is not configured' }, engineUsed: engine }
  }
  if (await box6Healthy(env)) {
    const res = await upstreamJson(box6Url(env, '/scan'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': env.BOX6_API_KEY || '' },
      body: JSON.stringify(body),
    }, 20000)
    if (res.status >= 200 && res.status < 300 && res.body && typeof res.body === 'object') {
      await mirrorRemoteScan(env, { ...res.body, engine_used: engine, requested_engine: body.requested_engine || engine })
    }
    return { status: res.status, body: res.body, engineUsed: engine }
  }

  const wake = await wakeBox6(env)
  if (wake.ready || (await box6Healthy(env))) {
    const res = await upstreamJson(box6Url(env, '/scan'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': env.BOX6_API_KEY || '' },
      body: JSON.stringify(body),
    }, 20000)
    if (res.status >= 200 && res.status < 300 && res.body && typeof res.body === 'object') {
      await mirrorRemoteScan(env, { ...res.body, engine_used: engine, requested_engine: body.requested_engine || engine })
    }
    return { status: res.status, body: res.body, engineUsed: engine }
  }

  // Box6 did not come up. Argus has no Render equivalent: fail loudly.
  if (engine === 'argus') {
    return {
      status: 503,
      body: { detail: 'Box6 engine box is asleep and did not wake in time. Please retry in about a minute; Argus cannot run on the always-on backend.' },
      engineUsed: 'argus',
    }
  }

  // URL engines: fall back to Render WebProbe-only, flagged explicitly.
  if (wake.state === 'wake_timeout' || wake.state === 'waking' || wake.state === 'resuming') {
    return {
      status: 202,
      body: { status: 'waking', engine, retry_after: 60, detail: 'Box6 is waking (up to about 90 seconds). Please retry this scan in about a minute.' },
      engineUsed: engine,
    }
  }
  const fallbackBody = buildFallbackRequest(body, engine)
  const res = await upstreamJson(`${renderUrl}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': renderKey },
    body: JSON.stringify(fallbackBody),
  }, 20000)
  const out = res.body && typeof res.body === 'object' ? res.body : {}
  out.engine_used = 'webprobe'
  out.requested_engine = engine
  out.fallback = true
  out.note = fallbackBody.fallback_note
  return { status: res.status, body: out, engineUsed: 'webprobe' }
}

// Status/report/abort: try Render first; a 404 there means the scan may
// live on box6, so try box6 (no wake — a scan that exists there was
// started while box6 was awake; if box6 is asleep its report cannot be
// fetched until it is woken by a new scan).
async function forwardById(env, request, path, method, body) {
  const renderUrl = (env.RENDER_API_URL || '').replace(/\/+$/, '')
  if (!env.RENDER_API_KEY) {
    return { status: 503, body: { detail: 'RENDER_API_KEY is not configured' }, headers: new Headers() }
  }
  const render = await upstreamJson(`${renderUrl}${path}`, {
    method,
    headers: { 'X-API-Key': env.RENDER_API_KEY || '', ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  }, 15000)
  const remoteScan = render.status === 404 && render.body && typeof render.body === 'object' && render.body.remote === 'box6';
  if (render.status !== 404) return render
  if (!env.BOX6_API_URL || !env.BOX6_API_KEY) {
    return remoteScan
      ? { status: 503, body: { detail: 'This scan is stored on the engine box, but the box6 proxy is not configured. Start a new full-engine scan to wake it.' }, headers: render.headers }
      : render
  }
  if (!(await box6Healthy(env))) {
    return remoteScan
      ? { status: 503, body: { detail: 'This scan is stored on the engine box, which is asleep. Start a new full-engine scan to wake it, then retry.' }, headers: render.headers }
      : render
  }
  const box = await upstreamJson(box6Url(env, path), {
    method,
    headers: { 'X-API-Key': env.BOX6_API_KEY, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  }, 15000)
  // Only persist terminal status changes here; the initial queued record is
  // mirrored at submit time. Avoid a mirror write on every console poll.
  if (box.status < 400 && box.body && typeof box.body === 'object' && box.body.scan_id
      && ['completed', 'failed', 'aborted', 'error'].includes(box.body.status)) {
    await mirrorRemoteScan(env, { ...box.body, remote: 'box6' })
  }
  return box.status === 404 ? render : box
}

export default {
  async fetch(request, rawEnv, ctx) {
    const env = resolveEnv(rawEnv)
    try {
      const url = new URL(request.url)
      const origin = request.headers.get('Origin') || ''

      // Preflight: only allowed origins, GET/POST only.
      if (request.method === 'OPTIONS') {
        const headers = corsHeaders(env, request)
        if (!headers['Access-Control-Allow-Origin']) {
          return new Response('Origin not allowed', { status: 400, headers: { Vary: 'Origin' } })
        }
        return new Response(null, {
          status: 204,
          headers: {
            ...headers,
            'Access-Control-Allow-Methods': 'GET, POST',
            'Access-Control-Allow-Headers': 'Content-Type, Accept',
            'Access-Control-Max-Age': '86400',
          },
        })
      }
      if (request.method !== 'GET' && request.method !== 'POST') {
        return jsonResponse(env, request, { detail: 'Method not allowed' }, 405)
      }
      // Same-origin calls have no Origin; cross-origin calls must be allowed.
      if (origin && !allowedOrigins(env).includes(origin)) {
        return jsonResponse(env, request, { detail: 'Origin not allowed' }, 400)
      }

      const renderUrl = (env.RENDER_API_URL || '').replace(/\/+$/, '')
      const renderKey = env.RENDER_API_KEY || ''

      // /api/health — Render only. Never contacts box6 (no keepalive polling).
      if (url.pathname === '/api/health' && request.method === 'GET') {
        if (!renderUrl) {
          return jsonResponse(env, request, { detail: 'RENDER_API_URL is not configured in Workers variables' }, 503)
        }
        const res = await upstreamJson(`${renderUrl}/health`, { headers: { Accept: 'application/json' } }, 15000)
        const body = res.body && typeof res.body === 'object' ? { ...res.body, proxy: 'workers', box6_engines: Object.keys(BOX6_ENGINES) } : res.body
        return jsonResponse(env, request, body, res.status)
      }

      // /api/engines — union of Render (live) and box6 (known installed,
      // wake on demand). No box6 contact, so no keepalive.
      if (url.pathname === '/api/engines' && request.method === 'GET') {
        if (!renderUrl) {
          return jsonResponse(env, request, { detail: 'RENDER_API_URL is not configured in Workers variables' }, 503)
        }
        const res = await upstreamJson(`${renderUrl}/engines`, { headers: { Accept: 'application/json' } }, 15000)
        const merged = res.body && typeof res.body === 'object' ? { ...res.body } : {}
        for (const [name, info] of Object.entries(BOX6_ENGINES)) merged[name] = info
        return jsonResponse(env, request, merged, res.status)
      }

      if (url.pathname === '/api/profiles' && request.method === 'GET') {
        if (!renderUrl) {
          return jsonResponse(env, request, { detail: 'RENDER_API_URL is not configured in Workers variables' }, 503)
        }
        const res = await upstreamJson(`${renderUrl}/profiles`, { headers: { Accept: 'application/json' } }, 15000)
        return jsonResponse(env, request, res.body, res.status)
      }

      if (url.pathname === '/api/scans' && request.method === 'GET') {
        if (!renderUrl) {
          return jsonResponse(env, request, { detail: 'RENDER_API_URL is not configured in Workers variables' }, 503)
        }
        const missing = requireSecrets(env, ['RENDER_API_KEY'])
        if (missing) return jsonResponse(env, request, missing, 503)
        const [res, remote] = await Promise.all([
          upstreamJson(`${renderUrl}/scans?limit=1000`, { headers: { 'X-API-Key': renderKey, Accept: 'application/json' } }, 15000),
          upstreamJson(`${renderUrl}/remote-scans?limit=1000`, { headers: { 'X-API-Key': renderKey, Accept: 'application/json' } }, 15000),
        ])
        if (res.status >= 400) return jsonResponse(env, request, res.body, res.status)
        const scans = mergeScanLists(res.body, remote.status < 400 ? remote.body : [])
        return jsonResponse(env, request, scans, 200)
      }

      if (url.pathname === '/api/scan' && request.method === 'POST') {
        let body
        try { body = await request.json() } catch { return jsonResponse(env, request, { detail: 'Invalid JSON body' }, 400) }
        if (!body || typeof body !== 'object') return jsonResponse(env, request, { detail: 'Invalid scan request' }, 400)
        const engine = body.engine || 'webprobe'
        if (!['webprobe', 'kagesec', 'openosint', 'argus', 'all'].includes(engine)) {
          return jsonResponse(env, request, { detail: `Unknown engine: ${engine}` }, 400)
        }
        if (engine === 'argus' && !body.repo) {
          return jsonResponse(env, request, { detail: "Engine 'argus' scans code: pass 'repo' as a git URL or a directory path." }, 400)
        }
        if (engine !== 'argus' && !body.url) {
          return jsonResponse(env, request, { detail: 'Pass a target URL for this engine.' }, 400)
        }
        const required = engine === 'webprobe'
          ? ['RENDER_API_KEY']
          : ['BOX6_API_KEY', 'WAKE_SECRET']
        const missing = requireSecrets(env, required)
        if (missing) return jsonResponse(env, request, missing, 503)
        const out = await forwardScan(env, body)
        return jsonResponse(env, request, out.body, out.status)
      }

      const scanMatch = url.pathname.match(/^\/api\/scan\/([^/]+)(\/abort|\/report)?$/)
      if (scanMatch) {
        const missing = requireSecrets(env, ['RENDER_API_KEY'])
        if (missing) return jsonResponse(env, request, missing, 503)
        const id = scanMatch[1]
        const suffix = scanMatch[2] || ''
        const path = `/scan/${encodeURIComponent(id)}${suffix}${url.search || ''}`
        if (suffix === '/abort' && request.method === 'POST') {
          const res = await forwardById(env, request, path, 'POST')
          return jsonResponse(env, request, res.body, res.status)
        }
        if (request.method === 'GET') {
          const res = await forwardById(env, request, path, 'GET')
          // Report downloads: pass through non-JSON bodies unchanged.
          if (suffix === '/report' && typeof res.body === 'string') {
            return new Response(res.body, { status: res.status, headers: { ...corsHeaders(env, request), 'Content-Type': res.headers.get('content-type') || 'text/plain' } })
          }
          return jsonResponse(env, request, res.body, res.status)
        }
      }

      // Anything else under /api is not proxied; other paths are the SPA.
      if (url.pathname.startsWith('/api/')) {
        return jsonResponse(env, request, { detail: 'Not found' }, 404)
      }
      return env.ASSETS.fetch(request)
    } catch (err) {
      return jsonResponse(env, request, { detail: `Workers proxy error: ${err?.message || err}` }, 500)
    }
  },
}
