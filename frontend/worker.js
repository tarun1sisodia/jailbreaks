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
// report or abort actually needs it.

const DEFAULT_ORIGINS = 'https://jailbreaks.coccoder999.workers.dev,http://localhost:5173'
const BOX6_ENGINES = {
  kagesec: { name: 'KageSec', description: 'DAST + CVE templates', url_scan: true, available: true, binary: 'kagesec', version: null, source: 'box6', wake_on_demand: true },
  openosint: { name: 'OpenOSINT', description: 'Passive recon intel', url_scan: true, available: true, binary: 'openosint', version: null, source: 'box6', wake_on_demand: true },
  argus: { name: 'Argus', description: 'SAST / SCA / secrets over code', url_scan: false, available: true, binary: 'argus', version: null, source: 'box6', wake_on_demand: true },
}
const URL_ENGINES = new Set(['webprobe', 'kagesec', 'openosint', 'all'])

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

async function forwardScan(env, body) {
  const engine = body.engine || 'webprobe'
  const renderUrl = (env.RENDER_API_URL || '').replace(/\/+$/, '')
  const renderKey = env.RENDER_API_KEY || ''

  // WebProbe always goes to Render: always on, no wake needed.
  if (engine === 'webprobe') {
    if (!renderUrl) {
      return { status: 503, body: { detail: 'RENDER_API_URL is not configured' }, engineUsed: 'webprobe' }
    }
    const res = await upstreamJson(`${renderUrl}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': renderKey },
      body: JSON.stringify(body),
    }, 20000)
    return { status: res.status, body: res.body, engineUsed: 'webprobe' }
  }

  // Other engines need box6.
  if (await box6Healthy(env)) {
    const res = await upstreamJson(box6Url(env, '/scan'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': env.BOX6_API_KEY || '' },
      body: JSON.stringify(body),
    }, 20000)
    return { status: res.status, body: res.body, engineUsed: engine }
  }

  const wake = await wakeBox6(env)
  if (wake.ready || (await box6Healthy(env))) {
    const res = await upstreamJson(box6Url(env, '/scan'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': env.BOX6_API_KEY || '' },
      body: JSON.stringify(body),
    }, 20000)
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
  const fallbackBody = { ...body, engine: 'webprobe', repo: undefined }
  const res = await upstreamJson(`${renderUrl}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': renderKey },
    body: JSON.stringify(fallbackBody),
  }, 20000)
  const out = res.body && typeof res.body === 'object' ? res.body : {}
  out.engine_used = 'webprobe'
  out.fallback = true
  out.note = 'Full engines were asleep, ran WebProbe only.'
  return { status: res.status, body: out, engineUsed: 'webprobe' }
}

// Status/report/abort: try Render first; a 404 there means the scan may
// live on box6, so try box6 (no wake — a scan that exists there was
// started while box6 was awake; if box6 is asleep its report cannot be
// fetched until it is woken by a new scan).
async function forwardById(env, request, path, method, body) {
  const renderUrl = (env.RENDER_API_URL || '').replace(/\/+$/, '')
  const render = await upstreamJson(`${renderUrl}${path}`, {
    method,
    headers: { 'X-API-Key': env.RENDER_API_KEY || '', ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  }, 15000)
  if (render.status !== 404) return render
  if (!env.BOX6_API_URL || !env.BOX6_API_KEY) return render
  if (!(await box6Healthy(env))) return render
  const box = await upstreamJson(box6Url(env, path), {
    method,
    headers: { 'X-API-Key': env.BOX6_API_KEY, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  }, 15000)
  return box.status === 404 ? render : box
}

export default {
  async fetch(request, env, ctx) {
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
        const res = await upstreamJson(`${renderUrl}/health`, { headers: { Accept: 'application/json' } }, 10000)
        const body = res.body && typeof res.body === 'object' ? { ...res.body, proxy: 'workers', box6_engines: Object.keys(BOX6_ENGINES) } : res.body
        return jsonResponse(env, request, body, res.status)
      }

      // /api/engines — union of Render (live) and box6 (known installed,
      // wake on demand). No box6 contact, so no keepalive.
      if (url.pathname === '/api/engines' && request.method === 'GET') {
        if (!renderUrl) {
          return jsonResponse(env, request, { detail: 'RENDER_API_URL is not configured in Workers variables' }, 503)
        }
        const res = await upstreamJson(`${renderUrl}/engines`, { headers: { Accept: 'application/json' } }, 10000)
        const merged = res.body && typeof res.body === 'object' ? { ...res.body } : {}
        for (const [name, info] of Object.entries(BOX6_ENGINES)) merged[name] = info
        return jsonResponse(env, request, merged, res.status)
      }

      if (url.pathname === '/api/profiles' && request.method === 'GET') {
        if (!renderUrl) {
          return jsonResponse(env, request, { detail: 'RENDER_API_URL is not configured in Workers variables' }, 503)
        }
        const res = await upstreamJson(`${renderUrl}/profiles`, { headers: { Accept: 'application/json' } }, 10000)
        return jsonResponse(env, request, res.body, res.status)
      }

      if (url.pathname === '/api/scans' && request.method === 'GET') {
        if (!renderUrl) {
          return jsonResponse(env, request, { detail: 'RENDER_API_URL is not configured in Workers variables' }, 503)
        }
        const res = await upstreamJson(`${renderUrl}/scans?limit=1000`, { headers: { 'X-API-Key': renderKey, Accept: 'application/json' } }, 10000)
        return jsonResponse(env, request, res.body, res.status)
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
        const out = await forwardScan(env, body)
        return jsonResponse(env, request, out.body, out.status)
      }

      const scanMatch = url.pathname.match(/^\/api\/scan\/([^/]+)(\/abort|\/report)?$/)
      if (scanMatch) {
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
