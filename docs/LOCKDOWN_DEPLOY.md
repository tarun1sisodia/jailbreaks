# Locked-down WebProbe — deploy runbook

Commit: f034104 (local main, NOT pushed yet — see step 1).

## What changed
- Frontend: no API key field, no editable API base URL, no key in the
  browser. All calls go same-origin to `/api` (the Workers proxy).
- Workers proxy: `frontend/worker.js`, entrypoint in `frontend/wrangler.jsonc`.
  Holds backend keys in Workers Secrets, routes webprobe -> Render,
  kagesec/openosint/argus/all -> box6, wakes box6 on demand.
- Render wake endpoint: `POST /api/wake/box6` in `backend/server.py`,
  gated by `WAKE_SECRET` (header `X-Wake-Secret`), polls InstaBox
  resume up to ~90s, returns 202 while still waking. No keepalive timer.
- Fallback: URL engines fall back to Render WebProbe-only with
  `fallback: true` in the response; Argus returns 503 instead.

Box6 needs NO redeploy for this change: its scan code is unchanged
(the wake endpoint lives on Render only). Its service was verified
healthy with all 4 engines during this work.

## Step 1 — Push (needs a FRESH single-use GitHub token)
Do NOT reuse the 2026-11-05 token. Tarun: paste a fresh token in the
WebProbe chat, revoke it after this one push.
```bash
cd ~/workspace/jailbreaks-fix
git log --oneline -2        # expect f034104 on top of 34d6478
git push origin main        # with the fresh token as the credential
```
Verify remote main is f034104 (`git ls-remote` / GitHub page).

## Step 2 — Render (auto-deploys on push)
Render service `jailbreaks-46uf` auto-deploys from main (rootDir backend).
After the push, wait for the deploy to show Live, then set these env vars
(Render dashboard -> service -> Environment; values are NOT in this repo):
- `WEBPROBE_ALLOWED_ORIGINS` = `https://jailbreaks.coccoder999.workers.dev,http://localhost:5173`
  (set this if not already set)
- `WAKE_SECRET` = a new random secret (generate one; same value goes to
  Workers below as WAKE_SECRET)
- `INSTABOX_API_KEY` = the box6 account's InstaBox API key (server-side only)
- `INSTABOX_BOX6_MACHINE_ID` = box6 machine id (optional; if unset, the
  wake endpoint uses the single machine on that account)
- `BOX6_HEALTH_URL` = optional, e.g. the box6 `/api/health` URL
`WEBPROBE_API_KEY` on Render is already set (Render-only key) — do not
change it, do not paste it anywhere else.

## Step 3 — Workers secrets + deploy
In `frontend/` on a machine with Cloudflare access (wrangler login):
```bash
cd frontend
npm run build
wrangler secret put RENDER_API_URL    # https://jailbreaks-46uf.onrender.com/api
wrangler secret put RENDER_API_KEY    # the Render-only key (already on Render)
wrangler secret put BOX6_API_URL      # https://8000-<id>.instabox.tech/api
wrangler secret put BOX6_API_KEY      # the box6-only key (in /opt/instabox/config/webprobe.env on box6)
wrangler secret put BOX6_PORT_TOKEN   # the InstaBox private-port token for box6
wrangler secret put WAKE_URL          # https://jailbreaks-46uf.onrender.com/api/wake/box6
wrangler secret put WAKE_SECRET       # same value as Render WAKE_SECRET
wrangler secret put ALLOWED_ORIGINS   # https://jailbreaks.coccoder999.workers.dev,http://localhost:5173
wrangler deploy
```
Never put any of these values in code, git, or chat.

## Step 4 — Verify live (clean browser, no key pasted)
a. Open https://jailbreaks.coccoder999.workers.dev/settings — confirm NO
   API key field exists.
b. Quick scan on https://example.com, engine=webprobe — must complete,
   no 401. Expect ~5 findings.
c. Scan on https://example.com, engine=openosint — must complete via
   box6. Expect 12 findings (7 info, 5 low, as measured on box6).
   If box6 was asleep, the first attempt may say "Box6 is waking —
   retry in about a minute"; retry once and it should run.
d. Direct POST to Render / box6 `/api/scan` without a key must still
   return 401.
e. CORS preflight from a disallowed origin must fail (400, no
   allow-origin header); from the Workers origin it must pass.

## Already verified before deploy (this work)
- Backend suite: 100 passed (incl. 5 new wake tests).
- Worker routing tests (mocked upstreams): 11/11 passed — health,
  engines union, disallowed preflight, webprobe->Render,
  openosint->box6, wake-then-box6, waking 202, argus 503 (no fallback),
  kagesec fallback flagged, status via box6 after Render 404, SPA fallback.
- Frontend build: clean; bundle contains no key, no auth-header name,
  no Render/box6 URL.
- Box6 live: service active, /api/health 200 (136 checks, all 4 engines),
  keyless scan 401, OpenOSINT scan on example.com completed, 12 findings.
- Render live: /api/health 200 (engines [webprobe]), keyless scan 401,
  CORS preflight disallowed -> 400, Workers origin -> 200.
- Proxy code run live against real Render: /api/health 200,
  /api/engines union correct; scan returned 401 only because no key
  was configured in that test run — expected, and it proves Render
  auth still gates the proxy path.
