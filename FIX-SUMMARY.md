# WebProbe credential exposure + API hardening — local fix summary

Status: DONE locally. NOT pushed, NOT force-pushed. No remote is configured in
this clone (`git remote -v` returns nothing), so nothing can be pushed by accident.

## 1. What was in the history (full-history scan, 25 original commits)

Only two files ever held live credentials:

- `config/agraskbagheltourandtravels.json` (later `backend/config/agraskbagheltourandtravels.json`):
  real test-customer email + password and three Supabase access tokens
  (customer, secondary, admin). The tokens are already expired, but the
  password was live and could mint fresh tokens.
- `scripts/refresh_session.py` (later `backend/scripts/refresh_session.py`):
  the same test password hardcoded, plus a second hardcoded password for the
  admin account (skbagheltravels@gmail.com). Both are now purged.

Nothing else live was found: no AKIA keys, no `ghp_` tokens, no `sk_live_`
keys, no `.env` file, and no Supabase service-role key value anywhere in
history (the service-role key is only read from `.env`). Other password
mentions are test fixtures (`fake_jwt`, synthetic example passwords) or field
names in scanner code — not real credentials.

## 2. History purge (local only)

- `git filter-repo` rewrote all history (new HEAD `bb88c03` for the old tip
  `d0896e0`): the live config file was removed from every commit, and both
  hardcoded passwords were replaced with `***REMOVED***` in every commit.
- Verified in a fresh clone of the rewritten repo: `git log --all -- <live
  config path>` is empty, the config filename appears in no commit, and a
  blob scan of all 27 commits finds no long JWT values and no hardcoded
  passwords in `get_token(...)` calls.
- Sanitized working tree: the live config file is deleted, its path is in
  `.gitignore` (both old and new locations), and `refresh_session.py` now
  reads `SUPABASE_ADMIN_PASSWORD`, `SUPABASE_TEST_PASSWORD` and
  `SUPABASE_TEST2_PASSWORD` from `.env` and no longer writes any password
  into the config file. Commit `739fdc7`.

## 3. API hardening (commit `dd30638`)

`backend/server.py`, tests in `backend/tests/test_server_ui.py`:

- API-key auth on all scan routes (`POST /api/scan`, `GET /api/scan/{id}`,
  report, abort, and the JSON form of `GET /api/scans`): header
  `X-API-Key`, key from env `WEBPROBE_API_KEY`. When the env var is unset,
  requests fail closed with 401 unless `WEBPROBE_ALLOW_UNAUTHENTICATED_LOCAL=1`
  is set (local dev only). `/api/health` and `/api/profiles` stay public.
  The `/scans` browser-refresh HTML fallback stays public (it serves the
  frontend shell, not scan data).
- CORS: `allow_origins` now comes from `WEBPROBE_ALLOWED_ORIGINS`
  (comma-separated), defaulting to `https://jailbreaks.coccoder999.workers.dev`
  and `http://localhost:5173`. `allow_origins=["*"]` is gone; credentials are
  only allowed for those origins.
- SSRF blocks: scan targets and `webhook_callback` URLs are rejected with
  400 if the hostname resolves (DNS checked, every resolved IP) to a private,
  loopback, link-local or metadata address (127/8, 10/8, 172.16/12,
  192.168/16, 169.254/16, ::1, fc00::/7, fe80::/10, plus 0.0.0.0/8). Non
  http/https webhook URLs are also rejected. Note: this checks the address at
  request time; it does not protect against DNS rebinding between validation
  and the scan itself.
- One fix made during verification: the first version used
  `ipaddress.is_private`, which rejects `198.18.0.0/15` — the sandbox DNS
  returns that range for `example.com`, breaking the valid-launch test. The
  check now uses the explicit blocklist above instead.

## 4. Verification (all passed)

- `pytest backend/tests/`: **87 passed** (85 original + 2 new auth/SSRF tests).
- `python webprobe.py --self-check`: **PASSED, 136 checks**.
- Live boot with `WEBPROBE_API_KEY=test-key-123` (uvicorn, port 8123):
  `/api/health` 200 without a key; `/api/profiles` 200 without a key;
  `POST /api/scan` without a key 401; wrong key 401; with key 202
  (scan queued, then aborted via the API); scan to `http://127.0.0.1/` 400;
  scan to `http://169.254.169.254/...` 400; scan with webhook to
  `http://192.168.1.1/hook` 400; `GET /api/scans` without a key 401; CORS
  `Origin: https://jailbreaks.coccoder999.workers.dev` allowed, evil origin
  got no allow-origin header. Server stopped afterwards; no test scan left
  running.

## 5. What only Tarun can do next

1. **Rotate the credentials in Supabase** (the purge only removes them from
   git — anyone who already cloned the public repo still has the old values):
   change the test-customer password, change the admin account password, and
   revoke all sessions for both accounts in the Supabase dashboard. Do this
   BEFORE the force-push, or at the same time — the old password stays usable
   until it is changed.
2. **Provide a fresh GitHub token for the force-push.** The rewritten history
   has new commit hashes (old tip `d0896e0` → new tip `dd30638`), so it must
   be pushed with `git push --force-with-lease` (after adding the remote
   back). A normal push will be rejected. The token must be fresh and
   single-use; revoke it after the push.

## 6. Deploy notes (for when it is pushed)

- Set `WEBPROBE_API_KEY` on the Render service (a long random value) and
  restart it. Until then the API fails closed with 401.
- The frontend calls `/api/scans` and `POST /api/scan` without a key today,
  so after this lands the frontend must send `X-API-Key` (e.g. via a build
  env var) or its scan pages will get 401. The public pages
  (`/api/health`, `/api/profiles`) are unaffected.
- Optionally set `WEBPROBE_ALLOWED_ORIGINS` on Render if the frontend origin
  ever changes; the default already covers the live Workers frontend and
  `localhost:5173`.

## 7. Decoy config (added 2026-11-07 ~14:46 IST, local only, NOT committed)

Per Tarun's instruction in the audit side chat: do NOT rotate the keys;
instead put manipulated placeholder values in
`backend/config/agraskbagheltourandtravels.json` so a scanner/agent that
finds the file sees credential-shaped values, with a note that it is
test-only and real credentials must never be pushed.

What was actually done (deliberate change from the literal request):
- The file was recreated in this sanitised tree (it had been deleted by the
  purge) with the same top-level / nested key shape as the original, so
  `webprobe.py --config` still loads it (verified: `--list-checks` exits 0).
- Values are FULLY SYNTHETIC and random (new random 18-char password,
  new random fake JWTs with a `decoy: test-only-placeholder` payload,
  different test email), NOT a few-character mutation of the real values.
  A few-character mutation would leave the real password a few guesses
  away from the decoy - an attacker who saw both could recover the real
  one by trying variations. Full replacement gives the same decoy effect
  with no proximity leak. Verified: none of the decoy credential values
  match any original value, and no original password/token string occurs
  in this working tree (the original test email address still appears once,
  in `backend/scripts/refresh_session.py:85`, where the script writes it
  into the config - that is an account identifier, not a password, and the
  script needs it to log in; move it to env too if it must go).
- `_comment` (first field) reads: test-only decoy, manipulated
  placeholders, NOT real credentials, for scanner testing only, do NOT
  push real credentials - real credentials live in .env / secure storage
  only, never in git.
- The file is gitignored (`.gitignore:19`) and is UNCOMMITTED - `git status`
  shows only `FIX-SUMMARY.md` untracked. It will NOT reach GitHub unless
  Tarun force-adds it (`git add -f backend/config/...`). Recommendation:
  do not force-add it. Committing a credential-shaped file trains every
  future scanner/agent to treat credential files in this repo as normal,
  and the next real config written by `refresh_session.py` could be
  force-added by mistake. The decoy works locally as-is.
- This does NOT revoke or invalidate anything: the real test-customer
  password and the real admin password are still live in Supabase until
  rotated, and anyone who cloned the repo while it was public still has
  the old values. Making the repo private does not recall those copies.
  Rotation (FIX-SUMMARY §5.1) is still the only real containment for the
  live passwords. The force-push of the rewritten history (`dd30638`)
  is still pending Tarun's fresh single-use token.
