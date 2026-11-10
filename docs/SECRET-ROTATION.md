# Secret rotation — exposed credentials

**Status (2026-11-10):** code-side containment is done. Provider-side
rotation is **still outstanding** for the Workers secrets, the provider keys
in `.env`, and the Supabase sessions.

## What was exposed

### 1. Workers proxy credentials (committed to git)

`frontend/worker.js` was committed with three production credentials in its
`DEFAULTS` block:

| Secret | Used for | Where it is validated |
|---|---|---|
| `RENDER_API_KEY` | `X-API-Key` to the Render WebProbe API | Render env `WEBPROBE_API_KEY` |
| `BOX6_API_KEY` | `X-API-Key` to the box6 engines API | box6 `/opt/instabox/config/webprobe.env` |
| `WAKE_SECRET` | `X-Wake-Secret` to `POST /api/wake/box6` | Render env `WAKE_SECRET` |

The repository is public. The values appeared in commit `eb60f2c` and were
still present at `88f4eae`, so anyone who cloned or cached the repo may have
them. Deleting them from the current working tree does **not** revoke them.

### 2. Local `.env` provider keys (never tracked, but world-readable)

`.env` at the repository root contained live Cloudflare, Supabase, Razorpay,
Resend, S3, database, LocationIQ, deploy-callback, and Pages deploy-hook
credentials. The file was mode `777`; it was never tracked by git.

### 3. Supabase session cookies (never tracked, but world-readable)

`backend/config/agraskbagheltourandtravels.json` contained a test-account
password and Supabase session cookies for customer, staff, and `super_admin`
accounts. The file was mode `777`; it was never tracked by git.

The access tokens in that file expire at Unix `1793778642`
(2026-11-04), so they are expired as of 2026-11-10. Passwords and refresh
tokens may still be valid.

## Why rotation is mandatory

- Git history is immutable for anyone who already fetched it; a later commit
  does not erase the old blob.
- GitHub keeps unreachable objects available for a period after a rewrite.
- The Worker keys authorize billable and potentially destructive scan
  operations.
- The `.env` keys can read/write production data, send email, charge
  customers, and modify Cloudflare deployments.
- Removing a secret from the current tree does not revoke it.

## Code-side containment completed on 2026-11-10

These steps reduce the blast radius but do **not** replace provider-side
rotation:

- `.env` and `backend/config/agraskbagheltourandtravels.json` are now mode
  `600`.
- Private backups were written to `/root/.secrets/jailbreaks/` with mode
  `700` on the directory and `600` on the files. The backups are outside the
  repository.
- Credential fields in the repo copy of the live scan config were replaced
  with `${WEBPROBE_*}` placeholders. The scanner expands placeholders from
  the environment and also accepts `WEBPROBE_<KEY>` overrides.
- `backend/scripts/refresh_session.py` now writes refreshed Supabase tokens
  to `~/.secrets/jailbreaks/agraskbagheltourandtravels.runtime.json`
  (mode `600`), never back into the repository config.
- `scripts/secret_scan.py` scans tracked files for high-signal credential
  patterns and checks that local secret files are untracked and mode `600`.
  It is covered by `backend/tests/test_secret_scan.py`.
- New Worker secrets were generated into
  `~/.secrets/jailbreaks/worker-secrets-2026-11-10.env` (mode `600`). They
  are staging values only and have **not** been applied to Render, box6, or
  the Cloudflare Worker.

Verify the code-side state with:

```bash
cd /root/jailbreaks
python3 scripts/secret_scan.py
cd backend && /root/.venv-jailbreaks/bin/python -m pytest -q
```

## Rotation procedure — Workers secrets

Generate new values locally, e.g.:

```bash
openssl rand -hex 32   # RENDER_API_KEY
openssl rand -base64 32 | tr -d '/+=' | cut -c1-40   # BOX6_API_KEY
openssl rand -hex 16   # WAKE_SECRET
```

### 1. Render

Render dashboard -> service `jailbreaks-46uf` -> Environment:

1. Set `WEBPROBE_API_KEY` to the new Render key.
2. Set `WAKE_SECRET` to the new wake secret.
3. Save and wait for the service to redeploy.

### 2. box6 / InstaBox

On box6, update `/opt/instabox/config/webprobe.env`:

```bash
WEBPROBE_API_KEY=<new BOX6_API_KEY>
```

Restart the box6 WebProbe service so the new key is loaded. Keep the file
mode `600` and owned by the service user.

### 3. Cloudflare Worker

From `frontend/` on a machine with Cloudflare access:

```bash
wrangler secret put RENDER_API_KEY   # new Render key
wrangler secret put BOX6_API_KEY     # new box6 key
wrangler secret put WAKE_SECRET      # new wake secret (same as Render)
wrangler deploy
```

Never put these values in `wrangler.jsonc`, `worker.js`, tracked `.env`
files, or chat. The Worker fails closed with HTTP 503 when a required secret
is missing, so a partial deploy is visible rather than silently using a
stale default.

## Rotation procedure — `.env` provider keys

Rotate each value in the provider dashboard, update the deployment
environment (Render / box6 / Cloudflare as applicable), then replace the
local `.env` value. The local file is only a development convenience; the
deployed services have their own copies.

| Variable | Provider action | Verify |
|---|---|---|
| `CLOUDFLARE_API_TOKEN` | Roll the API token; scope it to the required Pages/Workers permissions | Old token returns 401 |
| `SUPABASE_SERVICE_ROLE_KEY` | Rotate the Supabase service-role key / JWT secret | Old key returns 401 |
| `SUPABASE_JWT_SECRET` | Rotate the project JWT secret (invalidates all sessions) | Old JWTs rejected |
| `DATABASE_URL` | Change the database password and update the connection string | Old password rejected |
| `RAZORPAY_KEY_SECRET` | Regenerate the key secret | Old secret fails signature checks |
| `RAZORPAY_WEBHOOK_SECRET` | Regenerate the webhook secret | Old webhook signature rejected |
| `RESEND_API_KEY` | Revoke and create a new API key | Old key returns 401 |
| `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` | Rotate the S3 access key pair | Old pair returns 403 |
| `LOCATIONIQ_TOKEN` | Regenerate the access token | Old token returns 401 |
| `DEPLOY_CALLBACK_SECRET` | Generate a new shared secret and update both ends | Old secret returns 403 |
| `PAGES_DEPLOY_HOOK_URL` | Delete and recreate the deploy hook | Old hook returns 404/401 |

`RAZORPAY_KEY_ID`, `CLOUDFLARE_ACCOUNT_ID`, `SUPABASE_URL`, S3 endpoints,
and bucket names are identifiers, not secrets, but rotate the key ID with
its secret where the provider requires it.

Do not paste new values into this document, a commit message, a ticket, or
chat. Put them directly into the provider dashboard and the private `.env`
file.

## Rotation procedure — Supabase sessions

1. Revoke all sessions for the affected users in Supabase Auth (or rotate
   `SUPABASE_JWT_SECRET`, which invalidates every session).
2. Change the passwords for `skbagheltravels@gmail.com`,
   `test.customer@agraskbagheltourandtravels.com`, and
   `test.customer2@agraskbagheltourandtravels.com`.
3. Remove the old cookies from any local runtime config.
4. Refresh tokens only when needed:

   ```bash
   cd /root/jailbreaks/backend
   python scripts/refresh_session.py
   ```

   The script writes the runtime config to
   `~/.secrets/jailbreaks/agraskbagheltourandtravels.runtime.json` (mode
   `600`). Load it with `--config <path>`; do not copy it into the repo.

5. Re-check that no session cookie or password is present in tracked files:

   ```bash
   python3 scripts/secret_scan.py
   ```

## Verification

1. `curl -i https://jailbreaks.coccoder999.workers.dev/api/health` -> 200.
2. `curl -i -X POST https://jailbreaks-46uf.onrender.com/api/scan` with no
   key -> 401.
3. `curl -i -X POST https://jailbreaks-46uf.onrender.com/api/scan` with an
   **old** key -> 401 (proves rotation took effect).
4. Same checks against the box6 `/api/scan` endpoint.
5. `curl -i -X POST .../api/wake/box6` with the old `X-Wake-Secret` -> 403.
6. Run one authorized scan through the Worker with `engine=webprobe` and one
   with `engine=openosint` to confirm the new keys work end to end.
7. Exercise one Razorpay test payment, one Resend test email, and one S3
   upload with the new credentials.

## Git history

History rewrite and force-push have **not** been performed. They require the
repository owner's explicit approval because they break every existing clone
and open PR. If approved:

```bash
# Use git-filter-repo, not filter-branch. Put the OLD values in a private
# replacements file outside the repo; never commit that file.
# Format: literal-old-value==>REDACTED (one per line)
git filter-repo --replace-text /secure/path/old-secrets.txt
```

Do not paste the old values into this document, a commit message, or a
ticket. Keep the replacements file outside the working tree and delete it
after the rewrite.

Rotate first. A rewrite without rotation leaves the same secrets in forks,
caches, and GitHub's object store.

## Checklist

- [ ] New `RENDER_API_KEY` generated and set on Render.
- [ ] New `BOX6_API_KEY` generated and set on box6.
- [ ] New `WAKE_SECRET` generated and set on Render **and** the Worker.
- [ ] Worker redeployed with all three secrets.
- [ ] Old keys return 401 / old wake secret returns 403.
- [ ] Authorized scan succeeds through the Worker.
- [ ] Cloudflare API token rotated and old token rejected.
- [ ] Supabase service-role key and JWT secret rotated.
- [ ] Database password rotated.
- [ ] Razorpay key secret and webhook secret rotated.
- [ ] Resend API key rotated.
- [ ] S3 access key pair rotated.
- [ ] LocationIQ token rotated.
- [ ] Deploy callback secret and Pages deploy hook rotated.
- [ ] Supabase sessions revoked and test/admin passwords changed.
- [ ] `python3 scripts/secret_scan.py` exits 0.
- [ ] Backend test suite passes.
- [ ] Owner decision recorded on history rewrite/force-push.
