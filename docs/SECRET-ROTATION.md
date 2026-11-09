# Secret rotation — exposed Workers proxy credentials

**Status:** removal from HEAD is done; **rotation is still outstanding**.

## What was exposed

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

## Why rotation is mandatory

- Git history is immutable for anyone who already fetched it; a later commit
  does not erase the old blob.
- GitHub keeps unreachable objects available for a period after a rewrite.
- The keys authorize billable and potentially destructive scan operations.

## Rotation procedure

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

Never put these values in `wrangler.jsonc`, `worker.js`, `.env` files that
are tracked, or chat. The Worker now fails closed with HTTP 503 when a
required secret is missing, so a partial deploy is visible rather than
silently using a stale default.

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
- [ ] Owner decision recorded on history rewrite/force-push.
