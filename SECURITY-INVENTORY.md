# Jailbreaks / WebProbe — Security Inventory

**Verified:** 2026-11-10  
**Source:** local clone of `github.com/tarun1sisodia/jailbreaks`  
**HEAD:** local `main` at `341071b` (secret redaction/rotation tooling), after `6230ea3`, `cc49c54`, and the framework-CVE tooling commit.  
**GitHub:** `https://github.com/tarun1sisodia/jailbreaks` is **public** (verified 2026-11-09). The local commits are not pushed yet.

---

## 1. Headline numbers

| Metric | Count |
|---|---:|
| Registered security checks | **136** |
| — standard checks | 128 |
| — exploit checks (inside the 136) | 8 |
| Check phases | 6 |
| Scan profiles | 11 |
| Exploit-chain patterns | 5 |
| Post-exploitation proof generator | 1 |
| Named CVE IDs implemented (active + passive) | **63** |
| — active exploit CVE IDs | 4 |
| — passive fingerprint CVE IDs | 61 (25 products) |
| Framework CVEs in the research matrix | **1,002** (5 packages) |
| `Tricks-Web-Pentest` attack categories | 9 |
| `Tricks-Web-Pentest` exploit/payload source files | 23 |
| Bypass wordlists | 6 |
| Backend tests passing | **154** |
| Known bugs fixed (Phase 1 protocol) | 10 |
| Git commits in history | 42 |
| Commits matching security/fix/harden keywords | 12 |
| Latest full-scan raw findings | 103 |
| — high / medium / low / info | 30 / 1 / 1 / 71 |
| API-selectable scan engines | 4 |
| Additional VPS/MCP-only tools | 2 (TridentChain, SAST Server) |
| Safety controls | 5 |
| Protected control-plane routes | 6 (5 API-key + 1 wake-secret) |

---

## 2. Checks by phase

| Phase | Area | Checks |
|---|---|---:|
| P1 | Reconnaissance, JS, sitemaps, GraphQL, vhosts | 14 |
| P2 | Authentication, JWT, MFA, lockout, sessions | 29 |
| P3 | Injection: SQLi, NoSQL, XSS, SSTI, SSRF, CMDI, LFI | 25 |
| P4 | Authorization: IDOR, RBAC, tenant, mass assignment, GraphQL | 28 |
| P5 | Business logic: price, coupons, webhooks, races, refunds | 20 |
| P6 | Infrastructure: headers, TLS, cache, smuggling, debug, CVE | 20 |
| **Total** | | **136** |

Execution scopes: **33 early**, **81 late**, **22 parameter-point** checks.

### Profiles (checks overlap, so they do not sum to 136)

| Profile | Checks |
|---|---:|
| quick | 10 |
| recon | 16 |
| auth | 28 |
| injection | 26 |
| authz | 27 |
| business | 17 |
| config | 15 |
| owasp | 41 |
| api | 17 |
| full | 136 |
| exploit | 8 |

---

## 3. Exploits

### 3.1 Active exploit checks — 8

| Check | Phase | What it proves |
|---|---:|---|
| `react2shell_detect` | P6 | React2Shell / RSC Flight deserialization reachability (CVE-2025-55182 / CVE-2025-66478) |
| `react2shell_rce` | P6 | Opt-in RCE proof with a bounded command |
| `nextjs_mw_bypass` | P6 | Next.js middleware authorization bypass (CVE-2025-29927) |
| `rsc_cache_poison` | P6 | Next.js RSC/HTML cache-key confusion (CVE-2025-49005) |
| `supabase_rls` | P4 | Missing/permissive Supabase RLS, cross-tenant reads |
| `supabase_rpc` | P4 | `SECURITY DEFINER` RPC callable by `anon` |
| `razorpay_webhook` | P5 | Webhook signature bypass + replay/idempotency failure |
| `single_packet_race` | P5 | HTTP/2 single-packet race condition |

**Named CVEs:** CVE-2025-55182, CVE-2025-66478 (duplicate Next.js ID), CVE-2025-29927, CVE-2025-49005. React2Shell is CVSS 10.0, pre-auth.

### 3.2 Exploit-chain patterns — 5

1. OAuth redirect + open redirect → token theft
2. SSRF → internal service → RCE
3. IDOR + mass-assigned role → admin takeover
4. XSS + missing HttpOnly → session hijack
5. JWT `alg:none` + missing authorization → full access

### 3.3 Post-exploitation proof — 1 generator

`backend/webprobe/exploits/postex.py` runs only read-only proof commands (`id`, `uname -a`, `whoami`, `hostname`, `date`, `pwd`, env user, Windows equivalents) and records evidence without persistence or lateral movement. It defines **9 safe commands** and **4 proof payloads**.

**Exploit routine total:** 8 exploit checks + 5 chains + 1 post-ex generator = **14**.

### 3.4 `Tricks-Web-Pentest` knowledge base

| Category | Source/payload files |
|---|---:|
| brute-force | 1 |
| csrf | 4 |
| deserialization | 6 |
| obfuscation | 1 |
| others | 1 |
| sqli | 3 |
| ssrf_protocol_smuggling | 2 |
| webshells | 2 |
| xxe | 3 |
| **Total** | **23** |

Plus **6** bypass wordlists (headers, LFI, poisoning, SSRF local/metadata, XSS).

### 3.5 Passive CVE fingerprint database — 25 products / 61 CVE IDs

| Product | Source | CVE IDs |
|---|---|---:|
| Apache HTTP Server | headers | 2 |
| PHP | headers | 4 |
| Next.js | headers | 4 |
| ASP.NET Core | headers | 3 |
| .NET | headers | 2 |
| Jenkins | headers | 1 |
| jQuery | body | 2 |
| Bootstrap | body | 1 |
| GitLab | body | 1 |
| Confluence | body | 1 |
| TeamCity | body | 1 |
| GeoServer | body | 1 |
| nginx | headers | 2 |
| Apache Tomcat | headers | 3 |
| WordPress | body | 8 |
| Drupal | body | 4 |
| Joomla | body | 2 |
| AngularJS | body | 2 |
| lodash | body | 3 |
| Moment.js | body | 2 |
| Handlebars | body | 2 |
| Axios | body | 2 |
| DOMPurify | body | 2 |
| OpenSSL | headers | 3 |
| Atlassian Jira | body | 3 |
| **Total** | | **61** |

Detection is version-gated and passive: a finding is emitted only when a readable product version falls inside a published affected range. No exploit payload is sent by `check_cve`. The database is `backend/webprobe/data/cve_fingerprints.json`; `scripts/update_cve_db.py` refreshes it from NVD.

The Next.js, ASP.NET Core, and .NET rules fire only when a deployment exposes an explicit version banner (for example `X-Powered-By: Next.js/15.1.0` or `Server: Kestrel/8.0.20`). Standard production deployments usually do not, so these are opportunistic detections, not assumptions. PHP is the reliable case because `X-Powered-By: PHP/x.y.z` is commonly exposed.

### 3.6 Framework CVE research matrix — 1,002 CVEs

This is a research/reporting artifact, not a scanner check. It maps package versions to NVD CPE ranges, fixed versions, the component/endpoint named in the NVD description, CISA KEV status, and public-PoC references.

| Package | Ecosystem | CVEs | Critical | High | Medium | Low |
|---|---|---:|---:|---:|---:|---:|
| Next.js | npm | 63 | 2 | 25 | 33 | 3 |
| React | npm | 6 | 1 | 3 | 2 | 0 |
| PHP | php | 760 | 136 | 284 | 311 | 29 |
| ASP.NET Core | nuget | 41 | 3 | 31 | 7 | 0 |
| .NET | nuget | 132 | 7 | 95 | 30 | 0 |
| **Total** | | **1,002** | **149** | **438** | **383** | **32** |

- Data: `reports/framework_cves.json` (raw NVD pull), `reports/framework_cve_matrix.json` (normalized), `reports/framework_cves.csv`, `reports/FRAMEWORK-CVE-MATRIX.md`, and per-package tables in `reports/cve/`.
- Refreshers: `scripts/fetch_framework_cves.py`, `scripts/build_framework_matrix.py`.
- Offline lookup: `scripts/framework_cve_lookup.py --package next --version 15.1.0`, or `--manifest package.json|composer.json|*.csproj`.
- Known-exploited mapping: CISA KEV catalog `2026.11.09` (1,773 entries), 13 matches in the matrix.
- Severity is the NVD primary CVSS score; the CNA score is retained when different (for example CVE-2025-1861 is 9.8 on the NVD primary scale and 6.3 from the PHP CNA).
- Vendor corrections are recorded for CVE-2025-55182, CVE-2025-55184, CVE-2025-67779, CVE-2026-23864, and CVE-2025-1861.

---

## 4. Security engineering / hardening

- **API authentication:** `X-API-Key` on all scan routes; fails closed with 401 when `WEBPROBE_API_KEY` is unset (local-dev bypass only via explicit env flag).
- **CORS allowlist:** explicit origins/methods/headers; wildcard and credentialed wildcard removed.
- **SSRF guard:** resolves every target/webhook hostname and blocks private, loopback, link-local, and cloud-metadata ranges.
- **Wake endpoint:** `POST /api/wake/box6` gated by `X-Wake-Secret`.
- **Zero-credential browser model:** the SPA calls same-origin `/api`; the Cloudflare Worker injects backend keys server-side.
- **Scope guard:** `deploy/vps/bin/_guard.py` + `scope.toml` exit non-zero for out-of-scope targets.
- **Safety controls:** emergency abort file, 5xx instability monitor/backoff, rate limiting + thread cap, testing-window guard, append-only audit log.
- **Evidence handling:** CVSS, SARIF export, secret redaction, activity log.
- **Secret hygiene:** tracked files are scanned by `scripts/secret_scan.py`; `.env` and the live target config are git-ignored and now mode `600`. Live provider keys and Supabase session cookies were found in those local files on 2026-11-10 and still require provider-side rotation.
- **Workers proxy secrets:** the three production keys formerly hardcoded in `frontend/worker.js` (`RENDER_API_KEY`, `BOX6_API_KEY`, `WAKE_SECRET`) are removed from HEAD. `resolveEnv` no longer defaults them; every route that needs a credential fails closed with **HTTP 503** and names the missing secret. Regression tests in `backend/tests/test_security_posture.py` prevent reintroduction. See `docs/SECRET-ROTATION.md` — removal from HEAD does **not** invalidate keys that were already public in git history.
- **Authz false positives:** `check_rbac_matrix` now only reports sensitive endpoints (admin/account/API/order/etc.) whose anonymous and authenticated bodies differ and whose signed-in view contains identity markers. Public content pages (`/book.html`), identical bodies, and soft-login pages are ignored. Covered by 9 authz tests.
- **Passive CVE engine:** `check_cve` reads product versions from response headers and page bodies and maps them to published affected ranges from NVD/vendor advisories. It is detection-only — no exploit payload is sent. Current coverage: **25 products / 61 CVE IDs** in `backend/webprobe/data/cve_fingerprints.json`: Apache HTTP Server, PHP, Next.js, ASP.NET Core, .NET, Jenkins, jQuery, Bootstrap, GitLab, Confluence, TeamCity, GeoServer, nginx, Apache Tomcat, WordPress, Drupal, Joomla, AngularJS, lodash, Moment.js, Handlebars, Axios, DOMPurify, OpenSSL, and Atlassian Jira. Ranges support inclusive/exclusive bounds and letter-suffixed versions (OpenSSL 1.0.1f). The PHP CVE-2025-1861 ranges use the vendor advisory because NVD's CPE upper bounds conflict with the fixed releases. `scripts/update_cve_db.py` refreshes the database from NVD with a local cache; `backend/tests/test_cve_db.py` validates its schema.
- **Framework CVE matrix:** 1,002 NVD CVEs across Next.js (63), React (6), PHP (760), ASP.NET Core (41), and .NET (132), with version ranges, fixed releases, component/endpoint, KEV status, and PoC references. `scripts/framework_cve_lookup.py` matches an exact version or a `package.json`/`composer.json`/`*.csproj` offline. It is a dependency/SBOM lookup, not a remote scanner: these frameworks usually do not expose patch versions in HTTP responses.
- **Quality:** 10 known Phase-1 bugs fixed; **154 backend tests pass** (~60 s).
- **Scan engines:** 4 API-selectable (WebProbe, KageSec, OpenOSINT, Argus); VPS/MCP adds TridentChain and SAST Server. KageSec carries 7,400+ CVE templates; Argus orchestrates Semgrep, Bandit, Gitleaks, and Pip-Audit.

---

## 5. Latest full scan (repository report)

`reports/scan_latest.json` — target `https://agraskbagheltourandtravels.com`, profile `full`, 527.42 s:

- **103 raw findings**: 30 high, 1 medium, 1 low, 71 info
- 60 unique titles, 6 categories
- The 30 high findings are the same authz pattern (`Endpoint reachable unauthenticated AND authenticated`) repeated across 30 public URLs. A targeted `authz` re-run (`reports/scan_authz_verify.md`) returned **0 findings**, and the underlying check was fixed in this working tree (§4), so those 30 are not 30 confirmed distinct high-severity bugs. A fresh scan with the fixed check is still required to replace the stale report.
- Confirmed non-info issues in that report: 1 medium (CSP allows `unsafe-inline`) and 1 low (authenticated response missing `Cache-Control: no-store`).

No college-target report is present in the repository; the only full report is the travel-site scan above.

---

## 6. Secret exposure — code-side containment done, rotation still required

### 6.1 Workers proxy secrets (committed to git)

`frontend/worker.js` was tracked at commit `88f4eae` with **3 hardcoded production secrets** in its `DEFAULTS` block (lines 45, 47, 49):

- `RENDER_API_KEY`
- `BOX6_API_KEY`
- `WAKE_SECRET`

**Current working tree:** all three literals are removed; `resolveEnv` defaults them to empty strings, and every route that needs a credential fails closed with HTTP 503 naming the missing secret. Regression tests in `backend/tests/test_security_posture.py` guard against reintroduction. New staging values are in `/root/.secrets/jailbreaks/worker-secrets-2026-11-10.env` (mode `600`) but have **not** been applied to Render, box6, or Cloudflare.

### 6.2 Local `.env` provider keys (never tracked, previously world-readable)

`.env` at the repository root contained live Cloudflare, Supabase, Razorpay, Resend, S3, database, LocationIQ, deploy-callback, and Pages deploy-hook credentials. It was mode `777` and is now mode `600`; a private backup exists at `/root/.secrets/jailbreaks/env.backup-2026-11-10` (mode `600`). Removing the file from the repo does not revoke any key.

### 6.3 Supabase session cookies (never tracked, previously world-readable)

`backend/config/agraskbagheltourandtravels.json` contained a test-account password and customer/staff/`super_admin` Supabase cookies. It was mode `777` and is now mode `600`; a private backup exists at `/root/.secrets/jailbreaks/agraskbagheltourandtravels.backup-2026-11-10.json`. The access tokens expired at Unix `1793778642` (2026-11-04); passwords and refresh tokens may still be valid.

**Code-side containment:** credential fields in the repo config are now `${WEBPROBE_*}` placeholders, and `backend/webprobe/cli.py` expands placeholders and accepts `WEBPROBE_<KEY>` overrides. `backend/scripts/refresh_session.py` writes refreshed tokens to `~/.secrets/jailbreaks/agraskbagheltourandtravels.runtime.json` (mode `600`) instead of the repo. `scripts/secret_scan.py` plus `backend/tests/test_secret_scan.py` guard tracked files and local file permissions.

**Still required:** rotate all three Worker secrets at the Cloudflare/Render/InstaBox dashboards, then store the new values only with `wrangler secret put`. Rotate every provider key listed in `docs/SECRET-ROTATION.md`, revoke Supabase sessions, and change the test/admin passwords. The repository is public and the Worker values remain in git history (commits `eb60f2c` and `88f4eae`, among others); deleting them from HEAD does **not** invalidate them. Rewriting public history and force-pushing requires explicit owner approval.

No live Stripe/AWS/GitHub/Slack/private keys were found in tracked files; the only JWT-like strings are synthetic test fixtures explicitly marked `secret-scan: allow`.

---

## 7. Verification commands

```bash
cd backend
python3 webprobe.py --self-check
# [+] Self-check PASSED: 136 total checks registered
#     (33 early, 81 late, 22 points across 11 profiles).

python3 - <<'PY'
from webprobe.checks import ALL_CHECKS, GLOBAL_EARLY, GLOBAL_LATE, POINT_CHECKS, PROFILES
from webprobe.exploits import EXPLOIT_CHECKS
from webprobe.exploits.chainer import CHAIN_PATTERNS
from webprobe.exploits.postex import proof_payloads, SAFE_COMMANDS
print(len(ALL_CHECKS), len(EXPLOIT_CHECKS), len(CHAIN_PATTERNS),
      len(proof_payloads()), len(SAFE_COMMANDS))
PY
# 136 8 5 4 9

python3 -m pytest -q
# 154 passed

cd ..
python3 scripts/secret_scan.py
# [+] No exposed secrets found in tracked files; local secret files are private.
```

```bash
python3 - <<'PY'
import json, re
db = json.load(open('webprobe/data/cve_fingerprints.json'))
ids = {c for f in db['fingerprints'] for r in f['rules']
       for c in re.findall(r'CVE-\d{4}-\d{4,7}', r['cve'])}
print(len(db['fingerprints']), 'products;',
      sum(len(f['rules']) for f in db['fingerprints']), 'rules;',
      len(ids), 'CVE IDs')
PY
# 25 products; 60 rules; 61 CVE IDs
```

```bash
python3 - <<'PY'
import json, collections
d=json.load(open('reports/scan_latest.json'))
print(d['total_findings'], collections.Counter(f['severity'] for f in d['findings']))
PY
# 103 Counter({'info': 71, 'high': 30, 'medium': 1, 'low': 1})
```
