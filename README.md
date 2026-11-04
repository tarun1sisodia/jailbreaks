# WebProbe — Authorized Web Application Security Testing Framework

An enterprise-grade, zero-dependency, automated web application security scanner (`webprobe`) and assessment framework built for authorized security testing across modern application stacks (React/Next.js, Fastify/Node, Supabase PostgreSQL, Razorpay payments, Cloudflare/Render infrastructure).

Zero third-party packages required — uses standard library Python 3.8+.

---

## 🚀 Quick Start Guide

### 1. Prerequisites & Verification

Ensure Python 3.8+ is installed:

```bash
python --version
# Should report Python 3.8 or higher (e.g. Python 3.12.x)
```

> [!TIP]
> **Windows Tip:** If Windows opens Microsoft Store or prints `Python was not found`, either disable the App Execution Aliases in *Windows Settings > Apps > Advanced app settings > App execution aliases* or ensure your Python binary path in `~/.local/bin` is mapped to `python.exe`.

Verify internal check registries (no network requests made):

```bash
python webprobe.py --self-check
# Expected output: [+] Self-check PASSED: 106 total checks registered
```

---

### 2. Configure Your Target

Configuration files live in `config/`. You can copy `config/config.example.json` or use an existing config such as `config/agraskbagheltourandtravels.json`:

```json
{
  "url": "https://example.com",
  "profile": "quick",
  "operational_controls": {
    "rate_limit": 4.0,
    "threads": 4,
    "crawl_depth": 2,
    "max_pages": 40,
    "activity_log": "audit_activity.tsv",
    "abort_file": "webprobe.abort"
  },
  "credentials": {
    "test_email": "customer@example.com",
    "test_password": "TestPassword123!",
    "cookie": "sb-access-token=<token>; token=<token>",
    "secondary_cookie": "sb-access-token=<secondary_token>",
    "admin_cookie": "sb-access-token=<admin_token>"
  },
  "business_and_payments": {
    "webhook_url": "https://api.example.com/api/v1/payments/webhooks/razorpay",
    "refund_url": "https://api.example.com/api/v1/ops/admin/refunds",
    "state_url": "https://api.example.com/api/v1/ops/admin/bookings"
  },
  "output_settings": {
    "verbose": false,
    "json": false,
    "output": "report.txt"
  }
}
```

#### Automatic Session Token Refresh (Supabase Stacks)
For targets utilizing Supabase JWTs, tokens naturally expire. You can refresh active session tokens for Admin, Customer 1, and Customer 2 into your config in one command:

```bash
python scripts/refresh_session.py
```

---

### 3. Running Scans

#### A. Run All 106 Checks (Full Audit)
```bash
python webprobe.py --config config/agraskbagheltourandtravels.json --profile full
```

#### B. Full Audit with Deep Opt-In Probes
Enable time-based SQLi, stored XSS reflection, second-order forms, hidden parameter brute-force, and Wayback historical seed discovery:
```bash
python webprobe.py --config config/agraskbagheltourandtravels.json \
  --profile full \
  --time-based \
  --second-order \
  --stored-xss \
  --param-discovery \
  --wayback \
  --idempotency-test \
  --verbose
```
# 1. Detection only (safe; no RCE, no destructive writes)
python webprobe.py --config config/agraskbagheltourandtravels.json \
    --profile exploit --exploit --rate-limit 3

# 2. Full proof-of-impact (RCE proof + race + webhook replay)
python webprobe.py --config config/agraskbagheltourandtravels.json \
    --exploit --exploit-rce --rce-command "id" \
    --race-url "https://api.agraskbagheltourandtravels.com/api/v1/quotes/options" \
    --race-data '{"package_id":"TEST","guests":2}' \
    --race-count 40 --race-expect 1 \
    --rate-limit 3 --activity-log exploit.tsv

# 3. One specific chain
python webprobe.py --config config/agraskbagheltourandtravels.json \
    --checks react2shell_rce,nextjs_mw_bypass,supabase_rls
#### C. Run Targeted Profiles

| Profile | Checks | Purpose | Command |
|---|---|---|---|
| **`quick`** | 7 | Fast smoke test (Headers, CORS, basic SQLi/XSS/IDOR) | `python webprobe.py --config config/<target>.json --profile quick` |
| **`recon`** | 12 | Robots, sitemaps, JS endpoints, source maps, GraphQL | `python webprobe.py --config config/<target>.json --profile recon` |
| **`auth`** | 16 | Password policy, lockout, JWT analysis, session fixation, MFA | `python webprobe.py --config config/<target>.json --profile auth` |
| **`injection`** | 18 | UNION SQLi, stacked queries, NoSQL, stored/DOM XSS, SSTI, SSRF | `python webprobe.py --config config/<target>.json --profile injection` |
| **`authz`** | 10 | IDOR, horizontal & vertical escalation, admin route protection | `python webprobe.py --config config/<target>.json --profile authz` |
| **`business`** | 11 | Price tampering, coupon rules, webhooks, race probes | `python webprobe.py --config config/<target>.json --profile business` |
| **`config`** | 13 | TLS, security headers, cache poisoning, debug endpoints | `python webprobe.py --config config/<target>.json --profile config` |
| **`owasp`** | 21 | OWASP Top 10 web vulnerabilities covering injection & access control | `python webprobe.py --config config/<target>.json --profile owasp` |
| **`api`** | 15 | Dedicated REST & GraphQL API security testing | `python webprobe.py --config config/<target>.json --profile api` |

#### D. Run Specific Individual Checks
You can selectively run specific checks by name (overriding `--profile`):
```bash
# Example: test robots.txt and cache poisoning only
python webprobe.py --config config/agraskbagheltourandtravels.json --checks robots,cache
```

#### E. Export JSON Reports
For automated CI/CD pipelines or tool ingestion, pass `--json`:
```bash
python webprobe.py --config config/agraskbagheltourandtravels.json --profile quick --json -o report.json
```

---

## 🛡️ Safety & Circuit Breakers

`webprobe` enforces strict operational guardrails:

1. **Emergency Abort (`webprobe.abort`):**
   Touch or create `webprobe.abort` anytime to halt execution immediately:
   ```bash
   # Linux/macOS
   touch webprobe.abort

   # Windows PowerShell
   New-Item webprobe.abort
   ```
2. **Instability Monitor (5xx Threshold):**
   If 5xx server responses exceed `--instability-threshold` (default `0.20` or 20%) over rolling samples, the scanner automatically backs off or pauses to avoid degrading service.
3. **Throttled Concurrency:**
   `--rate-limit <rps>` (e.g. `4.0` requests/sec) and `--threads <int>` enforce strict request intervals across all worker threads.
4. **Testing Window Guard:**
   `--testing-hours "10:00-18:00"` prevents testing outside approved business windows.
5. **Audit Activity Log:**
   Append-only TSV logs recorded via `--activity-log <path>` track every request timestamp, URI, status, and payload.

---

## 📁 Repository Structure

```text
jailbreaks/
├── AGENT.md                                # Autonomous agent specification & handoff documentation
├── README.md                               # Project documentation & Getting Started guide
├── webprobe.py                             # Single executable CLI entrypoint
├── config/
│   ├── agraskbagheltourandtravels.json     # Live target configuration template
│   ├── config.example.json                 # Target configuration schema template
│   └── asset_register.example.md           # Engagement asset register and scope authorization template
├── scripts/
│   └── refresh_session.py                  # Supabase auth token refresher utility
├── docs/
│   ├── operational_controls.md             # Rules of engagement and circuit breaker protocols
│   └── playbooks/                          # Step-by-step methodologies for Phases 1 through 6
└── webprobe/                               # Modular Python Package
    ├── cli.py                              # CLI orchestration and report generation
    ├── core/                               # HTTP client, bounded crawler, models, safety monitor
    └── checks/                             # 106 check implementations organized by phase
        ├── phase1_recon.py                 # Reconnaissance, JS scanning, sitemaps
        ├── phase2_auth.py                  # Authentication, JWT, MFA, lockout
        ├── phase3_injection.py             # SQLi, NoSQL, XSS, SSRF, SSTI, CMDI, LFI
        ├── phase4_authorization.py         # IDOR, RBAC, forced browsing, storage
        ├── phase5_business_logic.py        # Webhooks, payment validation, replay attacks
        └── phase6_infra.py                 # Security headers, TLS, cache poisoning, debug flags
```

---

## 🛠️ CLI Reference & Help

To inspect all available command-line flags and argument groups:

```bash
python webprobe.py --help
```

To list all 106 registered checks with their phases and execution scopes:

```bash
python webprobe.py --list-checks
```
