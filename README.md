# WebProbe & Application Security Playbooks

An enterprise-grade, authorized web application security testing framework, automated scanner (`webprobe`), and multi-phase assessment playbooks tailored for modern application stacks (React/Next.js, Node/Express, Supabase PostgreSQL, Razorpay payments, n8n automations, Cloudflare/Render infrastructure).

> [!IMPORTANT]
> **Operational Hold:** Per user instructions, live automated scanning is currently **paused** pending explicit operator authorization. The codebase is organized, assembled, verified via internal self-checks, and ready for deployment.

---

## 1. Repository Architecture

```text
jailbreaks/
├── Full_Guide_For Website.txt              # Original comprehensive conversation guide & logs (preserved)
├── deepseek_4-Nov-2026.md                  # Assistant operating specification & alignment prompt
├── README.md                               # Repository documentation & usage guide
├── webprobe.py                             # Executable CLI entrypoint (zero third-party dependencies)
├── config/
│   ├── config.example.json                 # JSON configuration template (targets, cookies, rate limits)
│   └── asset_register.example.md           # Engagement asset register and scope authorization template
├── docs/
│   ├── operational_controls.md             # Rules of engagement, rate limits, emergency abort protocol
│   └── playbooks/                          # Detailed testing methodologies and test case catalogs
│       ├── phase1_reconnaissance.md        # Surface discovery, JS parsing, source maps, hidden params
│       ├── phase2_authentication.md        # Session lifecycle, lockout, JWT analysis, MFA, CSRF
│       ├── phase3_injection.md             # SQLi (UNION/stacked/second-order), NoSQL, XSS, uploads, CRLF
│       ├── phase4_authorization.md         # IDOR/BOLA, vertical escalation, role tampering, Supabase RLS
│       ├── phase5_business_logic.md        # Price tampering, coupons, booking IDs, webhooks, race probes
│       └── phase6_misconfiguration.md      # Headers, TLS/ciphers, CORS, verbose errors, debug endpoints
└── webprobe/                               # Modular Python Package
    ├── __init__.py                         # Version & package exports
    ├── cli.py                              # CLI argument parsing & test orchestrator
    ├── core/                               # Core engine components
    │   ├── models.py                       # Finding, Response, Point, Ctx, RoleMatrix dataclasses
    │   ├── http.py                         # HttpClient, RateLimiter, multipart builder, token utils
    │   ├── crawler.py                      # Bounded crawler, form & script extractor, point builder
    │   ├── logger.py                       # Audit activity logger (TSV), ANSI styling, JSON/text report
    │   └── safety.py                       # InstabilityMonitor, in_testing_window, abort file listener
    └── checks/                             # Modular check implementations (106 checks across 6 phases)
        ├── __init__.py                     # Registries (GLOBAL_EARLY, GLOBAL_LATE, POINT_CHECKS, PROFILES)
        ├── phase1_recon.py                 # Recon, robots, JS endpoints, source maps, GraphQL, params
        ├── phase2_auth.py                  # Password policies, default creds, session fixation, Supabase
        ├── phase3_injection.py             # SQLi, NoSQL, stored/DOM XSS, uploads, CRLF, SSTI, CMDI, LFI
        ├── phase4_authorization.py         # IDOR, vertical escalation, CORS, method tampering, storage
        ├── phase5_business_logic.py        # Price/coupon tampering, Razorpay webhook validation, refs
        └── phase6_infra.py                 # Security headers, sensitive files, TLS, debug endpoints
```

---

## 2. Safety & Operational Circuit Breakers

`webprobe` is built with non-negotiable operational controls designed to protect production and staging target stability:

1. **Emergency Abort File (`webprobe.abort`):**
   - The HTTP engine continuously polls for `webprobe.abort` (or `--abort-file <path>`).
   - If created, active worker threads immediately halt and exit with code `3`.
   - Halting command:
     ```bash
     touch webprobe.abort
     ```
2. **Instability Monitor (5xx Rate Limiter):**
   - Tracks response status codes in a rolling sliding window (default: 30 requests).
   - If server 5xx errors exceed the threshold (default: 20%), the engine backs off and pauses to prevent service outages.
3. **Strict Rate Limiting:**
   - `--rate-limit <rps>` enforces the minimum interval between requests across all concurrent threads (`--threads`).
4. **Authorized Testing Window:**
   - `--testing-hours <HH:MM-HH:MM>` (e.g. `10:00-20:00`) prevents running scans outside approved operational windows.
5. **Full Audit Logging:**
   - `--activity-log <path>` logs every outbound request, HTTP verb, status code, latency, and payload to an append-only TSV file.

---

## 3. Profiles & Check Catalog

`webprobe` categorizes 106 security checks into 10 purpose-built profiles:

| Profile | Checks | Primary Focus |
|---|---|---|
| `quick` | 7 | Fast smoke test: security headers, CORS, exposed files, basic SQLi, XSS, SSTI, IDOR. |
| `recon` | 12 | Surface mapping: robots, sitemaps, JS endpoints, source maps, infra headers, GraphQL, hidden params. |
| `auth` | 16 | Authentication: weak passwords, lockout, default creds, reset tokens, session fixation, JWT, MFA, Supabase auth. |
| `injection` | 18 | Deep injection: UNION SQLi, stacked queries, NoSQL bypass, stored/DOM XSS, file upload, CRLF, SSTI, SSRF. |
| `authz` | 10 | Broken access control: horizontal IDOR, vertical privilege escalation, UI-only API bypass, role tampering. |
| `business` | 11 | Business logic: price tampering, discount stacking, coupon rules, booking reference entropy, Razorpay webhooks. |
| `config` | 13 | Infrastructure: security headers, TLS configuration, permissions policy, debug endpoints, directory listings. |
| `owasp` | 21 | OWASP Top 10 web vulnerabilities covering injection, auth, access control, and misconfiguration. |
| `api` | 15 | REST and GraphQL API focus: CORS, JWT, GraphQL introspection & depth, mass assignment, rate limits. |
| `full` | 106 | Complete testing suite executing all registered checks across Phases 1 through 6. |

---

## 4. Verification & Inspection Commands

Run internal registry checks without issuing any network requests:

```bash
# Verify internal registry consistency and callable mappings (exits 0)
python webprobe.py --self-check

# List all 106 registered checks with their phase and scope
python webprobe.py --list-checks

# Show full CLI options and argument groups
python webprobe.py --help
```

---

## 5. Execution Syntax (Pending Authorization)

Once explicit written authorization and scope verification are confirmed:

```bash
# 1. Passive reconnaissance and endpoint discovery
python webprobe.py https://target.example.com --profile recon --rate-limit 3.0 --activity-log audit.tsv

# 2. Authentication and session audit with test credentials
python webprobe.py https://target.example.com --profile auth \
  --test-email "test-user@example.internal" \
  --test-password "TestPassword123!" \
  --testing-hours "10:00-18:00"

# 3. Horizontal and vertical authorization boundaries (IDOR & RBAC)
python webprobe.py https://target.example.com --profile authz \
  --cookie "session=customer_a_token" \
  --secondary-cookie "session=customer_b_token" \
  --staff-cookie "session=staff_token"

# 4. Business logic and webhook verification
python webprobe.py https://target.example.com --profile business \
  --test-coupon "TESTPROMO10" \
  --webhook-url "https://target.example.com/api/razorpay/webhook"

# 5. Output structured JSON report for ingestion
python webprobe.py https://target.example.com --profile quick --json -o report.json
```

