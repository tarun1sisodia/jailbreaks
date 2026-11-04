# Phase 1: Reconnaissance & Footprinting — Authorized Playbook

## 0. Pre-Engagement Gate
Before initiating any active reconnaissance requests:
- Confirm written authorization and signed scope register.
- Verify target hostnames, allowed testing hours (IST), and rate limits.
- Ensure automated discovery adheres to the operational limits (e.g., maximum depth, maximum requests per endpoint).
- Emergency abort file (`webprobe.abort`) must be monitored.

---

## 1. Objective & Scope Confirmation
**Objective:** Map all reachable endpoints, technological components, server configurations, leaked source maps, and hidden parameters across in-scope assets.

### Target Surfaces
- **Web Applications:** Frontend bundles, routing definitions, embedded API calls.
- **REST & GraphQL APIs:** Introspection endpoints, schema definitions, suggestion endpoints, undocumented routes.
- **Infrastructure & Origin:** Content Delivery Network (CDN) response headers, caching layers, backend servers.
- **Third-Party Integrations:** Payment gateway hooks (Razorpay), workflow automations (n8n), Supabase instances.

---

## 2. Test Case Catalog

### A. Surface Discovery & Mapping
| ID | Check | Description | Target / Method |
|---|---|---|---|
| A1 | **Robots & Sitemaps** | Parse `robots.txt`, `sitemap.xml`, and `sitemap_index.xml` | Extract disallowed routes and priority endpoints as initial crawl seeds. |
| A2 | **Security.txt Disclosure** | Check `/.well-known/security.txt` and `/security.txt` | Harvest contacts, vulnerability disclosure policies, and scope boundaries. |
| A3 | **Infrastructure & Header Fingerprinting** | Inspect response headers (`Via`, `X-Cache`, `CF-Ray`, `X-Backend-Server`, `X-Powered-By`) | Identify origin IP leaks, caching proxies, web application firewalls, and hosting platforms. |
| A4 | **HTTP Method Enumeration** | Send `OPTIONS`, `TRACE`, `PUT`, `DELETE` requests | Detect dangerous enabled methods and analyze `Allow` headers. |
| A5 | **Historical Endpoint Mining** | Query Wayback Machine / Archive.org CDX API | Uncover deprecated routes, staging paths, and previously exposed parameters. |

### B. Client Bundle & Source Map Analysis
| ID | Check | Description | Target / Method |
|---|---|---|---|
| B1 | **Client Script Extraction** | Parse crawled HTML pages for `<script>` tags | Extract first-party JavaScript bundles and third-party dependencies. |
| B2 | **Endpoint Extraction (Bare & Full URLs)** | Regex scan on JS files for API paths and endpoints | Identify routes (including bare paths like `/book`, `/packages`, `/routes`) and cross-origin links. |
| B3 | **Source Map Recovery** | Check for `//# sourceMappingURL=` comments and `.map` extensions | Download `.map` files; recover full original TypeScript/JavaScript source trees and routes. |
| B4 | **Hardcoded Secret Detection** | Pattern match for sensitive credentials | Scan bundles for AWS keys, Google API keys, Stripe/Razorpay keys, JWTs, private keys, and slack tokens. |

### C. Content & Directory Discovery
| ID | Check | Description | Target / Method |
|---|---|---|---|
| C1 | **Static & Dynamic Wordlist Probing** | Probe high-risk administrative, API, and sensitive paths | Soft-404 baseline detection with status code classification (200, 401, 403, 500). |
| C2 | **Extension & Backup Mutation** | Fuzz discovered files with extensions (`.bak`, `.old`, `.orig`, `.save`, `.zip`, `.sql`, `~`) | Identify unversioned source backups, database dumps, and editor temporary files. |
| C3 | **Directory Recursion** | Recurse into discovered directories (`admin/`, `api/`, `v1/`, `internal/`) | Perform bounded recursive probing on directory structures. |
| C4 | **N8N Automation & Razorpay Endpoints** | Target automation suites (`/rest/*`, `/webhook/*`) and payment verification paths | Detect exposed webhook triggers and unauthenticated administrative panels. |

### D. Parameter & API Enumeration
| ID | Check | Description | Target / Method |
|---|---|---|---|
| D1 | **Hidden Parameter Discovery** | Inject candidate parameters against endpoints with a randomized baseline control | Disclose debug modes, override flags (`admin=true`, `debug=1`, `role=admin`), and internal parameters. |
| D2 | **GraphQL GET & POST Introspection** | Test GraphQL endpoints (`/graphql`, `/api/graphql`) via POST and GET query params | Probe schema introspection and field-level suggestion leakage. |

---

## 3. Safe Execution Standards
- **Baseline Comparison:** Always capture a control response using randomized query tokens to eliminate false positives on parameter echoing.
- **Bandwidth & Rate Throttling:** Throttle requests using the `RateLimiter` to avoid triggering host rate-limits or impacting performance.
- **Source Map Size Limit:** Avoid downloading or parsing bundle files larger than 50MB.

