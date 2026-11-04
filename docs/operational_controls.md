# Operational Controls & Rules of Engagement

## 1. Legal & Engagement Prerequisites
All security testing must operate under strict, verified authorization.
1. **Written Authorization:** A signed testing charter/agreement by the authorized stakeholder must be in place.
2. **Asset Register:** Target hostnames, subdomains, APIs, and service IDs must be explicitly listed. Probing out-of-scope hosts or third-party infrastructure is strictly forbidden.
3. **Dedicated Credentials:** Testing accounts (customer, staff, admin) must use dedicated synthetic email addresses and segregated test credentials. Never test with real customer records.
4. **Authorized Hours:** Active probes must only execute during approved testing windows (e.g., agreed IST operational hours).

---

## 2. Safety Controls & Circuit Breakers

### A. Emergency Abort Mechanism (`webprobe.abort`)
The scanning engine continuously polls for the presence of an abort file:
- **File Name:** `webprobe.abort` (or custom path via `--abort-file`)
- **Behavior:** If `webprobe.abort` exists in the working directory during execution, the HTTP client immediately interrupts all active worker threads and terminates the process with exit code `3`.
- **Trigger:** To instantly halt execution at any time, run:
  ```bash
  touch webprobe.abort
  ```

### B. Instability Monitoring & Backoff
To avoid service degradation:
- The `InstabilityMonitor` tracks server responses in a rolling sliding window (default: 50 requests).
- If the 5xx (Server Error) error rate exceeds the configured threshold (default: 20%), the engine logs an alert and automatically activates exponential backoff / sleeps between requests.
- When server instability persists, scanning halts safely to prevent outage.

### C. Rate Limiting & Concurrency
- Configured via `--rate-limit` (requests per second) and `--threads` (maximum concurrent worker threads).
- The thread-safe `RateLimiter` enforces the minimum delay between consecutive outbound HTTP requests across all threads.

---

## 3. Reporting & Evidence Sanitization
- **Activity Log (`--activity-log <path>`):** All outbound requests, responses, HTTP methods, latency, and status codes are recorded into a timestamped audit log.
- **Data Redaction:** Never record raw passwords, unmasked credit card numbers, or live third-party secret tokens in test findings or reports.
- **Reporting Levels:**
  - `CRITICAL`: Immediate arbitrary code execution, SQL injection, unrestricted administrative takeover, or unauthenticated RLS bypass with write access.
  - `HIGH`: Authentication bypass, IDOR exposing sensitive customer records, stored XSS, or coupon/price tampering.
  - `MEDIUM`: Reflected XSS, verbose stack traces, rate-limiting absence on sensitive forms, or CSRF on state-changing actions.
  - `LOW`: Missing security headers, non-sensitive information leakage, or missing cookie flags.
  - `INFO`: Publicly reachable endpoint catalog, robots/sitemap parsing, or software version fingerprints.

