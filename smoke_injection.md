# webprobe Security Report - http://127.0.0.1:8765
- **Profile:** injection
- **Duration:** 8.66s
- **Total Findings:** 4

## [HIGH] No Content-Security-Policy header
- **Category:** csp
- **URL:** http://127.0.0.1:8765
- **Evidence:** CSP header absent; inline script execution unrestricted.
- **Remediation:** Deploy strict Content-Security-Policy with nonces or hashes.

## [HIGH] SQL injection (Error-based)
- **Category:** sqli
- **URL:** http://127.0.0.1:8765/search
- **Evidence:** SQL error pattern matched: (?i)you have an error in your sql syntax
- **Remediation:** Parameterize all database queries.

## [HIGH] SQL injection (Error-based)
- **Category:** sqli
- **URL:** http://127.0.0.1:8765/login
- **Evidence:** SQL error pattern matched: (?i)you have an error in your sql syntax
- **Remediation:** Parameterize all database queries.

## [HIGH] SQL injection (Error-based)
- **Category:** sqli
- **URL:** http://127.0.0.1:8765/login
- **Evidence:** SQL error pattern matched: (?i)you have an error in your sql syntax
- **Remediation:** Parameterize all database queries.

