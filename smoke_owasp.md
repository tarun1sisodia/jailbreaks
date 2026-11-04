# webprobe Security Report - http://127.0.0.1:8765
- **Profile:** owasp
- **Duration:** 6.70s
- **Total Findings:** 25

## [MEDIUM] Session cookie 'session_id' missing security flags
- **Category:** session
- **URL:** http://127.0.0.1:8765
- **Evidence:** Flags missing: HttpOnly, Secure, SameSite; Set-Cookie: session_id=probe_sess_12345; Path=/
- **Remediation:** Set 'HttpOnly; Secure; SameSite=Lax' on all session cookies.

## [LOW] Clickjacking protection missing (X-Frame-Options / frame-ancestors absent)
- **Category:** headers
- **URL:** http://127.0.0.1:8765
- **Evidence:** X-Frame-Options header absent
- **Remediation:** Set 'X-Frame-Options: DENY' or CSP frame-ancestors 'none'.

## [LOW] X-Content-Type-Options: nosniff header missing
- **Category:** headers
- **URL:** http://127.0.0.1:8765
- **Evidence:** Header: unset
- **Remediation:** Set 'X-Content-Type-Options: nosniff'.

## [INFO] Referrer-Policy header missing
- **Category:** headers
- **URL:** http://127.0.0.1:8765
- **Evidence:** Referrer-Policy header absent
- **Remediation:** Set 'Referrer-Policy: strict-origin-when-cross-origin'.

## [INFO] Server technology banners disclosed
- **Category:** headers
- **URL:** http://127.0.0.1:8765
- **Evidence:** Server: BaseHTTP/0.6 Python/3.12.13
- **Remediation:** Disable or strip Server and X-Powered-By response headers in reverse proxy configuration.

## [HIGH] Potentially sensitive file accessible: composer.json
- **Category:** files
- **URL:** http://127.0.0.1:8765/composer.json
- **Evidence:** HTTP 200 (892 bytes)
- **Remediation:** Remove or restrict access to database dumps and configuration files.

## [HIGH] Potentially sensitive file accessible: package.json
- **Category:** files
- **URL:** http://127.0.0.1:8765/package.json
- **Evidence:** HTTP 200 (892 bytes)
- **Remediation:** Remove or restrict access to database dumps and configuration files.

## [MEDIUM] Administrative path reachable without authentication: /admin
- **Category:** forced
- **URL:** http://127.0.0.1:8765/admin
- **Evidence:** HTTP 200 on unauthenticated request
- **Remediation:** Require authentication for all administration endpoints.

## [MEDIUM] Administrative path reachable without authentication: /admin/dashboard
- **Category:** forced
- **URL:** http://127.0.0.1:8765/admin/dashboard
- **Evidence:** HTTP 200 on unauthenticated request
- **Remediation:** Require authentication for all administration endpoints.

## [MEDIUM] Administrative path reachable without authentication: /admin/users
- **Category:** forced
- **URL:** http://127.0.0.1:8765/admin/users
- **Evidence:** HTTP 200 on unauthenticated request
- **Remediation:** Require authentication for all administration endpoints.

## [MEDIUM] Administrative path reachable without authentication: /admin/settings
- **Category:** forced
- **URL:** http://127.0.0.1:8765/admin/settings
- **Evidence:** HTTP 200 on unauthenticated request
- **Remediation:** Require authentication for all administration endpoints.

## [MEDIUM] Administrative path reachable without authentication: /admin/operations
- **Category:** forced
- **URL:** http://127.0.0.1:8765/admin/operations
- **Evidence:** HTTP 200 on unauthenticated request
- **Remediation:** Require authentication for all administration endpoints.

## [MEDIUM] Administrative path reachable without authentication: /staff
- **Category:** forced
- **URL:** http://127.0.0.1:8765/staff
- **Evidence:** HTTP 200 on unauthenticated request
- **Remediation:** Require authentication for all administration endpoints.

## [LOW] Form missing anti-CSRF token
- **Category:** csrf
- **URL:** http://127.0.0.1:8765/login
- **Evidence:** Form at http://127.0.0.1:8765 contains inputs ['username', 'password'] without CSRF token
- **Remediation:** Implement anti-CSRF tokens or SameSite=Lax/Strict cookie protection on POST forms.

## [LOW] Form missing anti-CSRF token
- **Category:** csrf
- **URL:** http://127.0.0.1:8765/login
- **Evidence:** Form at http://127.0.0.1:8765/login contains inputs ['username', 'password'] without CSRF token
- **Remediation:** Implement anti-CSRF tokens or SameSite=Lax/Strict cookie protection on POST forms.

## [HIGH] SQL injection (Error-based)
- **Category:** sqli
- **URL:** http://127.0.0.1:8765/search
- **Evidence:** SQL error pattern matched: (?i)you have an error in your sql syntax
- **Remediation:** Parameterize all database queries.

## [HIGH] Reflected cross-site scripting (XSS)
- **Category:** xss
- **URL:** http://127.0.0.1:8765/search
- **Evidence:** Injected payload reflected unencoded in response
- **Remediation:** Apply context-aware HTML entity encoding on all user inputs.

## [MEDIUM] Potential Prototype Pollution accepted
- **Category:** proto
- **URL:** http://127.0.0.1:8765/search
- **Evidence:** Prototype key reflected or accepted without validation
- **Remediation:** Freeze Object.prototype or sanitize object keys (block __proto__, constructor).

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

## [HIGH] Reflected cross-site scripting (XSS)
- **Category:** xss
- **URL:** http://127.0.0.1:8765/api/me
- **Evidence:** Injected payload reflected unencoded in response
- **Remediation:** Apply context-aware HTML entity encoding on all user inputs.

## [MEDIUM] Potential Prototype Pollution accepted
- **Category:** proto
- **URL:** http://127.0.0.1:8765/api/me
- **Evidence:** Prototype key reflected or accepted without validation
- **Remediation:** Freeze Object.prototype or sanitize object keys (block __proto__, constructor).

## [MEDIUM] Potential IDOR on parameter 'id'
- **Category:** idor
- **URL:** http://127.0.0.1:8765/api/me
- **Evidence:** Incremented ID 2 returned HTTP 200
- **Remediation:** Ensure user authorization is validated before fetching object records.

## [HIGH] Reflected XSS (context: html_body)
- **Category:** xss_ast
- **URL:** http://127.0.0.1:8765/api/me
- **Evidence:** Payload landed in html_body. Surrounding: ...'e": "customer", "account_id": "acc_\\"\'><img src=x onerror=WPASTwuyrkmdg()>", "balance": 1500.0, "name": "Test Customer \\'
- **Remediation:** Apply context-aware encoding (HTML entity, JS string escape, URL encode, JSON escape).

## [CRITICAL] Exploit chain: XSS + no HttpOnly → session hijack
- **Category:** xss
- **URL:** http://127.0.0.1:8765/search
- **Evidence:** xss → Reflected cross-site scripting (XSS) (http://127.0.0.1:8765/search); session → Session cookie 'session_id' missing security flags (http://127.0.0.1:8765)
- **Remediation:** Add HttpOnly/Secure/SameSite to all session cookies AND fix XSS output encoding.

