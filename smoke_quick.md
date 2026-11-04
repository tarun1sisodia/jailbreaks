# webprobe Security Report - http://127.0.0.1:8765
- **Profile:** quick
- **Duration:** 3.52s
- **Total Findings:** 16

## [INFO] security.txt present
- **Category:** recon
- **URL:** http://127.0.0.1:8765/.well-known/security.txt
- **Evidence:** contacts: 1; policy: https://example.com/security-policy; expires: 2027-12-31T23:59:59Z
- **Remediation:** Keep the file current and within its Expires window.

## [INFO] security.txt present
- **Category:** recon
- **URL:** http://127.0.0.1:8765/security.txt
- **Evidence:** contacts: 1; policy: https://example.com/security-policy; expires: 2027-12-31T23:59:59Z
- **Remediation:** Keep the file current and within its Expires window.

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

## [MEDIUM] Potential IDOR on parameter 'id'
- **Category:** idor
- **URL:** http://127.0.0.1:8765/api/me
- **Evidence:** Incremented ID 2 returned HTTP 200
- **Remediation:** Ensure user authorization is validated before fetching object records.

## [CRITICAL] Exploit chain: XSS + no HttpOnly → session hijack
- **Category:** xss
- **URL:** http://127.0.0.1:8765/search
- **Evidence:** xss → Reflected cross-site scripting (XSS) (http://127.0.0.1:8765/search); session → Session cookie 'session_id' missing security flags (http://127.0.0.1:8765)
- **Remediation:** Add HttpOnly/Secure/SameSite to all session cookies AND fix XSS output encoding.

