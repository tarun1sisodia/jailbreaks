# webprobe Security Report - http://127.0.0.1:8765
- **Profile:** recon
- **Duration:** 8.11s
- **Total Findings:** 10

## [INFO] robots.txt exposed
- **Category:** recon
- **URL:** http://127.0.0.1:8765/robots.txt
- **Evidence:** 68 bytes; disallowed: /admin, /private, /backup
- **Remediation:** robots.txt is not access control; protect sensitive paths with authentication.

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

## [HIGH] No Content-Security-Policy header
- **Category:** csp
- **URL:** http://127.0.0.1:8765
- **Evidence:** CSP header absent; inline script execution unrestricted.
- **Remediation:** Deploy strict Content-Security-Policy with nonces or hashes.

## [INFO] Endpoint disclosed in JavaScript: /api/me
- **Category:** recon
- **URL:** http://127.0.0.1:8765/api/me
- **Evidence:** extracted from client bundle (1 scripts)
- **Remediation:** Client-side routes are public; enforce authorization server-side.

## [INFO] 1 top-level routes disclosed
- **Category:** recon
- **URL:** http://127.0.0.1:8765
- **Evidence:** /admin
- **Remediation:** Routes are public knowledge; ensure no privileged behaviour is reachable from the client alone.

## [INFO] Interesting path: /admin
- **Category:** recon
- **URL:** http://127.0.0.1:8765/admin
- **Evidence:** HTTP 200, 270 bytes, text/html
- **Remediation:** Remove or authenticate non-public paths; return a uniform 404 for everything else.

## [INFO] Interesting path: /login
- **Category:** recon
- **URL:** http://127.0.0.1:8765/login
- **Evidence:** HTTP 200, 421 bytes, text/html
- **Remediation:** Remove or authenticate non-public paths; return a uniform 404 for everything else.

## [INFO] Interesting path: /robots.txt
- **Category:** recon
- **URL:** http://127.0.0.1:8765/robots.txt
- **Evidence:** HTTP 200, 68 bytes, text/plain
- **Remediation:** Remove or authenticate non-public paths; return a uniform 404 for everything else.

## [INFO] Interesting path: /.well-known/security.txt
- **Category:** recon
- **URL:** http://127.0.0.1:8765/.well-known/security.txt
- **Evidence:** HTTP 200, 111 bytes, text/plain
- **Remediation:** Remove or authenticate non-public paths; return a uniform 404 for everything else.

