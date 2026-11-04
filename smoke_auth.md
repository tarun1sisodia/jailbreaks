# webprobe Security Report - http://127.0.0.1:8765
- **Profile:** auth
- **Duration:** 0.62s
- **Total Findings:** 3

## [MEDIUM] Session cookie 'session_id' missing security flags
- **Category:** session
- **URL:** http://127.0.0.1:8765
- **Evidence:** Flags missing: HttpOnly, Secure, SameSite; Set-Cookie: session_id=probe_sess_12345; Path=/
- **Remediation:** Set 'HttpOnly; Secure; SameSite=Lax' on all session cookies.

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

