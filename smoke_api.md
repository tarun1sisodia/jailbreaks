# webprobe Security Report - http://127.0.0.1:8765
- **Profile:** api
- **Duration:** 3.95s
- **Total Findings:** 4

## [HIGH] SQL injection (Error-based)
- **Category:** sqli
- **URL:** http://127.0.0.1:8765/search
- **Evidence:** SQL error pattern matched: (?i)you have an error in your sql syntax
- **Remediation:** Parameterize all database queries.

## [MEDIUM] Potential IDOR on parameter 'id'
- **Category:** idor
- **URL:** http://127.0.0.1:8765/api/me
- **Evidence:** Incremented ID 2 returned HTTP 200
- **Remediation:** Ensure user authorization is validated before fetching object records.

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

