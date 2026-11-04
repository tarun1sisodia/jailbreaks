# webprobe Security Report - http://127.0.0.1:8765
- **Profile:** authz
- **Duration:** 1.61s
- **Total Findings:** 7

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

## [MEDIUM] Potential IDOR on parameter 'id'
- **Category:** idor
- **URL:** http://127.0.0.1:8765/api/me
- **Evidence:** Incremented ID 2 returned HTTP 200
- **Remediation:** Ensure user authorization is validated before fetching object records.

