# webprobe Security Report - http://127.0.0.1:8765
- **Profile:** config
- **Duration:** 2.05s
- **Total Findings:** 15

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

## [HIGH] Target is not using HTTPS
- **Category:** tls
- **URL:** http://127.0.0.1:8765
- **Evidence:** Scheme: http
- **Remediation:** Enforce HTTPS across all application traffic.

## [INFO] Permissions-Policy header missing
- **Category:** headers
- **URL:** http://127.0.0.1:8765
- **Evidence:** Header absent; camera/microphone/geolocation unconstrained by policy
- **Remediation:** Set 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.

## [MEDIUM] Exposed debug / management endpoint: /debug
- **Category:** config
- **URL:** http://127.0.0.1:8765/debug
- **Evidence:** HTTP 200 returned: <!DOCTYPE html>
        <html>
        <head>
          <title>Vulnerable Testbed Application</title>
          <script ...
- **Remediation:** Disable or restrict debug and monitoring endpoints to internal IPs.

## [MEDIUM] Exposed debug / management endpoint: /__debug__
- **Category:** config
- **URL:** http://127.0.0.1:8765/__debug__
- **Evidence:** HTTP 200 returned: <!DOCTYPE html>
        <html>
        <head>
          <title>Vulnerable Testbed Application</title>
          <script ...
- **Remediation:** Disable or restrict debug and monitoring endpoints to internal IPs.

## [MEDIUM] Exposed debug / management endpoint: /actuator
- **Category:** config
- **URL:** http://127.0.0.1:8765/actuator
- **Evidence:** HTTP 200 returned: <!DOCTYPE html>
        <html>
        <head>
          <title>Vulnerable Testbed Application</title>
          <script ...
- **Remediation:** Disable or restrict debug and monitoring endpoints to internal IPs.

## [MEDIUM] Exposed debug / management endpoint: /actuator/health
- **Category:** config
- **URL:** http://127.0.0.1:8765/actuator/health
- **Evidence:** HTTP 200 returned: <!DOCTYPE html>
        <html>
        <head>
          <title>Vulnerable Testbed Application</title>
          <script ...
- **Remediation:** Disable or restrict debug and monitoring endpoints to internal IPs.

## [MEDIUM] Exposed debug / management endpoint: /actuator/env
- **Category:** config
- **URL:** http://127.0.0.1:8765/actuator/env
- **Evidence:** HTTP 200 returned: <!DOCTYPE html>
        <html>
        <head>
          <title>Vulnerable Testbed Application</title>
          <script ...
- **Remediation:** Disable or restrict debug and monitoring endpoints to internal IPs.

## [MEDIUM] Exposed debug / management endpoint: /actuator/metrics
- **Category:** config
- **URL:** http://127.0.0.1:8765/actuator/metrics
- **Evidence:** HTTP 200 returned: <!DOCTYPE html>
        <html>
        <head>
          <title>Vulnerable Testbed Application</title>
          <script ...
- **Remediation:** Disable or restrict debug and monitoring endpoints to internal IPs.

## [INFO] HTTP/2 smuggling test skipped (pip install h2)
- **Category:** smuggle
- **URL:** http://127.0.0.1:8765
- **Evidence:** 
- **Remediation:** 

