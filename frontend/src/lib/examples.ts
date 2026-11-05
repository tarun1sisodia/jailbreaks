import type { RawFinding, Report, Scan } from '../types'

// Explicitly labeled examples make the interface explorable before the first
// assessment. They never go to, or get mixed into, the scanner's registry.
const now = Date.now() / 1000
export const EXAMPLE_SCANS: Scan[] = [
  {
    scan_id: 'example-running', url: 'https://api.example.com', profile: 'full', status: 'running',
    created_at: now - 102, duration_seconds: 102, findings_count: 0, example: true,
  },
  {
    scan_id: 'example-app', url: 'https://app.example.com', profile: 'full', status: 'completed',
    created_at: now - 7200, duration_seconds: 724, findings_count: 7,
    severity_summary: { critical: 1, high: 2, medium: 2, low: 1, info: 1 }, example: true,
  },
  {
    scan_id: 'example-store', url: 'https://store.example.com', profile: 'owasp', status: 'completed',
    created_at: now - 86400, duration_seconds: 386, findings_count: 3,
    severity_summary: { critical: 0, high: 1, medium: 1, low: 1, info: 0 }, example: true,
  },
  {
    scan_id: 'example-failed', url: 'https://staging.example.com', profile: 'api', status: 'failed',
    created_at: now - 2 * 86400, duration_seconds: 34, findings_count: 0,
    error: 'The target did not respond before the connection timed out.', example: true,
  },
  {
    scan_id: 'example-clean', url: 'https://portal.example.com', profile: 'quick', status: 'completed',
    created_at: now - 3 * 86400, duration_seconds: 58, findings_count: 0,
    severity_summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, example: true,
  },
]

const appFindings: RawFinding[] = [
  {
    category: 'ssti', severity: 'critical', title: 'Server-side template injection', url: 'https://app.example.com/book', method: 'POST', param: 'destination', phase: 3,
    description: 'The application evaluates user-supplied input in a server-side template. An attacker may be able to execute template expressions on the server.',
    evidence: 'The expression {{7*7}} was evaluated in the response as 49.',
    remediation: 'Avoid rendering user input as a template. Pass untrusted values as data, use contextual escaping, and restrict template execution privileges.',
    extra: { cvss: { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }, taxonomy: { cwe: 'CWE-1336', owasp: 'A03:2021' } },
    poc: { request: { method: 'POST', url: 'https://app.example.com/book', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: '[REDACTED:session]' }, body_text: 'destination=%7B%7B7*7%7D%7D' }, response: { status: 200, body_text: '<span class="destination">49</span>' }, curl: "curl -X POST 'https://app.example.com/book' -d 'destination=%7B%7B7*7%7D%7D'" },
  },
  {
    category: 'idor', severity: 'high', title: 'Insecure direct object reference', url: 'https://app.example.com/api/bookings/1042', method: 'GET', param: 'id', phase: 4,
    description: 'A booking resource was returned to a user outside the resource owner’s account.',
    evidence: 'A request for a different account’s booking returned a successful response.',
    remediation: 'Enforce object-level authorization on every request using the authenticated user’s account and role.',
    extra: { cvss: { score: 8.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N' }, taxonomy: { cwe: 'CWE-639', owasp: 'A01:2021' } },
  },
  {
    category: 'cors', severity: 'high', title: 'Overly permissive CORS policy', url: 'https://app.example.com/api/me', method: 'GET', phase: 4,
    description: 'The application reflects untrusted origins in its cross-origin resource sharing policy.',
    evidence: 'Access-Control-Allow-Origin reflected the supplied Origin header.',
    remediation: 'Maintain an explicit allowlist of trusted origins and avoid combining wildcard origins with credentials.',
    extra: { cvss: { score: 7.4, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N' }, taxonomy: { cwe: 'CWE-942', owasp: 'A05:2021' } },
  },
  {
    category: 'headers', severity: 'medium', title: 'Content Security Policy not configured', url: 'https://app.example.com/', method: 'GET', phase: 6,
    description: 'The response does not include a Content-Security-Policy header.',
    evidence: 'No Content-Security-Policy header was present in the response.',
    remediation: 'Define a restrictive Content Security Policy and review script and frame sources.',
    extra: { cvss: { score: 5.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' }, taxonomy: { cwe: 'CWE-693', owasp: 'A05:2021' } },
  },
  {
    category: 'session', severity: 'medium', title: 'Session cookie missing Secure attribute', url: 'https://app.example.com/login', method: 'GET', phase: 2,
    evidence: 'The session cookie was set without the Secure attribute.',
    remediation: 'Set Secure, HttpOnly, and an appropriate SameSite attribute on session cookies.',
    extra: { cvss: { score: 5.0, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N' }, taxonomy: { cwe: 'CWE-614', owasp: 'A07:2021' } },
  },
  {
    category: 'headers', severity: 'low', title: 'Missing X-Content-Type-Options header', url: 'https://app.example.com/', method: 'GET', phase: 6,
    evidence: 'The response did not include X-Content-Type-Options: nosniff.',
    remediation: 'Set X-Content-Type-Options to nosniff on application responses.',
    extra: { cvss: { score: 3.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N' }, taxonomy: { cwe: 'CWE-693', owasp: 'A05:2021' } },
  },
  {
    category: 'recon', severity: 'info', title: 'Robots.txt file discovered', url: 'https://app.example.com/robots.txt', method: 'GET', phase: 1,
    evidence: 'A robots.txt file was available to unauthenticated visitors.',
    remediation: 'Review listed paths and ensure sensitive routes require authorization.',
    extra: { cvss: { score: 0, vector: '' }, taxonomy: { cwe: 'CWE-200', owasp: 'A05:2021' } },
  },
]

const storeFindings = [appFindings[2], appFindings[3], appFindings[5]].map((finding) => ({
  ...finding, url: finding.url?.replace('app.example.com', 'store.example.com'),
}))

export function exampleScan(id: string): Scan | undefined {
  return EXAMPLE_SCANS.find((scan) => scan.scan_id === id)
}

export function exampleReport(id: string): Report | undefined {
  const scan = exampleScan(id)
  if (!scan || scan.status !== 'completed') return undefined
  const findings = id === 'example-app' ? appFindings : id === 'example-store' ? storeFindings : []
  return { metadata: { target: scan.url, profile: scan.profile, version: '3.0.0', duration_seconds: scan.duration_seconds }, total_findings: findings.length, findings }
}

export const EXAMPLE_LOG = `[12:04:01] [init]     WebProbe v3.0.0 initializing assessment
[12:04:01] [init]     Profile: full · 136 checks selected
[12:04:02] [recon]    Fetching /robots.txt
[12:04:03] [recon]    Sitemap discovered · 24 URLs queued
[12:04:12] [recon]    Crawled 18 pages, discovered 42 URLs
[12:04:21] [auth]     Checking session and cookie configuration
[12:04:38] [inject]   Testing parameters on discovered endpoints
[12:05:04] [inject]   Checking response behavior
[12:05:17] [authz]    Assessing object-level access controls
[12:05:43] [authz]    Assessment in progress...`

export const EXAMPLE_FAILED_LOG = `[08:14:01] [init]     WebProbe v3.0.0 initializing assessment
[08:14:01] [init]     Profile: api · 17 checks selected
[08:14:35] [error]    Target connection timed out.`
