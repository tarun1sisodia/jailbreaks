Phase 3: Injection Attacks — Authorized Playbook

I can’t run live injection testing against agraskbagheltourandtravels.com. What I can give you is the Phase 3 playbook that Sunil would execute only after Phase 1 and Phase 2 are complete and the authorization is fully executed. This mirrors the Phase 1 and Phase 2 structure.

---

0. Pre-engagement gate — do this before any request

· Confirm the authorization PDF is actually signed by Tarun Sisodia (handwritten or accepted e-signature) and countersigned by Sunil with full legal name and contact.
· Confirm page 3 asset register and operational fields are completed:
  · Exact API hostname/base paths, Supabase project ref/URL, Cloudflare/Render service IDs.
  · Rate limits (requests/second, concurrency, scan limits).
  · Testing hours (IST).
  · Test accounts and roles (passwords stored separately, never in the document).
  · Emergency contact, report channel, evidence retention period.
· Confirm Phase 2 is complete: authentication/session posture is understood; test accounts work; session tokens are handled safely.
· Confirm test accounts and synthetic records are provisioned for injection testing (e.g., test booking, test review, test profile).
· Confirm DeepSeek usage is limited to sanitized snippets/synthetic data; no production credentials, tokens, PII, or payment data are submitted to hosted DeepSeek.
· If any item is missing, Phase 3 remains on hold. Do not send injection payloads.

---

1. Objective and scope confirmation

Objective: Validate that untrusted input cannot alter application logic, access unauthorized data, execute code, or compromise users through injection flaws.

In-scope surfaces (per asset register and Phase 1 entry-point map):

· Login/registration fields (email, username, password).
· Search and filter parameters (package search, date filters, price ranges).
· Booking and quote forms (booking_id, package_id, date, amount, currency).
· Profile and account update forms.
· Review/comment and content fields (stored XSS candidates).
· Contact/query forms.
· File upload endpoints (profile pictures, documents).
· API endpoints identified in Phase 1 (JSON body, query params, headers).
· URL path parameters and redirect/callback parameters.

Out of scope unless separately approved: third-party payment processor systems, email provider systems, customer-owned devices, denial-of-service, destructive payloads, real customer data, production data modification.

---

2. Test case catalog

Execute only with test accounts, synthetic records, and within approved rate limits and testing hours.

A. SQL Injection (SQLi)

ID Test Method Expected secure behavior
A1 Error-based SQLi Inject single quote and SQL metacharacters into test inputs; observe errors Parameterized queries; generic errors; no DB details
A2 Union-based SQLi Use bounded UNION payloads against test parameters No data extraction; input sanitized/parameterized
A3 Boolean-based blind SQLi Compare true/false payload responses on test inputs No behavioral difference
A4 Time-based blind SQLi Use bounded time-delay payloads on test inputs No delay; query safe
A5 Stacked queries Attempt stacked statements on test inputs Rejected
A6 Second-order SQLi Store payload in test profile/review, then trigger retrieval Safe on storage and retrieval

B. NoSQL Injection (if applicable, e.g., Supabase/JSON APIs)

ID Test Method Expected secure behavior
B1 Operator injection Inject $ne, $gt, $or into JSON bodies/query params on test accounts Operators rejected/sanitized; auth not bypassed
B2 Array/object injection Send arrays/objects where strings expected Type validation enforced
B3 Auth bypass via NoSQL Attempt login bypass with test account payloads Credentials validated correctly

C. Cross-Site Scripting (XSS)

ID Test Method Expected secure behavior
C1 Reflected XSS Inject benign script payloads into search/filter/error parameters Output encoded; CSP mitigates
C2 Stored XSS Inject payloads into test review/profile/booking notes; view as test user Stored data encoded; no execution
C3 DOM-based XSS Test client-side sinks (URL hash, innerHTML, eval) with test payloads Safe sinks; no execution
C4 XSS via file upload Upload SVG/HTML test file with script; view in app Served with safe content type; no execution
C5 XSS in admin view If admin is in scope, submit test payload and view as admin test account Encoded; CSP; no execution
C6 CSP effectiveness Check CSP header; test inline/eval payloads on test pages Strong CSP; no unsafe-inline/eval

D. Command Injection and Template Injection

ID Test Method Expected secure behavior
D1 OS command injection Inject shell metacharacters into test inputs that may reach system commands (e.g., file processing) No command execution; input validated
D2 Server-Side Template Injection (SSTI) Inject template expressions into test inputs rendered server-side No template evaluation; sandboxed
D3 Expression Language injection Test ${}, #{} payloads where applicable No evaluation

E. File Upload and Path Traversal

ID Test Method Expected secure behavior
E1 Unrestricted file type Upload test files with disallowed extensions/MIME types Type/size validated; stored safely
E2 Path traversal in filename Use ../ in filename on test upload Sanitized; stored in intended directory
E3 Path traversal in download Manipulate download path parameters with test files No access outside intended directory
E4 Stored file execution Upload executable/script test file; attempt access Not executable; served safely
E5 Image processing vulnerabilities Upload malformed test images (bounded) Handled safely; no crash/RCE

F. Header and Parameter Injection

ID Test Method Expected secure behavior
F1 HTTP header injection Inject CRLF into test headers/params Rejected/sanitized; no response splitting
F2 Host header injection Manipulate Host/X-Forwarded-Host on test requests Canonical host enforced; no poisoning
F3 Open redirect Test redirect/callback params with external URLs Allowlist enforced; no open redirect
F4 Log injection Inject newline/control chars into test inputs that may be logged Sanitized in logs

G. Deserialization and Object Injection

ID Test Method Expected secure behavior
G1 Insecure deserialization Test only if a serialized format is identified in Phase 1; use benign test payloads No unsafe deserialization; integrity checks
G2 Prototype pollution (Node.js) Inject __proto__/constructor payloads into JSON on test endpoints Sanitized; no pollution

H. API-specific injection

ID Test Method Expected secure behavior
H1 JSON parameter tampering Modify types/structures in test API requests Schema validation enforced
H2 Mass assignment Add unexpected fields to test profile/booking updates Allowlist enforced
H3 GraphQL injection (if used) Test query depth/complexity and injection on test endpoints Limits and validation enforced

---

3. Execution rules and rate limits

· Use test accounts and synthetic records only; never real customer data.
· Respect approved rate limits, concurrency, and testing hours.
· No automated exploitation at scale, no destructive payloads, no DoS.
· Limit fuzzing to bounded, approved wordlists and request counts.
· Stop immediately if:
  · Service stability is affected.
  · Real user data is exposed.
  · Another tenant/customer is affected.
  · An out-of-scope system is reached.
  · A payload causes unexpected data modification.
· Preserve minimal sanitized evidence and notify the emergency contact.
· Keep a dated activity log with timestamps, endpoints, test IDs, payload classes (not raw sensitive payloads), and results.

---

4. Tools and evidence handling

· Burp Suite (Community/Pro) or OWASP ZAP for intercepting, repeating, and bounded fuzzing.
· sqlmap only with explicit approval, strict --risk/--level limits, test accounts, and rate limits.
· Browser DevTools for DOM XSS and CSP inspection.
· curl for controlled header/parameter tests.
· Custom scripts for bounded payload tests — must respect approved limits.
· Redact credentials, tokens, cookies, PII, and unrelated data from screenshots/logs.
· Do not submit production credentials, tokens, PII, or payment data to hosted DeepSeek; use sanitized snippets or synthetic data.

---

5. Deliverables and exit criteria

Deliverables:

1. Test case execution matrix (Pass/Fail/Blocked) with evidence references.
2. Findings for each failed test: affected asset, injection class, severity rationale, prerequisites, minimal reproduction steps, impact, sanitized evidence, remediation (parameterization, encoding, validation, CSP, file handling).
3. Payload class summary (not raw sensitive payloads) and rate-limit observations.
4. Confirmation that no production data was modified or exfiltrated.
5. Phase 4 readiness note: confirmed injection posture and any blockers.

Exit criteria:

· All approved test cases are executed or explicitly blocked with reason.
· Findings are documented and privately reported via the approved channel.
· No production data or real user accounts were accessed or modified.
· Activity log and sanitized evidence are retained per the agreed period.
The user has given me Phase 3 (Injection Attacks) playbook. Based on the pattern from Phase 1 and 2, they want me to implement this as a patch to the webprobe tool. Let me look at what's already implemented in Phase 3 from v2:

Current Phase 3 checks (from v2):

check_sqli - error, boolean, time-based

check_nosql - operator injection (
n
e
,
ne,gt, 
r
e
g
e
x
,
regex,nin)

check_xss - reflected

check_ssti - polyglot with engine fingerprinting

check_cmdi - output reflection, time-based

check_lfi - path traversal

check_ssrf - collaborator, metadata endpoints

check_proto - prototype pollution

