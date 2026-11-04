Phase 2: Authentication & Session Management — Authorized Playbook

I can’t run live authentication or session testing against agraskbagheltourandtravels.com. What I can give you is the Phase 2 playbook that Sunil would execute under a fully executed authorization and completed operational fields. This mirrors the Phase 1 structure.

---

0. Pre-engagement gate — do this before any request

· Confirm the authorization PDF is actually signed by Tarun Sisodia (handwritten or accepted e-signature) and countersigned by Sunil with full legal name and contact.
· Confirm page 3 asset register and operational fields are completed:
  · Exact API hostname/base paths, Supabase project ref/URL, Cloudflare/Render service IDs.
  · Rate limits (requests/second, concurrency, scan limits).
  · Testing hours (IST).
  · Test accounts and roles (passwords stored separately, never in the document).
  · Emergency contact, report channel, evidence retention period.
· Confirm written approval that admin.agraskbagheltourandtravels.com is active and company-controlled, if it will be tested.
· Confirm test accounts and synthetic records are provisioned.
· Confirm DeepSeek usage is limited to sanitized snippets/synthetic data; no production credentials, tokens, PII, or payment data are submitted to hosted DeepSeek.
· If any item is missing, Phase 2 remains on hold. Do not send active auth/session requests.

---

1. Objective and scope confirmation

Objective: Validate that authentication, session handling, and authorization boundaries cannot be bypassed, hijacked, or abused.

In-scope surfaces (per asset register):

· Customer login, registration, logout, password reset, “remember me”.
· Admin/staff login and role checks (only if confirmed active and controlled).
· Session cookies, tokens (JWT/opaque), Supabase auth sessions.
· MFA/OTP if present.
· Account lockout and rate-limiting behavior.
· CSRF protections on auth actions.
· OAuth/social login if present.

Out of scope unless separately approved: third-party identity providers, payment processor auth, email provider systems, customer-owned devices, denial-of-service, brute-force at scale, real customer accounts, production data modification.

---

2. Test case catalog

Execute only with test accounts and within approved rate limits and testing hours.

A. Authentication strength and enumeration

ID Test Method Expected secure behavior
A1 Weak password policy Register/login with short, common, predictable passwords on test accounts Policy enforced; weak passwords rejected
A2 Username/email enumeration Compare responses for valid vs invalid accounts on login, registration, reset Generic messages; no account existence leak
A3 Brute-force protection Bounded, rate-limited attempts against a test account Lockout, CAPTCHA, backoff, or alerting
A4 Credential stuffing simulation Small synthetic list against test accounts only, within limits Detection/blocking; no takeover
A5 Default/weak admin credentials Check admin login only if explicitly approved No default creds; MFA enforced

B. Password reset and account recovery

ID Test Method Expected secure behavior
B1 Reset token predictability Request reset for test account; inspect entropy/format High-entropy, single-use, time-limited token
B2 Host header injection in reset link Manipulate Host/X-Forwarded-Host on reset request (bounded) Link uses canonical domain; no attacker-controlled host
B3 Reset token reuse/expiry Reuse token after use and after expiry Invalidated after use and expiry
B4 User enumeration via reset Compare responses for valid vs invalid emails Generic response
B5 Reset link leakage Check Referer, logs, email content for token exposure Token not leaked to third parties

C. Session management

ID Test Method Expected secure behavior
C1 Cookie flags Inspect Set-Cookie for HttpOnly, Secure, SameSite, Path, Domain Appropriate flags set; no overly broad domain
C2 Session fixation Set pre-auth session ID, log in as test user, check ID rotation New session ID issued on login
C3 Session timeout Idle and absolute timeout behavior Reasonable timeouts; re-auth required
C4 Logout invalidation Logout, replay old session cookie/token Session invalidated server-side
C5 Concurrent sessions Log in from multiple browsers with test account Policy enforced (allowed or limited)
C6 “Remember me” token Inspect persistent token; test theft/replay with test account Token bound, rotatable, revocable, not guessable
C7 Session token in URL Check if session IDs appear in URLs or logs Not present
C8 Cache controls Check Cache-Control on authenticated pages no-store or equivalent

D. Token and JWT handling (if used)

ID Test Method Expected secure behavior
D1 JWT algorithm confusion Decode JWT; test alg:none or HS/RS confusion only on test tokens Algorithm enforced server-side
D2 JWT signature validation Tamper claims on a test token and replay Signature validated; tampering rejected
D3 Weak JWT secret Check only via approved, bounded methods Strong secret; rotation supported
D4 Token expiry and revocation Expired/revoked tokens rejected Enforced
D5 Sensitive data in JWT Decode payload No PII/secrets in claims

E. MFA/OTP (if present)

ID Test Method Expected secure behavior
E1 OTP brute force Bounded attempts on test account Rate limit/lockout
E2 OTP reuse Reuse a used OTP Rejected
E3 OTP bypass Attempt to skip MFA step with test account Enforced
E4 Backup codes Check entropy, single-use, revocation Secure

F. CSRF on authentication actions

ID Test Method Expected secure behavior
F1 Login CSRF Craft cross-site login request with test account Anti-CSRF token or SameSite protection
F2 Logout CSRF Cross-site logout request Protected or low impact
F3 Password/email change CSRF Cross-site change request on test account Anti-CSRF token required

G. Authorization boundaries (auth-related)

ID Test Method Expected secure behavior
G1 Role escalation Log in as customer; attempt admin/staff endpoints with test account Denied
G2 Forced browsing Request admin URLs directly Denied or redirected
G3 API role checks Call API endpoints with customer token Server-side authorization enforced
G4 IDOR on user profile Change user ID in profile/account endpoints with test accounts Denied for other users

---

3. Execution rules and rate limits

· Use test accounts only; never real customer accounts.
· Respect approved rate limits, concurrency, and testing hours.
· No automated brute-force at scale, DoS, or credential-stuffing against real users.
· Stop immediately if:
  · Service stability is affected.
  · Real user data is exposed.
  · Another tenant/customer is affected.
  · An out-of-scope system is reached.
· Preserve minimal sanitized evidence and notify the emergency contact.
· Keep a dated activity log with timestamps, endpoints, test IDs, and results.

---

4. Tools and evidence handling

· Burp Suite (Community/Pro) or OWASP ZAP for intercepting and repeating requests.
· Browser DevTools for cookie/session inspection.
· curl for controlled header/cookie tests.
· Local JWT decoder for test tokens only.
· Custom scripts for bounded rate-limit tests — must respect approved limits.
· Redact credentials, tokens, cookies, PII, and unrelated data from screenshots/logs.
· Do not submit production credentials, tokens, PII, or payment data to hosted DeepSeek; use sanitized snippets or synthetic data.

---

5. Deliverables and exit criteria

Deliverables:

1. Test case execution matrix (Pass/Fail/Blocked) with evidence references.
2. Findings for each failed test: affected asset, severity rationale, prerequisites, minimal reproduction steps, impact, sanitized evidence, remediation.
3. Rate-limit and lockout observations (within approved limits).
4. Session/token configuration summary (cookie flags, JWT claims, timeout behavior).
5. Phase 3 readiness note: confirmed auth/session posture and any blockers.

Exit criteria:

· All approved test cases are executed or explicitly blocked with reason.
· Findings are documented and privately reported via the approved channel.
· No production data or real user accounts were accessed.
· Activity log and sanitized evidence are retained per the agreed period.

If the authorization document is not fully executed and page 3 is incomplete, Phase 2 must remain on hold.
