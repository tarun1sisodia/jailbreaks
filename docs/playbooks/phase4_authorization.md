Phase 4: Broken Access Control (Authorization) — Authorized Playbook

I can’t run live authorization testing against agraskbagheltourandtravels.com. What I can give you is the Phase 4 playbook that Sunil would execute only after Phase 1–3 are complete and the authorization is fully executed. This mirrors the Phase 1–3 structure.

---

0. Pre-engagement gate — do this before any request

· Confirm the authorization PDF is actually signed by Tarun Sisodia (handwritten or accepted e-signature) and countersigned by Sunil with full legal name and contact.
· Confirm page 3 asset register and operational fields are completed:
  · Exact API hostname/base paths, Supabase project ref/URL, Cloudflare/Render service IDs.
  · Rate limits (requests/second, concurrency, scan limits).
  · Testing hours (IST).
  · Test accounts and roles (customer, staff, admin as applicable; passwords stored separately).
  · Emergency contact, report channel, evidence retention period.
· Confirm Phase 1–3 are complete: asset map, auth/session posture, injection posture known; test accounts work.
· Confirm at least two roles of test accounts are provisioned (e.g., customer and admin/staff) if role-based testing is in scope.
· Confirm written approval that admin.agraskbagheltourandtravels.com is active and company-controlled, if it will be tested.
· Confirm DeepSeek usage is limited to sanitized snippets/synthetic data; no production credentials, tokens, PII, or payment data are submitted to hosted DeepSeek.
· If any item is missing, Phase 4 remains on hold. Do not send authorization-boundary requests.

---

1. Objective and scope confirmation

Objective: Validate that users can only access resources and perform actions permitted by their role, and that server-side authorization is enforced consistently across UI, API, and business workflows.

In-scope surfaces (per asset register and Phase 1 entry-point map):

· Customer frontend routes and API calls.
· Admin/staff frontend routes and API calls (only if confirmed active and controlled).
· Booking, reservation, quote, fare, coupon, and payment-state workflows.
· User profile and account endpoints.
· Object references: booking_id, user_id, package_id, order_id, invoice_id, coupon_id, file_id.
· Role and permission checks in backend/API (company-developed).
· Supabase row-level security (RLS) policies, storage bucket policies, and functions — only for the company-owned project/resources listed in the asset register.
· Cloudflare/Render configuration only where explicitly listed and approved.

Out of scope unless separately approved: third-party payment processor systems, email provider systems, customer-owned devices, denial-of-service, destructive testing, real customer data, production data modification, lateral movement beyond listed assets.

---

2. Test case catalog

Execute only with test accounts, synthetic records, and within approved rate limits and testing hours.

A. Horizontal access control (same role, different user)

ID Test Method Expected secure behavior
A1 IDOR on booking references With test user A, access test user B’s booking_id via UI/API Denied; ownership enforced server-side
A2 IDOR on profile/account Change user_id in profile/account endpoints between test accounts Denied for other users
A3 IDOR on invoices/receipts Access another test user’s invoice/receipt IDs Denied
A4 IDOR on uploaded files Access another test user’s uploaded document/profile image Denied; storage policy enforced
A5 IDOR on reviews/content Access or modify another test user’s review/draft Denied
A6 IDOR on coupon usage Apply or inspect another test user’s coupon/redemption Denied; coupon bound correctly

B. Vertical access control (role escalation)

ID Test Method Expected secure behavior
B1 Customer → admin route Request admin URLs directly with customer test account Denied or redirected
B2 Customer → admin API Call admin/staff API endpoints with customer token Server-side role check enforced
B3 Staff → admin action Attempt admin-only actions with staff test account (if applicable) Denied per role matrix
B4 Forced browsing Enumerate admin/staff paths from Phase 1 map with customer account Denied
B5 UI-only enforcement Bypass hidden/disabled UI controls; replay request via API Backend enforces authorization
B6 Role parameter tampering Modify role/claims in test request body/headers Rejected; server derives role from trusted source

C. Context-dependent and business-logic authorization

ID Test Method Expected secure behavior
C1 Booking state transitions Attempt invalid transitions (e.g., cancel after completion) with test bookings State machine enforced
C2 Coupon/pricing authorization Apply restricted coupons or manipulate pricing fields with test accounts Server recomputes; restrictions enforced
C3 Payment-state tampering Modify payment status/amount fields in test requests Server validates with payment provider; no trust in client
C4 Refund/cancellation authorization Attempt refund/cancel on another test user’s booking Denied
C5 Multi-tenant boundary (if applicable) Access another tenant’s test records, if tenancy exists Denied; tenant isolation enforced
C6 Workflow bypass Skip required steps (e.g., payment) in test booking flow Server enforces sequence

D. Supabase RLS and storage policies (only if in asset register)

ID Test Method Expected secure behavior
D1 RLS on tables With test user tokens, query/update rows owned by another test user Denied by RLS
D2 RLS bypass via functions Call company functions with test tokens to access other test rows Denied; function security definer/invoker reviewed
D3 Storage bucket policies Access another test user’s file path in approved bucket Denied
D4 Anon vs authenticated access Compare anon key vs test user token access to in-scope resources Least privilege enforced
D5 Policy gap review Review policies for USING/WITH CHECK gaps using test data only Policies cover read/write appropriately

E. API and method-level authorization

ID Test Method Expected secure behavior
E1 Missing auth on endpoint Call in-scope API endpoints without token 401/403
E2 Method tampering Change GET→POST/PUT/DELETE on test endpoints Method-level auth enforced
E3 Mass assignment on role/owner fields Add role, owner_id, user_id to test update requests Allowlist enforced; fields ignored/rejected
E4 GraphQL/RPC authorization (if used) Query/mutate other test users’ data via in-scope GraphQL/RPC Resolver-level authorization enforced
E5 CORS misconfiguration Test cross-origin requests from a controlled test origin CORS restricted to approved origins

F. Forced browsing and information disclosure

ID Test Method Expected secure behavior
F1 Directory/file enumeration Bounded enumeration of admin/staff paths with test account No sensitive files/routes exposed
F2 Backup/config exposure Check for common exposed files (.env, backups) only via approved, bounded checks Not exposed
F3 Error message leakage Trigger authorization errors with test requests Generic errors; no internal details
F4 Verbose API responses Inspect test API responses for excessive data Least data returned

---

3. Execution rules and rate limits

· Use test accounts and synthetic records only; never real customer data.
· Respect approved rate limits, concurrency, and testing hours.
· No automated exploitation at scale, no destructive payloads, no DoS.
· Do not modify real bookings, payments, refunds, or customer records.
· Stop immediately if:
  · Service stability is affected.
  · Real user data is exposed.
  · Another tenant/customer is affected.
  · An out-of-scope system is reached.
  · A test action risks financial impact.
· Preserve minimal sanitized evidence and notify the emergency contact.
· Keep a dated activity log with timestamps, endpoints, test IDs, role used, and results.

---

4. Tools and evidence handling

· Burp Suite (Community/Pro) or OWASP ZAP for intercepting and replaying requests across test roles.
· Browser DevTools for UI vs API comparison and hidden control testing.
· curl for controlled token/role tests.
· Supabase dashboard/SQL only for reviewing RLS policies using test data and approved access; no production exports.
· Custom scripts for bounded IDOR enumeration using test IDs — must respect approved limits.
· Redact credentials, tokens, cookies, PII, and unrelated data from screenshots/logs.
· Do not submit production credentials, tokens, PII, or payment data to hosted DeepSeek; use sanitized snippets or synthetic data.

---

5. Deliverables and exit criteria

Deliverables:

1. Test case execution matrix (Pass/Fail/Blocked) with evidence references.
2. Findings for each failed test: affected asset, authorization flaw class (IDOR, vertical escalation, missing auth, RLS gap, etc.), severity rationale, prerequisites, minimal reproduction steps with test accounts, impact, sanitized evidence, remediation (server-side checks, RLS policies, allowlists, ownership validation).
3. Role/permission matrix observed vs expected.
4. Confirmation that no production data was accessed or modified.
5. Phase 5 readiness note: confirmed authorization posture and any blockers.

Exit criteria:

· All approved test cases are executed or explicitly blocked with reason.
· Findings are documented and privately reported via the approved channel.
· No production data or real user accounts were accessed or modified.
· Activity log and sanitized evidence are retained per the agreed period.

