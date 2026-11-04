Phase 5: Business Logic & Payment Flows — Authorized Playbook

I can’t run live business-logic or payment testing against agraskbagheltourandtravels.com. What I can give you is the Phase 5 playbook that Sunil would execute only after Phase 1–4 are complete and the authorization is fully executed. This mirrors the Phase 1–4 structure.

---

0. Pre-engagement gate — do this before any request

· Confirm the authorization PDF is actually signed by Tarun Sisodia (handwritten or accepted e-signature) and countersigned by Sunil with full legal name and contact.
· Confirm page 3 asset register and operational fields are completed:
  · Exact API hostname/base paths, Supabase project ref/URL, Cloudflare/Render service IDs.
  · Rate limits (requests/second, concurrency, scan limits).
  · Testing hours (IST).
  · Test accounts and roles (customer, staff, admin as applicable; passwords stored separately).
  · Emergency contact, report channel, evidence retention period.
· Confirm Phase 1–4 are complete: asset map, auth/session posture, injection posture, and authorization posture are known; test accounts work.
· Confirm test payment configuration is approved:
  · Razorpay test mode keys or sandbox environment are provisioned.
  · No real payment captures, refunds, or settlements will occur.
  · Written confirmation that test transactions are permitted within the authorized scope.
· Confirm test bookings, test coupons, test packages, and synthetic records are provisioned.
· Confirm DeepSeek usage is limited to sanitized snippets/synthetic data; no production credentials, tokens, PII, or payment data are submitted to hosted DeepSeek.
· If any item is missing, Phase 5 remains on hold. Do not send business-logic or payment requests.

---

1. Objective and scope confirmation

Objective: Validate that booking, pricing, coupon, payment-state, and webhook workflows cannot be manipulated to bypass controls, alter financial outcomes, or disrupt booking integrity.

In-scope surfaces (per asset register and Phase 1 entry-point map):

· Booking and reservation flows (create, modify, cancel).
· Quote and fare calculation endpoints.
· Coupon application and redemption logic.
· Payment initiation, callback, and webhook endpoints (company-developed only).
· Payment-state and order-state transitions.
· Refund and cancellation workflows (test mode only).
· Booking reference and order ID generation.
· Cart/checkout session handling.
· Email-trigger logic tied to booking/payment events (company-developed).
· Company deployment configuration only where explicitly listed and approved.

Out of scope unless separately approved: Razorpay’s internal systems, payment processor infrastructure, real payment captures/refunds, email provider infrastructure, third-party systems, denial-of-service, real customer bookings, production data modification.

---

2. Test case catalog

Execute only with test accounts, test-mode payments, synthetic records, and within approved rate limits and testing hours.

A. Price and amount tampering

ID Test Method Expected secure behavior
A1 Client-side price modification Modify amount, price, total in test checkout requests Server recomputes from trusted source; tampering rejected
A2 Currency manipulation Change currency in test requests Server enforces allowed currency and recomputes
A3 Quantity/guest count tampering Modify quantity, guests, rooms in test requests Server validates and recomputes
A4 Discount stacking Apply multiple coupons or combine discounts on test bookings Rules enforced; no unauthorized stacking
A5 Negative/zero values Submit negative, zero, or extreme values in test requests Rejected; bounds enforced
A6 Rounding and tax manipulation Manipulate tax/fee fields in test requests Server recomputes; no trust in client

B. Coupon and promotion logic

ID Test Method Expected secure behavior
B1 Coupon reuse Reuse a single-use test coupon across test bookings Rejected after first use
B2 Coupon expiry bypass Apply expired test coupon via direct request Rejected
B3 Coupon eligibility bypass Apply restricted test coupon to ineligible test booking Rejected
B4 Coupon enumeration Bounded guessing of test coupon codes Rate-limited; no mass enumeration
B5 Coupon tampering Modify coupon value/type in test request Server validates against stored rules
B6 Race condition on coupon Concurrent redemption of same test coupon Only one succeeds

C. Booking workflow and state manipulation

ID Test Method Expected secure behavior
C1 Workflow step bypass Skip payment or verification step in test booking flow Server enforces sequence
C2 Booking state tampering Modify booking status directly in test requests Server validates transitions
C3 Double booking / race condition Concurrent test booking requests for same slot One succeeds; conflict handled
C4 Booking reference predictability Inspect test booking reference format/entropy High-entropy, non-sequential
C5 Cancellation after completion Attempt cancel on completed test booking Rejected per state machine
C6 Modification after cutoff Attempt to modify test booking after allowed window Rejected
C7 Duplicate submission Replay test booking submission Idempotency enforced; no duplicates

D. Payment initiation and callback security

ID Test Method Expected secure behavior
D1 Payment amount mismatch Initiate test payment with tampered amount vs order Server validates amount against order
D2 Callback tampering Modify test callback parameters (order ID, status, signature) Signature verified; tampering rejected
D3 Callback replay Replay a valid test callback Idempotency enforced; no duplicate state change
D4 Callback forgery Send forged test callback without valid signature Rejected
D5 Order ID manipulation Change order_id in test callback to another test order Signature and ownership validated
D6 Payment status spoofing Mark test order as paid without valid payment Server verifies with payment provider
D7 Test/live key confusion Confirm test mode uses test keys only No live key exposure; environment isolated

E. Webhook security (company-developed endpoints only)

ID Test Method Expected secure behavior
E1 Webhook signature validation Send test webhook with invalid/missing signature Rejected
E2 Webhook replay Replay a valid test webhook Idempotency enforced
E3 Webhook payload tampering Modify test webhook payload fields Signature validation rejects
E4 Webhook source validation Send test webhook from unauthorized source Rejected or ignored
E5 Webhook ordering Send out-of-order test webhooks State machine handles correctly

F. Refund and cancellation logic (test mode only)

ID Test Method Expected secure behavior
F1 Refund amount tampering Modify refund amount in test requests Server validates against booking/payment
F2 Refund on unpaid booking Attempt refund on unpaid test booking Rejected
F3 Double refund Attempt multiple refunds on same test booking Idempotency enforced
F4 Cancellation fee bypass Manipulate cancellation fee in test requests Server recomputes per policy
F5 Refund authorization Attempt refund on another test user’s booking Denied

G. Session, cart, and checkout integrity

ID Test Method Expected secure behavior
G1 Cart tampering Modify cart contents/prices in test session Server recomputes
G2 Session swap Swap test session/cart between test users Denied
G3 Checkout CSRF Cross-site checkout request with test account Anti-CSRF protection
G4 Cart persistence Inspect test cart storage for sensitive data No sensitive data client-side
G5 Expired checkout Use expired test checkout session Rejected

H. Email-trigger and notification logic (company-developed)

ID Test Method Expected secure behavior
H1 Trigger abuse Trigger booking/payment emails repeatedly with test accounts Rate-limited; no spam vector
H2 Template injection Inject content into test booking fields that reach emails Sanitized; no injection
H3 Recipient manipulation Modify recipient fields in test requests Server enforces recipient from trusted source
H4 Sensitive data in emails Inspect test emails for tokens/PII Minimal data; no secrets

I. Rate limiting and abuse resistance on business actions

ID Test Method Expected secure behavior
I1 Booking rate limit Bounded rapid test booking attempts Rate-limited
I2 Coupon attempt limit Bounded rapid test coupon attempts Rate-limited
I3 Payment initiation limit Bounded rapid test payment initiations Rate-limited
I4 Enumeration resistance Bounded enumeration of booking/order IDs No mass disclosure

---

3. Execution rules and rate limits

· Use test accounts, test-mode payments, and synthetic records only; never real customer data or real payment captures.
· Respect approved rate limits, concurrency, and testing hours.
· No automated exploitation at scale, no destructive payloads, no DoS.
· Do not issue real payment captures, refunds, or settlements.
· Do not modify real bookings, payments, refunds, or customer records.
· Stop immediately if:
  · A real payment capture or refund occurs.
  · Service stability is affected.
  · Real user data is exposed.
  · Another tenant/customer is affected.
  · An out-of-scope system is reached.
  · A test action risks financial impact.
· Preserve minimal sanitized evidence and notify the emergency contact.
· Keep a dated activity log with timestamps, endpoints, test IDs, test order/booking references, and results.

---

4. Tools and evidence handling

· Burp Suite (Community/Pro) or OWASP ZAP for intercepting and replaying booking/payment requests.
· Browser DevTools for checkout flow inspection.
· curl for controlled callback/webhook tests with test signatures.
· Razorpay test dashboard only for verifying test-mode transactions; no live keys.
· Custom scripts for bounded race-condition and rate-limit tests — must respect approved limits.
· Redact credentials, tokens, cookies, PII, payment data, and unrelated data from screenshots/logs.
· Do not submit production credentials, tokens, PII, or payment data to hosted DeepSeek; use sanitized snippets or synthetic data.

---

5. Deliverables and exit criteria

Deliverables:

1. Test case execution matrix (Pass/Fail/Blocked) with evidence references.
2. Findings for each failed test: affected asset, business-logic flaw class (price tampering, coupon abuse, workflow bypass, callback forgery, webhook replay, race condition, etc.), severity rationale, prerequisites, minimal reproduction steps with test accounts/test orders, impact (financial, operational, data), sanitized evidence, remediation (server-side recomputation, signature verification, idempotency, state machines, rate limits).
3. Payment/callback/webhook validation summary (test mode only).
4. Confirmation that no real payment captures, refunds, or production data modifications occurred.
5. Phase 6 readiness note: confirmed business-logic posture and any blockers.
