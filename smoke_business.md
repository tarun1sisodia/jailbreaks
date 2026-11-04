# webprobe Security Report - http://127.0.0.1:8765
- **Profile:** business
- **Duration:** 0.69s
- **Total Findings:** 4

## [CRITICAL] Webhook accepted unauthenticated without signature: /api/razorpay/webhook
- **Category:** business
- **URL:** http://127.0.0.1:8765/api/razorpay/webhook
- **Evidence:** Unsigned payload returned HTTP 200
- **Remediation:** Enforce HMAC SHA256 signature verification before processing webhook events.

## [CRITICAL] Webhook accepted unauthenticated without signature: /razorpay/webhook
- **Category:** business
- **URL:** http://127.0.0.1:8765/razorpay/webhook
- **Evidence:** Unsigned payload returned HTTP 200
- **Remediation:** Enforce HMAC SHA256 signature verification before processing webhook events.

## [CRITICAL] Webhook accepted unauthenticated without signature: /api/webhooks/razorpay
- **Category:** business
- **URL:** http://127.0.0.1:8765/api/webhooks/razorpay
- **Evidence:** Unsigned payload returned HTTP 200
- **Remediation:** Enforce HMAC SHA256 signature verification before processing webhook events.

## [CRITICAL] Webhook accepted unauthenticated without signature: /webhook
- **Category:** business
- **URL:** http://127.0.0.1:8765/webhook
- **Evidence:** Unsigned payload returned HTTP 200
- **Remediation:** Enforce HMAC SHA256 signature verification before processing webhook events.

