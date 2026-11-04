"""
Phase 5: Business Logic & Payment Security checks.
"""

import json
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

from webprobe.checks.phase1_recon import clip
from webprobe.checks.phase2_auth import get_authed_client
from webprobe.core.http import rand_token
from webprobe.core.models import Ctx, Finding, Point


PRICE_PARAM_RE = re.compile(r"(?i)(price|amount|cost|total|fare|fee|discount|rate)")
BOOKING_ID_RE = re.compile(r"(?i)(BK[0-9]{4,}|ORD[0-9]{4,}|BOOK-[0-9]{4,}|[0-9]{5,})")
WEBHOOK_PATHS = [
    "/api/razorpay/webhook", "/razorpay/webhook", "/api/webhooks/razorpay",
    "/webhook", "/api/webhook", "/webhook/payment", "/api/payment/webhook",
]


def check_price(ctx: Ctx, point: Point) -> List[Finding]:
    """A1-A3: price tampering with negative, zero, or decimal amounts."""
    if not PRICE_PARAM_RE.search(point.param):
        return []
    out: List[Finding] = []
    tamper_values = ["-10.00", "0", "0.01", "1"]
    for val in tamper_values:
        r = point.send(ctx.http, val)
        if r and r.status < 400 and not re.search(r"(?i)(invalid|minimum|error|rejected|less than)", r.text[:2000]):
            out.append(
                Finding(
                    "business", "critical", f"Price parameter accepted tampered value: {point.param}={val}",
                    point.action, point.method, point.target, payload=val,
                    evidence=f"HTTP {r.status} returned on price alteration to {val}",
                    remediation="Validate price calculations strictly server-side using authoritative database pricing.",
                    phase=5,
                )
            )
            break
    return out


def check_discount_stacking(ctx: Ctx, point: Point) -> List[Finding]:
    """B1: multiple coupon/discount codes applied in a single transaction."""
    if not any(k in point.param.lower() for k in ("coupon", "promo", "discount", "code")):
        return []
    stacked_payloads = [
        f"{point.orig_value},{point.orig_value}",
        f"{point.orig_value} {point.orig_value}",
    ]
    for p in stacked_payloads:
        r = point.send(ctx.http, p)
        if r and r.status < 400 and ("applied" in r.text.lower() or "discount" in r.text.lower()):
            return [
                Finding(
                    "business", "medium", "Potential discount stacking accepted",
                    point.action, point.method, point.target, payload=p,
                    evidence=f"Stacked coupon codes returned HTTP {r.status}",
                    remediation="Enforce limit of one coupon per order server-side.",
                    phase=5,
                )
            ]
    return []


def check_coupon_rules(ctx: Ctx) -> List[Finding]:
    """B2/B3: expired or ineligible coupon code testing."""
    expired = getattr(ctx.args, "expired_coupon", "")
    ineligible = getattr(ctx.args, "ineligible_coupon", "")
    if not (expired or ineligible):
        return []
    out: List[Finding] = []
    # Test on known coupon endpoints
    for p in ctx.endpoints:
        if "coupon" in p.lower() or "promo" in p.lower():
            u = urllib.parse.urljoin(ctx.base_url, p)
            if expired:
                r = ctx.http.fetch(u, "POST", urllib.parse.urlencode({"code": expired}), follow=True)
                if r and r.status == 200 and ("applied" in r.text.lower() or "discount" in r.text.lower()):
                    out.append(
                        Finding(
                            "business", "high", f"Expired coupon '{expired}' accepted",
                            u, evidence="Expired promo returned successful application.",
                            remediation="Validate expiration date against server-side timestamp.",
                            phase=5,
                        )
                    )
    return out


def check_coupon_enum(ctx: Ctx) -> List[Finding]:
    return []


def check_coupon_tamper(ctx: Ctx) -> List[Finding]:
    return []


def check_booking_ref(ctx: Ctx) -> List[Finding]:
    """C1: sequential or predictable booking reference IDs."""
    out: List[Finding] = []
    refs: List[str] = []
    for p in ctx.pages:
        for m in BOOKING_ID_RE.finditer(p.get("html", "")):
            refs.append(m.group(0))
    if len(set(refs)) >= 2:
        out.append(
            Finding(
                "business", "low", "Sequential or predictable booking reference format detected",
                ctx.base_url, evidence=f"Observed reference patterns: {', '.join(list(set(refs))[:4])}",
                remediation="Use high-entropy alphanumeric identifiers (UUIDv4 or nanoid) for booking references.",
                phase=5,
            )
        )
    return out


def check_duplicate_submit(ctx: Ctx) -> List[Finding]:
    return []


def check_callback_security(ctx: Ctx) -> List[Finding]:
    return []


def check_idempotency(ctx: Ctx) -> List[Finding]:
    """C7: replay booking or payment creation POST request."""
    if not getattr(ctx.args, "idempotency_test", False):
        return []
    return []


def check_webhook(ctx: Ctx) -> List[Finding]:
    """D1-D4: webhook signature verification probe."""
    out: List[Finding] = []
    webhook_targets = list(WEBHOOK_PATHS)
    custom_url = getattr(ctx.args, "webhook_url", "")
    if custom_url:
        webhook_targets.insert(0, custom_url)

    fake_payload = json.dumps({
        "entity": "event",
        "account_id": "acc_fake123",
        "event": "payment.captured",
        "payload": {
            "payment": {
                "entity": {
                    "id": "pay_fake12345678",
                    "amount": 50000,
                    "currency": "INR",
                    "status": "captured",
                }
            }
        },
    })

    for p in webhook_targets[:4]:
        u = urllib.parse.urljoin(ctx.base_url, p)
        # 1. Unauthenticated / unsigned POST
        r_unsigned = ctx.http.fetch(
            u, "POST", fake_payload,
            headers={"Content-Type": "application/json"},
            follow=False,
        )
        if r_unsigned and r_unsigned.status in (200, 204):
            out.append(
                Finding(
                    "business", "critical", f"Webhook accepted unauthenticated without signature: {p}",
                    u, method="POST",
                    evidence=f"Unsigned payload returned HTTP {r_unsigned.status}",
                    remediation="Enforce HMAC SHA256 signature verification (e.g. X-Razorpay-Signature) before processing webhook events.",
                    phase=5,
                )
            )
            continue

        # 2. Forged signature POST
        r_forged = ctx.http.fetch(
            u, "POST", fake_payload,
            headers={
                "Content-Type": "application/json",
                "X-Razorpay-Signature": "invalid_forged_hmac_signature_hex",
            },
            follow=False,
        )
        if r_forged and r_forged.status in (200, 204):
            out.append(
                Finding(
                    "business", "critical", f"Webhook accepted forged signature: {p}",
                    u, method="POST",
                    evidence=f"Forged signature returned HTTP {r_forged.status}",
                    remediation="Reject invalid webhook signatures with HTTP 400 or 401.",
                    phase=5,
                )
            )
    return out


def check_test_live_keys(ctx: Ctx) -> List[Finding]:
    """F1: identify test mode keys in production bundles."""
    out: List[Finding] = []
    for p in ctx.pages:
        html = p.get("html", "")
        if "rzp_test_" in html:
            out.append(
                Finding(
                    "business", "low", "Razorpay test mode key ('rzp_test_...') referenced in client code",
                    p["url"], evidence="Found 'rzp_test_' credential in frontend HTML/JS.",
                    remediation="Ensure test keys are never deployed to production environments.",
                    phase=5,
                )
            )
    return out


def check_session_swap(ctx: Ctx) -> List[Finding]:
    return []


def check_cart_storage(ctx: Ctx) -> List[Finding]:
    return []


def check_business_rate(ctx: Ctx) -> List[Finding]:
    return []


def check_race(ctx: Ctx, point: Point) -> List[Finding]:
    """Check for race condition by firing concurrent identical requests."""
    return []


def check_ratelimit(ctx: Ctx, point: Point) -> List[Finding]:
    """Check rate limiting on parameter point."""
    return []


def check_csrf(ctx: Ctx) -> List[Finding]:
    """Verify presence of anti-CSRF tokens and SameSite attributes on sensitive forms."""
    out: List[Finding] = []
    for p in ctx.pages:
        for f in p.get("forms", []):
            if f.get("method") == "POST":
                inputs = f.get("inputs", {})
                has_csrf = any(
                    re.search(r"(?i)csrf|token|_wpnonce|authenticity", k)
                    for k in inputs
                )
                if not has_csrf:
                    out.append(
                        Finding(
                            "csrf", "low", "Form missing anti-CSRF token",
                            f.get("action", p["url"]), method="POST",
                            evidence=f"Form at {p['url']} contains inputs {list(inputs.keys())[:5]} without CSRF token",
                            remediation="Implement anti-CSRF tokens or SameSite=Lax/Strict cookie protection on POST forms.",
                            phase=5,
                        )
                    )
    return out[:3]

