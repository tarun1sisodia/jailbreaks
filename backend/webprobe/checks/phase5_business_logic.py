"""
Phase 5: Business Logic & Payment Security checks.
"""

import json
import re
import socket
import ssl
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

from webprobe.checks.phase1_recon import clip
from webprobe.checks.phase2_auth import get_authed_client
from webprobe.core.http import rand_token
from webprobe.core.models import Ctx, Finding, Point


PRICE_PARAM_RE = re.compile(r"(?i)(price|amount|cost|total|fare|fee|discount|rate)")

# Require CONTEXT — not just any 5+ digit number
BOOKING_REF_CONTEXT_PATTERNS = [
    re.compile(
        r'"(?:booking_id|booking_ref|booking_reference|booking_number|'
        r'order_id|order_ref|reservation_id|reservation_ref|pnr|'
        r'confirmation_code|confirmation_id)"\s*:\s*"([A-Za-z0-9][A-Za-z0-9_\-]{3,40})"',
        re.I,
    ),
    re.compile(
        r"/(?:booking|bookings|reservation|reservations|order|orders|"
        r"confirmation|invoice)/([A-Z0-9][A-Z0-9_\-]{3,40})(?:[/?#]|$)",
        re.I,
    ),
    re.compile(
        r"(?:booking|reservation|order)[\s_]?(?:id|ref|no|number)\s*[:=]\s*"
        r"[\"']?([A-Z0-9][A-Z0-9_\-]{3,40})[\"']?",
        re.I,
    ),
]

WEBHOOK_PATHS = [
    "/api/razorpay/webhook", "/razorpay/webhook", "/api/webhooks/razorpay",
    "/webhook", "/api/webhook", "/webhook/payment", "/api/payment/webhook",
]


def check_price(ctx: Ctx, point: Point) -> List[Finding]:
    if not PRICE_PARAM_RE.search(point.param):
        return []
    out: List[Finding] = []
    tamper_values = ["-10.00", "0", "0.01", "1"]
    for val in tamper_values:
        r = point.send(ctx.http, val)
        if r and r.status < 400 and not re.search(
                r"(?i)(invalid|minimum|error|rejected|less than)", r.text[:2000]):
            out.append(Finding(
                "business", "critical",
                f"Price parameter accepted tampered value: {point.param}={val}",
                point.action, point.method, point.target, payload=val,
                evidence=f"HTTP {r.status} returned on price alteration to {val}",
                remediation="Validate price calculations strictly server-side using authoritative database pricing.",
                phase=5,
            ))
            break
    return out


def check_discount_stacking(ctx: Ctx, point: Point) -> List[Finding]:
    if not any(k in point.param.lower() for k in ("coupon", "promo", "discount", "code")):
        return []
    stacked_payloads = [
        f"{point.orig_value},{point.orig_value}",
        f"{point.orig_value} {point.orig_value}",
    ]
    for p in stacked_payloads:
        r = point.send(ctx.http, p)
        if r and r.status < 400 and ("applied" in r.text.lower() or "discount" in r.text.lower()):
            return [Finding(
                "business", "medium", "Potential discount stacking accepted",
                point.action, point.method, point.target, payload=p,
                evidence=f"Stacked coupon codes returned HTTP {r.status}",
                remediation="Enforce limit of one coupon per order server-side.",
                phase=5,
            )]
    return []


def check_coupon_rules(ctx: Ctx) -> List[Finding]:
    expired = getattr(ctx.args, "expired_coupon", "")
    ineligible = getattr(ctx.args, "ineligible_coupon", "")
    if not (expired or ineligible):
        return []
    out: List[Finding] = []
    for p in ctx.endpoints:
        if "coupon" in p.lower() or "promo" in p.lower():
            u = urllib.parse.urljoin(ctx.base_url, p)
            if expired:
                r = ctx.http.fetch(u, "POST", urllib.parse.urlencode({"code": expired}), follow=True)
                if r and r.status == 200 and ("applied" in r.text.lower() or "discount" in r.text.lower()):
                    out.append(Finding(
                        "business", "high", f"Expired coupon '{expired}' accepted",
                        u, evidence="Expired promo returned successful application.",
                        remediation="Validate expiration date against server-side timestamp.",
                        phase=5,
                    ))
    return out


def check_coupon_enum(ctx: Ctx) -> List[Finding]:
    return []


def check_coupon_tamper(ctx: Ctx) -> List[Finding]:
    return []


def check_booking_ref(ctx: Ctx) -> List[Finding]:
    """Sequential/predictable booking refs.

    FIX: Require surrounding CONTEXT (JSON key, URL path, or explicit label).
    The old regex matched any 5-digit number, which fired on pincodes,
    phone numbers, and prices.
    """
    out: List[Finding] = []
    refs: List[Tuple[str, str]] = []  # (ref_value, source_url)

    for p in ctx.pages:
        html = p.get("html", "")
        for pattern in BOOKING_REF_CONTEXT_PATTERNS:
            for m in pattern.finditer(html):
                refs.append((m.group(1), p["url"]))

    refs = list(dict.fromkeys(refs))
    if len(refs) < 2:
        return out

    # Purely numeric refs with sequential pattern
    numeric = [(r, u) for r, u in refs if r.isdigit()]
    if len(numeric) >= 2:
        ints = sorted(int(r) for r, _ in numeric[:10])
        gaps = [b - a for a, b in zip(ints, ints[1:])]
        if gaps and max(gaps) <= 10 and all(g > 0 for g in gaps):
            out.append(Finding(
                "business", "medium", "Sequential numeric booking references",
                numeric[0][1],
                evidence=f"Sequential refs observed: {ints[:5]}",
                remediation="Use random identifiers (UUIDv4 or nanoid) — not sequential integers.",
                phase=5,
            ))
            return out

    # Low-entropy refs
    for ref, url in refs:
        if len(ref) >= 6:
            from collections import Counter
            import math
            counts = Counter(ref)
            n = len(ref)
            entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
            if entropy < 3.0:
                out.append(Finding(
                    "business", "low",
                    "Low-entropy booking reference",
                    url,
                    evidence=f"Reference {ref!r} — {entropy:.2f} bits/char",
                    remediation="Use ≥128 bits of entropy for booking references.",
                    phase=5,
                ))
                break

    return out


def check_duplicate_submit(ctx: Ctx) -> List[Finding]:
    return []


def check_callback_security(ctx: Ctx) -> List[Finding]:
    return []


def check_idempotency(ctx: Ctx) -> List[Finding]:
    if not getattr(ctx.args, "idempotency_test", False):
        return []
    return []


def check_webhook(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    targets = list(WEBHOOK_PATHS)
    custom = getattr(ctx.args, "webhook_url", "")
    if custom:
        targets.insert(0, custom)

    fake_payload = json.dumps({
        "entity": "event",
        "event": "payment.captured",
        "payload": {"payment": {"entity": {
            "id": "pay_fake" + rand_token("", 8),
            "amount": 50000, "currency": "INR", "status": "captured",
        }}},
    })

    for p in targets[:4]:
        u = urllib.parse.urljoin(ctx.base_url, p)
        r_unsigned = ctx.http.fetch(
            u, "POST", fake_payload,
            headers={"Content-Type": "application/json"}, follow=False,
        )
        if r_unsigned and r_unsigned.status in (200, 204):
            out.append(Finding(
                "business", "critical",
                f"Webhook accepted unauthenticated without signature: {p}",
                u, method="POST",
                evidence=f"Unsigned payload returned HTTP {r_unsigned.status}",
                remediation="Enforce HMAC SHA256 signature verification before processing webhook events.",
                phase=5,
            ))
            continue

        r_forged = ctx.http.fetch(
            u, "POST", fake_payload,
            headers={
                "Content-Type": "application/json",
                "X-Razorpay-Signature": "invalid_forged_hmac_hex",
            }, follow=False,
        )
        if r_forged and r_forged.status in (200, 204):
            out.append(Finding(
                "business", "critical",
                f"Webhook accepted forged signature: {p}",
                u, method="POST",
                evidence=f"Forged signature returned HTTP {r_forged.status}",
                remediation="Reject invalid webhook signatures with HTTP 400 or 401.",
                phase=5,
            ))
    return out


def check_test_live_keys(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    for p in ctx.pages:
        html = p.get("html", "")
        if re.search(r"rzp_live_[0-9A-Za-z]{10,}", html):
            out.append(Finding(
                "business", "critical",
                "Razorpay LIVE key ('rzp_live_...') exposed in client code",
                p["url"],
                evidence="Found 'rzp_live_' prefix — production key leaked to frontend",
                remediation="Rotate the key immediately; move to server-side only.",
                phase=5,
            ))
        if "rzp_test_" in html:
            out.append(Finding(
                "business", "info",
                "Razorpay test key ('rzp_test_...') referenced in client code",
                p["url"],
                evidence="Found 'rzp_test_' credential in frontend HTML/JS.",
                remediation="Ensure test keys are never deployed to production environments.",
                phase=5,
            ))
    return out


def check_session_swap(ctx: Ctx) -> List[Finding]:
    return []


def check_cart_storage(ctx: Ctx) -> List[Finding]:
    return []


def check_business_rate(ctx: Ctx) -> List[Finding]:
    return []


def check_race(ctx: Ctx) -> List[Finding]:
    """Race condition test via last-byte synchronization.

    Requires --race-url, --race-data (optional), --race-count, --race-expect.
    Sends N identical POSTs whose final byte is released simultaneously.
    If the number of successful responses exceeds --race-expect, a race is
    confirmed (e.g. coupon redemption, inventory decrement, booking slot).
    """
    race_url = getattr(ctx.args, "race_url", "")
    if not race_url:
        return []

    race_data = getattr(ctx.args, "race_data", "")
    race_count = getattr(ctx.args, "race_count", 20)
    race_expect = getattr(ctx.args, "race_expect", None)

    sp = urllib.parse.urlsplit(race_url)
    if sp.scheme not in ("http", "https") or not sp.hostname:
        return []

    is_https = sp.scheme == "https"
    port = sp.port or (443 if is_https else 80)
    path = sp.path or "/"
    if sp.query:
        path += "?" + sp.query

    body = race_data.encode("utf-8") if race_data else b""
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {sp.hostname}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
    )
    # Include auth cookie if provided
    cookie = getattr(ctx.args, "cookie", "")
    if cookie:
        headers += f"Cookie: {cookie}\r\n"
    headers += "\r\n"
    full_request = headers.encode() + body

    def _make_socket():
        if is_https:
            sctx = ssl.create_default_context()
            if ctx.args.insecure:
                sctx.check_hostname = False
                sctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((sp.hostname, port), timeout=10)
            return sctx.wrap_socket(sock, server_hostname=sp.hostname)
        return socket.create_connection((sp.hostname, port), timeout=10)

    socks = []
    responses = []

    try:
        # Phase 1: connect + send all-but-last-byte
        for _ in range(race_count):
            try:
                s = _make_socket()
                s.sendall(full_request[:-1])
                socks.append((s, full_request[-1:]))
            except Exception:
                pass

        if len(socks) < 2:
            return []

        # Phase 2: release last byte in a tight loop
        for s, last in socks:
            try:
                s.sendall(last)
            except Exception:
                pass

        # Phase 3: read responses
        for s, _ in socks:
            try:
                s.settimeout(10)
                data = b""
                while True:
                    try:
                        chunk = s.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    data += chunk
                responses.append(data)
            except Exception:
                responses.append(b"")

        # Parse status codes
        statuses = []
        for resp in responses:
            m = re.match(rb"HTTP/\d\.\d (\d{3})", resp)
            statuses.append(int(m.group(1)) if m else 0)

        successes = sum(1 for s in statuses if 200 <= s < 300)

        if race_expect is not None and successes > race_expect:
            return [Finding(
                "race", "high",
                f"Race condition: {successes} successes exceeded expected {race_expect}",
                race_url, method="POST",
                payload=f"{race_count} concurrent requests via last-byte sync",
                evidence=f"successes={successes}/{race_count}, "
                         f"statuses={sorted(set(statuses))}",
                remediation="Serialize check-and-act with a database lock or atomic "
                            "conditional update; make the operation idempotent.",
                phase=5,
            )]
        return [Finding(
            "race", "info",
            f"Race probe executed ({successes}/{race_count} successes)",
            race_url, method="POST",
            payload=f"{race_count} concurrent requests",
            evidence=f"statuses={sorted(set(statuses))} — "
                     f"review manually against business expectations",
            remediation="Set --race-expect to the expected success count to enable "
                        "automatic flagging.",
            phase=5,
        )]
    finally:
        for s, _ in socks:
            try:
                s.close()
            except Exception:
                pass


def check_ratelimit(ctx: Ctx) -> List[Finding]:
    return []


def check_csrf(ctx: Ctx) -> List[Finding]:
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
                    out.append(Finding(
                        "csrf", "low", "Form missing anti-CSRF token",
                        f.get("action", p["url"]), method="POST",
                        evidence=f"Form at {p['url']} contains inputs "
                                 f"{list(inputs.keys())[:5]} without CSRF token",
                        remediation="Implement anti-CSRF tokens or SameSite=Lax/Strict "
                                    "cookie protection on POST forms.",
                        phase=5,
                    ))
    return out[:3]


# ============ NEW: FSM workflow enforcer ============
def check_fsm_workflow(ctx: Ctx) -> List[Finding]:
    """Detect workflow state-machine gaps by skipping intermediate steps."""
    if not getattr(ctx.args, "state_url", ""):
        return []

    steps = [s.strip() for s in
             getattr(ctx.args, "state_actions", "").split(",") if s.strip()]
    if not steps:
        return []

    customer = get_authed_client(ctx)
    if not customer:
        return []

    out: List[Finding] = []
    base = getattr(ctx.args, "state_url", "")

    precondition_url = getattr(ctx.args, "state_precondition", "")
    if precondition_url:
        customer.fetch(precondition_url, "POST", "{}",
                       headers={"Content-Type": "application/json"}, follow=False)

    # For each step, try calling it as the FIRST call (skipping prerequisites)
    for step in steps:
        url = f"{base.rstrip('/')}/{step}"
        for method in ("POST", "PATCH", "PUT"):
            r = customer.fetch(url, method,
                              json.dumps({"action": step}),
                              headers={"Content-Type": "application/json"},
                              follow=False)
            if r and r.status < 400:
                if not re.search(r"(?i)(invalid|state|transition|precondition|"
                                r"not allowed|must complete|previous)", r.text[:2000]):
                    out.append(Finding(
                        "business", "high",
                        f"Workflow step `{step}` accepted without prerequisites",
                        url, method=method,
                        evidence=f"HTTP {r.status} on direct call; "
                                 f"response: {clip(r.text, 180)}",
                        remediation="Model the workflow as an explicit FSM server-side; "
                                    "reject transitions whose precondition state "
                                    "is not met.",
                        confidence="medium", phase=5,
                    ))
                    break
    return out


# ============ NEW: numeric precision / overflow ============
def check_numeric_precision(ctx: Ctx, point: Point) -> List[Finding]:
    """Detect arithmetic precision, overflow, and negative-value flaws."""
    if not PRICE_PARAM_RE.search(point.param) and not re.search(
            r"(?i)(qty|quantity|amount|total|credits)", point.param):
        return []

    probes = [
        ("neg_zero", "-0.00"),
        ("float_overflow", "1e308"),
        ("int_overflow", "9223372036854775808"),
        ("tiny", "0.00000001"),
        ("fraction_split", "0.00001731"),  # prime-like; never a natural price
        ("negative", "-99999.37"),         # prime-like
    ]

    base = point.send(ctx.http, point.orig_value)
    base_text = base.text if base else ""

    for label, val in probes:
        r = point.send(ctx.http, val)
        if r is None:
            continue
        if r.status < 400 and val in r.text and val not in base_text:
            return [Finding(
                "business", "high",
                f"Numerical boundary accepted ({label}): {point.param}={val}",
                point.action, point.method, point.target, payload=val,
                evidence=f"Server accepted {val!r} (HTTP {r.status}) "
                         f"in a financial parameter",
                remediation="Validate numeric ranges with bounded decimals "
                            "(Decimal, not float); reject negatives for "
                            "non-refundable fields.",
                confidence="medium", phase=5,
            )]
    return []


# ============ NEW: idempotency nonce ============
def check_idempotency_nonce(ctx: Ctx) -> List[Finding]:
    """Missing Idempotency-Key handling on financial endpoints."""
    if not getattr(ctx.args, "idempotency_test", False):
        return []

    customer = get_authed_client(ctx)
    if not customer:
        return []

    candidates = [u for u in ctx.discovered
                  if re.search(r"(?i)(/payment|/charge|/order|/booking|/refund)", u)][:5]

    if not candidates:
        return []

    out: List[Finding] = []
    for url in candidates:
        full = url if url.startswith("http") else urllib.parse.urljoin(ctx.base_url, url)
        body = json.dumps({"amount": 100, "currency": "INR"})
        idem_key = "wp-idem-" + rand_token("", 12)

        r1 = customer.fetch(full, "POST", body,
                           headers={"Content-Type": "application/json",
                                    "Idempotency-Key": idem_key},
                           follow=True)
        r2 = customer.fetch(full, "POST", body,
                           headers={"Content-Type": "application/json",
                                    "Idempotency-Key": idem_key},
                           follow=True)
        if r1 is None or r2 is None:
            continue

        id_re = re.compile(r'"(?:id|charge_id|order_id|transaction_id)"\s*:\s*"([^"]+)"')
        ids = set()
        for r in (r1, r2):
            for m in id_re.finditer(r.text):
                ids.add(m.group(1))

        if len(ids) >= 2:
            out.append(Finding(
                "idempotency", "high",
                "Idempotency-Key ignored on financial endpoint",
                full, method="POST",
                evidence=f"Two POSTs with same `Idempotency-Key: {idem_key}` "
                         f"created distinct IDs: {list(ids)[:3]}",
                remediation="Store idempotency keys with a unique constraint; "
                            "return the original result on retry.",
                confidence="medium", phase=5,
            ))
    return out
