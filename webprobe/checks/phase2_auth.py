"""
Phase 2: Authentication & Session Management checks.
"""

import base64
import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from webprobe.core.crawler import parse_page
from webprobe.core.http import HttpClient, rand_token
from webprobe.core.models import Ctx, Finding


WEAK_PASSWORDS = [
    "123456", "password", "abc123", "12345678", "qwerty",
    "111111", "letmein", "welcome", "admin", "1q2w3e",
]

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "123456"), ("admin", "letmein"), ("administrator", "admin"),
    ("administrator", "password"), ("root", "root"), ("root", "toor"),
    ("test", "test"), ("test", "test123"),
]

LOGIN_USER_RE = re.compile(r"(?i)(user|email|login|identifier|uname|username)")
LOGIN_PASS_RE = re.compile(r"(?i)(pass|pwd|password|passwd)")
CSRF_FIELD_RE = re.compile(r"(?i)token|csrf|nonce|authenticity|_wpnonce")

RESET_URL_RE = re.compile(r"(?i)(forgot|reset|recover|password-reset)")
RESET_TOKEN_RE = re.compile(r"(?i)[?&](?:token|t|code|key)=([A-Za-z0-9_\-]{16,})")

SESSION_COOKIE_RE = re.compile(
    r"(?i)(sess|sid|auth|jwt|remember|token|^jsessionid$|"
    r"^phpsessid$|^laravel_session$|^_rails_session$|"
    r"^asp\.net_sessionid$|^connect\.sid$)"
)

PII_CLAIMS = [
    "email", "phone", "ssn", "address", "dob", "birth", "given_name",
    "family_name", "credit", "card", "passport", "national_id",
    "tax_id", "iban", "account", "salary",
]

ADMIN_PATHS_P2 = [
    "/admin", "/admin/dashboard", "/admin/users", "/admin/settings",
    "/admin/operations", "/staff", "/manage", "/dashboard",
    "/api/admin", "/api/v1/admin", "/api/admin/users",
    "/admin/operations/tax.php",
    "/api/v1/ops/admin/bookings", "/api/v1/ops/admin/audit-logs",
]

MFA_URL_RE = re.compile(
    r"(?i)(/mfa|/2fa|/otp|/verify|/challenge|/two-factor|/second-factor|/auth/code)"
)
MFA_FIELD_RE = re.compile(
    r"(?i)^(otp|code|totp|mfa|2fa|auth.?code|verification.?code|token|digit)$"
)


def decode_jwt(token: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Decode a JWT header and payload without verifying signature."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        def b64_decode(s: str) -> Any:
            rem = len(s) % 4
            if rem > 0:
                s += "=" * (4 - rem)
            return json.loads(base64.urlsafe_b64decode(s.encode()).decode("utf-8", errors="replace"))

        header = b64_decode(parts[0])
        payload = b64_decode(parts[1])
        return header, payload
    except Exception:
        return None


def find_login_form(ctx: Ctx) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    if ctx.login_form is not None:
        return ctx.login_page_url, ctx.login_form
    for page in ctx.pages:
        for f in page.get("forms", []):
            if f.get("method") != "POST":
                continue
            fields = f.get("inputs", {})
            if any(LOGIN_USER_RE.search(k) for k in fields) and any(LOGIN_PASS_RE.search(k) for k in fields):
                ctx.login_page_url = page["url"]
                ctx.login_form = f
                return page["url"], f
    return None, None


def _fill_login(f: Dict[str, Any], email: str, password: str) -> Dict[str, str]:
    data = dict(f.get("inputs", {}))
    for k in data:
        if LOGIN_USER_RE.search(k):
            data[k] = email
        elif LOGIN_PASS_RE.search(k):
            data[k] = password
    return data


def _refresh_csrf(client: HttpClient, page_url: str, f: Dict[str, Any], params: Dict[str, str]) -> Dict[str, str]:
    csrf_fields = [k for k in f.get("inputs", {}) if CSRF_FIELD_RE.search(k)]
    if not csrf_fields:
        return params
    r = client.fetch(page_url, follow=True)
    if not r:
        return params
    try:
        _, forms, _ = parse_page(r.text, r.url)
    except Exception:
        return params
    for fresh_f in forms:
        if fresh_f.get("action") == f.get("action"):
            for cf in csrf_fields:
                if cf in fresh_f.get("inputs", {}):
                    params[cf] = fresh_f["inputs"][cf]
            break
    return params


def auto_login_into(client: HttpClient, ctx: Ctx, email: str, password: str) -> bool:
    page_url, f = find_login_form(ctx)
    if not f or not page_url:
        return False
    data = _fill_login(f, email, password)
    data = _refresh_csrf(client, page_url, f, data)
    r = client.fetch(f["action"], "POST", urllib.parse.urlencode(data), follow=True)
    if not r:
        return False
    return r.status in (200, 302) and not re.search(r"(?i)(invalid|incorrect|wrong|failed|denied)", r.text[:2000])


def get_authed_client(ctx: Ctx) -> Optional[HttpClient]:
    if ctx.authed_client is not None:
        return ctx.authed_client
    cookie = getattr(ctx.args, "cookie", "")
    if cookie:
        ctx.authed_client = ctx.http.clone(cookie=cookie)
        return ctx.authed_client
    email = getattr(ctx.args, "test_email", "")
    password = getattr(ctx.args, "test_password", "")
    if email and password:
        c = ctx.http.clone(cookie="")
        if auto_login_into(c, ctx, email, password):
            ctx.authed_client = c
            return c
    return None


def _login_and_classify(ctx: Ctx) -> Tuple[Optional[HttpClient], str]:
    page_url, f = find_login_form(ctx)
    if not f or not page_url:
        return None, "no_form"
    email = getattr(ctx.args, "test_email", "")
    password = getattr(ctx.args, "test_password", "")
    if not (email and password):
        return None, "no_creds"
    c = ctx.http.clone(cookie="")
    params = _fill_login(f, email, password)
    params = _refresh_csrf(c, page_url, f, params)
    r = c.fetch(f["action"], "POST", urllib.parse.urlencode(params), follow=True)
    if r is None:
        return None, "failed"
    if MFA_URL_RE.search(r.url) or MFA_URL_RE.search(r.header("Location")):
        return c, "mfa"
    try:
        _, forms, _ = parse_page(r.text, r.url)
    except Exception:
        forms = []
    for form in forms:
        if any(MFA_FIELD_RE.match(k) for k in form.get("inputs", {})):
            return c, "mfa"
    if r.status >= 400:
        return c, "failed"
    if re.search(r"(?i)(invalid|incorrect|wrong|failed|denied)", r.text[:3000]):
        return c, "rejected"
    return c, "authed"


def _find_reset_form(ctx: Ctx) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    for page in ctx.pages:
        for f in page.get("forms", []):
            if f.get("method") != "POST":
                continue
            action = f.get("action", "")
            if RESET_URL_RE.search(action) or any(RESET_URL_RE.search(k) for k in f.get("inputs", {})):
                return page["url"], f
    return None, None


def _find_supabase_anon_key(pages: List[Dict[str, Any]]) -> Optional[str]:
    for page in pages:
        for m in re.finditer(
            r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
            page.get("html", ""),
        ):
            dec = decode_jwt(m.group(0))
            if dec and dec[1].get("role") == "anon":
                return m.group(0)
    return None


def _supabase_login(sb_host: str, anon_key: str, email: str, password: str) -> Optional[str]:
    probe = HttpClient()
    r = probe.fetch(
        sb_host.rstrip("/") + "/auth/v1/token?grant_type=password",
        "POST",
        json.dumps({"email": email, "password": password}),
        headers={"apikey": anon_key, "Content-Type": "application/json"},
    )
    if r is None or r.status != 200:
        return None
    try:
        return json.loads(r.text).get("access_token")
    except Exception:
        return None


def check_password_policy(ctx: Ctx) -> List[Finding]:
    if not getattr(ctx.args, "password_policy_test", False):
        return []
    out: List[Finding] = []
    page_url, f = find_login_form(ctx)
    if not f or not page_url:
        return []
    accepted = []
    for pwd in WEAK_PASSWORDS[:4]:
        fresh = ctx.http.clone(cookie="")
        params = _fill_login(f, f"wp-weak-{rand_token('', 6)}@example.com", pwd)
        params = _refresh_csrf(fresh, page_url, f, params)
        r = fresh.fetch(f["action"], "POST", urllib.parse.urlencode(params), follow=True)
        if r and r.status < 400 and not re.search(r"(?i)(complexity|length|character|weak|policy)", r.text[:2000]):
            accepted.append(pwd)
    if accepted:
        out.append(
            Finding(
                "auth", "medium", "Weak passwords accepted by login/registration form",
                f["action"], evidence=f"Accepted weak candidates: {', '.join(accepted)}",
                remediation="Enforce minimum length of 12+ characters and block common breached password lists.",
                phase=2,
            )
        )
    return out


def check_enumeration(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    page_url, f = find_login_form(ctx)
    if not f or not page_url:
        return []
    fresh = ctx.http.clone(cookie="")
    known = getattr(ctx.args, "test_email", "admin@example.com")
    fake = f"nonexistent_{rand_token('', 10)}@example.invalid"

    p1 = _fill_login(f, known, "WrongPasswordProbe123!")
    p1 = _refresh_csrf(fresh, page_url, f, p1)
    r1 = fresh.fetch(f["action"], "POST", urllib.parse.urlencode(p1), follow=True)

    p2 = _fill_login(f, fake, "WrongPasswordProbe123!")
    p2 = _refresh_csrf(fresh, page_url, f, p2)
    r2 = fresh.fetch(f["action"], "POST", urllib.parse.urlencode(p2), follow=True)

    if r1 and r2 and (r1.status != r2.status or abs(len(r1.body) - len(r2.body)) > 150):
        out.append(
            Finding(
                "auth", "low", "Username/email enumeration via login response disparity",
                f["action"], evidence=f"Status known: {r1.status} ({len(r1.body)}B), fake: {r2.status} ({len(r2.body)}B)",
                remediation="Return identical error messages and uniform response timing for valid and invalid accounts.",
                phase=2,
            )
        )
    return out


def check_bruteforce(ctx: Ctx) -> List[Finding]:
    if not getattr(ctx.args, "rate_test", False):
        return []
    out: List[Finding] = []
    page_url, f = find_login_form(ctx)
    if not f or not page_url:
        return []
    fresh = ctx.http.clone(cookie="")
    statuses = []
    rate_count = getattr(ctx.args, "rate_count", 6)
    for i in range(rate_count):
        params = _fill_login(f, f"probe_{i}@example.invalid", "WrongPassword123!")
        params = _refresh_csrf(fresh, page_url, f, params)
        r = fresh.fetch(f["action"], "POST", urllib.parse.urlencode(params), follow=True)
        if r:
            statuses.append(r.status)
    if 429 not in statuses and not any(s in (403, 401) and statuses.count(s) > 3 for s in set(statuses)):
        out.append(
            Finding(
                "auth", "medium", "No account lockout or rate limiting detected on login form",
                f["action"], evidence=f"Sent {rate_count} login attempts without HTTP 429 or lockout.",
                remediation="Implement IP rate limiting and progressive delays/lockouts on authentication endpoints.",
                phase=2,
            )
        )
    return out


def check_default_creds(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    page_url, f = find_login_form(ctx)
    if not f or not page_url or not getattr(ctx.args, "admin_login", False):
        return []
    for user, pwd in DEFAULT_CREDS[:4]:
        fresh = ctx.http.clone(cookie="")
        params = _fill_login(f, user, pwd)
        params = _refresh_csrf(fresh, page_url, f, params)
        r = fresh.fetch(f["action"], "POST", urllib.parse.urlencode(params), follow=True)
        if r and r.status < 400 and not re.search(r"(?i)(invalid|incorrect|failed|wrong)", r.text[:2000]):
            out.append(
                Finding(
                    "auth", "critical", f"Default credentials accepted: {user}:{pwd}",
                    f["action"], evidence=f"Logged in successfully using {user}:{pwd}",
                    remediation="Disable default administrative credentials immediately; enforce forced password change.",
                    phase=2,
                )
            )
            break
    return out


def check_reset_token(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    for page in ctx.pages:
        for m in RESET_TOKEN_RE.finditer(page.get("html", "")):
            token = m.group(1)
            out.append(
                Finding(
                    "auth", "high", "Password reset token leaked in page content/links",
                    page["url"], evidence=f"Found reset token: {token[:8]}... in HTML",
                    remediation="Never expose password reset tokens in referrer headers or publicly crawled responses.",
                    phase=2,
                )
            )
    return out


def check_host_header_reset(ctx: Ctx) -> List[Finding]:
    page_url, f = _find_reset_form(ctx)
    if not f or not page_url:
        return []
    out: List[Finding] = []
    fake_host = "attacker.example.com"
    r = ctx.http.fetch(f["action"], "POST", urllib.parse.urlencode(f.get("inputs", {})), headers={"Host": fake_host}, follow=False)
    if r and fake_host in r.text:
        out.append(
            Finding(
                "auth", "high", "Host header injection in password reset flow",
                f["action"], evidence=f"Injected host {fake_host} was reflected in response body/headers.",
                remediation="Use a locked server-side hostname setting rather than trusting the incoming Host header.",
                phase=2,
            )
        )
    return out


def check_session_fixation(ctx: Ctx) -> List[Finding]:
    page_url, f = find_login_form(ctx)
    if not f or not page_url:
        return []
    email = getattr(ctx.args, "test_email", "")
    password = getattr(ctx.args, "test_password", "")
    if not (email and password):
        return []
    out: List[Finding] = []
    fresh = ctx.http.clone(cookie="")
    # Visit page to obtain initial session cookie
    r_pre = fresh.fetch(page_url, follow=True)
    pre_cookies = dict(fresh.cookies)
    params = _fill_login(f, email, password)
    params = _refresh_csrf(fresh, page_url, f, params)
    r_post = fresh.fetch(f["action"], "POST", urllib.parse.urlencode(params), follow=True)
    post_cookies = dict(fresh.cookies)
    for k, v in pre_cookies.items():
        if SESSION_COOKIE_RE.search(k) and post_cookies.get(k) == v:
            out.append(
                Finding(
                    "session", "medium", f"Session cookie '{k}' unchanged across login (Session Fixation)",
                    f["action"], evidence=f"Cookie {k} preserved pre- and post-authentication.",
                    remediation="Always regenerate and issue a new session token upon successful authentication.",
                    phase=2,
                )
            )
    return out


def check_logout_invalidation(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    client = get_authed_client(ctx)
    if not client:
        return []
    logout_urls = [u for u in ctx.discovered if re.search(r"(?i)(/logout|/signout)", u)]
    if not logout_urls:
        return []
    target_logout = logout_urls[0]
    r_out = client.fetch(target_logout, follow=True)
    # Check if previously accessible authed resource still returns 200
    r_check = client.fetch(ctx.base_url, follow=True)
    if r_check and re.search(r"(?i)(welcome|profile|account|dashboard|logout)", r_check.text[:2000]):
        out.append(
            Finding(
                "session", "high", "Session remains active after logout endpoint requested",
                target_logout, evidence="Protected content still visible after invoking logout.",
                remediation="Server-side session store must destroy session keys on logout.",
                phase=2,
            )
        )
    return out


def check_concurrent_sessions(ctx: Ctx) -> List[Finding]:
    # Placeholder for concurrent session policy audit
    return []


def check_remember_me(ctx: Ctx) -> List[Finding]:
    page_url, f = find_login_form(ctx)
    if not f or not page_url:
        return []
    out: List[Finding] = []
    rem_fields = [k for k in f.get("inputs", {}) if re.search(r"(?i)remember", k)]
    if rem_fields:
        out.append(
            Finding(
                "auth", "info", f"Remember-me functionality present on login form ({rem_fields[0]})",
                page_url, evidence=f"Field: {rem_fields[0]}",
                remediation="Ensure remember-me tokens use crypto-random identifiers and expire safely.",
                phase=2,
            )
        )
    return out


def check_token_in_url(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    token_url_re = re.compile(r"(?i)[?&](?:access_token|bearer|jwt|token|sid|session_id)=([A-Za-z0-9_\-\.]{10,})")
    for u in ctx.discovered:
        m = token_url_re.search(u)
        if m:
            out.append(
                Finding(
                    "session", "medium", "Authentication token or session ID transmitted in URL",
                    u, evidence=f"URL contains sensitive token parameter: {m.group(0)[:30]}...",
                    remediation="Pass tokens via Authorization headers or HttpOnly cookies to avoid browser history and access log leakage.",
                    phase=2,
                )
            )
    return out


def check_cache_controls(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    authed = get_authed_client(ctx)
    if not authed:
        return []
    r = authed.fetch(ctx.base_url, follow=True)
    if r:
        cc = r.header("Cache-Control").lower()
        if not ("no-store" in cc or "private" in cc):
            out.append(
                Finding(
                    "session", "low", "Authenticated response missing Cache-Control: no-store",
                    r.url, evidence=f"Cache-Control: {r.header('Cache-Control') or 'unset'}",
                    remediation="Set 'Cache-Control: no-store, private' on all authenticated pages.",
                    phase=2,
                )
            )
    return out


def check_jwt(ctx: Ctx) -> List[Finding]:
    """JWT security: decode + actually submit forged tokens to test enforcement."""
    import hashlib
    import hmac

    out: List[Finding] = []
    jwt_re = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")

    # Collect tokens from pages
    tokens_to_check: List[Tuple[str, str]] = []
    for p in ctx.pages:
        for m in jwt_re.finditer(p.get("html", "")):
            tokens_to_check.append((p["url"], m.group(0)))

    # Get baseline anon response for auth comparison
    anon = ctx.http.clone(cookie="").fetch(ctx.base_url, follow=True)
    anon_text = anon.text if anon else ""

    WEAK_SECRETS = [
        "secret", "secretkey", "secret_key", "jwt_secret", "jwtsecret",
        "supersecret", "password", "changeme", "test", "dev", "development",
        "your-256-bit-secret", "key", "private", "admin", "root", "123456",
    ]

    def _b64url_enc(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    def _b64url_dec(s: str) -> bytes:
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)

    def _jwt_accepted(name: str, forged: str) -> bool:
        """Submit forged token and check if accepted (similarity to anon < 0.9)."""
        test_client = ctx.http.clone(cookie=f"{name}={forged}")
        r = test_client.fetch(ctx.base_url, follow=True)
        if not r or r.status >= 400:
            return False
        from difflib import SequenceMatcher
        similarity_to_anon = SequenceMatcher(
            None, anon_text[:3000], r.text[:3000]
        ).ratio()
        return similarity_to_anon < 0.85  # Response meaningfully differs from anon

    for url, tok in tokens_to_check[:10]:
        parts = tok.split(".")
        if len(parts) != 3:
            continue

        try:
            hdr = json.loads(_b64url_dec(parts[0]))
            payload = json.loads(_b64url_dec(parts[1]))
        except Exception:
            continue

        alg = hdr.get("alg", "")
        cookie_name = "token"  # common fallback

        # 1. alg:none — actually submit
        if alg != "none":
            for none_variant in ("none", "None", "NONE"):
                hdr_none = dict(hdr)
                hdr_none["alg"] = none_variant
                header_b64 = _b64url_enc(
                    json.dumps(hdr_none, separators=(",", ":")).encode())
                payload_b64 = _b64url_enc(
                    json.dumps(payload, separators=(",", ":")).encode())
                forged = f"{header_b64}.{payload_b64}."
                if _jwt_accepted(cookie_name, forged):
                    out.append(Finding(
                        "jwt", "critical",
                        "JWT accepts 'alg:none' forged token (server-side enforcement missing)",
                        url,
                        evidence=f"Submitted {cookie_name}=<forged_none>; server "
                                 f"returned authenticated-content response",
                        remediation="Pin accepted algorithms server-side; explicitly "
                                    "reject 'none'.",
                        phase=2,
                    ))
                    break

        # 2. Weak HMAC secret — verify + submit
        if alg.startswith("HS"):
            signing_input = f"{parts[0]}.{parts[1]}"
            for secret in WEAK_SECRETS:
                hash_fn = {
                    "HS256": hashlib.sha256,
                    "HS384": hashlib.sha384,
                    "HS512": hashlib.sha512,
                }.get(alg, hashlib.sha256)
                expected_sig = hmac.new(
                    secret.encode(), signing_input.encode(), hash_fn).digest()
                expected_b64 = _b64url_enc(expected_sig)
                if hmac.compare_digest(expected_b64, parts[2]):
                    # Signature matches → secret is recoverable
                    out.append(Finding(
                        "jwt", "critical",
                        "JWT signed with guessable HMAC secret",
                        url,
                        evidence=f"Recovered secret: {secret!r} (verified via HMAC)",
                        remediation="Rotate to a random 256-bit secret from a secret "
                                    "manager.",
                        phase=2,
                    ))
                    break

        # 3. exp claim missing
        if "exp" not in payload:
            out.append(Finding(
                "jwt", "medium", "JWT token lacks expiration ('exp') claim",
                url,
                evidence=f"alg={alg}, claims={list(payload.keys())[:6]}",
                remediation="Always set short-lived 'exp' expiration on issued JWTs.",
                phase=2,
            ))

        # 4. PII in payload
        leaked = [c for c in PII_CLAIMS if c in payload]
        if leaked:
            out.append(Finding(
                "jwt", "low",
                f"JWT payload contains sensitive PII fields: {', '.join(leaked)}",
                url, evidence=f"Payload keys: {', '.join(leaked)}",
                remediation="Avoid storing sensitive PII in client-readable JWT payloads.",
                phase=2,
            ))

    return out


def check_jwt_expiry(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    jwt_re = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
    for p in ctx.pages:
        for m in jwt_re.finditer(p.get("html", "")):
            dec = decode_jwt(m.group(0))
            if dec:
                _, payload = dec
                if "exp" not in payload:
                    out.append(
                        Finding(
                            "jwt", "medium", "JWT token lacks expiration ('exp') claim",
                            p["url"], evidence="Decoded payload has no 'exp' claim.",
                            remediation="Always set short-lived 'exp' expiration on issued JWTs.",
                            phase=2,
                        )
                    )
    return out


def check_jwt_pii(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    jwt_re = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
    for p in ctx.pages:
        for m in jwt_re.finditer(p.get("html", "")):
            dec = decode_jwt(m.group(0))
            if dec:
                _, payload = dec
                leaked = [c for c in PII_CLAIMS if c in payload]
                if leaked:
                    out.append(
                        Finding(
                            "jwt", "low", f"JWT payload contains sensitive PII fields: {', '.join(leaked)}",
                            p["url"], evidence=f"Payload keys: {', '.join(leaked)}",
                            remediation="Avoid storing sensitive PII in client-readable unencrypted JWT payloads.",
                            phase=2,
                        )
                    )
    return out


def check_login_csrf(ctx: Ctx) -> List[Finding]:
    page_url, f = find_login_form(ctx)
    if not f or not page_url:
        return []
    email = getattr(ctx.args, "test_email", "")
    password = getattr(ctx.args, "test_password", "")
    if not (email and password):
        return []
    params = _fill_login(f, email, password)
    params = _refresh_csrf(ctx.http, page_url, f, params)
    forged = {
        "Origin": "https://wp-csrf-attacker.example",
        "Referer": "https://wp-csrf-attacker.example/",
    }
    fresh = ctx.http.clone(cookie="")
    resp = fresh.fetch(f["action"], "POST", urllib.parse.urlencode(params), headers=forged, follow=True)
    if resp and resp.status < 400 and not re.search(r"(?i)(csrf|forbidden|origin|rejected)", resp.text[:2000]):
        return [
            Finding(
                "auth", "medium", "Login form does not enforce Origin/Referer (Login CSRF risk)",
                f["action"], evidence="Login POST accepted with cross-origin Origin header.",
                remediation="Validate Origin and Referer headers on login POST requests.",
                phase=2,
            )
        ]
    return []


def check_logout_csrf(ctx: Ctx) -> List[Finding]:
    logout_urls = [u for u in ctx.discovered if re.search(r"(?i)(/logout|/signout)", u)]
    if not logout_urls:
        return []
    out: List[Finding] = []
    for u in logout_urls[:2]:
        r = ctx.http.fetch(u, "GET", headers={"Origin": "https://evil.example"}, follow=False)
        if r and r.status in (200, 302):
            out.append(
                Finding(
                    "auth", "low", "Logout action accessible via GET or lacks CSRF validation",
                    u, evidence=f"HTTP {r.status} on GET logout request.",
                    remediation="Require POST requests with valid anti-CSRF token for session termination.",
                    phase=2,
                )
            )
    return out


def check_auth_change_csrf(ctx: Ctx) -> List[Finding]:
    return []


def check_mfa_presence(ctx: Ctx) -> List[Finding]:
    client, outcome = _login_and_classify(ctx)
    if outcome == "mfa":
        return [
            Finding(
                "auth", "info", "MFA/2FA challenge prompt detected on login",
                ctx.base_url, evidence="Login redirects or prompts for multi-factor authentication code.",
                remediation="Ensure rate-limiting and lockout exist on MFA challenge submissions.",
                phase=2,
            )
        ]
    return []


def check_mfa_bypass(ctx: Ctx) -> List[Finding]:
    return []


def check_otp_bruteforce(ctx: Ctx) -> List[Finding]:
    return []


def check_supabase(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    sb_hosts = set()
    for url in ctx.discovered + ctx.endpoints:
        m = re.search(r"https?://([a-z0-9\-]+)\.supabase\.co", url)
        if m:
            sb_hosts.add(m.group(0))
    for host in list(sb_hosts)[:4]:
        probe = host.rstrip("/") + "/rest/v1/"
        r = ctx.http.fetch(probe, follow=True)
        if r and r.status == 200 and re.search(r"(?i)(\"paths\"|openapi|swagger)", r.text):
            out.append(
                Finding(
                    "supabase", "high", "Supabase REST API OpenAPI schema reachable unauthenticated",
                    probe, evidence="HTTP 200 with OpenAPI schema disclosure",
                    remediation="Require anon key at minimum; enforce strict Row Level Security (RLS) on all tables.",
                    phase=2,
                )
            )
    return out


def check_password_change(ctx: Ctx) -> List[Finding]:
    return []


def check_email_change(ctx: Ctx) -> List[Finding]:
    return []


def check_session(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    r = ctx.http.fetch(ctx.base_url, follow=True)
    if not r:
        return out
    cookies = r.header_all("Set-Cookie")
    for c in cookies:
        cookie_name = c.split("=")[0].strip()
        if SESSION_COOKIE_RE.search(cookie_name):
            missing_flags = []
            if "httponly" not in c.lower():
                missing_flags.append("HttpOnly")
            if "secure" not in c.lower():
                missing_flags.append("Secure")
            if "samesite" not in c.lower():
                missing_flags.append("SameSite")
            if missing_flags:
                out.append(
                    Finding(
                        "session", "medium", f"Session cookie '{cookie_name}' missing security flags",
                        r.url, evidence=f"Flags missing: {', '.join(missing_flags)}; Set-Cookie: {c[:80]}",
                        remediation="Set 'HttpOnly; Secure; SameSite=Lax' on all session cookies.",
                        phase=2,
                    )
                )
    return out

