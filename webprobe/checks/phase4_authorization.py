"""
Phase 4: Broken Access Control (Authorization) checks.
"""

import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from webprobe.checks.phase1_recon import clip
from webprobe.checks.phase2_auth import ADMIN_PATHS_P2, get_authed_client
from webprobe.core.crawler import parse_page
from webprobe.core.http import rand_token
from webprobe.core.models import Ctx, Finding, Point, RoleMatrix


ADMIN_PATHS_P4 = [
    "/admin", "/admin/dashboard", "/admin/users", "/admin/settings",
    "/admin/operations", "/staff", "/manage", "/dashboard",
    "/api/admin", "/api/v1/admin", "/api/admin/users",
    "/admin/operations/tax.php", "/api/staff", "/internal",
    "/api/v1/ops/admin/bookings", "/api/v1/ops/admin/audit-logs",
    "/api/v1/ops/admin/inquiries", "/api/v1/ops/admin/payments",
    "/api/v1/ops/admin/fare-rules", "/api/v1/ops/admin/refunds",
]

COUPON_FIELD_RE = re.compile(r"(?i)(coupon|promo|voucher|discount)")
ID_PARAM_RE = re.compile(r"(?i)^(id|user_id|account_id|booking_id|order_id|invoice_id)$")


def _id_resource_type(param: str, url: str) -> Optional[str]:
    combined = f"{param} {url}".lower()
    if "booking" in combined:
        return "booking"
    if "user" in combined or "profile" in combined:
        return "user"
    if "order" in combined or "invoice" in combined:
        return "order"
    if "payment" in combined:
        return "payment"
    if "coupon" in combined:
        return "coupon"
    return "resource"


def _authed_view_urls(ctx: Ctx, client: Any) -> List[str]:
    urls = [ctx.base_url]
    for p in ctx.pages:
        urls.append(p["url"])
    for u in ctx.discovered:
        if any(k in u.lower() for k in ("dashboard", "profile", "account", "booking", "order")):
            urls.append(u)
    return list(dict.fromkeys(urls))[:10]


def _harvest_resource_urls(ctx: Ctx, client: Any) -> List[Tuple[str, str, str]]:
    """Return [(url, param_name, current_val)]."""
    out: List[Tuple[str, str, str]] = []
    for u in ctx.discovered:
        sp = urllib.parse.urlsplit(u)
        qs = urllib.parse.parse_qs(sp.query)
        for k, v in qs.items():
            if ID_PARAM_RE.search(k) and v and v[0].isdigit():
                out.append((u, k, v[0]))
    return out[:10]


def _find_coupon_endpoint(ctx: Ctx) -> Optional[str]:
    for p in ctx.pages:
        for f in p.get("forms", []):
            if any(COUPON_FIELD_RE.search(k) for k in f.get("inputs", {})):
                return f.get("action")
    for u in ctx.discovered:
        if COUPON_FIELD_RE.search(u):
            return u
    return None


def check_coupon_authz(ctx: Ctx) -> List[Finding]:
    """A6 - coupon application authorization."""
    endpoint = _find_coupon_endpoint(ctx)
    if not endpoint:
        return []
    out: List[Finding] = []
    anon = ctx.http.clone(cookie="")
    coupon = getattr(ctx.args, "test_coupon", "DISCOUNT10")
    r = anon.fetch(endpoint, "POST", urllib.parse.urlencode({"code": coupon, "coupon": coupon}), follow=True)
    if r and r.status < 400 and ("discount" in r.text.lower() or "applied" in r.text.lower()):
        out.append(
            Finding(
                "authz", "low", "Coupon validation endpoint accessible unauthenticated",
                endpoint, evidence=f"Coupon probe accepted anonymously: HTTP {r.status}",
                remediation="Ensure coupon application checks account entitlement and usage limits.",
                phase=4,
            )
        )
    return out


def check_idor_resources(ctx: Ctx) -> List[Finding]:
    """A1-A5 - IDOR checks on resource URLs with secondary customer cookie."""
    customer1 = get_authed_client(ctx)
    sec_cookie = getattr(ctx.args, "secondary_cookie", "")
    if not (customer1 and sec_cookie):
        return []
    customer2 = ctx.http.clone(cookie=sec_cookie)
    out: List[Finding] = []
    items = _harvest_resource_urls(ctx, customer1)
    for url, param, val in items:
        rtype = _id_resource_type(param, url)
        # Try accessing user 1's resource as user 2
        r2 = customer2.fetch(url, follow=True)
        if r2 and r2.status == 200 and len(r2.body) > 100:
            out.append(
                Finding(
                    "idor", "high", f"IDOR on {rtype} endpoint: cross-tenant access granted",
                    url, param=param,
                    evidence=f"Customer 2 successfully accessed Customer 1's {param}={val}",
                    remediation="Verify object ownership server-side on every resource retrieval.",
                    phase=4,
                )
            )
    return out


def check_authz_customer(ctx: Ctx) -> List[Finding]:
    """B1-B3 - customer accessing administrative panels."""
    customer = get_authed_client(ctx)
    if not customer:
        return []
    out: List[Finding] = []
    for path in ADMIN_PATHS_P4:
        url = urllib.parse.urljoin(ctx.base_url, path)
        r = customer.fetch(url, follow=True)
        if r and r.status == 200:
            if not re.search(r"(?i)(login|sign in|unauthorized|forbidden|denied)", r.text[:2000]):
                out.append(
                    Finding(
                        "authz", "critical", f"Vertical privilege escalation: admin panel reachable as customer: {path}",
                        url, evidence=f"HTTP 200 returned for authenticated customer: {clip(r.text, 120)}",
                        remediation="Enforce strict role-based access control (RBAC) on all administrative routes.",
                        phase=4,
                    )
                )
    return out


def check_ui_only_bypass(ctx: Ctx) -> List[Finding]:
    """Verify backend enforces authorization for API routes hidden from UI."""
    customer = get_authed_client(ctx)
    if not customer:
        return []
    out: List[Finding] = []
    hidden_api_candidates = [
        "/api/admin/config", "/api/v1/users", "/api/admin/roles",
        "/api/reports", "/api/v1/export", "/api/admin/export",
    ]
    for p in hidden_api_candidates:
        u = urllib.parse.urljoin(ctx.base_url, p)
        r = customer.fetch(u, follow=True)
        if r and r.status == 200:
            out.append(
                Finding(
                    "authz", "high", f"UI-only protection bypass: API endpoint reachable: {p}",
                    u, evidence=f"Direct HTTP call to hidden API returned 200: {clip(r.text, 120)}",
                    remediation="Enforce role checks on the backend API, not only in client UI components.",
                    phase=4,
                )
            )
    return out


def check_role_tampering(ctx: Ctx) -> List[Finding]:
    """B6 - attempt role elevation via user profile update."""
    customer = get_authed_client(ctx)
    if not customer:
        return []
    out: List[Finding] = []
    profile_forms = []
    for p in ctx.pages:
        for f in p.get("forms", []):
            if f.get("method") == "POST" and any("profile" in f.get("action", "").lower() or "user" in f.get("action", "").lower() for _ in [1]):
                profile_forms.append((p["url"], f))
    for purl, f in profile_forms[:2]:
        forged = dict(f.get("inputs", {}))
        forged["role"] = "admin"
        forged["is_admin"] = "true"
        r = customer.fetch(f["action"], "POST", urllib.parse.urlencode(forged), follow=True)
        if r and r.status < 400 and ("admin" in r.text or "updated" in r.text.lower()):
            out.append(
                Finding(
                    "authz", "high", "Role tampering accepted in profile update",
                    f["action"], method="POST",
                    evidence="Server accepted role elevation parameter.",
                    remediation="Never allow users to assign or modify their own role/permissions.",
                    phase=4,
                )
            )
    return out


def check_payment_tampering(ctx: Ctx, point: Point) -> List[Finding]:
    """Test modification of price, currency, or order amount."""
    if not any(k in point.param.lower() for k in ("price", "amount", "total", "cost")):
        return []
    r = point.send(ctx.http, "0.01")
    if r and r.status < 400 and not re.search(r"(?i)(invalid|rejected|error|minimum)", r.text[:2000]):
        return [
            Finding(
                "business", "critical", f"Price/amount tampering accepted: {point.param}=0.01",
                point.action, point.method, point.target, payload="0.01",
                evidence="Reduced price accepted without server-side validation error.",
                remediation="Recalculate order prices server-side from authoritative product database.",
                phase=4,
            )
        ]
    return []


def check_workflow_bypass(ctx: Ctx) -> List[Finding]:
    return []


def check_state_transitions(ctx: Ctx) -> List[Finding]:
    state_url = getattr(ctx.args, "state_url", "")
    actions = getattr(ctx.args, "state_actions", "")
    if not state_url or not actions:
        return []
    out: List[Finding] = []
    customer = get_authed_client(ctx)
    client = customer if customer else ctx.http
    for act in actions.split(","):
        act = act.strip()
        if not act:
            continue
        u = f"{state_url.rstrip('/')}/{act}"
        r = client.fetch(u, "POST", data={}, follow=True)
        if r and r.status < 400:
            out.append(
                Finding(
                    "business", "high", f"State transition forced: {act}",
                    u, method="POST", evidence=f"State action '{act}' returned HTTP {r.status}",
                    remediation="Validate business state machines and permissions before allowing state transitions.",
                    phase=4,
                )
            )
    return out


def check_refund_authz(ctx: Ctx) -> List[Finding]:
    refund_url = getattr(ctx.args, "refund_url", "")
    if not refund_url:
        return []
    customer = get_authed_client(ctx)
    if not customer:
        return []
    r = customer.fetch(refund_url, "POST", data={}, follow=True)
    if r and r.status < 400 and not re.search(r"(?i)(forbidden|unauthorized|denied)", r.text[:2000]):
        return [
            Finding(
                "authz", "critical", "Customer can invoke administrative refund endpoint",
                refund_url, method="POST",
                evidence=f"HTTP {r.status} on refund action as non-staff user",
                remediation="Restrict refund capabilities to authorized staff/admin roles.",
                phase=4,
            )
        ]
    return []


def check_tenant_boundary(ctx: Ctx) -> List[Finding]:
    return []


def check_missing_auth(ctx: Ctx) -> List[Finding]:
    """Test API endpoints without auth.

    FIX: exclude static media (jpg/webp/pdf/...) — those are expected to be
    public. Require JSON content-type and auth-bearing fields in the response.
    """
    STATIC_EXTS = (
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
        ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
        ".mp3", ".pdf", ".avif", ".map", ".js",
    )
    AUTH_FIELDS = re.compile(
        r'"(?:email|user_id|account_id|session_id|access_token|'
        r'refresh_token|password_hash|role|admin|is_admin|sub|'
        r'auth_user|current_user)"\s*:'
    )
    PUBLIC_HINTS = (
        "login", "register", "signup", "forgot", "reset", "public",
        "auth/v1/token", "auth/v1/signup", "auth/v1/recover",
        "tour-packages/media", "/media/", "/images/", "/static/",
        "/assets/", "/health", "/status", "/version",
    )

    out: List[Finding] = []
    anon = ctx.http.clone(cookie="")
    seen = set()

    for u in ctx.endpoints:
        if not any(prefix in u for prefix in ("/api/", "/rest/", "/v1/", "/v2/")):
            continue
        if any(hint in u.lower() for hint in PUBLIC_HINTS):
            continue
        sp = urllib.parse.urlsplit(u)
        if any(sp.path.lower().endswith(ext) for ext in STATIC_EXTS):
            continue
        full = urllib.parse.urljoin(ctx.base_url, u)
        if full in seen:
            continue
        seen.add(full)

        r = anon.fetch(full, follow=False)
        if not r or r.status != 200:
            continue
        if "json" not in r.content_type.lower():
            continue
        if not AUTH_FIELDS.search(r.text):
            continue
        out.append(Finding(
            "authz", "medium", f"API endpoint returns auth-scoped data without authentication",
            full,
            evidence=f"HTTP 200 JSON response with auth-bearing fields "
                     f"({clip(r.text, 120)})",
            remediation="Enforce authentication middleware across all non-public /api/* routes.",
            phase=4,
        ))
        if len(out) >= 5:
            break
    return out


def check_method_tampering(ctx: Ctx) -> List[Finding]:
    """Test HTTP method substitution (HEAD, PUT, OPTIONS, POST) to bypass authz."""
    out: List[Finding] = []
    anon = ctx.http.clone(cookie="")
    for path in ADMIN_PATHS_P4[:5]:
        u = urllib.parse.urljoin(ctx.base_url, path)
        r_get = anon.fetch(u, "GET", follow=False)
        if r_get and r_get.status in (401, 403):
            for method in ("HEAD", "POST", "OPTIONS"):
                r_test = anon.fetch(u, method, follow=False)
                if r_test and r_test.status == 200:
                    out.append(
                        Finding(
                            "authz", "high", f"Authentication bypass via HTTP {method} method tampering on {path}",
                            u, method=method,
                            evidence=f"GET returned {r_get.status}, but {method} returned 200 OK",
                            remediation="Enforce authorization checks uniformly across all HTTP verbs.",
                            phase=4,
                        )
                    )
    return out


def check_graphql_authz(ctx: Ctx) -> List[Finding]:
    return []


def check_error_leak(ctx: Ctx) -> List[Finding]:
    """Test for stack traces and verbose database error disclosure."""
    out: List[Finding] = []
    probes = ["/'", "/..;", "/%00", "/<wp>"]
    for p in probes:
        r = ctx.http.fetch(ctx.base_url + p, follow=True)
        if r and r.status >= 500:
            if re.search(r"(?i)(stack trace|traceback|at\s+[a-z0-9_\.]+\s*\([a-z0-9_\.]+:\d+:\d+\)|node_modules)", r.text):
                out.append(
                    Finding(
                        "leak", "low", "Verbose server stack trace leaked in error response",
                        r.url, evidence=f"Internal stack trace matched in HTTP {r.status} body",
                        remediation="Configure production error handlers to return generic error messages.",
                        phase=4,
                    )
                )
                break
    return out


def check_verbose_api(ctx: Ctx) -> List[Finding]:
    return []


def check_staff_to_admin(ctx: Ctx) -> List[Finding]:
    staff_cookie = getattr(ctx.args, "staff_cookie", "")
    if not staff_cookie:
        return []
    client = ctx.http.clone(cookie=staff_cookie)
    out: List[Finding] = []
    admin_only = ["/admin/users/roles", "/admin/settings/security", "/admin/keys"]
    for path in admin_only:
        u = urllib.parse.urljoin(ctx.base_url, path)
        r = client.fetch(u, follow=True)
        if r and r.status == 200 and not re.search(r"(?i)(forbidden|unauthorized|denied)", r.text[:2000]):
            out.append(
                Finding(
                    "authz", "high", f"Staff to Admin vertical privilege escalation: {path}",
                    u, evidence=f"Staff account reached administrative route: {clip(r.text, 100)}",
                    remediation="Segregate staff and superadmin permissions strictly.",
                    phase=4,
                )
            )
    return out


def check_supabase_storage(ctx: Ctx) -> List[Finding]:
    """Check for public Supabase storage bucket enumeration."""
    out: List[Finding] = []
    sb_hosts = [u for u in ctx.discovered + ctx.endpoints if ".supabase.co" in u]
    if not sb_hosts:
        return []
    host = sb_hosts[0].split("/")[2]
    storage_url = f"https://{host}/storage/v1/bucket"
    r = ctx.http.fetch(storage_url, follow=True)
    if r and r.status == 200 and ("name" in r.text or "public" in r.text):
        out.append(
            Finding(
                "authz", "high", "Supabase storage buckets enumerated unauthenticated",
                storage_url, evidence=f"HTTP 200 on /storage/v1/bucket: {clip(r.text, 140)}",
                remediation="Restrict bucket listing and enforce storage RLS policies.",
                phase=4,
            )
        )
    return out


def check_cors(ctx: Ctx) -> List[Finding]:
    """Check for permissive CORS configurations (e.g. Origin: null, reflection)."""
    out: List[Finding] = []
    origins_to_test = ["https://evil.example.com", "null"]
    for orig in origins_to_test:
        r = ctx.http.fetch(ctx.base_url, headers={"Origin": orig}, follow=False)
        if r:
            acao = r.header("Access-Control-Allow-Origin")
            acac = r.header("Access-Control-Allow-Credentials")
            if acao == orig or (orig == "null" and acao == "null"):
                sev = "high" if acac.lower() == "true" else "medium"
                out.append(
                    Finding(
                        "cors", sev, f"Permissive CORS: Origin '{orig}' reflected",
                        r.url, evidence=f"ACAO: {acao}; ACAC: {acac}",
                        remediation="Do not dynamically reflect arbitrary Origin headers; avoid 'Access-Control-Allow-Credentials: true' with null origin.",
                        phase=4,
                    )
                )
                break
    return out


def check_mass_assignment_implicit(ctx: Ctx) -> List[Finding]:
    return []


def check_idor_multi(ctx: Ctx) -> List[Finding]:
    return []


def check_vertical_escalation(ctx: Ctx) -> List[Finding]:
    return []


def check_idor(ctx: Ctx, point: Point) -> List[Finding]:
    """Baseline IDOR check on parameter IDs."""
    if not ID_PARAM_RE.search(point.param) or not point.orig_value.isdigit():
        return []
    val = int(point.orig_value)
    probe_val = str(val + 1)
    r = point.send(ctx.http, probe_val)
    if r and r.status == 200 and len(r.body) > 100:
        return [
            Finding(
                "idor", "medium", f"Potential IDOR on parameter '{point.param}'",
                point.action, point.method, point.target, payload=probe_val,
                evidence=f"Incremented ID {probe_val} returned HTTP 200",
                remediation="Ensure user authorization is validated before fetching object records.",
                phase=4,
            )
        ]
    return []


def check_forced_browsing(ctx: Ctx) -> List[Finding]:
    """Detect unauthenticated access to admin/privileged directories."""
    out: List[Finding] = []
    anon = ctx.http.clone(cookie="")
    for path in ADMIN_PATHS_P4[:6]:
        url = urllib.parse.urljoin(ctx.base_url, path)
        r = anon.fetch(url, follow=False)
        if r and r.status == 200:
            out.append(
                Finding(
                    "forced", "medium", f"Administrative path reachable without authentication: {path}",
                    url, evidence=f"HTTP 200 on unauthenticated request",
                    remediation="Require authentication for all administration endpoints.",
                    phase=4,
                )
            )
    return out



# ============ NEW: RBAC matrix ============
def _bodies_match_as_same_user(a: str, b: str) -> bool:
    import json, re
    try:
        ja, jb = json.loads(a), json.loads(b)
    except Exception:
        return a[:500] == b[:500]
    if not (isinstance(ja, dict) and isinstance(jb, dict)):
        return a[:500] == b[:500]
    # Strip identity-bearing fields before comparison
    IDENT = re.compile(r"(?i)^(user|user_id|id|email|owner_id|account_id)$")
    sa = {k: v for k, v in ja.items() if not IDENT.match(k)}
    sb = {k: v for k, v in jb.items() if not IDENT.match(k)}
    return sa == sb


def check_rbac_matrix(ctx: Ctx) -> List[Finding]:
    """Test every discovered endpoint across every provided role and flag gaps."""
    roles = {}
    for label, flag in (("anon", None),
                        ("customer", getattr(ctx.args, "cookie", "")),
                        ("secondary", getattr(ctx.args, "secondary_cookie", "")),
                        ("staff", getattr(ctx.args, "staff_cookie", "")),
                        ("admin", getattr(ctx.args, "admin_cookie", ""))):
        if flag is None:
            roles[label] = ctx.http.clone(cookie="")
        elif flag:
            roles[label] = ctx.http.clone(cookie=flag)

    if len(roles) < 2:
        return []

    out: List[Finding] = []
    endpoints = [u if u.startswith("http") else urllib.parse.urljoin(ctx.base_url, u)
                 for u in ctx.discovered[:30]]
    endpoints = list(dict.fromkeys(endpoints))

    for url in endpoints:
        row = {}
        bodies = {}
        for label, client in roles.items():
            r = client.fetch(url, follow=True)
            if r is None:
                row[label] = 0
                continue
            row[label] = r.status
            bodies[label] = r.text[:1000]

        # Anon 200 + customer 200 → endpoint has no authz
        if row.get("anon") == 200 and row.get("customer") == 200:
            out.append(Finding(
                "authz", "high",
                "Endpoint reachable unauthenticated AND authenticated",
                url,
                evidence=f"anon HTTP 200; customer HTTP 200",
                remediation="Require authentication on non-public endpoints; "
                            "enforce ownership checks on every resource.",
                phase=4,
            ))
            continue

        # Customer and secondary both see 200 with SAME body → no cross-user check
        if (row.get("customer") == 200 and row.get("secondary") == 200
                and _bodies_match_as_same_user(bodies.get("customer", ""), bodies.get("secondary", ""))
                and len(bodies.get("customer", "")) > 200):
            out.append(Finding(
                "authz", "high",
                "Two distinct customers see identical response (IDOR)",
                url,
                evidence=f"customer response identical to secondary customer "
                         f"({len(bodies['customer'])} bytes match)",
                remediation="Scope every query by the authenticated owner ID.",
                phase=4,
            ))

        # Staff and admin both see 200 → staff has admin rights
        if row.get("staff") == 200 and row.get("admin") == 200:
            if bodies.get("staff", "")[:500] == bodies.get("admin", "")[:500]:
                out.append(Finding(
                    "authz", "medium",
                    "Staff role has admin-level response",
                    url,
                    evidence="staff identity sees same content as admin",
                    remediation="Separate staff and admin permissions at the "
                                "backend; do not collapse to 'privileged'.",
                    phase=4,
                ))
    return out


# ============ NEW: mass assignment schema discrepancy ============
def check_mass_assign_schema(ctx: Ctx) -> List[Finding]:
    """Read a resource, extract internal fields, inject them into update."""
    customer = get_authed_client(ctx)
    if not customer:
        return []

    HIDDEN_FIELDS = ("role", "is_admin", "is_staff", "verified", "credits",
                     "balance", "tier", "plan", "owner_id", "tenant_id",
                     "billing_tier", "is_verified")

    resources = []
    for u in ctx.discovered[:20]:
        if re.search(r"(?i)(/api|/rest)", u):
            r = customer.fetch(u, follow=True)
            if r and r.status == 200 and "json" in r.content_type:
                try:
                    data = json.loads(r.text)
                    if isinstance(data, dict):
                        resources.append((u, data))
                    elif isinstance(data, list) and data and isinstance(data[0], dict):
                        resources.append((u, data[0]))
                except Exception:
                    pass

    out: List[Finding] = []
    for url, sample in resources[:5]:
        present_hidden = [k for k in HIDDEN_FIELDS if k in sample]
        if not present_hidden:
            continue

        tampered = dict(sample)
        for field in present_hidden:
            if isinstance(sample[field], bool):
                tampered[field] = not sample[field]
            elif isinstance(sample[field], int):
                tampered[field] = sample[field] + 1
            elif isinstance(sample[field], str):
                tampered[field] = "wp" + rand_token("", 6)

        for method in ("PATCH", "PUT", "POST"):
            r = customer.fetch(url, method, json.dumps(tampered),
                              headers={"Content-Type": "application/json"},
                              follow=False)
            if r and r.status < 400 and any(f in r.text for f in present_hidden):
                out.append(Finding(
                    "mass_assign", "critical",
                    f"Mass assignment: hidden fields written via {method}",
                    url, method=method,
                    evidence=f"Sent tampered {present_hidden}, server accepted "
                             f"(HTTP {r.status})",
                    remediation="Use response DTOs that whitelist writable "
                                "fields. Never bind raw request JSON to the model.",
                    confidence="medium", phase=4,
                ))
                break
    return out


# ============ NEW: GraphQL resolver-level authz ============
def check_graphql_resolver(ctx: Ctx) -> List[Finding]:
    """Probe nested GraphQL fields with lower-privilege tokens."""
    customer = get_authed_client(ctx)
    if not customer:
        return []

    candidates = [e for e in ctx.endpoints if "graphql" in e.lower()] + \
                 ["/graphql", "/api/graphql"]
    out: List[Finding] = []

    for p in dict.fromkeys(candidates):
        url = urllib.parse.urljoin(ctx.base_url, p)
        intro = customer.fetch(url, "POST",
                              json.dumps({"query": "{__schema{types{name fields{name}}}}"}),
                              headers={"Content-Type": "application/json"})
        if intro is None or intro.status != 200 or "__schema" not in intro.text:
            continue

        try:
            data = json.loads(intro.text)
        except Exception:
            continue
        types = data.get("data", {}).get("__schema", {}).get("types", []) or []
        for t in types:
            type_name = t.get("name", "")
            fields = t.get("fields") or []
            sensitive = [f["name"] for f in fields
                         if isinstance(f, dict) and "name" in f and re.search(
                             r"(?i)(email|phone|admin|role|secret|password|invoice|payment|address|ssn)",
                             f["name"])]
            if not sensitive:
                continue
            q = f"{{ {type_name.lower()}s {{ {' '.join(sensitive[:3])} }} }}"
            r = customer.fetch(url, "POST", json.dumps({"query": q}),
                              headers={"Content-Type": "application/json"})
            if r and r.status == 200 and "errors" not in r.text[:500]:
                out.append(Finding(
                    "graphql_authz", "high",
                    f"GraphQL resolver exposes sensitive fields on {type_name}",
                    url, method="POST", payload=q,
                    evidence=f"Query succeeded with customer token; fields: "
                             f"{sensitive[:3]}",
                    remediation="Add per-field resolvers that check authz; "
                                "never trust top-level query-level auth.",
                    confidence="medium", phase=4,
                ))
                break
    return out
