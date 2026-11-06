"""
Phase 1: Reconnaissance & Footprinting checks.
"""

import base64
import difflib
import json
import math
import re
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Set, Tuple

from webprobe.core.http import rand_token
from webprobe.core.models import Ctx, Finding


ENDPOINT_PATH_RE = re.compile(
    r"""["'`](/(?!/)[A-Za-z0-9_\-][A-Za-z0-9_\-/{}.:$~%]{1,200})["'`]"""
)
ENDPOINT_URL_RE = re.compile(
    r"""["'`](https?://[A-Za-z0-9.\-]+(?::\d+)?/[^"'`\s<>]{0,200})["'`]"""
)

STATIC_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".mp3", ".pdf",
    ".map",
)
INTERNAL_PREFIX = (
    "/_next/", "/static/", "/__", "/node_modules/", "/.well-known/",
    "/favicon",
)

SECRET_RES = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "info"),
    ("Stripe live key", re.compile(r"(?:sk|pk)_live_[0-9A-Za-z]{20,}"), "critical"),
    ("Razorpay key", re.compile(r"rzp_(?:live|test)_[0-9A-Za-z]{10,}"), "info"),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "critical"),
    ("GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{30,}"), "critical"),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "info"),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "critical"),
    ("Generic secret", re.compile(r"""(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*["']([^"']{10,})["']"""), "medium"),
]

N8N_PATHS = [
    "/rest/login", "/rest/logout", "/rest/workflows", "/rest/credentials",
    "/rest/executions", "/rest/settings", "/rest/active", "/rest/me",
    "/webhook", "/webhook-test", "/webhook-waiting",
    "/api/v1/workflows", "/api/v1/credentials", "/api/v1/executions",
    "/signin", "/setup", "/n8n", "/healthz", "/metrics",
]

RAZORPAY_PATHS = [
    "/api/razorpay/webhook", "/razorpay/webhook", "/api/webhooks/razorpay",
    "/api/payment/verify", "/api/payment/capture", "/api/order",
    "/api/order/create", "/api/checkout", "/api/razorpay/order",
    "/api/razorpay/verify", "/api/razorpay/callback", "/checkout/verify",
]

MUTATION_EXT = [
    ".bak", ".old", ".orig", ".save", ".swp", ".tmp", ".json", ".txt",
    ".zip", ".sql", ".php", "~", ".1", ".copy", ".backup", ".tar.gz",
    ".log", ".lock",
]

RECURSE_CHILDREN = [
    "index", "admin", "api", "config", "backup", "test", "dev",
    "internal", "v1", "v2", "dashboard", "login", "health", "status",
    "metrics", "debug",
]

HIDDEN_PARAMS = [
    "debug", "admin", "test", "internal", "raw", "output", "format", "download",
    "export", "file", "path", "url", "uri", "redirect", "next", "callback", "dest",
    "id", "user_id", "account_id", "user", "role", "is_admin", "token", "api_key",
    "key", "secret", "password", "email", "phone", "include", "fields", "expand",
    "_method", "_debug", "__debug__", "verbose", "trace", "log", "src", "source",
    "q", "query", "filter", "where", "sort", "order", "limit", "offset",
]

INFRA_HEADERS = [
    "Via", "X-Cache", "X-Served-By", "X-Backend-Server", "X-Varnish",
    "X-CDN", "X-Origin", "CF-Ray", "X-Amz-Cf-Id", "X-Akamai-Transformed",
    "X-Proxy-Id", "X-Real-IP", "X-Forwarded-Server",
]

DISCOVERY = [
    "admin", "administrator", "login", "signin", "auth", "api", "api/v1",
    "api/v2", "v1", "v2", "dashboard", "portal", "controlpanel", "cpanel",
    "phpmyadmin", "pma", "db", "database", "sql", "backup", "backups",
    "dump", "data", "test", "demo", "dev", "staging", "uat", "beta",
    "internal", "private", "secret", "console", "server-status", "status",
    "health", "healthz", "metrics", "info", "version", "config", "settings",
    "setup", "install", "upload", "uploads", "files", "static", "assets",
    "docs", "swagger", "swagger-ui", "swagger.json", "openapi.json",
    "redoc", "graphql", "graphiql", "actuator", "actuator/health",
    "actuator/env", "actuator/metrics", ".env", ".env.local", ".env.production",
    ".git/HEAD", ".git/config", ".gitignore", ".svn/entries", ".htaccess",
    "web.config", "composer.json", "package.json", "Dockerfile", "docker-compose.yml",
    "robots.txt", "sitemap.xml", ".well-known/security.txt", "crossdomain.xml",
]


def clip(s: str, n: int = 120) -> str:
    """Clip a string to length n with an ellipsis if truncated."""
    return s[:n] + "..." if len(s) > n else s


def shannon(data: str) -> float:
    """Calculate Shannon entropy for secret detection."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = float(len(data))
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def similar(a: Optional[str], b: Optional[str]) -> float:
    """Compute string similarity ratio between 0.0 and 1.0."""
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:3000], b[:3000]).ratio()


def check_robots(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    sitemaps_from_robots: List[str] = []
    r = ctx.http.fetch(ctx.root + "/robots.txt", follow=True)
    if r is not None and r.status == 200 and "html" not in r.content_type:
        paths = re.findall(r"(?im)^(?:Disallow|Allow):\s*(\S+)", r.text)
        sitemaps_from_robots = re.findall(r"(?im)^Sitemap:\s*(\S+)", r.text)
        for p in paths:
            if p in ("/", ""):
                continue
            ctx.extra_seeds.append(ctx.root + "/" + p.lstrip("/"))
        ev = f"{len(r.body)} bytes"
        if paths:
            ev += f"; disallowed: {', '.join(paths[:8])}"
        out.append(
            Finding(
                "recon", "info", "robots.txt exposed", r.url,
                evidence=clip(ev, 300),
                remediation="robots.txt is not access control; protect sensitive paths with authentication.",
                phase=1,
            )
        )
    sitemaps = ["sitemap.xml", "sitemap_index.xml"] + sitemaps_from_robots
    seen = set()
    for name in sitemaps:
        url = name if name.startswith("http") else ctx.root + "/" + name
        if url in seen:
            continue
        seen.add(url)
        r = ctx.http.fetch(url, follow=True)
        if r is None or r.status != 200 or "html" in r.content_type:
            continue
        locs = re.findall(r"<loc>\s*([^<\s]+)", r.text)
        for loc in locs:
            ctx.extra_seeds.append(loc)
        if locs:
            out.append(
                Finding(
                    "recon", "info", "sitemap exposed", r.url,
                    evidence=f"{len(locs)} urls; first: {locs[0][:120]}",
                    remediation="Ensure sitemap does not enumerate sensitive URLs.",
                    phase=1,
                )
            )
    return out


def check_security_txt(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    for path in ("/.well-known/security.txt", "/security.txt"):
        r = ctx.http.fetch(ctx.root + path, follow=True)
        if r is None or r.status != 200 or "text/plain" not in r.content_type:
            continue
        contacts = re.findall(r"(?im)^Contact:\s*(.+)$", r.text)
        policy = re.findall(r"(?im)^Policy:\s*(.+)$", r.text)
        expires = re.findall(r"(?im)^Expires:\s*(.+)$", r.text)
        if contacts or policy:
            out.append(
                Finding(
                    "recon", "info", "security.txt present", r.url,
                    evidence=f"contacts: {len(contacts)}; policy: "
                             f"{policy[0] if policy else 'none'}; "
                             f"expires: {expires[0] if expires else 'unset'}",
                    remediation="Keep the file current and within its Expires window.",
                    phase=1,
                )
            )
    return out


def check_infra(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    r = ctx.http.fetch(ctx.base_url, follow=True)
    if r is None:
        return out
    hints = [f"{h}: {r.header(h)}" for h in INFRA_HEADERS if r.header(h)]
    if hints:
        out.append(
            Finding(
                "recon", "info", "Infrastructure headers exposed", r.url,
                evidence="; ".join(hints),
                remediation="Strip hop-by-hop and CDN-internal headers at the edge.",
                phase=1,
            )
        )
    return out


def check_methods(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    r = ctx.http.fetch(ctx.base_url, "OPTIONS", follow=False)
    if r and r.header("Allow"):
        allowed = [m.strip().upper() for m in r.header("Allow").split(",")]
        dangerous = [m for m in allowed if m in ("PUT", "DELETE", "TRACE", "PATCH", "CONNECT")]
        if dangerous:
            out.append(
                Finding(
                    "recon", "low", "Dangerous HTTP methods advertised",
                    r.url, evidence=f"Allow: {r.header('Allow')}",
                    remediation="Restrict methods at the server or proxy.",
                    phase=1,
                )
            )
    r = ctx.http.fetch(ctx.base_url, "TRACE", follow=False)
    if r and r.status == 200 and r.text.lstrip().startswith("TRACE"):
        out.append(
            Finding(
                "recon", "medium", "TRACE method enabled (XST)", ctx.base_url,
                evidence=clip(r.text, 120),
                remediation="Disable TRACE at the server.",
                phase=1,
            )
        )
    return out


def check_wayback(ctx: Ctx) -> List[Finding]:
    if not getattr(ctx.args, "wayback", False):
        return []
    host = urllib.parse.urlsplit(ctx.base_url).netloc
    q = (
        f"https://web.archive.org/cdx/search/cdx?url={host}/*&output=json"
        f"&limit=500&collapse=urlkey&filter=statuscode:200"
    )
    r = ctx.http.fetch(q, follow=True, timeout=25.0)
    if r is None or r.status != 200:
        return []
    try:
        rows = json.loads(r.text)
    except Exception:
        return []
    if not isinstance(rows, list) or len(rows) < 2 or "original" not in rows[0]:
        return []
    idx = rows[0].index("original")
    urls, paths = [], set()
    for row in rows[1:]:
        if len(row) <= idx:
            continue
        u = row[idx]
        if not u.startswith(("http://", "https://")):
            continue
        urls.append(u)
        ctx.extra_seeds.append(u)
        paths.add(urllib.parse.urlsplit(u).path)
    if not paths:
        return []
    sorted_paths = sorted(paths)
    return [
        Finding(
            "recon", "info", "Historical URLs from Wayback Machine", ctx.base_url,
            evidence=f"{len(sorted_paths)} unique paths, e.g. {', '.join(sorted_paths[:8])}",
            remediation="Review historical paths; retired endpoints are often left deployed without their former auth checks.",
            phase=1,
        )
    ]


def _interesting_path(p: str) -> bool:
    if len(p) < 2 or len(p) > 200:
        return False
    lp = p.lower()
    if lp.endswith(STATIC_EXT):
        return False
    if any(lp.startswith(x) for x in INTERNAL_PREFIX):
        return False
    segs = [s for s in p.split("/") if s]
    return bool(segs)


def _harvest_source_map(
    ctx: Ctx,
    data: dict,
    source: str,
    found_paths: set,
    found_urls: set,
    found_secrets: list,
) -> None:
    host = urllib.parse.urlsplit(ctx.base_url).netloc
    for sname in (data.get("sources") or []):
        if not isinstance(sname, str):
            continue
        for m in ENDPOINT_PATH_RE.finditer(sname):
            if _interesting_path(m.group(1)):
                found_paths.add(m.group(1))
    for content in (data.get("sourcesContent") or []):
        if not isinstance(content, str):
            continue
        for m in ENDPOINT_PATH_RE.finditer(content):
            if _interesting_path(m.group(1)):
                found_paths.add(m.group(1))
        for m in ENDPOINT_URL_RE.finditer(content):
            u = m.group(1)
            sp = urllib.parse.urlsplit(u)
            if sp.netloc and sp.netloc != host:
                found_urls.add(u)
        for label, rx, *_ in SECRET_RES:
            for m in rx.finditer(content):
                val = m.group(1) if m.groups() else m.group(0)
                if label == "Generic secret" and shannon(val) < 2.5:
                    continue
                found_secrets.append((label, val, source))


def check_js(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    scripts: List[str] = []
    for page in ctx.pages:
        scripts.extend(page.get("scripts", []))
    max_js = getattr(ctx.args, "max_js", 20)
    scripts = list(dict.fromkeys(s for s in scripts if s.startswith("http")))[:max_js]
    if not scripts:
        return out

    found_paths: Set[str] = set()
    found_urls: Set[str] = set()
    found_secrets: List[Tuple[str, str, str]] = []
    source_maps: List[str] = []
    host = urllib.parse.urlsplit(ctx.base_url).netloc

    for src in scripts:
        r = ctx.http.fetch(src, follow=True)
        if r is None or r.status != 200 or len(r.body) > 5_000_000:
            continue
        text = r.text
        for m in ENDPOINT_PATH_RE.finditer(text):
            if _interesting_path(m.group(1)):
                found_paths.add(m.group(1))
        for m in ENDPOINT_URL_RE.finditer(text):
            u = m.group(1)
            sp = urllib.parse.urlsplit(u)
            if sp.netloc and sp.netloc != host:
                found_urls.add(u)
        for label, rx, _sev in SECRET_RES:
            for m in rx.finditer(text):
                val = m.group(1) if m.groups() else m.group(0)
                if label == "Generic secret" and shannon(val) < 2.5:
                    continue
                # Refine JWT severity by role claim
                if label == "JWT":
                    try:
                        parts = val.split(".")
                        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
                        payload_data = json.loads(base64.urlsafe_b64decode(payload_b64))
                        role = payload_data.get("role", "")
                        if role == "anon":
                            continue  # Supabase anon key is public by design
                        if role == "service_role":
                            found_secrets.append(
                                ("JWT (SERVICE_ROLE — CRITICAL LEAK)", val, src))
                        else:
                            found_secrets.append(("JWT", val, src))
                    except Exception:
                        pass
                else:
                    found_secrets.append((label, val, src))
        sm = re.search(r"[#@]\s*sourceMappingURL=(\S+)", text)
        if sm:
            smurl = sm.group(1)
            if smurl.startswith("data:"):
                try:
                    _, payload = smurl.split(",", 1)
                    if "base64" in smurl.split(",", 1)[0]:
                        data = json.loads(base64.b64decode(payload))
                    else:
                        data = json.loads(urllib.parse.unquote(payload))
                    _harvest_source_map(ctx, data, src, found_paths, found_urls, found_secrets)
                except Exception:
                    pass
            else:
                source_maps.append(urllib.parse.urljoin(src, smurl))
        else:
            source_maps.append(src + ".map")

    for map_url in source_maps[:10]:
        r = ctx.http.fetch(map_url, follow=True)
        if r is None or r.status != 200 or len(r.body) > 50_000_000:
            continue
        try:
            data = json.loads(r.text)
        except Exception:
            continue
        _harvest_source_map(ctx, data, map_url, found_paths, found_urls, found_secrets)
        ctx.source_maps.append(map_url)
        sources = data.get("sources") or []
        contents = data.get("sourcesContent") or []
        out.append(
            Finding(
                "recon", "medium", "JavaScript source map exposed", map_url,
                evidence=f"{len(sources)} source files, "
                         f"{sum(1 for c in contents if c)} with embedded content, "
                         f"{len(r.body)} bytes",
                remediation="Do not publish source maps in production, or serve them only behind authentication from a separate origin.",
                phase=1,
            )
        )

    ctx.endpoints = sorted(found_paths | found_urls)
    ctx.external_hosts = sorted({urllib.parse.urlsplit(u).netloc for u in found_urls})

    for u in sorted(found_urls)[:20]:
        out.append(
            Finding(
                "recon", "info",
                f"External host referenced in JS: {urllib.parse.urlsplit(u).netloc}",
                u, evidence="referenced from a client bundle",
                remediation="Confirm non-public hosts are not reachable and do not expose internal APIs.",
                phase=1,
            )
        )

    multi = sorted(p for p in found_paths if p.count("/") >= 2)
    for p in multi[:40]:
        out.append(
            Finding(
                "recon", "info", f"Endpoint disclosed in JavaScript: {p}",
                urllib.parse.urljoin(ctx.base_url, p),
                evidence=f"extracted from client bundle ({len(scripts)} scripts)",
                remediation="Client-side routes are public; enforce authorization server-side.",
                phase=1,
            )
        )

    single = sorted(p for p in found_paths if p.count("/") < 2)
    if single:
        out.append(
            Finding(
                "recon", "info", f"{len(single)} top-level routes disclosed",
                ctx.base_url, evidence=", ".join(single[:20]),
                remediation="Routes are public knowledge; ensure no privileged behaviour is reachable from the client alone.",
                phase=1,
            )
        )

    SEV_MAP = {
        "AWS access key": "critical",
        "Stripe live key": "critical",
        "Slack token": "critical",
        "GitHub token": "critical",
        "Private key": "critical",
        "JWT (SERVICE_ROLE — CRITICAL LEAK)": "critical",
        "JWT": "medium",
        "Generic secret": "medium",
        "Google API key": "info",
        "Razorpay key": "info",
    }
    for label, val, src in found_secrets[:20]:
        sev = SEV_MAP.get(label, "medium")
        out.append(Finding(
            "recon", sev, f"Secret in client bundle: {label}", src,
            evidence=f"{val[:6]}...{val[-4:]} ({len(val)} chars)",
            remediation="Remove from client code, rotate the credential, load it server-side from a secret store.",
            phase=1,
        ))
    return out


def check_graphql(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    paths = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/api/graphiql", "/graph"]
    paths += [e for e in ctx.endpoints if "graphql" in e.lower()]
    q = "{__schema{queryType{name} mutationType{name} types{name kind}}}"
    for p in dict.fromkeys(paths):
        url = urllib.parse.urljoin(ctx.base_url, p)
        r, used = None, "POST"
        r = ctx.http.fetch(
            url, "POST", json.dumps({"query": q}),
            headers={"Content-Type": "application/json"},
        )
        if r is None or r.status != 200 or "__schema" not in r.text:
            used = "GET"
            r = ctx.http.fetch(url + "?query=" + urllib.parse.quote(q), follow=True)
        if r is None or r.status != 200 or "__schema" not in r.text:
            used = "POST (batched)"
            r = ctx.http.fetch(
                url, "POST", json.dumps([{"query": q}]),
                headers={"Content-Type": "application/json"},
            )
        if r is None or r.status != 200 or "__schema" not in r.text:
            continue
        types = re.findall(r'"name":"([A-Za-z_][A-Za-z0-9_]*)"', r.text)
        out.append(
            Finding(
                "graphql", "medium", "GraphQL introspection enabled", url,
                method=used,
                evidence=f"{len(set(types))} types, e.g. {', '.join(sorted(set(types))[:8])}",
                remediation="Disable introspection in production; add depth/cost limits and per-field authorization.",
                phase=1,
            )
        )
        sug = ctx.http.fetch(
            url, "POST", json.dumps({"query": "{__typenamX}"}),
            headers={"Content-Type": "application/json"},
        )
        if sug is not None and "suggestions" in sug.text:
            out.append(
                Finding(
                    "graphql", "low", "GraphQL field suggestions enabled", url,
                    evidence=clip(sug.text, 200),
                    remediation="Disable did-you-mean suggestions in production.",
                    phase=1,
                )
            )
        break
    return out


def check_discovery(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    soft = ctx.http.fetch(ctx.root + "/" + rand_token("nope-", 14), follow=True)
    soft_text = soft.text if soft and soft.status == 200 else None
    soft_status = soft.status if soft else 404

    discover_max = getattr(ctx.args, "discover_max", 120)
    base_list = list(dict.fromkeys(list(DISCOVERY) + N8N_PATHS + RAZORPAY_PATHS))[:discover_max]

    def probe(path: str):
        url = ctx.root + "/" + path.lstrip("/")
        r = ctx.http.fetch(url, follow=True)
        if r is None:
            return None
        if r.status in (200, 401, 403) and (
            r.status != soft_status or similar(soft_text, r.text) < 0.95
        ):
            return (path, r)
        return None

    def record(path: str, r: Any):
        sev = "medium" if re.search(
            r"(backup|dump|\.sql|\.env|config|\.git|private|internal|webhook|rest/)",
            path,
        ) else "info"
        out.append(
            Finding(
                "recon", sev,
                f"Interesting path: /{path.lstrip('/')}", r.url,
                evidence=f"HTTP {r.status}, {len(r.body)} bytes, {r.content_type or 'no content-type'}",
                remediation="Remove or authenticate non-public paths; return a uniform 404 for everything else.",
                phase=1,
            )
        )
        ctx.discovered.append(r.url)
        ctx.extra_discovered.append(r.url)

    threads = getattr(ctx.args, "threads", 4)
    found: List[str] = []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        for res in ex.map(probe, base_list):
            if res:
                found.append(res[0])
                record(*res)

    if not getattr(ctx.args, "discover_recursive", False):
        return out

    mutations: List[str] = []
    for p in found[:25]:
        if any(p.lower().endswith(e) for e in STATIC_EXT):
            continue
        base = p.rstrip("/")
        for ext in MUTATION_EXT:
            mutations.append(base + ext)
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        for res in ex.map(probe, mutations):
            if res:
                record(*res)

    children: List[str] = []
    for p in found[:20]:
        base = p if p.endswith("/") else p + "/"
        for child in RECURSE_CHILDREN:
            children.append(base + child)
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        for res in ex.map(probe, children):
            if res:
                record(*res)
    return out


def check_params(ctx: Ctx) -> List[Finding]:
    if not getattr(ctx.args, "param_discovery", False):
        return []
    out: List[Finding] = []
    host = urllib.parse.urlsplit(ctx.base_url).netloc
    ends: List[str] = []
    for p in ctx.pages:
        sp = urllib.parse.urlsplit(p["url"])
        ends.append(urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path, "", "")))
    for e in ctx.endpoints:
        sp = urllib.parse.urlsplit(urllib.parse.urljoin(ctx.base_url, e))
        if sp.netloc == host:
            ends.append(urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path, "", "")))
    param_max = getattr(ctx.args, "param_max", 30)
    ends = list(dict.fromkeys(ends))[:param_max]

    random_param = rand_token("wprand", 8)
    for end in ends:
        base = ctx.http.fetch(end, follow=True)
        if base is None or base.status >= 500:
            continue
        ctrl = ctx.http.fetch(end + "?" + random_param + "=wpctrl", follow=True)
        ctrl_text = ctrl.text if ctrl else base.text
        for param in HIDDEN_PARAMS:
            canary = rand_token("wpc", 6)
            sep = "&" if "?" in end else "?"
            r = ctx.http.fetch(end + sep + param + "=" + canary, follow=True)
            if r is None:
                continue
            status_changed = r.status != base.status and r.status < 500
            text_changed = similar(base.text, r.text) < 0.9
            ctrl_safe = similar(ctrl_text, r.text) < 0.85 if ctrl else True
            canary_reflected = canary in r.text
            size_changed = (
                len(r.body) > len(base.body) * 1.3 or len(r.body) < len(base.body) * 0.5
            )
            if (status_changed or text_changed) and ctrl_safe and (canary_reflected or size_changed):
                out.append(
                    Finding(
                        "params", "low", f"Undocumented parameter accepted: {param}",
                        end, param=param,
                        evidence=f"baseline HTTP {base.status} ({len(base.body)}B), with "
                                 f"param HTTP {r.status} ({len(r.body)}B), "
                                 f"canary {'reflected' if canary_reflected else 'not reflected'}",
                        remediation="Validate and document every accepted parameter; strip or reject unknown parameters.",
                        confidence="low", phase=1,
                    )
                )
                ctx.hidden_params.append((end, param))
                break
    return out


def check_payment_keys(ctx: Ctx) -> List[Finding]:
    """Inspect client pages and scripts for embedded payment gateway credentials."""
    out: List[Finding] = []
    texts_to_check: List[Tuple[str, str]] = []
    for page in ctx.pages:
        texts_to_check.append((page["url"], page.get("html", "")))
    scripts = [s for p in ctx.pages for s in p.get("scripts", []) if s.startswith("http")]
    for s in scripts[:10]:
        r = ctx.http.fetch(s, follow=True)
        if r and r.status == 200:
            texts_to_check.append((s, r.text))

    for source_url, content in texts_to_check:
        if not content:
            continue
        for label, rx, *_ in SECRET_RES:
            if "Stripe" in label or "Razorpay" in label:
                for m in rx.finditer(content):
                    val = m.group(0)
                    is_live = "_live_" in val
                    sev = "critical" if is_live else "medium"
                    out.append(
                        Finding(
                            "recon", sev, f"Payment key exposed: {label}", source_url,
                            evidence=f"Key {val[:12]}... in {source_url}",
                            remediation="Do not hardcode payment secret or live keys in client code.",
                            phase=1,
                        )
                    )
    return out



# ============ NEW: virtual host fuzzing ============
VHOST_PREFIXES = [
    "admin", "api", "staging", "dev", "test", "uat", "internal",
    "dashboard", "manage", "ops", "backend", "app", "portal",
    "beta", "preview", "sandbox", "qa", "stage",
]


def check_vhost(ctx: Ctx) -> List[Finding]:
    """Fuzz Host header against the target to find internal virtual hosts."""
    if not getattr(ctx.args, "vhost_test", False):
        return []
    sp = urllib.parse.urlsplit(ctx.base_url)
    host = sp.hostname
    if not host:
        return []

    out: List[Finding] = []
    baseline = ctx.http.fetch(ctx.base_url, follow=True)
    baseline_hash = hash(baseline.body) if baseline else None

    for prefix in VHOST_PREFIXES:
        vhost = f"{prefix}.{host}"
        r = ctx.http.fetch(ctx.base_url, headers={"Host": vhost}, follow=False)
        if r is None:
            continue
        if r.status in (200, 302, 401, 403) and hash(r.body) != baseline_hash:
            out.append(Finding(
                "vhost", "low", f"Virtual host responds: {vhost}",
                ctx.base_url, payload=f"Host: {vhost}",
                evidence=f"HTTP {r.status}, {len(r.body)} bytes "
                         f"(differs from default baseline)",
                remediation="Ensure the reverse proxy enforces a strict vhost "
                            "allowlist and does not route unknown Host headers.",
                confidence="medium", phase=1,
            ))
    return out


# ============ NEW: favicon hash fingerprint ============
def check_favicon_hash(ctx: Ctx) -> List[Finding]:
    """Compute favicon MurmurHash3 for Shodan-style tech matching."""
    for page in ctx.pages[:1]:
        html = page.get("html", "")
        m = re.search(r"""<link[^>]*rel=["'](?:icon|shortcut icon)["'][^>]*href=["']([^"']+)["']""",
                      html, re.I)
        if not m:
            continue
        icon_url = urllib.parse.urljoin(page["url"], m.group(1))
        r = ctx.http.fetch(icon_url, follow=True)
        if r is None or r.status != 200:
            return []
        try:
            import base64 as _b64
            mmh3 = _import_mmh3()
            if mmh3 is None:
                return [Finding(
                    "recon", "info",
                    "Favicon fetched but mmh3 not installed (pip install mmh3)",
                    icon_url, evidence=f"{len(r.body)} bytes",
                    confidence="high", phase=1,
                )]
            encoded = _b64.encodebytes(r.body)
            hash_val = mmh3.hash(encoded)
            return [Finding(
                "recon", "info", f"Favicon MurmurHash3: {hash_val}",
                icon_url,
                evidence=f"hash={hash_val}; correlate at shodan.io/search?query=hash:{hash_val}",
                remediation="No action needed; fingerprint only.",
                phase=1,
            )]
        except Exception:
            return []
    return []


def _import_mmh3():
    try:
        import mmh3  # type: ignore
        return mmh3
    except ImportError:
        return None


# ============ NEW: build manifest route extraction ============
def check_manifest_routes(ctx: Ctx) -> List[Finding]:
    """Decompile Next.js/Vite/Webpack manifests into the full route tree."""
    from webprobe.core.manifest import extract_all
    result = extract_all(ctx)
    if not result["routes"]:
        return []
    routes = result["routes"]
    for r in routes:
        full = urllib.parse.urljoin(ctx.base_url, r)
        if full not in ctx.discovered:
            ctx.discovered.append(full)
    return [Finding(
        "recon", "info",
        f"Build manifest exposed {len(routes)} routes ({result['framework']})",
        ctx.base_url,
        evidence=f"Sample: {', '.join(routes[:10])}. "
                 f"Sources: {', '.join(s.split('/')[-1] for s in result['sources'][:3])}",
        remediation="Client-side routes are public; enforce server-side authz on "
                    "every privileged route.",
        phase=1,
    )]


# ============ NEW: GraphQL schema reconstruction from JS ============
def check_graphql_js_schema(ctx: Ctx) -> List[Finding]:
    """Reconstruct GraphQL schema from client-side fragments/mutations when introspection is off."""
    js_urls = [s for p in ctx.pages for s in p.get("scripts", []) if s.startswith("http")][:20]
    fragments: set = set()
    mutations: set = set()
    queries: set = set()

    frag_re = re.compile(r"(?:fragment|query|mutation)\s+([A-Za-z_][A-Za-z0-9_]*)", re.I)
    field_re = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\([^)]*\))?\s*(?=[{\\n])")

    for src in js_urls:
        r = ctx.http.fetch(src, follow=True)
        if r is None or r.status != 200:
            continue
        for m in frag_re.finditer(r.text):
            word = m.group(0).lower()
            name = m.group(1)
            if word.startswith("fragment"):
                fragments.add(name)
            elif word.startswith("mutation"):
                mutations.add(name)
            elif word.startswith("query"):
                queries.add(name)

    if not (fragments or mutations or queries):
        return []

    return [Finding(
        "graphql", "info",
        "GraphQL schema fragments recovered from JS (introspection likely off)",
        ctx.base_url,
        evidence=f"queries={len(queries)}, mutations={len(mutations)}, "
                 f"fragments={len(fragments)}. "
                 f"Mutations: {', '.join(list(mutations)[:8])}",
        remediation="Introspection being off is good, but the client bundle still "
                    "exposes the schema. Treat every operation as public and "
                    "authorize each resolver.",
        phase=1,
    )]
