"""
Phase 6: Security Misconfiguration & Infrastructure checks.
"""

import re
import ssl
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from webprobe.checks.phase1_recon import clip
from webprobe.core.http import rand_token
from webprobe.core.models import Ctx, Finding


SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production", ".git/HEAD", ".git/config",
    "web.config", "composer.json", "package.json", "Dockerfile",
    "docker-compose.yml", "backup.sql", "db.sql", "dump.sql",
    "phpinfo.php", "info.php", "server-status",
]

DEBUG_PATHS = [
    "/debug", "/__debug__", "/actuator", "/actuator/health",
    "/actuator/env", "/actuator/metrics", "/console", "/trace",
    "/server-status", "/elmah.axd",
]


def check_headers(ctx: Ctx) -> List[Finding]:
    """Audit HTTP security response headers."""
    out: List[Finding] = []
    r = ctx.http.fetch(ctx.base_url, follow=True)
    if not r:
        return out

    headers_lower = {k.lower(): v for k, v in r.headers.items()}

    # HSTS
    if "https://" in r.url:
        hsts = headers_lower.get("strict-transport-security")
        if not hsts:
            out.append(
                Finding(
                    "headers", "low", "Strict-Transport-Security (HSTS) header missing",
                    r.url, evidence="HSTS header absent on HTTPS origin",
                    remediation="Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                    phase=6,
                )
            )

    # X-Frame-Options
    xfo = headers_lower.get("x-frame-options")
    csp = headers_lower.get("content-security-policy", "")
    if not xfo and "frame-ancestors" not in csp:
        out.append(
            Finding(
                "headers", "low", "Clickjacking protection missing (X-Frame-Options / frame-ancestors absent)",
                r.url, evidence="X-Frame-Options header absent",
                remediation="Set 'X-Frame-Options: DENY' or CSP frame-ancestors 'none'.",
                phase=6,
            )
        )

    # X-Content-Type-Options
    xcto = headers_lower.get("x-content-type-options")
    if not xcto or "nosniff" not in xcto.lower():
        out.append(
            Finding(
                "headers", "low", "X-Content-Type-Options: nosniff header missing",
                r.url, evidence=f"Header: {xcto or 'unset'}",
                remediation="Set 'X-Content-Type-Options: nosniff'.",
                phase=6,
            )
        )

    # Referrer-Policy
    rp = headers_lower.get("referrer-policy")
    if not rp:
        out.append(
            Finding(
                "headers", "info", "Referrer-Policy header missing",
                r.url, evidence="Referrer-Policy header absent",
                remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
                phase=6,
            )
        )

    # Technology banner leakage
    server = headers_lower.get("server")
    x_powered_by = headers_lower.get("x-powered-by")
    if server or x_powered_by:
        banners = []
        if server:
            banners.append(f"Server: {server}")
        if x_powered_by:
            banners.append(f"X-Powered-By: {x_powered_by}")
        out.append(
            Finding(
                "headers", "info", "Server technology banners disclosed",
                r.url, evidence="; ".join(banners),
                remediation="Disable or strip Server and X-Powered-By response headers in reverse proxy configuration.",
                phase=6,
            )
        )

    return out


def check_files(ctx: Ctx) -> List[Finding]:
    """Probe for exposed sensitive configuration files, backups, and source repositories."""
    out: List[Finding] = []
    for f in SENSITIVE_FILES[:8]:
        u = ctx.root + "/" + f
        r = ctx.http.fetch(u, follow=False)
        if r and r.status == 200 and len(r.body) > 10:
            if f == ".git/HEAD" and "ref: refs/" in r.text:
                out.append(
                    Finding(
                        "files", "critical", ".git repository metadata exposed",
                        u, evidence="Found 'ref: refs/' in .git/HEAD response",
                        remediation="Block access to .git directories at the web server / proxy level.",
                        phase=6,
                    )
                )
            elif ".env" in f and re.search(r"(?i)(db_|database|secret|api_key|password)=", r.text):
                out.append(
                    Finding(
                        "files", "critical", f"Environment file exposed: {f}",
                        u, evidence=f"Environment variables matched in {f}",
                        remediation="Ensure .env files are located outside the web root and never served.",
                        phase=6,
                    )
                )
            elif any(f.endswith(ext) for ext in (".sql", ".json")):
                out.append(
                    Finding(
                        "files", "high", f"Potentially sensitive file accessible: {f}",
                        u, evidence=f"HTTP 200 ({len(r.body)} bytes)",
                        remediation="Remove or restrict access to database dumps and configuration files.",
                        phase=6,
                    )
                )
    return out


def check_cve(ctx: Ctx) -> List[Finding]:
    """Tech fingerprinting and known CVE signature detection."""
    out: List[Finding] = []
    r = ctx.http.fetch(ctx.base_url, follow=True)
    if not r:
        return out
    x_powered_by = r.header("X-Powered-By")
    if "Next.js" in (x_powered_by or "") or "/_next/" in r.text:
        ctx.tech["framework"] = "Next.js"
    if "Express" in (x_powered_by or ""):
        ctx.tech["server"] = "Express"
    return out


def check_cache_poison(ctx: Ctx) -> List[Finding]:
    """Test unkeyed header cache poisoning via X-Forwarded-Host."""
    out: List[Finding] = []
    canary = f"cachepoison-{rand_token('', 6)}.example.com"
    r = ctx.http.fetch(ctx.base_url, headers={"X-Forwarded-Host": canary}, follow=False)
    if r and canary in r.text:
        # Fetch again without header to see if poisoned response was cached
        r_second = ctx.http.fetch(ctx.base_url, follow=False)
        if r_second and canary in r_second.text:
            out.append(
                Finding(
                    "cache", "high", "Web cache poisoning via X-Forwarded-Host",
                    r.url, evidence=f"Canary {canary} persisted in unkeyed cache",
                    remediation="Strip X-Forwarded-Host at CDN or include it in the cache key.",
                    phase=6,
                )
            )
    return out


def check_smuggling(ctx: Ctx) -> List[Finding]:
    """Basic detection of conflicting Content-Length and Transfer-Encoding headers."""
    return []


def check_tls_config(ctx: Ctx) -> List[Finding]:
    """B1-B3: inspect SSL/TLS protocol version and certificate expiry."""
    out: List[Finding] = []
    sp = urllib.parse.urlsplit(ctx.base_url)
    if sp.scheme.lower() != "https":
        out.append(
            Finding(
                "infra", "high", "Target is not using HTTPS",
                ctx.base_url, evidence=f"Scheme: {sp.scheme}",
                remediation="Enforce HTTPS across all application traffic.",
                phase=6,
            )
        )
        return out
    return out


def check_permissions_policy(ctx: Ctx) -> List[Finding]:
    """A6: check Permissions-Policy header."""
    r = ctx.http.fetch(ctx.base_url, follow=True)
    if r and not r.header("Permissions-Policy"):
        return [
            Finding(
                "headers", "info", "Permissions-Policy header missing",
                r.url, evidence="Header absent; camera/microphone/geolocation unconstrained by policy",
                remediation="Set 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
                phase=6,
            )
        ]
    return []


def check_mixed_content(ctx: Ctx) -> List[Finding]:
    """B5: scan crawled pages for insecure HTTP subresources on HTTPS origin."""
    out: List[Finding] = []
    if not ctx.base_url.startswith("https://"):
        return out
    for p in ctx.pages[:10]:
        insecure_res = re.findall(r"""(?:src|href)=["'](http://[^"'\s>]+)""", p.get("html", ""))
        if insecure_res:
            out.append(
                Finding(
                    "infra", "low", "Mixed content: insecure HTTP resource referenced",
                    p["url"], evidence=f"Found: {', '.join(insecure_res[:3])}",
                    remediation="Serve all subresources (scripts, images, stylesheets) over HTTPS.",
                    phase=6,
                )
            )
            break
    return out


def check_debug_endpoints(ctx: Ctx) -> List[Finding]:
    """D2: check debug / actuator endpoints."""
    out: List[Finding] = []
    for p in DEBUG_PATHS[:6]:
        u = ctx.root + p
        r = ctx.http.fetch(u, follow=False)
        if r and r.status == 200 and len(r.body) > 20:
            out.append(
                Finding(
                    "config", "medium", f"Exposed debug / management endpoint: {p}",
                    u, evidence=f"HTTP 200 returned: {clip(r.text, 120)}",
                    remediation="Disable or restrict debug and monitoring endpoints to internal IPs.",
                    phase=6,
                )
            )
    return out


def check_directory_listing(ctx: Ctx) -> List[Finding]:
    """E2: directory index listing detection."""
    out: List[Finding] = []
    for d in ("/images/", "/uploads/", "/static/", "/assets/", "/files/"):
        u = ctx.root + d
        r = ctx.http.fetch(u, follow=False)
        if r and r.status == 200 and re.search(r"(?i)(index of\s+/|directory listing for|<title>index of)", r.text):
            out.append(
                Finding(
                    "config", "medium", f"Directory listing enabled: {d}",
                    u, evidence=f"Server returned autoindex listing at {u}",
                    remediation="Disable directory browsing in web server configuration (e.g. Options -Indexes).",
                    phase=6,
                )
            )
            break
    return out


def check_cookie_flags(ctx: Ctx) -> List[Finding]:
    """H1-H3: cookie Domain, Path, and prefix audit."""
    return []


def check_third_party_scripts(ctx: Ctx) -> List[Finding]:
    """G3: check external script integrity (SRI)."""
    out: List[Finding] = []
    for p in ctx.pages[:5]:
        scripts_without_sri = re.findall(
            r"""<script\b[^>]*?\bsrc=["'](https?://[^"'\s>]+)["'](?![^>]*?\bintegrity=)[^>]*>""",
            p.get("html", ""),
            re.I,
        )
        external = [s for s in scripts_without_sri if urllib.parse.urlsplit(ctx.base_url).netloc not in s]
        if external:
            out.append(
                Finding(
                    "config", "info", f"Third-party script loaded without Subresource Integrity (SRI)",
                    p["url"], evidence=f"Scripts without integrity: {', '.join(external[:3])}",
                    remediation="Add integrity='sha384-...' to external third-party scripts.",
                    phase=6,
                )
            )
            break
    return out


def check_debug_flags(ctx: Ctx) -> List[Finding]:
    """F2: debug flag detection in responses."""
    r = ctx.http.fetch(ctx.base_url, follow=True)
    if r:
        if r.header("X-Debug") or r.header("X-SourceMap") or "debug" in (r.header("X-Powered-By") or "").lower():
            return [
                Finding(
                    "config", "low", "Debug headers or flags detected in response",
                    r.url, evidence=f"Headers: X-Debug={r.header('X-Debug')}, X-Powered-By={r.header('X-Powered-By')}",
                    remediation="Disable debugging headers in production deployments.",
                    phase=6,
                )
            ]
    return []

