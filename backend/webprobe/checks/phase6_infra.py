"""
Phase 6: Security Misconfiguration & Infrastructure checks.
"""

import json
import re
import socket
import ssl
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from webprobe.checks.phase1_recon import clip
from webprobe.checks.phase2_auth import get_authed_client
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

DEBUG_HEADER_NAMES = [
    "X-Debug", "X-Debug-Token", "X-Debug-Token-Link",
    "X-Runtime", "X-Generator", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Backend-Server", "X-Server-Name", "X-Env", "X-Environment",
    "X-Stage", "X-Debug-Timestamp", "X-Route",
]

DEBUG_QUERY_PARAMS = ["debug=1", "debug=true", "test=1", "dev=1", "trace=1"]

DEBUG_BODY_MARKERS = re.compile(
    r"(?i)(stack trace|traceback \(|django debug|laravel debug|"
    r"development mode|werkzeug debugger|pycharm debug|"
    r"symfony profiler|whoops|error_reporting)"
)

STATIC_EXTS = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
    ".mp3", ".pdf", ".avif", ".map",
)


def _version_tuple(value: str) -> Tuple[int, int, int, int]:
    """Parse a version into four comparable integers.

    Numeric components are used as-is. A trailing letter suffix is encoded
    in the fourth slot (a=1 ... z=26, multi-letter suffixes in base 26), so
    OpenSSL-style versions such as 1.0.1f sort correctly.
    """
    tokens = re.findall(r"(\d+)([a-z]*)", (value or "").lower())
    parts: List[int] = []
    suffix = 0
    for num, letters in tokens:
        if len(parts) >= 3:
            if letters:
                suffix = sum(
                    (ord(ch) - 96) * (26 ** (len(letters) - 1 - i))
                    for i, ch in enumerate(letters)
                )
            break
        parts.append(int(num))
        if letters:
            suffix = sum(
                (ord(ch) - 96) * (26 ** (len(letters) - 1 - i))
                for i, ch in enumerate(letters)
            )
            break
    while len(parts) < 3:
        parts.append(0)
    return (parts[0], parts[1], parts[2], suffix)


def _range_tuple(value: Any) -> Tuple[int, int, int, int]:
    if isinstance(value, str):
        return _version_tuple(value)
    if isinstance(value, (list, tuple)):
        parts = [int(p) for p in value][:4]
        while len(parts) < 4:
            parts.append(0)
        return (parts[0], parts[1], parts[2], parts[3])
    return (0, 0, 0, 0)


def _in_range(version: str, rng: Any) -> bool:
    """Check a version against an inclusive or exclusive range object.

    Range objects look like:
        {"low": [2, 4, 49], "high": [2, 4, 50], "high_exclusive": true}
    A legacy ``[low, high]`` pair is treated as inclusive on both ends.
    """
    if isinstance(rng, (list, tuple)) and len(rng) == 2:
        return _range_tuple(rng[0]) <= _version_tuple(version) <= _range_tuple(rng[1])
    if not isinstance(rng, dict):
        return False
    v = _version_tuple(version)
    low = _range_tuple(rng.get("low", []))
    high = _range_tuple(rng.get("high", []))
    low_ok = v > low if rng.get("low_exclusive") else v >= low
    high_ok = v < high if rng.get("high_exclusive") else v <= high
    return low_ok and high_ok


# Passive CVE fingerprints live in a JSON database so they can be updated
# without editing Python. Each rule is version-gated: the scanner reports a
# CVE only when it can read a vulnerable version from a response header or
# the page body. No active exploitation happens here.
CVE_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "cve_fingerprints.json"


def _load_cve_fingerprints() -> List[Dict[str, Any]]:
    try:
        payload = json.loads(CVE_DB_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if isinstance(payload, dict):
        fingerprints = payload.get("fingerprints", [])
    else:
        fingerprints = payload
    return fingerprints if isinstance(fingerprints, list) else []


CVE_FINGERPRINTS = _load_cve_fingerprints()


def check_headers(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    r = ctx.http.fetch(ctx.base_url, follow=True)
    if not r:
        return out

    headers_lower = {k.lower(): v for k, v in r.headers.items()}

    if "https://" in r.url:
        if not headers_lower.get("strict-transport-security"):
            out.append(Finding(
                "headers", "low", "Strict-Transport-Security (HSTS) header missing",
                r.url, evidence="HSTS header absent on HTTPS origin",
                remediation="Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                phase=6,
            ))

    xfo = headers_lower.get("x-frame-options")
    csp = headers_lower.get("content-security-policy", "")
    if not xfo and "frame-ancestors" not in csp:
        out.append(Finding(
            "headers", "low",
            "Clickjacking protection missing (X-Frame-Options / frame-ancestors absent)",
            r.url, evidence="X-Frame-Options header absent",
            remediation="Set 'X-Frame-Options: DENY' or CSP frame-ancestors 'none'.",
            phase=6,
        ))

    xcto = headers_lower.get("x-content-type-options")
    if not xcto or "nosniff" not in xcto.lower():
        out.append(Finding(
            "headers", "low", "X-Content-Type-Options: nosniff header missing",
            r.url, evidence=f"Header: {xcto or 'unset'}",
            remediation="Set 'X-Content-Type-Options: nosniff'.",
            phase=6,
        ))

    if not headers_lower.get("referrer-policy"):
        out.append(Finding(
            "headers", "info", "Referrer-Policy header missing",
            r.url, evidence="Referrer-Policy header absent",
            remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
            phase=6,
        ))

    server = headers_lower.get("server")
    x_powered_by = headers_lower.get("x-powered-by")
    if server or x_powered_by:
        banners = []
        if server:
            banners.append(f"Server: {server}")
        if x_powered_by:
            banners.append(f"X-Powered-By: {x_powered_by}")
        out.append(Finding(
            "headers", "info", "Server technology banners disclosed",
            r.url, evidence="; ".join(banners),
            remediation="Disable or strip Server and X-Powered-By response headers in reverse proxy configuration.",
            phase=6,
        ))

    return out


def check_files(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    for f in SENSITIVE_FILES[:10]:
        u = ctx.root + "/" + f
        r = ctx.http.fetch(u, follow=False)
        if not r or r.status != 200 or len(r.body) < 10:
            continue
        if f == ".git/HEAD" and "ref: refs/" in r.text:
            out.append(Finding(
                "files", "critical", ".git repository metadata exposed",
                u, evidence="Found 'ref: refs/' in .git/HEAD response",
                remediation="Block access to .git directories at the web server / proxy level.",
                phase=6,
            ))
        elif ".env" in f and re.search(r"(?i)(db_|database|secret|api_key|password)=", r.text):
            out.append(Finding(
                "files", "critical", f"Environment file exposed: {f}",
                u, evidence=f"Environment variables matched in {f}",
                remediation="Ensure .env files are located outside the web root and never served.",
                phase=6,
            ))
        elif any(f.endswith(ext) for ext in (".sql", ".json")):
            out.append(Finding(
                "files", "high", f"Potentially sensitive file accessible: {f}",
                u, evidence=f"HTTP 200 ({len(r.body)} bytes)",
                remediation="Remove or restrict access to database dumps and configuration files.",
                phase=6,
            ))
    return out


def check_cve(ctx: Ctx) -> List[Finding]:
    """Passive CVE fingerprinting from headers and page content.

    This is detection-only: it never sends an exploit payload. A finding is
    emitted only when a product version is readable and falls inside a
    published affected range.
    """
    out: List[Finding] = []
    r = ctx.http.fetch(ctx.base_url, follow=True)
    if not r:
        return out

    header_blob = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    body = r.text[:200000]
    x_powered_by = r.header("X-Powered-By") or ""
    if "Next.js" in x_powered_by or "/_next/" in body:
        ctx.tech["framework"] = "Next.js"
    if "Express" in x_powered_by:
        ctx.tech["server"] = "Express"

    seen = set()
    for fingerprint in CVE_FINGERPRINTS:
        haystack = header_blob if fingerprint["source"] == "headers" else body
        match = re.search(fingerprint["regex"], haystack)
        if not match:
            continue
        version = match.group(1)
        for rule in fingerprint["rules"]:
            if not any(_in_range(version, rng) for rng in rule["ranges"]):
                continue
            key = (fingerprint["product"], rule["cve"])
            if key in seen:
                continue
            seen.add(key)
            evidence = (f"{fingerprint['product']} {version} detected via "
                        f"{fingerprint['source']}; affected by {rule['cve']}")
            if rule.get("note"):
                evidence += f". {rule['note']}"
            out.append(Finding(
                "cve", rule["severity"], rule["title"], r.url,
                evidence=evidence,
                remediation=rule["remediation"],
                phase=6,
            ))
    return out


def check_cache_poison(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    canary = f"cachepoison-{rand_token('', 6)}.example.com"
    r = ctx.http.fetch(ctx.base_url, headers={"X-Forwarded-Host": canary}, follow=False)
    if r and canary in r.text:
        r2 = ctx.http.fetch(ctx.base_url, follow=False)
        if r2 and canary in r2.text:
            out.append(Finding(
                "cache", "high", "Web cache poisoning via X-Forwarded-Host",
                r.url, evidence=f"Canary {canary} persisted in unkeyed cache",
                remediation="Strip X-Forwarded-Host at CDN or include it in the cache key.",
                phase=6,
            ))
    return out


def check_smuggling(ctx: Ctx) -> List[Finding]:
    """CL.TE / TE.CL timing probes using raw sockets."""
    out: List[Finding] = []
    sp = urllib.parse.urlsplit(ctx.base_url)
    if sp.scheme.lower() not in ("http", "https"):
        return out
    host = sp.hostname
    if not host:
        return out
    is_https = sp.scheme.lower() == "https"
    port = sp.port or (443 if is_https else 80)
    path = sp.path or "/"

    probes = {
        "CL.TE": (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 13\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n\r\n"
            f"0\r\n\r\nSMUGGLE_X\r\n"
        ).encode(),
        "TE.CL": (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n\r\n"
            f"5c\r\nGPOST / HTTP/1.1\r\nHost: {host}\r\n\r\n0\r\n\r\n"
        ).encode(),
    }

    for label, payload in probes.items():
        try:
            if is_https:
                sctx = ssl.create_default_context()
                if ctx.args.insecure:
                    sctx.check_hostname = False
                    sctx.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((host, port), timeout=8)
                ssock = sctx.wrap_socket(sock, server_hostname=host)
            else:
                ssock = socket.create_connection((host, port), timeout=8)
            t0 = time.monotonic()
            ssock.sendall(payload)
            try:
                data = ssock.recv(4096)
            except socket.timeout:
                data = b""
            elapsed = time.monotonic() - t0
            ssock.close()
            if elapsed > 4.5 and (not data or b"400" in data or b"408" in data):
                out.append(Finding(
                    "smuggle", "medium",
                    f"Possible HTTP request smuggling ({label})",
                    ctx.base_url, method="POST",
                    evidence=f"probe delayed {elapsed:.1f}s with no/short response",
                    remediation="Normalize Content-Length vs Transfer-Encoding at the edge; "
                                "reject requests with both headers.",
                    phase=6,
                ))
        except (socket.timeout, OSError, ssl.SSLError):
            continue
    return out


def check_tls_config(ctx: Ctx) -> List[Finding]:
    """Real TLS audit: version, cipher, cert expiry."""
    out: List[Finding] = []
    sp = urllib.parse.urlsplit(ctx.base_url)
    if sp.scheme.lower() != "https":
        out.append(Finding(
            "tls", "high", "Target is not using HTTPS",
            ctx.base_url, evidence=f"Scheme: {sp.scheme}",
            remediation="Enforce HTTPS across all application traffic.",
            phase=6,
        ))
        return out

    host = sp.hostname
    port = sp.port or 443
    if not host:
        return out

    try:
        sctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with sctx.wrap_socket(sock, server_hostname=host) as ssock:
                proto = ssock.version() or ""
                cipher = ssock.cipher() or ("unknown", "", 0)
                cert = ssock.getpeercert() or {}

                if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    out.append(Finding(
                        "tls", "high", f"Outdated TLS version negotiated: {proto}",
                        ctx.base_url,
                        evidence=f"Version: {proto}, cipher: {cipher[0]}",
                        remediation="Disable TLS 1.0/1.1; require TLS 1.2 or 1.3.",
                        phase=6,
                    ))

                cipher_name = cipher[0] if cipher else ""
                weak_cipher_re = re.compile(
                    r"(?i)(RC4|DES|3DES|MD5|NULL|EXPORT|anon|RC2)"
                )
                if weak_cipher_re.search(cipher_name):
                    out.append(Finding(
                        "tls", "medium", f"Weak cipher negotiated: {cipher_name}",
                        ctx.base_url, evidence=f"Cipher: {cipher_name}",
                        remediation="Restrict to modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
                        phase=6,
                    ))

                if "notAfter" in cert:
                    expiry = ssl.cert_time_to_seconds(cert["notAfter"])
                    days_left = (expiry - time.time()) / 86400
                    if days_left < 0:
                        out.append(Finding(
                            "tls", "critical", "TLS certificate expired",
                            ctx.base_url,
                            evidence=f"expired {abs(int(days_left))} days ago ({cert['notAfter']})",
                            remediation="Renew TLS certificate immediately.",
                            phase=6,
                        ))
                    elif days_left < 30:
                        out.append(Finding(
                            "tls", "low", f"TLS certificate expires in {int(days_left)} days",
                            ctx.base_url,
                            evidence=f"Expires: {cert['notAfter']}",
                            remediation="Renew TLS certificate.",
                            phase=6,
                        ))
    except ssl.SSLCertVerificationError as e:
        out.append(Finding(
            "tls", "critical", "TLS certificate verification failed",
            ctx.base_url, evidence=str(e)[:200],
            remediation="Fix certificate chain (intermediate certs, valid hostname, trust anchor).",
            phase=6,
        ))
    except Exception:
        pass

    return out


def check_permissions_policy(ctx: Ctx) -> List[Finding]:
    r = ctx.http.fetch(ctx.base_url, follow=True)
    if r and not r.header("Permissions-Policy"):
        return [Finding(
            "headers", "info", "Permissions-Policy header missing",
            r.url, evidence="Header absent; camera/microphone/geolocation unconstrained by policy",
            remediation="Set 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
            phase=6,
        )]
    return []


def check_mixed_content(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    if not ctx.base_url.startswith("https://"):
        return out
    for p in ctx.pages[:10]:
        insecure = re.findall(r"""(?:src|href)=["'](http://[^"'\s>]+)""", p.get("html", ""))
        if insecure:
            out.append(Finding(
                "infra", "low", "Mixed content: insecure HTTP resource referenced",
                p["url"], evidence=f"Found: {', '.join(insecure[:3])}",
                remediation="Serve all subresources (scripts, images, stylesheets) over HTTPS.",
                phase=6,
            ))
            break
    return out


def check_debug_endpoints(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    for p in DEBUG_PATHS[:6]:
        u = ctx.root + p
        r = ctx.http.fetch(u, follow=False)
        if r and r.status == 200 and len(r.body) > 20:
            out.append(Finding(
                "config", "medium", f"Exposed debug / management endpoint: {p}",
                u, evidence=f"HTTP 200 returned: {clip(r.text, 120)}",
                remediation="Disable or restrict debug and monitoring endpoints to internal IPs.",
                phase=6,
            ))
    return out


def check_directory_listing(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    for d in ("/images/", "/uploads/", "/static/", "/assets/", "/files/"):
        u = ctx.root + d
        r = ctx.http.fetch(u, follow=False)
        if r and r.status == 200 and re.search(
                r"(?i)(index of\s+/|directory listing for|<title>index of)", r.text):
            out.append(Finding(
                "config", "medium", f"Directory listing enabled: {d}",
                u, evidence=f"Server returned autoindex listing at {u}",
                remediation="Disable directory browsing in web server configuration (e.g. Options -Indexes).",
                phase=6,
            ))
            break
    return out


def check_cookie_flags(ctx: Ctx) -> List[Finding]:
    """H1-H3: Domain, Path, __Host-/__Secure- prefix audit."""
    out: List[Finding] = []
    r = ctx.http.fetch(ctx.base_url, follow=True)
    if not r:
        return out

    for raw in r.header_all("Set-Cookie"):
        parts = [p.strip() for p in raw.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        domain = None
        path = "/"
        has_secure = False
        for p in parts[1:]:
            lp = p.lower()
            if lp.startswith("domain="):
                domain = p.split("=", 1)[1]
            elif lp.startswith("path="):
                path = p.split("=", 1)[1]
            elif lp == "secure":
                has_secure = True

        if domain and domain.startswith("."):
            out.append(Finding(
                "cookie", "low", f"Cookie '{name}' uses wildcard Domain={domain}",
                r.url, param=name, evidence=f"Domain={domain}",
                remediation="Use host-only cookies (omit Domain) unless cross-subdomain sharing is required.",
                phase=6,
            ))

        if name.startswith("__Host-"):
            if domain:
                out.append(Finding(
                    "cookie", "medium", f"__Host- cookie '{name}' sets Domain",
                    r.url, param=name, evidence=f"Domain={domain}",
                    remediation="__Host- prefix requires: no Domain, Path=/, Secure.",
                    phase=6,
                ))
            if path != "/":
                out.append(Finding(
                    "cookie", "medium", f"__Host- cookie '{name}' Path not /",
                    r.url, param=name, evidence=f"Path={path}",
                    remediation="__Host- prefix requires: no Domain, Path=/, Secure.",
                    phase=6,
                ))
            if not has_secure:
                out.append(Finding(
                    "cookie", "medium", f"__Host- cookie '{name}' missing Secure",
                    r.url, param=name, evidence=raw[:100],
                    remediation="__Host- prefix requires: no Domain, Path=/, Secure.",
                    phase=6,
                ))

        if name.startswith("__Secure-") and not has_secure:
            out.append(Finding(
                "cookie", "medium", f"__Secure- cookie '{name}' missing Secure",
                r.url, param=name, evidence=raw[:100],
                remediation="__Secure- prefix requires the Secure attribute.",
                phase=6,
            ))

    return out


def check_third_party_scripts(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    for p in ctx.pages[:5]:
        html = p.get("html", "")
        scripts = re.findall(
            r"""<script\b[^>]*?\bsrc=["'](https?://[^"'\s>]+)["']([^>]*)>""",
            html, re.I,
        )
        external = [(src, attrs) for src, attrs in scripts
                    if urllib.parse.urlsplit(ctx.base_url).netloc not in src]
        missing_sri = [src for src, attrs in external if "integrity=" not in attrs.lower()]
        if missing_sri:
            out.append(Finding(
                "config", "info",
                "Third-party script loaded without Subresource Integrity (SRI)",
                p["url"], evidence=f"Scripts without integrity: {', '.join(missing_sri[:3])}",
                remediation="Add integrity='sha384-...' to external third-party scripts.",
                phase=6,
            ))
            break
    return out


def check_debug_flags(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    r = ctx.http.fetch(ctx.base_url, follow=True)
    if not r:
        return out

    for h in DEBUG_HEADER_NAMES:
        val = r.header(h)
        if val:
            out.append(Finding(
                "debug", "low", f"Debug header disclosed: {h}",
                r.url, evidence=f"{h}: {val}",
                remediation="Strip debug/informational headers in production.",
                phase=6,
            ))

    for qp in DEBUG_QUERY_PARAMS:
        sep = "&" if "?" in r.url else "?"
        pr = ctx.http.fetch(r.url + sep + qp, follow=True)
        if pr and pr.status == 200 and DEBUG_BODY_MARKERS.search(pr.text[:8000]):
            out.append(Finding(
                "debug", "medium", f"Debug mode activated via query string: {qp}",
                pr.url, evidence="Response contains debug markers "
                                 "(stack trace / framework debug banner)",
                remediation="Disable debug mode in production regardless of query parameters.",
                phase=6,
            ))
            break

    return out


# ============ NEW: HTTP/2 downgrade smuggling ============
def check_h2_smuggling(ctx: Ctx) -> List[Finding]:
    """H2.CL / H2.TE probes via raw HTTP/2 (requires h2 package)."""
    try:
        import importlib
        h2_config = importlib.import_module("h2.config")
        h2_connection = importlib.import_module("h2.connection")
    except ImportError:
        return [Finding(
            "smuggle", "info",
            "HTTP/2 smuggling test skipped (pip install h2)",
            ctx.base_url, confidence="high", phase=6,
        )]

    sp = urllib.parse.urlsplit(ctx.base_url)
    if sp.scheme != "https":
        return []
    host = sp.hostname
    port = sp.port or 443
    if not host:
        return []

    out: List[Finding] = []

    def _probe(extra_headers, body=b"", label=""):
        try:
            cfg = h2_config.H2Configuration(client_side=True)
            conn = h2_connection.H2Connection(config=cfg)
            raw = socket.create_connection((host, port), timeout=10)
            sctx = ssl.create_default_context()
            if ctx.args.insecure:
                sctx.check_hostname = False
                sctx.verify_mode = ssl.CERT_NONE
            sctx.set_alpn_protocols(["h2"])
            sock = sctx.wrap_socket(raw, server_hostname=host)

            conn.initiate_connection()
            sock.sendall(conn.data_to_send())
            sid = conn.get_next_available_stream_id()
            headers = [
                (":method", "POST"), (":scheme", "https"),
                (":authority", host), (":path", "/"),
            ] + extra_headers
            conn.send_headers(sid, headers, end_stream=False)
            if body:
                conn.send_data(sid, body, end_stream=True)
            sock.sendall(conn.data_to_send())

            t0 = time.monotonic()
            data = sock.recv(4096)
            elapsed = time.monotonic() - t0
            sock.close()
            return data, elapsed
        except Exception:
            return None, 0

    # H2.TE: transfer-encoding header is forbidden in H2 but some proxies
    # pass it through to the backend
    data, elapsed = _probe([("transfer-encoding", "chunked"),
                            ("content-length", "6")], b"0\r\n\r\nX")
    if data and elapsed > 4.0:
        out.append(Finding(
            "smuggle", "high",
            "H2.TE downgrade smuggling (proxy passes TE header to backend)",
            ctx.base_url, method="POST",
            evidence=f"probe delayed {elapsed:.1f}s",
            remediation="Reject client-supplied Transfer-Encoding on HTTP/2; "
                        "normalize headers at the edge.",
            confidence="medium", phase=6,
        ))

    # H2.CL: conflicting content-length on H2 (spec violation)
    data, elapsed = _probe([("content-length", "0"),
                            ("content-length", "6")], b"6\r\nX\r\n")
    if data and elapsed > 4.0:
        out.append(Finding(
            "smuggle", "high",
            "H2.CL downgrade smuggling (conflicting Content-Length)",
            ctx.base_url, method="POST",
            evidence=f"probe delayed {elapsed:.1f}s",
            remediation="Reject duplicate Content-Length at the edge.",
            confidence="medium", phase=6,
        ))

    return out


# ============ NEW: web cache deception ============
def check_cache_deception(ctx: Ctx) -> List[Finding]:
    """Append static extensions to auth pages; check if CDN caches the body."""
    customer = get_authed_client(ctx)
    if not customer:
        return []

    out: List[Finding] = []
    suffix_candidates = [
        "/test.css", "/test.js", "/test.png", ";test.css",
        "/test.css?x=1", "/robots.txt",
    ]

    for base in ctx.discovered[:5]:
        if not re.search(r"(?i)(profile|account|dashboard|settings|user|admin)", base):
            continue
        for suffix in suffix_candidates:
            url = base.rstrip("/") + suffix
            r1 = customer.fetch(url, follow=True)
            if r1 is None or r1.status != 200:
                continue

            cache_status = (r1.header("X-Cache") + r1.header("CF-Cache-Status")).lower()
            age = r1.header("Age")
            has_content = bool(re.search(
                r"(?i)(email|phone|account|booking|user_id|order)", r1.text[:5000]))

            if has_content and ("hit" in cache_status or age and age != "0"):
                out.append(Finding(
                    "cache_deception", "high",
                    "Web cache deception on authenticated endpoint",
                    url,
                    evidence=f"Appending `{suffix}` returned {len(r1.body)} bytes "
                             f"of authenticated content with cache headers: "
                             f"X-Cache={cache_status or 'unset'}, "
                             f"Age={age or 'unset'}",
                    remediation="Do not cache responses based on extension. "
                                "Set Cache-Control: no-store on all authenticated "
                                "responses. Normalize paths at the edge.",
                    confidence="medium", phase=6,
                ))
                break
    return out


# ============ NEW: dynamic CORS reflection ============
def check_cors_dynamic(ctx: Ctx) -> List[Finding]:
    """Try multiple origin patterns to detect trust boundary failures."""
    host = ctx.base_url.split("://")[-1].split("/")[0]
    test_origins = [
        "null",
        "https://evil.example",
        "https://attacker.evil.example",
        # Prefix-based bugs: if server allowlists *.target.com by prefix check
        f"https://{host}.evil.example",
        # Suffix bypass
        f"https://evil{host}",
        # Unanchored regex bypass
        "https://target.example.evil.example",
    ]

    out: List[Finding] = []
    for origin in test_origins:
        r = ctx.http.fetch(ctx.base_url, headers={"Origin": origin}, follow=False)
        if r is None:
            continue
        acao = r.header("Access-Control-Allow-Origin")
        acac = r.header("Access-Control-Allow-Credentials").lower() == "true"

        if acao == origin and acac:
            out.append(Finding(
                "cors", "critical",
                f"CORS reflects untrusted origin with credentials",
                ctx.base_url,
                evidence=f"Origin: {origin} → ACAO: {acao}, ACAC: true",
                remediation="Use an exact-match allowlist for origins. "
                            "Never reflect arbitrary Origin when ACAC is true.",
                phase=6,
            ))
        elif acao == origin:
            out.append(Finding(
                "cors", "medium",
                f"CORS reflects untrusted origin",
                ctx.base_url,
                evidence=f"Origin: {origin} → ACAO: {acao}",
                remediation="Use an exact-match allowlist.",
                phase=6,
            ))
        elif acao == "*" and acac:
            out.append(Finding(
                "cors", "high",
                "CORS wildcard with credentials",
                ctx.base_url,
                evidence="ACAO: * and ACAC: true",
                remediation="Remove the wildcard or the credentials flag.",
                phase=6,
            ))
    return out
