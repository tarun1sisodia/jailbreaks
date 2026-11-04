"""
HTTP client with rate limiting, cookie tracking, emergency abort, and instability monitoring.
"""

import http.client
import os
import random
import re
import ssl
import string
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from webprobe.core.models import Response


DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 webprobe/3.0"


def rand_token(prefix: str = "", length: int = 10) -> str:
    """Generate a random alphanumeric token with an optional prefix."""
    chars = string.ascii_lowercase + string.digits
    suffix = "".join(random.choice(chars) for _ in range(length))
    return f"{prefix}{suffix}"


def ensure_scheme(url: str, default_scheme: str = "https") -> str:
    """Ensure URL has an http:// or https:// scheme."""
    if not url:
        return ""
    if not re.match(r"^https?://", url, re.I):
        return f"{default_scheme}://{url}"
    return url


def strip_fragment(url: str) -> str:
    """Remove URL fragment (#...)."""
    if not url:
        return ""
    sp = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path, sp.query, ""))


class RateLimiter:
    """Enforces minimum interval between consecutive requests."""

    def __init__(self, rps: float = 0.0):
        self.rps = float(rps) if rps else 0.0
        self.min_interval = (1.0 / self.rps) if self.rps > 0 else 0.0
        self._last = 0.0
        self._lock = threading.Lock()

    def throttle(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._last + self.min_interval - now
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()


class HttpClient:
    """
    Production-grade HTTP client implementing:
    - Session and cookie management
    - Rate-limiting throttle
    - Emergency abort checks
    - Instability monitoring (5xx tracking)
    - Automatic redirection and SSL configuration
    """

    def __init__(
        self,
        cookie: str = "",
        rps: float = 0.0,
        timeout: float = 12.0,
        insecure: bool = False,
        verbose: bool = False,
        headers: Optional[Dict[str, str]] = None,
        abort_fn: Optional[Callable[[], bool]] = None,
        instability: Optional[Any] = None,
        activity: Optional[Any] = None,
    ):
        self.cookie = cookie or ""
        self.rps = float(rps) if rps else 0.0
        self.timeout = float(timeout) if timeout else 12.0
        self.insecure = insecure
        self.verbose = verbose
        self.custom_headers = dict(headers or {})
        self._abort_fn = abort_fn
        self.instability = instability
        self.activity = activity

        self.min_interval = (1.0 / self.rps) if self.rps > 0 else 0.0
        self._rl_last = 0.0
        self._rl_lock = threading.Lock()

        # Cookie jar storing dict: {cookie_name: cookie_value}
        self.cookies: Dict[str, str] = {}
        if self.cookie:
            self._parse_cookie_header(self.cookie)

        # SSL context
        if self.insecure:
            self.ssl_ctx = ssl._create_unverified_context()
        else:
            try:
                self.ssl_ctx = ssl.create_default_context()
            except Exception:
                self.ssl_ctx = ssl._create_unverified_context()

    def _parse_cookie_header(self, header_val: str) -> None:
        for part in header_val.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                self.cookies[k.strip()] = v.strip()

    def _get_cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def _throttle(self) -> None:
        if self.min_interval <= 0:
            return
        with self._rl_lock:
            now = time.monotonic()
            wait = self._rl_last + self.min_interval - now
            if wait > 0:
                time.sleep(wait)
            self._rl_last = time.monotonic()

    def _abort_check(self) -> bool:
        f = getattr(self, "_abort_fn", None)
        return bool(f and f())

    def clone(self, cookie: Optional[str] = None) -> "HttpClient":
        """Create an isolated client instance sharing rate limits and abort checks."""
        c = HttpClient(
            cookie=self.cookie if cookie is None else cookie,
            rps=self.rps,
            timeout=self.timeout,
            insecure=self.insecure,
            verbose=self.verbose,
            headers=dict(self.custom_headers),
            abort_fn=self._abort_fn,
            instability=self.instability,
            activity=self.activity,
        )
        return c

    def fetch(
        self,
        url: str,
        method: str = "GET",
        data: Any = None,
        headers: Optional[Dict[str, str]] = None,
        follow: bool = True,
        timeout: Optional[float] = None,
    ) -> Optional[Response]:
        """Public fetch method wrapping throttle, abort, and instability monitoring."""
        if self._abort_check():
            raise SystemExit(3)
        self._throttle()
        resp = self._fetch_inner(url, method, data, headers, follow, timeout)
        if resp is not None and self.instability is not None:
            self.instability.observe(resp.status)
        return resp

    def _fetch_inner(
        self,
        url: str,
        method: str = "GET",
        data: Any = None,
        headers: Optional[Dict[str, str]] = None,
        follow: bool = True,
        timeout: Optional[float] = None,
        redirect_depth: int = 0,
    ) -> Optional[Response]:
        """Inner fetch executing network call using standard library urllib/http.client."""
        if redirect_depth > 6:
            return None

        url = ensure_scheme(url)
        method = method.upper()
        req_headers: Dict[str, str] = {
            "User-Agent": DEFAULT_UA,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        req_headers.update(self.custom_headers)
        if headers:
            req_headers.update(headers)

        cookie_str = self._get_cookie_header()
        if cookie_str and "Cookie" not in req_headers:
            req_headers["Cookie"] = cookie_str

        encoded_data = None
        if data is not None:
            if isinstance(data, bytes):
                encoded_data = data
            elif isinstance(data, str):
                encoded_data = data.encode("utf-8")
            elif isinstance(data, dict):
                encoded_data = urllib.parse.urlencode(data).encode("utf-8")
                if "Content-Type" not in req_headers:
                    req_headers["Content-Type"] = "application/x-www-form-urlencoded"

        effective_timeout = timeout if timeout is not None else self.timeout

        parsed = urllib.parse.urlsplit(url)
        is_https = parsed.scheme.lower() == "https"
        host = parsed.netloc
        port = parsed.port or (443 if is_https else 80)
        netloc_clean = parsed.hostname or host
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        try:
            if is_https:
                conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                    netloc_clean, port=port, timeout=effective_timeout, context=self.ssl_ctx
                )
            else:
                conn = http.client.HTTPConnection(
                    netloc_clean, port=port, timeout=effective_timeout
                )

            conn.request(method, path, body=encoded_data, headers=req_headers)
            res = conn.getresponse()
            raw_body = res.read()
            status = res.status
            raw_headers = res.getheaders()
            conn.close()

            # Normalize headers dict
            headers_dict = {k.lower(): v for k, v in raw_headers}

            # Update cookies from Set-Cookie
            for k, v in raw_headers:
                if k.lower() == "set-cookie":
                    cookie_part = v.split(";")[0]
                    if "=" in cookie_part:
                        ck, cv = cookie_part.split("=", 1)
                        self.cookies[ck.strip()] = cv.strip()

            resp = Response(
                status=status,
                url=url,
                headers=headers_dict,
                raw_headers=raw_headers,
                body=raw_body,
            )

            # Handle redirects
            if follow and status in (301, 302, 303, 307, 308):
                location = headers_dict.get("location")
                if location:
                    new_url = urllib.parse.urljoin(url, location)
                    new_method = "GET" if status in (301, 302, 303) and method != "HEAD" else method
                    return self._fetch_inner(
                        new_url,
                        method=new_method,
                        data=None if new_method == "GET" else data,
                        headers=headers,
                        follow=True,
                        timeout=timeout,
                        redirect_depth=redirect_depth + 1,
                    )

            return resp

        except Exception:
            return None


def build_multipart(fields: Dict[str, Any], files: Dict[str, Tuple[str, bytes, str]]) -> Tuple[bytes, str]:
    """
    Build multipart/form-data body and Content-Type header.
    files: {field_name: (filename, content_bytes, content_type)}
    """
    boundary = "----wp" + rand_token("", 14)
    body = b""
    for name, value in fields.items():
        body += f"--{boundary}\r\n".encode()
        body += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        body += str(value).encode() + b"\r\n"
    for name, (fname, content, mime) in files.items():
        body += f"--{boundary}\r\n".encode()
        body += (
            f'Content-Disposition: form-data; name="{name}"; filename="{fname}"\r\n'
        ).encode()
        body += f"Content-Type: {mime}\r\n\r\n".encode()
        body += content + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"

