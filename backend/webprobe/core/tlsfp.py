"""TLS Client Hello spoofing to bypass JA3/JA4 WAF fingerprinting.

Uses curl_cffi when installed (mirrors real Chrome/Firefox handshakes).
Falls back to stdlib urllib with a clear warning.
"""

from typing import Any, Dict, Optional


def _try_curl_cffi():
    try:
        from curl_cffi import requests as curl_requests  # type: ignore
        return curl_requests
    except ImportError:
        return None


BROWSER_PROFILES = [
    "chrome120", "chrome119", "chrome110",
    "firefox120", "safari17_0", "edge101",
]


class TLSClient:
    """Wrapper that prefers curl_cffi (browser-like TLS) and falls back to urllib."""

    def __init__(self, impersonate: str = "chrome120", proxy: Optional[str] = None,
                 timeout: float = 15.0, insecure: bool = False):
        self.curl = _try_curl_cffi()
        self.impersonate = impersonate
        self.proxy = proxy
        self.timeout = timeout
        self.insecure = insecure
        self.available = self.curl is not None

    def fetch(self, url: str, method: str = "GET", data: Any = None,
              headers: Optional[Dict[str, str]] = None) -> Optional[Any]:
        if not self.available:
            # Fallback: defer to stdlib urllib (same behaviour as HttpClient)
            import urllib.request
            req = urllib.request.Request(url, data=data, method=method,
                                        headers=headers or {})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return r.read(), r.status, dict(r.headers)
            except Exception:
                return None

        kwargs: Dict[str, Any] = {
            "impersonate": self.impersonate,
            "timeout": self.timeout,
            "verify": not self.insecure,
        }
        if self.proxy:
            kwargs["proxies"] = {"http": self.proxy, "https": self.proxy}
        try:
            resp = self.curl.request(
                method.upper(), url, headers=headers or {},
                data=data, **kwargs,
            )
            return resp.content, resp.status_code, dict(resp.headers)
        except Exception:
            return None

    def status(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "impersonate": self.impersonate,
            "backend": "curl_cffi" if self.available else "urllib",
        }
