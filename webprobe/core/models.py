"""
Core data models for webprobe security testing engine.
"""

import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Finding:
    category: str
    severity: str  # critical, high, medium, low, info
    title: str
    url: str
    evidence: str = ""
    remediation: str = ""
    phase: int = 0
    param: str = ""
    method: str = ""
    payload: str = ""
    poc: Optional[Dict[str, Any]] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        category: str,
        severity: str,
        title: str,
        url: str,
        *args: Any,
        evidence: str = "",
        remediation: str = "",
        phase: int = 0,
        param: str = "",
        method: str = "",
        payload: str = "",
        poc: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ):
        self.category = category
        self.severity = severity
        self.title = title
        self.url = url
        # Handle positional args if passed like (category, sev, title, action, method, target, payload)
        if len(args) >= 1 and not method:
            self.method = str(args[0])
        if len(args) >= 2 and not param:
            self.param = str(args[1])
        if len(args) >= 3 and not payload:
            self.payload = str(args[2])

        self.evidence = evidence
        self.remediation = remediation
        self.phase = phase
        if param:
            self.param = param
        if method:
            self.method = method
        if payload:
            self.payload = payload
        self.poc = poc
        self.extra = kwargs
        self._enrich()

    def _enrich(self) -> None:
        """Populate CVSS and taxonomy information."""
        try:
            from webprobe.core import cvss, taxonomy
            if "cvss" not in self.extra:
                score, vector = cvss.score_for_category(self.category)
                self.extra["cvss"] = {"score": score, "vector": vector}
            if "taxonomy" not in self.extra:
                entry = taxonomy.lookup(self.category)
                self.extra["taxonomy"] = {
                    "cwe": entry.get("cwe", ""),
                    "owasp": entry.get("owasp", ""),
                    "pci": entry.get("pci", []),
                }
        except Exception:
            pass

    def __post_init__(self) -> None:
        self._enrich()

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "url": self.url,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "phase": self.phase,
            "param": self.param,
            "method": self.method,
            "payload": self.payload,
        }
        if self.poc is not None:
            d["poc"] = self.poc
        if self.extra:
            d["extra"] = self.extra
        return d


@dataclass
class Response:
    status: int
    url: str
    headers: Dict[str, str]
    raw_headers: List[Tuple[str, str]]
    body: bytes
    text: str = ""
    content_type: str = ""
    elapsed: float = 0.0
    received_at: float = 0.0

    def __post_init__(self) -> None:
        if not self.received_at:
            self.received_at = time.time()
        if not self.text and self.body:
            try:
                self.text = self.body.decode("utf-8", errors="replace")
            except Exception:
                self.text = ""
        if not self.content_type:
            self.content_type = self.header("content-type")

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def header_all(self, name: str) -> List[str]:
        target = name.lower()
        return [v for k, v in self.raw_headers if k.lower() == target]


@dataclass
class Point:
    url: str
    method: str
    param: str
    param_type: str  # "query", "body", "json"
    orig_value: str
    params: Dict[str, str] = field(default_factory=dict)
    form_meta: Optional[Dict[str, Any]] = None

    @property
    def action(self) -> str:
        return self.url

    @property
    def target(self) -> str:
        return self.param

    def send(self, http: Any, payload: str, extra_headers: Optional[Dict[str, str]] = None) -> Optional[Response]:
        """Send a test request injecting the payload at this point's target parameter."""
        test_params = dict(self.params)
        test_params[self.target] = payload

        t0 = time.monotonic()
        if self.method == "POST":
            resp = http.fetch(
                self.url,
                method="POST",
                data=test_params,
                headers=extra_headers,
                follow=True,
            )
        else:
            sep = "&" if "?" in self.url else "?"
            qs = urllib.parse.urlencode(test_params)
            target_url = f"{self.url}{sep}{qs}" if qs else self.url
            resp = http.fetch(
                target_url,
                method="GET",
                headers=extra_headers,
                follow=True,
            )
        if resp is not None:
            resp.elapsed = time.monotonic() - t0
        return resp


@dataclass
class RoleMatrix:
    endpoint: str
    method: str
    roles: Dict[str, int] = field(default_factory=dict)


@dataclass
class Ctx:
    http: Any  # HttpClient
    args: Any  # argparse.Namespace
    base_url: str
    collab: Optional[Any] = None
    tech: Dict[str, Any] = field(default_factory=dict)
    pages: List[Dict[str, Any]] = field(default_factory=list)
    discovered: List[str] = field(default_factory=list)
    discovered_extra: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    tokens: List[Tuple[str, str]] = field(default_factory=list)
    root: str = ""
    extra_seeds: List[str] = field(default_factory=list)
    extra_discovered: List[str] = field(default_factory=list)
    source_maps: List[str] = field(default_factory=list)
    hidden_params: List[Tuple[str, str]] = field(default_factory=list)
    external_hosts: List[str] = field(default_factory=list)
    activity: Optional[Any] = None  # ActivityLog
    instability: Optional[Any] = None  # InstabilityMonitor
    login_form: Optional[Dict[str, Any]] = None
    login_page_url: str = ""
    authed_client: Optional[Any] = None
