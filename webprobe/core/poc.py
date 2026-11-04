"""Serialize each finding's exact request/response bytes for replay."""

import base64
import json
from typing import Any, Dict, Optional


MAX_BODY = 4096


def _trunc(body: bytes) -> str:
    if len(body) <= MAX_BODY:
        return body.decode("utf-8", errors="replace")
    head = body[:MAX_BODY].decode("utf-8", errors="replace")
    return head + f"\n... [{len(body) - MAX_BODY} more bytes]"


def _curl_command(method: str, url: str, headers: Dict[str, str],
                  body: bytes) -> str:
    parts = [f"curl -X {method.upper()}"]
    for k, v in headers.items():
        if k.lower() == "cookie":
            v = v.split("=")[0] + "=<REDACTED>"
        parts.append(f"-H {json.dumps(f'{k}: {v}')}")
    if body:
        parts.append(f"--data-raw {json.dumps(_trunc(body)[:400])}")
    parts.append(json.dumps(url))
    return " ".join(parts)


def build_poc(request: Any, response: Optional[Any], finding: Any) -> Dict:
    """Convert a captured request/response pair into a reproducible PoC blob."""
    headers = dict(getattr(request, "headers", {}) or {})
    body = getattr(request, "body", b"") or b""
    if isinstance(body, str):
        body = body.encode()

    poc = {
        "request": {
            "method": getattr(request, "method", "GET"),
            "url": getattr(request, "url", ""),
            "headers": headers,
            "body_base64": base64.b64encode(body).decode() if body else "",
            "body_text": _trunc(body),
        },
        "response": None,
        "curl": _curl_command(
            getattr(request, "method", "GET"),
            getattr(request, "url", ""),
            headers,
            body,
        ),
        "test": {
            "category": getattr(finding, "category", ""),
            "title": getattr(finding, "title", ""),
            "phase": getattr(finding, "phase", 0),
            "severity": getattr(finding, "severity", ""),
        },
    }

    if response is not None:
        resp_headers = dict(getattr(response, "headers", {}) or {})
        resp_body = getattr(response, "body", b"") or b""
        poc["response"] = {
            "status": getattr(response, "status", 0),
            "headers": resp_headers,
            "body_base64": base64.b64encode(resp_body).decode() if resp_body else "",
            "body_text": _trunc(resp_body),
        }
    return poc


def attach_to_finding(finding: Any, poc: Dict) -> None:
    finding.extra = getattr(finding, "extra", {})
    finding.extra["poc"] = poc
