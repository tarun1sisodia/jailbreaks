"""Deterministic scrubbing of PII, secrets, and payment data from evidence."""

import hashlib
import re
from typing import Any, Dict, Tuple


REDACTION_TOKEN = "[REDACTED:{}]"

PATTERNS: Dict[str, re.Pattern] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "phone_intl": re.compile(r"\+?\d{1,3}[\s\-.]?\(?\d{2,4}\)?[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}"),
    "aadhaar": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
    "pan": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "cvv": re.compile(r"\b(?:cvv|cvc|security.?code)['\"]?\s*[:=]\s*['\"]?(\d{3,4})", re.I),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "stripe_key": re.compile(r"(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{20,}"),
    "razorpay_key": re.compile(r"rzp_(?:live|test)_[0-9A-Za-z]{10,}"),
    "bearer_token": re.compile(r"Bearer\s+([A-Za-z0-9._\-]{20,})", re.I),
    "password_field": re.compile(r"(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{4,})['\"]"),
    "supabase_anon": re.compile(r"sb-[a-z\-]*token=[A-Za-z0-9._\-]{20,}"),
}


def _hash_hint(original: str) -> str:
    digest = hashlib.sha256(original.encode()).hexdigest()[:8]
    return digest


def _redact_match(kind: str, m: re.Match) -> str:
    full = m.group(0)
    # Show first/last 2 chars + hash so evidence remains recognizable
    if len(full) <= 6:
        return REDACTION_TOKEN.format(kind)
    hint = f"{full[:2]}…{full[-2:]}"
    return f"[REDACTED:{kind}:{hint}:h{_hash_hint(full)}]"


def redact_text(text: str, kinds: Tuple[str, ...] = None) -> str:
    """Return text with configured sensitive patterns masked."""
    if not text:
        return text
    kinds = kinds or tuple(PATTERNS.keys())
    out = text
    for kind in kinds:
        pat = PATTERNS.get(kind)
        if not pat:
            continue
        out = pat.sub(lambda m, k=kind: _redact_match(k, m), out)
    return out


def redact_dict(obj: Any, kinds: Tuple[str, ...] = None) -> Any:
    """Recursively redact strings in any JSON-serializable object."""
    if isinstance(obj, str):
        return redact_text(obj, kinds)
    if isinstance(obj, dict):
        return {k: redact_dict(v, kinds) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_dict(v, kinds) for v in obj]
    return obj


def redact_finding(finding) -> None:
    """Redact a Finding in place. Preserves field types."""
    for attr in ("evidence", "payload", "url", "param"):
        try:
            current = getattr(finding, attr, "")
            if isinstance(current, str) and current:
                setattr(finding, attr, redact_text(current))
        except AttributeError:
            pass
    if hasattr(finding, "extra") and isinstance(finding.extra, dict):
        finding.extra = redact_dict(finding.extra)
