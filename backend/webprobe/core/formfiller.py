"""Classify form inputs and generate syntactically valid synthetic values."""

import re
from typing import Dict, List, Tuple


CLASSIFIERS: List[Tuple[str, re.Pattern]] = [
    ("email", re.compile(r"(?i)(email|e-mail|mail)")),
    ("phone", re.compile(r"(?i)(phone|mobile|tel|whatsapp|contact)")),
    ("first_name", re.compile(r"(?i)(first[_\-]?name|fname|given[_\-]?name)")),
    ("last_name", re.compile(r"(?i)(last[_\-]?name|lname|family[_\-]?name|surname)")),
    ("full_name", re.compile(r"(?i)^(name|full[_\-]?name|your[_\-]?name)$")),
    ("username", re.compile(r"(?i)(user[_\-]?name|login|handle|nick)")),
    ("password", re.compile(r"(?i)(pass(word)?|pwd)")),
    ("address1", re.compile(r"(?i)(address|street|line[_\s]?1)")),
    ("city", re.compile(r"(?i)(city|town)")),
    ("state", re.compile(r"(?i)(state|province|region)")),
    ("country", re.compile(r"(?i)country")),
    ("postal", re.compile(r"(?i)(zip|postal|post[_\-]?code|pin[_\-]?code|pincode)")),
    ("dob", re.compile(r"(?i)(dob|birth|bday|birthday|date[_\-]?of[_\-]?birth)")),
    ("date", re.compile(r"(?i)(date|when|departure|arrival|checkin|checkout|travel[_\-]?date)")),
    ("time", re.compile(r"(?i)(time|hour)")),
    ("url", re.compile(r"(?i)(url|website|link|homepage)")),
    ("age", re.compile(r"(?i)^age$")),
    ("quantity", re.compile(r"(?i)(qty|quantity|guests|rooms|pax|adults|children|persons|travellers|nights)")),
    ("price", re.compile(r"(?i)(price|amount|total|cost|fee)")),
    ("coupon", re.compile(r"(?i)(coupon|promo|voucher|discount)")),
    ("search", re.compile(r"(?i)(search|q|query|keyword)")),
    ("message", re.compile(r"(?i)(message|comment|review|feedback|notes|description|inquiry|query|subject)")),
    ("card", re.compile(r"(?i)(card|credit|pan)")),
    ("csv", re.compile(r"(?i)(cvv|cvc|security[_\-]?code)")),
    ("iban", re.compile(r"(?i)(iban|account[_\-]?number)")),
]


VALUES = {
    "email": "test.user@example.test",
    "phone": "+919876543210",
    "first_name": "Test",
    "last_name": "User",
    "full_name": "Test User",
    "username": "testuser2026",
    "password": "TestPassword@2026!",
    "address1": "1 Test Street",
    "city": "Agra",
    "state": "Uttar Pradesh",
    "country": "IN",
    "postal": "282001",
    "dob": "1990-01-15",
    "date": "2026-06-15",
    "time": "14:30",
    "url": "https://example.test/test",
    "age": "30",
    "quantity": "2",
    "price": "100",
    "coupon": "TESTCODE",
    "search": "test",
    "message": "Automated test inquiry — safe to delete.",
    "card": "4111111111111111",
    "csv": "123",
    "iban": "GB33BUKB20201555555555",
}


def classify(field_name: str, extra_hint: str = "") -> str:
    target = f"{field_name} {extra_hint}"
    for label, pat in CLASSIFIERS:
        if pat.search(target):
            return label
    return "default"


def _fill_by_type(kind: str) -> str:
    return VALUES.get(kind, "test")


def _fill_by_input_type(input_type: str) -> str:
    m = {
        "email": VALUES["email"],
        "tel": VALUES["phone"],
        "number": "2",
        "date": VALUES["date"],
        "time": VALUES["time"],
        "datetime-local": "2026-06-15T14:30",
        "url": VALUES["url"],
        "password": VALUES["password"],
        "checkbox": "on",
        "radio": "on",
    }
    return m.get(input_type.lower(), "")


def synthesize(field_name: str, input_type: str = "text",
               hint: str = "") -> str:
    """Pick the most valid value for a form field."""
    kind = classify(field_name, hint)
    if kind != "default":
        return _fill_by_type(kind)
    return _fill_by_input_type(input_type) or "test"


def fill_form(form: Dict) -> Dict[str, str]:
    """Given a parsed form dict (from crawler.parse_page), synthesize all inputs."""
    filled = {}
    for name, default_value in form.get("inputs", {}).items():
        if default_value:
            filled[name] = default_value
            continue
        filled[name] = synthesize(name)
    return filled
