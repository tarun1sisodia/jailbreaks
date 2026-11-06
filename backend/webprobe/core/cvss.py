"""CVSS v3.1 and v4.0 base-score calculation from vector strings."""

import math
import re
from typing import Dict, Optional, Tuple


V31_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "N": {"U": 0.85, "C": 0.85},
        "L": {"U": 0.62, "C": 0.68},
        "H": {"U": 0.27, "C": 0.5},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 0.0, "C": 0.0},  # marker
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _parse_v31(vector: str) -> Dict[str, str]:
    m = re.match(r"^CVSS:3\.[01]/", vector)
    if not m:
        raise ValueError("not a CVSS v3.x vector")
    parts = vector[m.end():].split("/")
    return dict(p.split(":", 1) for p in parts if ":" in p)


def _roundup_v31(x: float) -> float:
    return math.ceil(x * 10) / 10.0


def base_v31(vector: str) -> Optional[float]:
    """Compute CVSS v3.1 base score. Returns None on malformed vector."""
    try:
        c = _parse_v31(vector)
    except (ValueError, KeyError):
        return None

    scope_changed = c.get("S") == "C"
    av = V31_WEIGHTS["AV"][c["AV"]]
    ac = V31_WEIGHTS["AC"][c["AC"]]
    pr = V31_WEIGHTS["PR"][c["PR"]]["C" if scope_changed else "U"]
    ui = V31_WEIGHTS["UI"][c["UI"]]
    cia = [V31_WEIGHTS[k][c[k]] for k in ("C", "I", "A")]
    iss = 1.0 - (1.0 - cia[0]) * (1.0 - cia[1]) * (1.0 - cia[2])

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup_v31(min(1.08 * (impact + exploitability), 10.0))
    return _roundup_v31(min(impact + exploitability, 10.0))


def vector_v31(
    av: str = "N", ac: str = "L", pr: str = "N", ui: str = "N",
    scope: str = "U", c: str = "H", i: str = "H", a: str = "H",
) -> str:
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"


# Convenience vectors keyed by vulnerability class
CWE_VECTORS = {
    "sqli": vector_v31(av="N", ac="L", pr="N", ui="N", c="H", i="H", a="H"),
    "cmdi": vector_v31(av="N", ac="L", pr="N", ui="N", c="H", i="H", a="H"),
    "ssti": vector_v31(av="N", ac="L", pr="N", ui="N", c="H", i="H", a="H"),
    "ssrf": vector_v31(av="N", ac="L", pr="N", ui="N", c="H", i="L", a="N"),
    "lfi":  vector_v31(av="N", ac="L", pr="N", ui="N", c="H", i="N", a="N"),
    "xss":  vector_v31(av="N", ac="L", pr="N", ui="R", scope="C", c="L", i="L", a="N"),
    "idor": vector_v31(av="N", ac="L", pr="L", ui="N", c="H", i="N", a="N"),
    "authz": vector_v31(av="N", ac="L", pr="L", ui="N", c="H", i="H", a="N"),
    "jwt": vector_v31(av="N", ac="H", pr="N", ui="N", c="H", i="H", a="H"),
    "csrf": vector_v31(av="N", ac="L", pr="N", ui="R", c="L", i="L", a="N"),
    "headers": vector_v31(av="N", ac="H", pr="N", ui="R", c="L", i="N", a="N"),
    "cors": vector_v31(av="N", ac="L", pr="N", ui="R", c="H", i="N", a="N"),
    "tls": vector_v31(av="N", ac="H", pr="N", ui="N", c="H", i="H", a="N"),
    "race": vector_v31(av="N", ac="H", pr="L", ui="N", c="H", i="H", a="N"),
    "webhook": vector_v31(av="N", ac="L", pr="N", ui="N", c="H", i="H", a="H"),
    "react2shell": vector_v31(av="N", ac="L", pr="N", ui="N", c="H", i="H", a="H"),
    "nextjs-mw": vector_v31(av="N", ac="L", pr="N", ui="N", c="H", i="H", a="H"),
    "supabase-rls": vector_v31(av="N", ac="L", pr="N", ui="N", c="H", i="H", a="N"),
    "smuggle": vector_v31(av="N", ac="H", pr="N", ui="N", c="H", i="H", a="N"),
    "cache": vector_v31(av="N", ac="H", pr="N", ui="R", c="L", i="L", a="N"),
    "recon": vector_v31(av="N", ac="H", pr="N", ui="R", c="L", i="N", a="N"),
}


def score_for_category(category: str) -> Tuple[Optional[float], Optional[str]]:
    vec = CWE_VECTORS.get(category.lower())
    if not vec:
        return None, None
    return base_v31(vec), vec


def severity_from_score(score: float) -> str:
    if score == 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"
