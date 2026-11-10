#!/usr/bin/env python3
"""Normalize the framework CVE pull into a lookupable matrix.

Input : reports/framework_cves.json  (produced by fetch_framework_cves.py)
Output: reports/framework_cve_matrix.json
        reports/framework_cves.csv
        reports/cve/<package>.md
        reports/FRAMEWORK-CVE-MATRIX.md

The matrix keeps the NVD facts (CVE ID, severity, CVSS, CWE, affected
ranges, references) and adds three derived fields that are clearly marked
as derived:

  location  - component/endpoint named in the NVD description
  impact    - short impact label taken from the NVD description/CWE
  exploit   - CISA KEV / public-PoC references found in the NVD references

Nothing here sends traffic. This is a research and reporting helper.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "reports" / "framework_cves.json"
KEV = REPO / "reports" / "cisa_kev.json"
OUT_JSON = REPO / "reports" / "framework_cve_matrix.json"
OUT_CSV = REPO / "reports" / "framework_cves.csv"
OUT_MD = REPO / "reports" / "FRAMEWORK-CVE-MATRIX.md"
OUT_DIR = REPO / "reports" / "cve"

PACKAGES = {
    "Next.js": {
        "package": "next.js",
        "aliases": ["next", "nextjs", "next.js"],
        "ecosystem": "npm",
        "cpe": "cpe:2.3:a:vercel:next.js",
    },
    "React": {
        "package": "react",
        "aliases": [
            "react", "react-dom", "react-server-dom-webpack",
            "react-server-dom-parcel", "react-server-dom-turbopack",
        ],
        "ecosystem": "npm",
        "cpe": "cpe:2.3:a:facebook:react",
    },
    "PHP": {
        "package": "php",
        "aliases": ["php"],
        "ecosystem": "php",
        "cpe": "cpe:2.3:a:php:php",
    },
    "ASP.NET Core": {
        "package": "aspnetcore",
        "aliases": [
            "aspnetcore", "asp.net core", "microsoft.aspnetcore",
            "microsoft.aspnetcore.app", "microsoft.aspnetcore.mvc",
            "microsoft.aspnetcore.kestrel",
        ],
        "ecosystem": "nuget",
        "cpe": "cpe:2.3:a:microsoft:asp.net_core",
    },
    ".NET": {
        "package": "dotnet",
        "aliases": [
            "dotnet", ".net", "microsoft.netcore.app",
            "microsoft.netcore.app.runtime", "microsoft.aspnetcore.app.runtime",
        ],
        "ecosystem": "nuget",
        "cpe": "cpe:2.3:a:microsoft:.net",
    },
}

# Ordered from most specific to most general. The first two matches are
# kept so the "where" column stays readable.
LOCATION_PATTERNS: list[tuple[str, str]] = [
    (r"x-middleware-subrequest|middleware", "middleware authorization"),
    (r"server action|server function", "Server Actions / Server Function endpoint"),
    (r"/_next/image|image optimization", "Image Optimization API (/_next/image)"),
    (r"react server components|\brsc\b|flight", "React Server Components payload handling"),
    (r"partial prerendering|next-resume|\bppr\b", "Partial Prerendering / postponed state"),
    (r"websocket", "WebSocket upgrade handling"),
    (r"i18n|locale", "i18n routing"),
    (r"rewrites?", "rewrites/proxy routing"),
    (r"next dev|development server", "development server"),
    (r"cache|cdn", "response cache / CDN"),
    (r"kestrel|\bquic\b|http/3", "Kestrel HTTP/3 (QUIC)"),
    (r"signalr", "SignalR"),
    (r"cookie", "cookie parsing / authentication"),
    (r"soapserver|\bsoap\b", "SOAP extension / SoapServer"),
    (r"pdo::quote|pdo_", "PDO driver"),
    (r"firebird", "PDO Firebird driver"),
    (r"postgres", "PDO PostgreSQL driver"),
    (r"sqlite", "PDO SQLite driver"),
    (r"ldap_escape|\bldap\b", "LDAP extension"),
    (r"mbstring|mb_[a-z_]+", "mbstring extension"),
    (r"proc_open", "proc_open() on Windows"),
    (r"php-cgi|cgi\.force_redirect", "PHP-CGI"),
    (r"brotli", "Brotli decoder"),
    (r"\bDOMNode\b|XML (?:parser|document|data)|libxml", "XML/DOM parser"),
    (r"redirect location|url truncation", "HTTP redirect / Location header handling"),
    (r"asp\.net core", "ASP.NET Core request pipeline"),
    (r"\.net framework", ".NET Framework runtime"),
    (r"\.net core|\.net runtime|\.net 8|\.net 9|\.net 10", ".NET runtime"),
]

IMPACT_PATTERNS: list[tuple[str, str]] = [
    ("RCE", r"remote code execution|arbitrary (?:php )?code|execute code|"
            r"command injection|code injection|buffer overflow|out-of-bounds write|"
            r"use-after-free|type confusion"),
    ("Auth bypass", r"bypass.*(authorization|authentication)|authorization bypass|"
                    r"authentication bypass|security feature bypass|"
                    r"incorrect authorization|improper authorization"),
    ("SQL injection", r"sql injection"),
    ("XSS", r"cross-site scripting|\bxss\b"),
    ("SSRF", r"server-side request forgery|\bssrf\b"),
    ("Request smuggling", r"request/response smuggling|request smuggling"),
    ("Cache poisoning", r"cache poisoning"),
    ("Redirect manipulation", r"redirect location|url truncation|"
                              r"redirecting to a wrong location"),
    ("Open redirect", r"open redirect"),
    ("Path traversal", r"path traversal|directory traversal"),
    ("DoS", r"denial of service|denial-of-service|resource consumption|"
            r"infinite loop|crash|excessive (cpu|memory)|connection exhaustion|"
            r"exhaust (?:worker|server|process)|hang"),
    ("Info disclosure", r"information disclosure|source code exposure|"
                        r"source code|disclose|information leak|leak"),
    ("Privilege escalation", r"elevation of privilege|privilege escalation"),
    ("Spoofing", r"spoofing"),
    ("Tampering", r"tampering"),
]

# Vendor advisories that correct or supersede the NVD CPE ranges. Keep this
# short and evidence-based; the NVD ranges stay in the matrix unchanged.
VENDOR_NOTES = {
    "CVE-2025-55182": (
        "React advisory: fixed in react-server-dom-* 19.0.1 / 19.1.2 / 19.2.1. "
        "Next.js final fixed releases: 14.2.35, 15.0.8, 15.1.12, 15.2.9, "
        "15.3.9, 15.4.11, 15.5.10, 16.0.11, 16.1.5. NVD's Next.js upper "
        "bounds (15.0.5, 15.1.9, ...) are the initial patches."
    ),
    "CVE-2025-55184": (
        "Intermediate patches 19.0.2 / 19.1.3 / 19.2.2 were incomplete. "
        "React advisory final fixed versions: 19.0.4 / 19.1.5 / 19.2.4."
    ),
    "CVE-2025-67779": (
        "Final fixed versions: 19.0.4 / 19.1.5 / 19.2.4."
    ),
    "CVE-2026-23864": (
        "Final fixed versions: 19.0.4 / 19.1.5 / 19.2.4."
    ),
    "CVE-2025-1861": (
        "NVD CPE upper bounds conflict with the PHP advisory. Vendor patched "
        "versions: 8.1.32, 8.2.28, 8.3.19, 8.4.5."
    ),
}

ENDPOINT_RE = re.compile(
    r"(?<![\w.])"
    r"(/(?:_next|api|secure|ViewUserHover|QueryComponent|login|admin|"
    r"wp-[a-z]+|xmlrpc|soap|graphql|signalr|identity|account|oauth)"
    r"[A-Za-z0-9_./{}<>!$'\"-]*)"
)


def version_key(value: str) -> tuple[int, ...]:
    """Parse a dotted version into a comparable tuple.

    Handles 8.2.35, 4.8.04690.02 and 19.0.0. Prerelease suffixes are
    ignored for range matching; they are kept separately in the JSON.
    """
    parts = [int(p) for p in re.findall(r"\d+", value or "")[:4]]
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts)


def cpe_parts(criteria: str) -> list[str]:
    return criteria.split(":")


def cpe_version(criteria: str) -> tuple[str, str]:
    parts = cpe_parts(criteria)
    if len(parts) < 7:
        return "", ""
    return parts[5], parts[6]


def norm_range(low: str | None, high: str | None,
               low_exclusive: bool = False,
               high_exclusive: bool = False) -> dict[str, Any]:
    return {
        "low": low or "",
        "high": high or "",
        "low_exclusive": bool(low_exclusive),
        "high_exclusive": bool(high_exclusive),
    }


def range_label(r: dict[str, Any]) -> str:
    if r.get("exact"):
        return f"={r['exact']}"
    low, high = r.get("low", ""), r.get("high", "")
    if low and high:
        op_low = ">" if r.get("low_exclusive") else ">="
        op_high = "<" if r.get("high_exclusive") else "<="
        return f"{op_low}{low} {op_high}{high}"
    if low:
        return f"{'>' if r.get('low_exclusive') else '>='}{low}"
    if high:
        return f"{'<' if r.get('high_exclusive') else '<='}{high}"
    return "*"


def normalize_ranges(item: dict[str, Any], cpe_prefix: str) -> tuple[list[dict], list[dict]]:
    ranges: list[dict] = []
    prereleases: list[dict] = []
    for raw in item.get("ranges", []):
        criteria = raw.get("criteria", "")
        if not criteria.startswith(cpe_prefix):
            continue
        low = raw.get("start_including") or raw.get("start_excluding")
        high = raw.get("end_including") or raw.get("end_excluding")
        if low or high:
            ranges.append(norm_range(
                low,
                high,
                low_exclusive=bool(raw.get("start_excluding")),
                high_exclusive=bool(raw.get("end_excluding")),
            ))
            continue
        version, update = cpe_version(criteria)
        if version in ("", "*", "-"):
            continue
        if update not in ("", "*", "-"):
            prereleases.append({"exact": f"{version}-{update}"})
        else:
            ranges.append({"exact": version})
    # Deduplicate while preserving order.
    def dedupe(items: list[dict]) -> list[dict]:
        seen = set()
        out = []
        for item in items:
            key = json.dumps(item, sort_keys=True)
            if key not in seen:
                seen.add(key)
                out.append(item)
        return out
    ranges = dedupe(ranges)
    ranges.sort(key=lambda r: (version_key(r.get("low") or r.get("exact") or "0"),
                               version_key(r.get("high") or r.get("exact") or "0")))
    return ranges, dedupe(prereleases)


def fixed_versions(ranges: list[dict]) -> list[str]:
    fixed = set()
    for r in ranges:
        if r.get("exact"):
            continue
        if r.get("high") and r.get("high_exclusive"):
            fixed.add(r["high"])
    return sorted(fixed, key=version_key)


def classify_location(description: str) -> str:
    found: list[str] = []
    for pattern, label in LOCATION_PATTERNS:
        if re.search(pattern, description, re.I) and label not in found:
            found.append(label)
    for endpoint in ENDPOINT_RE.findall(description):
        endpoint = endpoint.rstrip(".,;:)")
        if endpoint not in found:
            found.append(endpoint)
    return "; ".join(found[:3]) or "see NVD description"


def classify_component(description: str) -> str:
    """Name the concrete npm package when NVD groups several under React."""
    low = description.lower()
    if "react-server-dom" in low:
        return "react-server-dom-*"
    if "reactdomserver" in low or "react-dom" in low:
        return "react-dom/server"
    return ""


def classify_impact(description: str, cwes: list[str]) -> str:
    found: list[str] = []
    for label, pattern in IMPACT_PATTERNS:
        if re.search(pattern, description, re.I) and label not in found:
            found.append(label)
    if not found:
        for cwe in cwes:
            if cwe in ("CWE-79",):
                found.append("XSS")
            elif cwe in ("CWE-89",):
                found.append("SQL injection")
            elif cwe in ("CWE-918",):
                found.append("SSRF")
            elif cwe in ("CWE-502",):
                found.append("RCE")
            elif cwe in ("CWE-400", "CWE-770", "CWE-834"):
                found.append("DoS")
    return ", ".join(found[:2]) or "see NVD description"


def load_kev() -> dict[str, dict[str, Any]]:
    if not KEV.exists():
        return {}
    payload = json.loads(KEV.read_text(encoding="utf-8"))
    return {v["cveID"]: v for v in payload.get("vulnerabilities", [])}


def exploit_info(item: dict[str, Any],
                 kev: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    refs = item.get("references", [])
    desc = item.get("description", "").lower()
    kev_entry = (kev or {}).get(item.get("id", ""))
    known = bool(kev_entry) or \
        any("known-exploited" in r.lower() for r in refs) or \
        "exploited in the wild" in desc or "actively exploited" in desc
    poc: list[str] = []
    for ref in refs:
        low = ref.lower()
        if any(x in low for x in ("exploit-db.com", "packetstormsecurity",
                                  "metasploit", "rapid7.com/db")):
            poc.append(ref)
            continue
        if "github.com" not in low:
            continue
        if any(x in low for x in ("/security/advisories/", "/commit/",
                                  "/pull/", "/releases/", "/issues/",
                                  "/blob/", "/tree/", "/compare/")):
            continue
        if re.search(r"cve-\d{4}-\d+|poc|exploit", low):
            poc.append(ref)
    out = {"known_exploited": known, "public_poc": poc[:5]}
    if kev_entry:
        out["kev"] = {
            "date_added": kev_entry.get("dateAdded", ""),
            "due_date": kev_entry.get("dueDate", ""),
            "required_action": kev_entry.get("requiredAction", ""),
            "known_ransomware": kev_entry.get("knownRansomwareCampaignUse", ""),
            "vendor_project": kev_entry.get("vendorProject", ""),
            "product": kev_entry.get("product", ""),
        }
    return out


def build() -> dict[str, Any]:
    payload = json.loads(SRC.read_text(encoding="utf-8"))
    kev = load_kev()
    out: dict[str, Any] = {
        "generated": payload.get("generated", ""),
        "source": "NVD 2.0 API via scripts/fetch_framework_cves.py",
        "kev_source": "CISA Known Exploited Vulnerabilities catalog",
        "kev_catalog_version": (json.loads(KEV.read_text(encoding="utf-8"))
                                .get("catalogVersion", "")
                                if KEV.exists() else ""),
        "note": "Derived fields location/impact/exploit are labelled; "
                "everything else is copied from NVD.",
        "packages": {},
    }
    for label, meta in PACKAGES.items():
        target = payload.get("targets", {}).get(label)
        if not target:
            continue
        items = []
        for raw in target.get("items", []):
            ranges, prereleases = normalize_ranges(raw, meta["cpe"])
            desc = raw.get("description", "")
            items.append({
                "cve": raw["id"],
                "package": meta["package"],
                "ecosystem": meta["ecosystem"],
                "severity": raw.get("severity", "unknown"),
                "score": raw.get("score", 0.0),
                "cvss": raw.get("cvss", {}),
                "published": (raw.get("published") or "")[:10],
                "cwe": raw.get("cwe", []),
                "description": desc,
                "affected": ranges,
                "affected_labels": [range_label(r) for r in ranges],
                "fixed": fixed_versions(ranges),
                "vendor_note": VENDOR_NOTES.get(raw["id"], ""),
                "prerelease_versions": prereleases,
                "location": classify_location(desc),
                "component": classify_component(desc),
                "impact": classify_impact(desc, raw.get("cwe", [])),
                "exploit": exploit_info(raw, kev),
                "references": raw.get("references", []),
            })
        items.sort(key=lambda x: (x["published"], x["cve"]), reverse=True)
        out["packages"][meta["package"]] = {
            "label": label,
            "package": meta["package"],
            "aliases": meta["aliases"],
            "ecosystem": meta["ecosystem"],
            "cpe": meta["cpe"],
            "total": target.get("total", len(items)),
            "count": len(items),
            "severity_counts": count_severity(items),
            "items": items,
        }
    return out


def count_severity(items: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    return dict(sorted(counts.items()))


def md_escape(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.replace("|", "\\|").replace("\n", " ")


def write_csv(matrix: dict[str, Any]) -> None:
    with OUT_CSV.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "package", "cve", "severity", "cvss", "cna_score",
            "cna_severity", "published", "cwe",
            "affected", "fixed", "impact", "location", "component",
            "known_exploited", "kev_date_added", "kev_ransomware",
            "public_poc", "description",
        ])
        for pkg in matrix["packages"].values():
            for item in pkg["items"]:
                writer.writerow([
                    pkg["package"], item["cve"], item["severity"],
                    item["score"],
                    (item.get("cvss", {}).get("cna") or {}).get("score", ""),
                    (item.get("cvss", {}).get("cna") or {}).get("severity", ""),
                    item["published"], " ".join(item["cwe"]),
                    " ; ".join(item["affected_labels"]),
                    " ".join(item["fixed"]), item["impact"], item["location"],
                    item.get("component", ""),
                    item["exploit"]["known_exploited"],
                    item["exploit"].get("kev", {}).get("date_added", ""),
                    item["exploit"].get("kev", {}).get("known_ransomware", ""),
                    " ".join(item["exploit"]["public_poc"]),
                    item["description"],
                ])


def write_package_md(pkg: dict[str, Any]) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f"{pkg['package']}.md"
    lines = [
        f"# {pkg['label']} — CVE list",
        "",
        f"- Package: `{pkg['package']}` ({pkg['ecosystem']})",
        f"- NVD CPE: `{pkg['cpe']}`",
        f"- CVEs: **{pkg['count']}**",
        f"- Severity: {', '.join(f'{k} {v}' for k, v in pkg['severity_counts'].items())}",
        "",
        "| CVE | Severity | Affected | Fixed | Impact | Where it exists | Exploit |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in pkg["items"]:
        exploit = "KEV" if item["exploit"]["known_exploited"] else ""
        if item["exploit"]["public_poc"]:
            exploit = (exploit + " PoC").strip()
        lines.append(
            "| {cve} | {sev} {score} | {affected} | {fixed} | {impact} | {loc} | {exploit} |".format(
                cve=item["cve"],
                sev=item["severity"],
                score=item["score"],
                affected=md_escape(" ; ".join(item["affected_labels"]) or "see NVD"),
                fixed=md_escape(" ".join(item["fixed"]) or "see NVD"),
                impact=md_escape(item["impact"]),
                loc=md_escape(item["location"]),
                exploit=md_escape(exploit),
            )
        )
    notes = [i for i in pkg["items"] if i.get("vendor_note")]
    if notes:
        lines.append("")
        lines.append("## Vendor notes / corrections")
        lines.append("")
        for item in notes:
            lines.append(f"- **{item['cve']}** — {item['vendor_note']}")
    lines.append("")
    lines.append("Affected/fixed ranges are copied from NVD CPE match data. "
                 "Where the range is exact-only, `=x.y.z` is shown. "
                 "`KEV` = CISA Known Exploited Vulnerabilities reference; "
                 "`PoC` = a public exploit/PoC reference in NVD.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_summary(matrix: dict[str, Any]) -> None:
    lines = [
        "# Framework CVE matrix — Next.js, React, PHP, ASP.NET Core, .NET",
        "",
        f"**Generated:** {matrix['generated']}  ",
        "**Source:** NVD 2.0 API, fetched with `scripts/fetch_framework_cves.py`  ",
        "**Full data:** `reports/framework_cve_matrix.json`, `reports/framework_cves.csv`",
        "",
        "This is a **defensive reference**: it maps package versions to published "
        "CVEs and the component/endpoint named in the NVD description. It does "
        "not contain exploit payloads and it does not scan anything.",
        "",
        "**Severity** is the NVD primary CVSS score. Where a CNA supplied a "
        "different score, both are kept in the JSON (`cvss.primary` and "
        "`cvss.cna`) and in the CSV (`cvss`, `cna_score`). Example: "
        "CVE-2025-1861 is 9.8 on the NVD primary scale but 6.3 (medium) from "
        "the PHP CNA.",
        "",
        "## Counts",
        "",
        "| Package | Ecosystem | CVEs | Critical | High | Medium | Low |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for pkg in matrix["packages"].values():
        sc = pkg["severity_counts"]
        lines.append(
            f"| {pkg['label']} | {pkg['ecosystem']} | **{pkg['count']}** | "
            f"{sc.get('critical', 0)} | {sc.get('high', 0)} | "
            f"{sc.get('medium', 0)} | {sc.get('low', 0)} |"
        )
    kev_items = [
        (pkg["label"], item)
        for pkg in matrix["packages"].values()
        for item in pkg["items"]
        if item["exploit"]["known_exploited"]
    ]
    lines += [
        "",
        f"**CISA KEV matches:** {len(kev_items)}"
        + (" — " + ", ".join(f"`{item['cve']}` ({label})"
                             for label, item in kev_items) if kev_items else ""),
        "",
        "Per-package full tables: "
        + ", ".join(f"[{p['label']}](cve/{p['package']}.md)"
                    for p in matrix["packages"].values()),
        "",
        "## Vendor corrections worth knowing",
        "",
    ]
    for pkg in matrix["packages"].values():
        for item in pkg["items"]:
            if item.get("vendor_note"):
                lines.append(f"- **{item['cve']}** ({pkg['label']}) — "
                             f"{item['vendor_note']}")
    lines += [
        "",
        "## How to use it with a real site",
        "",
        "```bash",
        "# One package/version:",
        "python3 scripts/framework_cve_lookup.py --package next --version 15.1.0",
        "",
        "# A package.json / composer.json / .csproj:",
        "python3 scripts/framework_cve_lookup.py --manifest package.json",
        "python3 scripts/framework_cve_lookup.py --manifest composer.json",
        "python3 scripts/framework_cve_lookup.py --manifest MyApp.csproj",
        "```",
        "",
        "The lookup is an offline match against the NVD ranges in this matrix. "
        "A version is reported only when it falls inside a published affected "
        "range. Always confirm against the vendor advisory before acting.",
        "",
        "## Highest-signal items",
        "",
        "### Next.js",
        "",
        "| CVE | Severity | Affected | Fixed | Where / impact |",
        "|---|---|---|---|---|",
    ]
    next_pkg = matrix["packages"].get("next.js", {})
    for item in next_pkg.get("items", []):
        if item["severity"] not in ("critical", "high"):
            continue
        lines.append(
            f"| {item['cve']} | {item['severity']} {item['score']} | "
            f"{md_escape(' ; '.join(item['affected_labels']))} | "
            f"{md_escape(' '.join(item['fixed']) or 'see NVD')} | "
            f"{md_escape(item['location'])} — {md_escape(item['impact'])} |"
        )
    lines += [
        "",
        "### React",
        "",
        "| CVE | Severity | Affected | Fixed | Where / impact |",
        "|---|---|---|---|---|",
    ]
    for item in matrix["packages"].get("react", {}).get("items", []):
        lines.append(
            f"| {item['cve']} | {item['severity']} {item['score']} | "
            f"{md_escape(' ; '.join(item['affected_labels']))} | "
            f"{md_escape(' '.join(item['fixed']) or 'see NVD')} | "
            f"{md_escape(item['location'])} — {md_escape(item['impact'])} |"
        )
    lines += [
        "",
        "### PHP — critical/high since 2024",
        "",
        "| CVE | Severity | Affected | Fixed | Where / impact |",
        "|---|---|---|---|---|",
    ]
    php = matrix["packages"].get("php", {})
    for item in php.get("items", []):
        if item["published"] < "2024-01-01":
            continue
        if item["severity"] not in ("critical", "high"):
            continue
        lines.append(
            f"| {item['cve']} | {item['severity']} {item['score']} | "
            f"{md_escape(' ; '.join(item['affected_labels']))} | "
            f"{md_escape(' '.join(item['fixed']) or 'see NVD')} | "
            f"{md_escape(item['location'])} — {md_escape(item['impact'])} |"
        )
    lines += [
        "",
        "### ASP.NET Core",
        "",
        "| CVE | Severity | Affected | Fixed | Where / impact |",
        "|---|---|---|---|---|",
    ]
    for item in matrix["packages"].get("aspnetcore", {}).get("items", []):
        if item["severity"] not in ("critical", "high"):
            continue
        lines.append(
            f"| {item['cve']} | {item['severity']} {item['score']} | "
            f"{md_escape(' ; '.join(item['affected_labels']))} | "
            f"{md_escape(' '.join(item['fixed']) or 'see NVD')} | "
            f"{md_escape(item['location'])} — {md_escape(item['impact'])} |"
        )
    lines += [
        "",
        "### .NET — critical and network-facing high findings",
        "",
        "| CVE | Severity | Affected | Fixed | Where / impact |",
        "|---|---|---|---|---|",
    ]
    dotnet = matrix["packages"].get("dotnet", {})
    for item in dotnet.get("items", []):
        if item["severity"] == "critical" or (
            item["severity"] == "high"
            and re.search(r"remote|network|unauthorized", item["description"], re.I)
        ):
            lines.append(
                f"| {item['cve']} | {item['severity']} {item['score']} | "
                f"{md_escape(' ; '.join(item['affected_labels']))} | "
                f"{md_escape(' '.join(item['fixed']) or 'see NVD')} | "
                f"{md_escape(item['location'])} — {md_escape(item['impact'])} |"
            )
    lines += [
        "",
        "## Important caveats",
        "",
        "- NVD CPE ranges are the source of truth here. A `fixed` value is the "
        "first version after an exclusive upper bound; for inclusive upper "
        "bounds, read the range as `<=` and check the vendor advisory.",
        "- Next.js, React, ASP.NET Core and .NET often do **not** expose their "
        "patch version in HTTP responses. The lookup tool is for dependency "
        "manifests, SBOMs, container image labels and build metadata. A web "
        "fingerprint alone is usually not enough to prove a version.",
        "- PHP is the exception: `X-Powered-By: PHP/x.y.z` often exposes the "
        "version, which is why the scanner has passive PHP CVE fingerprints.",
        "- `KEV` means CISA lists the CVE as exploited in the wild; `PoC` means "
        "NVD references a public exploit/PoC. Neither means a specific site is "
        "vulnerable — the installed version and configuration still decide that.",
        "",
    ]
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    if not SRC.exists():
        print(f"missing {SRC}; run scripts/fetch_framework_cves.py first",
              file=sys.stderr)
        return 2
    matrix = build()
    OUT_JSON.write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")
    write_csv(matrix)
    for pkg in matrix["packages"].values():
        write_package_md(pkg)
    write_summary(matrix)
    print(f"wrote {OUT_JSON}")
    print(f"wrote {OUT_CSV}")
    print(f"wrote {OUT_MD}")
    print(f"wrote {len(matrix['packages'])} package tables in {OUT_DIR}")
    for pkg in matrix["packages"].values():
        print(f"  {pkg['label']}: {pkg['count']} CVEs {pkg['severity_counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
