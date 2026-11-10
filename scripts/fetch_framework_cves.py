#!/usr/bin/env python3
"""Fetch framework CVE metadata from NVD for the framework matrix.

This is a research/reporting helper. It writes a compact JSON file that the
scanner's CVE database can be extended from, and a Markdown summary.

Usage:
  python3 scripts/fetch_framework_cves.py
  python3 scripts/fetch_framework_cves.py --refresh
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT_JSON = REPO / "reports" / "framework_cves.json"
CACHE = Path.home() / ".cache" / "jailbreaks-nvd-cpe"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"

TARGETS = [
    ("Next.js", "cpe:2.3:a:vercel:next.js"),
    ("React", "cpe:2.3:a:facebook:react"),
    ("PHP", "cpe:2.3:a:php:php"),
    ("ASP.NET Core", "cpe:2.3:a:microsoft:asp.net_core"),
    (".NET", "cpe:2.3:a:microsoft:.net"),
]


def fetch(cpe: str, refresh: bool = False) -> dict | None:
    CACHE.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^a-z0-9]+", "_", cpe.lower()).strip("_") + ".json"
    cache = CACHE / name
    if cache.exists() and not refresh:
        return json.loads(cache.read_text(encoding="utf-8"))
    query = urllib.parse.urlencode({
        "virtualMatchString": cpe,
        "resultsPerPage": "2000",
    })
    req = urllib.request.Request(
        f"{NVD}?{query}",
        headers={"User-Agent": "jailbreaks-framework-cve-matrix/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            payload = json.load(resp)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"  ! {cpe}: {exc}", file=sys.stderr)
        return None
    cache.write_text(json.dumps(payload), encoding="utf-8")
    time.sleep(7)
    return payload


def cvss_summary(cve: dict) -> dict:
    """Return the NVD primary score plus the CNA score when they differ."""
    metrics = cve.get("metrics", {})
    all_scores = []
    for key, version in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV2", "2.0"),
    ):
        for item in metrics.get(key) or []:
            data = item.get("cvssData", {})
            all_scores.append({
                "version": data.get("version", version),
                "score": float(data.get("baseScore", 0.0)),
                "severity": (data.get("baseSeverity")
                             or item.get("baseSeverity") or "").lower(),
                "source": item.get("source", ""),
                "type": item.get("type", ""),
            })
    primary = next((s for s in all_scores if s["source"] == "nvd@nist.gov"), None)
    if not primary:
        primary = next((s for s in all_scores if s["type"] == "Primary"), None)
    if not primary and all_scores:
        primary = all_scores[0]
    cna = next((s for s in all_scores if s["source"] != "nvd@nist.gov"), None)
    return {
        "severity": primary["severity"] if primary else "unknown",
        "score": primary["score"] if primary else 0.0,
        "cvss": {"primary": primary, "cna": cna, "all": all_scores},
    }


def ranges(cve: dict, cpe_prefix: str) -> list[dict]:
    out = []
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria", "")
                if not criteria.startswith(cpe_prefix):
                    continue
                out.append({
                    "criteria": criteria,
                    "start_including": match.get("versionStartIncluding"),
                    "start_excluding": match.get("versionStartExcluding"),
                    "end_including": match.get("versionEndIncluding"),
                    "end_excluding": match.get("versionEndExcluding"),
                    "exact": match.get("version") if not any(
                        match.get(k) for k in (
                            "versionStartIncluding", "versionStartExcluding",
                            "versionEndIncluding", "versionEndExcluding")
                    ) else None,
                })
    # Deduplicate identical range tuples.
    seen = set()
    unique = []
    for r in out:
        key = json.dumps(r, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args()

    result = {"generated": time.strftime("%Y-%m-%d"), "targets": {}}
    for label, cpe in TARGETS:
        print(f"[{label}] {cpe}", file=sys.stderr)
        payload = fetch(cpe, refresh=args.refresh)
        if not payload:
            result["targets"][label] = {"cpe": cpe, "error": "fetch failed"}
            continue
        items = []
        for vuln in payload.get("vulnerabilities", []) or []:
            cve = vuln.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            desc = next(
                (d["value"] for d in cve.get("descriptions", [])
                 if d.get("lang") == "en"), "")
            cvss = cvss_summary(cve)
            cwes = sorted({
                d.get("value") for w in cve.get("weaknesses", [])
                for d in w.get("description", []) if d.get("value")
            })
            refs = sorted({r.get("url") for r in cve.get("references", []) if r.get("url")})
            items.append({
                "id": cid,
                "published": cve.get("published", ""),
                "severity": cvss["severity"],
                "score": cvss["score"],
                "cvss": cvss["cvss"],
                "description": desc,
                "cwe": cwes,
                "ranges": ranges(cve, cpe),
                "references": refs[:6],
            })
        items.sort(key=lambda x: x["id"])
        result["targets"][label] = {
            "cpe": cpe,
            "total": payload.get("totalResults", len(items)),
            "items": items,
        }
        print(f"  {len(items)} CVEs", file=sys.stderr)

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT_JSON}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
