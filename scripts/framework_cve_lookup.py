#!/usr/bin/env python3
"""Look up framework CVEs for an exact version or a dependency manifest.

Examples:
  python3 scripts/framework_cve_lookup.py --package next --version 15.1.0
  python3 scripts/framework_cve_lookup.py --package react-server-dom-webpack --version 19.0.0
  python3 scripts/framework_cve_lookup.py --package php --version 8.2.12
  python3 scripts/framework_cve_lookup.py --manifest package.json
  python3 scripts/framework_cve_lookup.py --manifest composer.json
  python3 scripts/framework_cve_lookup.py --manifest MyApp.csproj
  python3 scripts/framework_cve_lookup.py --list-packages

The match is offline and uses the NVD ranges in
reports/framework_cve_matrix.json. It is a lead generator, not proof:
confirm the installed patch version and the vendor advisory before acting.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
MATRIX = REPO / "reports" / "framework_cve_matrix.json"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def version_key(value: str) -> tuple[int, int, int, int]:
    parts = [int(p) for p in re.findall(r"\d+", value or "")[:4]]
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts)  # type: ignore[return-value]


def load_matrix() -> dict[str, Any]:
    if not MATRIX.exists():
        raise SystemExit(
            f"missing {MATRIX}; run scripts/build_framework_matrix.py first")
    return json.loads(MATRIX.read_text(encoding="utf-8"))


def resolve_package(matrix: dict[str, Any], name: str) -> dict[str, Any] | None:
    needle = name.strip().lower()
    for pkg in matrix["packages"].values():
        if needle == pkg["package"].lower():
            return pkg
        if needle in (a.lower() for a in pkg.get("aliases", [])):
            return pkg
        if needle.startswith("microsoft.aspnetcore.") and pkg["package"] == "aspnetcore":
            return pkg
        if needle.startswith("microsoft.netcore.") and pkg["package"] == "dotnet":
            return pkg
    return None


def match_item(item: dict[str, Any], version: str) -> bool:
    v = version_key(version)
    for rng in item.get("affected", []):
        if rng.get("exact"):
            if version_key(rng["exact"]) == v:
                return True
            continue
        low = version_key(rng.get("low", "")) if rng.get("low") else (0, 0, 0, 0)
        high = version_key(rng.get("high", "")) if rng.get("high") else (999, 999, 999, 999)
        low_ok = v > low if rng.get("low_exclusive") else v >= low
        high_ok = v < high if rng.get("high_exclusive") else v <= high
        if low_ok and high_ok:
            return True
    # Pre-release builds are listed separately by NVD.
    for pre in item.get("prerelease_versions", []):
        exact = pre.get("exact", "")
        if exact and (version == exact or version.replace(".", "") == exact.replace(".", "")):
            return True
    return False


def component_filter(name: str, strict_react_core: bool = False) -> str | None:
    """Return the concrete component a dependency name refers to.

    NVD groups React core, react-dom/server, and the react-server-dom-*
    packages under one CPE. A manifest lists them separately, so matching
    the CPE alone over-reports. ``None`` means "no component filter".
    """
    needle = name.strip().lower()
    if needle.startswith("react-server-dom"):
        return "react-server-dom-*"
    if needle in ("react-dom", "react-dom-server", "react-dom/server"):
        return "react-dom/server"
    if needle == "react" and strict_react_core:
        return ""
    return None


def filter_component(items: list[dict[str, Any]], name: str,
                     strict_react_core: bool = False) -> list[dict[str, Any]]:
    wanted = component_filter(name, strict_react_core)
    if wanted is None:
        return items
    return [item for item in items if item.get("component", "") == wanted]


def lookup(pkg: dict[str, Any], version: str) -> list[dict[str, Any]]:
    found = [item for item in pkg["items"] if match_item(item, version)]
    found.sort(key=lambda i: (SEVERITY_ORDER.get(i["severity"], 9),
                              -float(i.get("score", 0)), i["cve"]))
    return found


def format_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item["cve"],
        "severity": item["severity"],
        "score": item["score"],
        "affected": item["affected_labels"],
        "fixed": item["fixed"],
        "impact": item["impact"],
        "location": item["location"],
        "component": item.get("component", ""),
        "known_exploited": item["exploit"]["known_exploited"],
        "kev": item["exploit"].get("kev", {}),
        "public_poc": item["exploit"]["public_poc"],
        "vendor_note": item.get("vendor_note", ""),
        "references": item.get("references", []),
    }


def print_table(pkg: dict[str, Any], version: str, matches: list[dict[str, Any]],
                alias: str = "") -> None:
    label = pkg["label"]
    if alias and alias.lower() not in (label.lower(), pkg["package"].lower()):
        label = f"{label} (alias {alias})"
    print(f"\n{label} {version}")
    if pkg["package"] == "react" and alias.strip().lower() == "react":
        print("  note: 5 of these affect react-server-dom-* (RSC); "
              "1 affects react-dom/server. Check which package is installed.")
    if not matches:
        print("  no matching CVE ranges in the matrix")
        return
    print(f"  {len(matches)} matching CVE(s):\n")
    for item in matches:
        flags = []
        if item["known_exploited"]:
            flags.append("KEV")
        if item["public_poc"]:
            flags.append("PoC")
        flag_text = f" [{'/'.join(flags)}]" if flags else ""
        print(f"  {item['cve']}  {item['severity']} {item['score']}{flag_text}")
        print(f"    affected : {' ; '.join(item['affected'])}")
        print(f"    fixed    : {' '.join(item['fixed']) or 'see vendor advisory'}")
        print(f"    impact   : {item['impact']}")
        if item.get("component"):
            print(f"    component: {item['component']}")
        print(f"    where    : {item['location']}")
        if item.get("vendor_note"):
            print(f"    note     : {item['vendor_note']}")
        print()


def parse_package_json(path: Path) -> list[tuple[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: list[tuple[str, str]] = []
    for key in ("dependencies", "devDependencies", "optionalDependencies",
                "peerDependencies"):
        for name, constraint in (data.get(key) or {}).items():
            out.append((name, str(constraint)))
    return out


def constraint_min_version(constraint: str) -> str | None:
    """Extract a usable version from a semver/npm constraint.

    This is intentionally conservative: it returns the first concrete
    version mentioned, so `^15.1.0` becomes 15.1.0. That is the minimum
    the constraint allows, not necessarily the installed version.
    """
    text = constraint.strip()
    if not text or text in ("*", "latest", "workspace:*"):
        return None
    match = re.search(r"\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.-]+)?", text)
    return match.group(0) if match else None


def parse_composer_json(path: Path) -> list[tuple[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: list[tuple[str, str]] = []
    for key in ("require", "require-dev"):
        for name, constraint in (data.get(key) or {}).items():
            out.append((name, str(constraint)))
    return out


def parse_csproj(path: Path) -> list[tuple[str, str]]:
    tree = ET.parse(path)
    root = tree.getroot()
    out: list[tuple[str, str]] = []
    for elem in root.iter():
        tag = elem.tag.split("}")[-1]
        if tag == "TargetFramework" and elem.text:
            tfm = elem.text.strip()
            match = re.match(r"net(\d+)\.(\d+)", tfm)
            if match:
                out.append((".net", f"{match.group(1)}.{match.group(2)}.0"))
        elif tag == "RuntimeFrameworkVersion" and elem.text:
            out.append((".net", elem.text.strip()))
        elif tag == "PackageReference":
            name = elem.attrib.get("Include", "")
            version = elem.attrib.get("Version", "")
            if not version:
                child = next((c for c in elem if c.tag.split("}")[-1] == "Version"), None)
                version = (child.text or "").strip() if child is not None else ""
            if name and version:
                out.append((name, version))
    return out


def manifest_dependencies(path: Path) -> list[tuple[str, str]]:
    name = path.name.lower()
    if name == "package.json":
        return parse_package_json(path)
    if name == "composer.json":
        return parse_composer_json(path)
    if name.endswith(".csproj"):
        return parse_csproj(path)
    raise SystemExit(f"unsupported manifest: {path} (use package.json, "
                     f"composer.json or *.csproj)")


def print_manifest(matrix: dict[str, Any], path: Path, as_json: bool) -> int:
    deps = manifest_dependencies(path)
    rows: list[dict[str, Any]] = []
    for name, constraint in deps:
        pkg = resolve_package(matrix, name)
        if not pkg:
            continue
        version = constraint_min_version(constraint)
        if not version:
            rows.append({"package": pkg["package"], "dependency": name,
                         "constraint": constraint, "version": None,
                         "matches": [], "note": "no concrete version in constraint"})
            continue
        matches = [format_item(i) for i in filter_component(
            lookup(pkg, version), name, strict_react_core=True)]
        rows.append({
            "package": pkg["package"],
            "dependency": name,
            "constraint": constraint,
            "version": version,
            "matches": matches,
            "note": ("constraint minimum; confirm the installed version"
                     if constraint.strip() != version else ""),
        })
    if as_json:
        print(json.dumps(rows, indent=2))
        return 0
    total = 0
    for row in rows:
        print(f"\n{row['dependency']} {row['constraint']}")
        if not row["version"]:
            print(f"  {row['note']}")
            continue
        print(f"  interpreted as minimum version {row['version']}"
              + (f" ({row['note']})" if row["note"] else ""))
        if not row["matches"]:
            print("  no matching CVE ranges")
            continue
        total += len(row["matches"])
        for item in row["matches"]:
            flags = []
            if item["known_exploited"]:
                flags.append("KEV")
            if item["public_poc"]:
                flags.append("PoC")
            flag_text = f" [{'/'.join(flags)}]" if flags else ""
            component = f" [{item['component']}]" if item.get("component") else ""
            print(f"    {item['cve']} {item['severity']} {item['score']}{flag_text} "
                  f"— {item['impact']} — {item['location']}{component}")
    print(f"\n{total} matching CVE row(s) across {len(rows)} recognized dependency(ies)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--package", help="package name or alias (next, react, php, aspnetcore, dotnet)")
    parser.add_argument("--version", help="exact installed version, e.g. 15.1.0")
    parser.add_argument("--manifest", type=Path,
                        help="package.json, composer.json or *.csproj")
    parser.add_argument("--format", choices=("table", "json", "csv"), default="table")
    parser.add_argument("--list-packages", action="store_true",
                        help="show package names and aliases")
    args = parser.parse_args()

    matrix = load_matrix()
    if args.list_packages:
        for pkg in matrix["packages"].values():
            print(f"{pkg['package']:12s} {pkg['label']:15s} "
                  f"{pkg['ecosystem']:6s} aliases: {', '.join(pkg['aliases'])}")
        return 0

    if args.manifest:
        return print_manifest(matrix, args.manifest, args.format == "json")

    if not args.package or not args.version:
        parser.print_help()
        return 2
    pkg = resolve_package(matrix, args.package)
    if not pkg:
        print(f"unknown package: {args.package}", file=sys.stderr)
        print("use --list-packages to see the supported names", file=sys.stderr)
        return 2
    matches = [format_item(i) for i in filter_component(
        lookup(pkg, args.version), args.package)]
    if args.format == "json":
        print(json.dumps({
            "package": pkg["package"],
            "label": pkg["label"],
            "version": args.version,
            "matches": matches,
        }, indent=2))
        return 0
    if args.format == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(["package", "version", "cve", "severity", "score",
                         "affected", "fixed", "impact", "location",
                         "component", "known_exploited", "public_poc",
                         "vendor_note"])
        for item in matches:
            writer.writerow([
                pkg["package"], args.version, item["cve"], item["severity"],
                item["score"], " ; ".join(item["affected"]),
                " ".join(item["fixed"]), item["impact"], item["location"],
                item["component"], item["known_exploited"],
                " ".join(item["public_poc"]), item["vendor_note"],
            ])
        return 0
    print_table(pkg, args.version, matches, alias=args.package)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
