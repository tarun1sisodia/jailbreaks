"""Pluggable scan engines for the WebProbe API.

WebProbe is the built-in engine. KageSec and OpenOSINT are external CLIs
that are only used when their binary is actually installed on the host --
`GET /api/engines` reports that, so the frontend never offers a missing
engine. Argus is NOT a URL engine: it scans a code path (a repo path on
the host, or a git URL cloned shallow first), so /api/scan takes `repo`
for it instead of `url`. Its SARIF output goes through the same
normalizer as KageSec's SARIF.

Normalizers map each engine's native output to the WebProbe finding shape
that Report.tsx already renders via normalizeFinding():
  title, severity, category, url, endpoint, method, parameter, phase,
  cvss_score, cvss_vector, remediation, evidence, engine.
"""

import json
import os
import re
import shutil
import subprocess

SEVERITIES = ("critical", "high", "medium", "low", "info")

ENGINES = {
    "webprobe": {
        "name": "WebProbe",
        "description": "Built-in checks: 136 checks across 11 profiles",
        "url_scan": True,
        "bin_env": None,
        "default_bin": None,
    },
    "kagesec": {
        "name": "KageSec",
        "description": "DAST + CVE templates (pip install kagesec; github.com/ZulAmi/KageSecurity)",
        "url_scan": True,
        "bin_env": "KAGESEC_BIN",
        "default_bin": "kagesec",
    },
    "openosint": {
        "name": "OpenOSINT",
        "description": "Passive OSINT intel: DNS, WHOIS, RDAP, exposure, dorks (pip install openosint; github.com/OpenOSINT/OpenOSINT)",
        "url_scan": True,
        "bin_env": "OPENOSINT_BIN",
        "default_bin": "openosint",
    },
    "argus": {
        "name": "Argus",
        "description": "Code scanner (argus-code-scanning, MIT): SAST/SCA/secrets over a repo path or git URL — not a live-URL engine",
        "url_scan": False,
        "bin_env": "ARGUS_BIN",
        "default_bin": "argus",
    },
}


def engine_binary(name):
    cfg = ENGINES[name]
    if cfg["bin_env"]:
        path = os.environ.get(cfg["bin_env"], "").strip()
        if path:
            return path
    binary = cfg["default_bin"]
    if not binary:
        return None
    found = shutil.which(binary)
    if found:
        return found
    # The API runs from a venv (systemd ExecStart is the venv's uvicorn)
    # but its PATH does not include the venv bin dir, so look there too.
    # Do NOT resolve() sys.executable: the venv python is a symlink to the
    # system interpreter, and resolving it points at /usr/bin instead.
    import sys
    from pathlib import Path
    venv_bin = Path(sys.executable).parent / binary
    if venv_bin.is_file():
        return str(venv_bin)
    return binary


def engine_available(name):
    if name == "webprobe":
        return True
    binary = engine_binary(name)
    return bool(binary and shutil.which(binary))


def argus_scan_env():
    """Env for running `argus`: its own bin dir first on PATH.

    argus-scan shells out to the real scanners (semgrep, bandit, gitleaks,
    pip-audit), so they must be findable on PATH too. On box6 they live in
    a separate venv (.venv-argus) next to the argus binary, not in the
    server venv and not on the systemd PATH.
    """
    env = dict(os.environ)
    binary = engine_binary("argus")
    if binary and os.path.sep in binary:
        bindir = os.path.dirname(binary)
        env["PATH"] = bindir + os.pathsep + env.get("PATH", "")
    # Never let a scan hang waiting for git credentials.
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def kagesec_browser_available():
    """True when a Playwright Chromium is actually installed.

    `pip install "kagesec[browser]"` alone is not enough: KageSec's
    browser crawler imports playwright AND needs the downloaded Chromium
    binary, otherwise `kagesec scan` dies with ModuleNotFoundError.
    """
    import glob
    import pathlib
    if shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome"):
        return True
    browsers_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or str(pathlib.Path.home() / ".cache" / "ms-playwright")
    return bool(glob.glob(os.path.join(browsers_path, "chromium-*")))


def engine_version(name):
    if name == "webprobe":
        return "built-in"
    binary = engine_binary(name)
    if not binary or not shutil.which(binary):
        return None
    try:
        proc = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=15
        )
        text = (proc.stdout or proc.stderr or "").strip().splitlines()
        first = text[0].strip() if text else ""
        if not first or first.startswith("usage:"):
            return "installed"
        return first[:120]
    except Exception:
        return "installed"


def engine_status():
    out = {}
    for name, cfg in ENGINES.items():
        binary = engine_binary(name)
        out[name] = {
            "name": cfg["name"],
            "description": cfg["description"],
            "url_scan": cfg["url_scan"],
            "available": engine_available(name),
            "binary": binary if name != "webprobe" else None,
            "version": engine_version(name),
        }
    return out


def _severity(value):
    value = str(value or "info").lower()
    return value if value in SEVERITIES else "info"


def _cvss_number(value):
    if isinstance(value, (int, float)):
        return float(value) if 0 <= value <= 10 else None
    if isinstance(value, dict):
        return _cvss_number(value.get("score"))
    if isinstance(value, str):
        match = re.search(r"(\d+(?:\.\d+)?)", value)
        if match:
            return _cvss_number(float(match.group(1)))
    return None


def normalize_kagesec(data, redact=True):
    """KageSec JSON report: {"summary": {...}, "findings": [...]}.

    Finding fields (verified against kagesec 0.3.2, cli/main.py
    _findings_dict): title, severity, owasp_category, url, parameter,
    payload, evidence, verified, confidence, cwe, cvss, remediation,
    standards, poc_curl.
    """
    findings = []
    for raw in data.get("findings", []) or []:
        finding = {
            "id": "",
            "title": raw.get("title") or "Untitled finding",
            "severity": _severity(raw.get("severity")),
            "category": raw.get("owasp_category") or "",
            "url": raw.get("url") or "",
            "endpoint": raw.get("url") or "",
            "method": "",
            "parameter": raw.get("parameter") or "",
            "phase": "",
            "cvss_score": _cvss_number(raw.get("cvss")),
            "cvss_vector": "",
            "remediation": raw.get("remediation") or "",
            "evidence": raw.get("evidence") or "",
            "engine": "kagesec",
            "extra": {
                "cwe": raw.get("cwe") or "",
                "confidence": raw.get("confidence"),
                "verified": raw.get("verified"),
            },
        }
        if not redact:
            finding["extra"]["payload"] = raw.get("payload") or ""
            finding["extra"]["poc_curl"] = raw.get("poc_curl") or ""
        findings.append(finding)
    return findings


def normalize_sarif(data, engine="argus"):
    """SARIF 2.1.0 -> WebProbe findings. Used for any engine that emits
    SARIF (KageSec --output sarif, Argus -f sarif)."""
    findings = []
    for run in data.get("runs", []) or []:
        rules = {}
        driver = (run.get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules", []) or []:
            rules[rule.get("id")] = rule
        for result in run.get("results", []) or []:
            rule = rules.get(result.get("ruleId") or "", {})
            level = str(result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning").lower()
            severity = {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(level, "medium")
            props = result.get("properties") or {}
            sec_sev = str(props.get("security-severity") or "")
            if sec_sev:
                score = _cvss_number(sec_sev)
                if score is not None:
                    severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info"
            locations = result.get("locations", []) or []
            uri = ""
            if locations:
                phys = (locations[0].get("physicalLocation") or {})
                uri = ((phys.get("artifactLocation") or {}).get("uri") or "")
            message = (result.get("message") or {}).get("text") or ""
            findings.append({
                "id": "",
                "title": (rule.get("name") or result.get("ruleId") or message[:80] or "Untitled finding"),
                "severity": severity,
                "category": "",
                "url": uri,
                "endpoint": uri,
                "method": "",
                "parameter": "",
                "phase": "",
                "cvss_score": _cvss_number(sec_sev) if sec_sev else None,
                "cvss_vector": "",
                "remediation": (rule.get("help") or {}).get("text") or "",
                "evidence": message,
                "engine": engine,
                "extra": {"cwe": "", "rule_id": result.get("ruleId") or ""},
            })
    return findings


def _openosint_json(text):
    """OpenOSINT --json prints a human line, then a JSON object."""
    start = text.find("{")
    if start < 0:
        return None
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError:
        return None


def normalize_openosint(outputs):
    """One info finding per OpenOSINT direct-tool run.

    Each output is the parsed JSON of one `openosint --json <tool> <target>`
    call: {"tool": "search_dns", "target": "...", "results": [strings],
    "error": ...}. OpenOSINT returns intel, not vulnerabilities, so every
    finding is info unless a result line starts with "[!]".
    """
    findings = []
    for data in outputs:
        if not isinstance(data, dict):
            continue
        if isinstance(data.get("findings"), list) and data.get("domain"):
            for raw in data["findings"]:
                if not isinstance(raw, dict):
                    continue
                findings.append({
                    "id": "",
                    "title": raw.get("title") or raw.get("id") or "OpenOSINT exposure finding",
                    "severity": _severity(raw.get("severity")),
                    "category": raw.get("category") or "osint",
                    "url": data.get("domain") or "",
                    "endpoint": data.get("domain") or "",
                    "method": "",
                    "parameter": "",
                    "phase": "",
                    "cvss_score": None,
                    "cvss_vector": "",
                    "remediation": raw.get("recommendation") or "",
                    "evidence": raw.get("evidence") or "",
                    "engine": "openosint",
                    "extra": {"tool": "exposure", "grade": data.get("grade"), "score": data.get("score")},
                })
            continue
        tool = data.get("tool") or "openosint"
        target = data.get("target") or ""
        results = data.get("results") or []
        if data.get("error"):
            results = list(results) + [f"Error: {data['error']}"]
        severity = "low" if any(str(r).startswith("[!]") for r in results) else "info"
        findings.append({
            "id": "",
            "title": f"OpenOSINT {tool}: {target}",
            "severity": severity,
            "category": "osint",
            "url": target,
            "endpoint": target,
            "method": "",
            "parameter": "",
            "phase": "",
            "cvss_score": None,
            "cvss_vector": "",
            "remediation": "",
            "evidence": "\n".join(str(r) for r in results)[:4000],
            "engine": "openosint",
            "extra": {"tool": tool},
        })
    return findings


def dedupe_findings(findings):
    seen = set()
    out = []
    for finding in findings:
        key = (finding.get("title", ""), finding.get("url", ""), finding.get("parameter", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def webprobe_report(target, engine, engines, findings, duration_seconds):
    for index, finding in enumerate(findings):
        finding["id"] = finding.get("id") or f"finding-{index}"
    return {
        "metadata": {
            "target": target,
            "engine": engine,
            "engines": engines,
            "duration_seconds": duration_seconds,
        },
        "findings": findings,
    }


def sarif_from_findings(findings, target):
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    results = []
    for finding in findings:
        results.append({
            "ruleId": finding.get("extra", {}).get("rule_id") or finding.get("title", ""),
            "level": level.get(finding.get("severity", "info"), "note"),
            "message": {"text": finding.get("title", "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.get("url") or target}}}],
            "properties": {"security-severity": str(finding.get("cvss_score") or "")},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "WebProbe", "version": "3.0.0", "informationUri": target}}, "results": results}],
    }


def markdown_summary(target, engine, findings):
    lines = [f"# WebProbe report\n\nTarget: {target}\n\nEngine: {engine}\n\n"]
    for finding in findings:
        lines.append(f"## [{finding['severity'].upper()}] {finding['title']}\n\n{finding.get('evidence') or ''}\n\nRemediation: {finding.get('remediation') or ''}\n")
    return "\n".join(lines)
