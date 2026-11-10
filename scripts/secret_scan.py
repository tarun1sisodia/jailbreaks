#!/usr/bin/env python3
"""Fail-closed secret hygiene check for the repository.

Scans tracked files for high-signal credential patterns and verifies that
known local secret files are neither tracked nor group/world readable.

Usage:
    python3 scripts/secret_scan.py
    python3 scripts/secret_scan.py --json

Exit codes:
    0  no findings
    1  one or more findings
    2  repository could not be inspected
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set

REPO_ROOT = Path(__file__).resolve().parents[1]

# Values that are clearly documentation or test placeholders are ignored by
# the generic assignment rule. High-signal token formats are never ignored.
PLACEHOLDER_MARKERS = (
    "example",
    "synthetic",
    "placeholder",
    "changeme",
    "change-me",
    "change_me",
    "your-",
    "your_",
    "redacted",
    "dummy",
    "test-only",
    "test_only",
    "testpassword",
    "test-password",
    "xxxx",
    "****",
    "${",
    "<",
    "…",
)

GENERIC_KEY = (
    r"(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?key|auth[_-]?token|"
    r"password|passwd|private[_-]?key|client[_-]?secret)"
)

RULES = (
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "github-token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    ),
    ("razorpay-live-key", re.compile(r"\brzp_live_[A-Za-z0-9]{10,}\b")),
    ("resend-key", re.compile(r"\bre_[A-Za-z0-9]{20,}\b")),
    ("stripe-live-key", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
    ),
    (
        "generic-secret-assignment",
        re.compile(
            rf"(?i)\b{GENERIC_KEY}\b[\"']?\s*[:=]\s*[\"']([^\"'\s]{{16,}})[\"']"
        ),
    ),
)

SENSITIVE_LOCAL_FILES = (
    Path(".env"),
    Path("backend/.env"),
    Path("backend/config/agraskbagheltourandtravels.json"),
    Path("config/agraskbagheltourandtravels.json"),
)


class Finding:
    def __init__(self, rule: str, path: str, line: int = 0, detail: str = ""):
        self.rule = rule
        self.path = path
        self.line = line
        self.detail = detail

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "path": self.path,
            "line": self.line,
            "detail": self.detail,
        }

    def __str__(self) -> str:
        location = self.path if not self.line else f"{self.path}:{self.line}"
        suffix = f" ({self.detail})" if self.detail else ""
        return f"[high] {self.rule} {location}{suffix}"


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def scan_text(text: str, path: str = "<text>") -> List[Finding]:
    """Return credential findings for a text blob."""
    findings: List[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if "secret-scan: allow" in line:
            continue
        for rule, pattern in RULES:
            for match in pattern.finditer(line):
                if rule == "generic-secret-assignment":
                    value = match.group(1)
                    if _is_placeholder(value):
                        continue
                findings.append(Finding(rule, path, line_no))
                break
    return findings


def _git_tracked(root: Path) -> Set[str]:
    try:
        raw = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"unable to list tracked files: {exc}") from exc
    return {
        item.decode("utf-8", "replace")
        for item in raw.split(b"\0")
        if item
    }


def _iter_tracked_files(root: Path, tracked: Set[str]) -> Iterable[Path]:
    for rel in sorted(tracked):
        path = root / rel
        if not path.is_file():
            continue
        try:
            if b"\0" in path.read_bytes()[:4096]:
                continue
        except OSError:
            continue
        yield path


def scan_repo(root: Path = REPO_ROOT) -> List[Finding]:
    """Scan every tracked text file in the repository."""
    root = root.resolve()
    tracked = _git_tracked(root)
    findings: List[Finding] = []
    for path in _iter_tracked_files(root, tracked):
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(text, rel))
    return findings


def check_sensitive_permissions(
    root: Path = REPO_ROOT, tracked: Optional[Set[str]] = None
) -> List[Finding]:
    """Check that local credential files are untracked and mode 0600."""
    root = root.resolve()
    if tracked is None:
        tracked = _git_tracked(root)
    findings: List[Finding] = []
    candidates = list(SENSITIVE_LOCAL_FILES)
    for pattern in (".env.*", "backend/.env.*"):
        candidates.extend(Path(p) for p in root.glob(pattern) if p.is_file())
    for rel in candidates:
        path = root / rel
        if not path.is_file():
            continue
        rel_str = rel.as_posix()
        if rel_str in tracked:
            findings.append(Finding("tracked-secret-file", rel_str, 0, "must be gitignored"))
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            findings.append(
                Finding(
                    "secret-file-permissions",
                    rel_str,
                    0,
                    f"mode {mode:04o}; expected 0600",
                )
            )
    return findings


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Scan the repository for exposed secrets")
    parser.add_argument("--root", default=str(REPO_ROOT), help="Repository root")
    parser.add_argument("--json", action="store_true", help="Emit JSON findings")
    args = parser.parse_args(argv)

    root = Path(args.root).expanduser().resolve()
    try:
        findings = scan_repo(root)
        findings.extend(check_sensitive_permissions(root))
    except RuntimeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([f.as_dict() for f in findings], indent=2))
    else:
        for finding in findings:
            print(finding)
        if findings:
            print(f"\n[!] {len(findings)} secret hygiene finding(s)", file=sys.stderr)
        else:
            print("[+] No exposed secrets found in tracked files; local secret files are private.")

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
