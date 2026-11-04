"""
Terminal styling, audit activity logging, and report output for webprobe.
"""

import json
import os
import sys
import threading
import time
from typing import Any, Dict, List, Optional


class C:
    """ANSI color codes for formatted terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    @classmethod
    def bold(cls, text: str) -> str:
        return f"{cls.BOLD}{text}{cls.RESET}"

    @classmethod
    def dim(cls, text: str) -> str:
        return f"{cls.DIM}{text}{cls.RESET}"

    @classmethod
    def red(cls, text: str) -> str:
        return f"{cls.RED}{text}{cls.RESET}"

    @classmethod
    def green(cls, text: str) -> str:
        return f"{cls.GREEN}{text}{cls.RESET}"

    @classmethod
    def yellow(cls, text: str) -> str:
        return f"{cls.YELLOW}{text}{cls.RESET}"

    @classmethod
    def blue(cls, text: str) -> str:
        return f"{cls.BLUE}{text}{cls.RESET}"

    @classmethod
    def cyan(cls, text: str) -> str:
        return f"{cls.CYAN}{text}{cls.RESET}"

    @classmethod
    def white(cls, text: str) -> str:
        return f"{cls.WHITE}{text}{cls.RESET}"


def log(msg: str, dim: bool = False, err: bool = False) -> None:
    """Print an operational log message to stderr or stdout."""
    output = C.dim(msg) if dim else msg
    stream = sys.stderr if err else sys.stdout
    stream.write(output + "\n")
    stream.flush()


class ActivityLog:
    """Thread-safe append-only activity log for audit compliance."""

    def __init__(self, path: str, version: str = "3.0.0"):
        self.path = path
        self.lock = threading.Lock()
        if path:
            parent = os.path.dirname(path)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(
                    f"# webprobe v{version} audit log started "
                    f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n"
                    "# Timestamp\tTestID\tOutcome\tDescription\tEvidence\n"
                )

    def record(
        self,
        test_id: str,
        outcome: str,
        description: str,
        evidence: str = "",
    ) -> None:
        if not self.path:
            return
        clean_desc = description.replace("\t", " ").replace("\n", " ")
        clean_ev = evidence.replace("\t", " ").replace("\n", " ")[:500]
        line = (
            f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')}\t"
            f"{test_id}\t{outcome}\t{clean_desc}\t{clean_ev}\n"
        )
        with self.lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)


def format_findings_text(findings: List[Any], duration: float) -> str:
    """Generate a clean, readable terminal summary of findings."""
    lines = []
    lines.append(C.bold(f"\nScan completed in {duration:.2f}s. Total Findings: {len(findings)}\n"))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: (severity_order.get(f.severity.lower(), 5), f.phase, f.category),
    )

    by_sev: Dict[str, List[Any]] = {}
    for f in sorted_findings:
        by_sev.setdefault(f.severity.lower(), []).append(f)

    for sev in ["critical", "high", "medium", "low", "info"]:
        items = by_sev.get(sev, [])
        if not items:
            continue
        color_fn = {
            "critical": C.red,
            "high": C.red,
            "medium": C.yellow,
            "low": C.cyan,
            "info": C.dim,
        }.get(sev, C.white)

        lines.append(color_fn(f"[{sev.upper()}] ({len(items)})"))
        for item in items:
            lines.append(f"  * [P{item.phase}] {item.title} - {item.url}")
            if item.evidence:
                lines.append(C.dim(f"    Evidence: {item.evidence[:160]}"))
            if item.remediation:
                lines.append(C.dim(f"    Remediation: {item.remediation[:160]}"))
        lines.append("")

    return "\n".join(lines)


def format_findings_json(findings: List[Any], metadata: Dict[str, Any]) -> str:
    """Generate a JSON structured report for CI/CD and automated ingestion."""
    data = {
        "metadata": metadata,
        "total_findings": len(findings),
        "findings": [f.to_dict() if hasattr(f, "to_dict") else vars(f) for f in findings],
    }
    return json.dumps(data, indent=2)

