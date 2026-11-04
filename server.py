"""
WebProbe Cloud API Service
FastAPI wrapper to execute webprobe vulnerability and logic scans on-demand.
"""

import asyncio
import json
import os
import sys
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, status
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, HttpUrl

from webprobe.checks import ALL_CHECKS, PROFILES
from webprobe.cli import VERSION

app = FastAPI(
    title="WebProbe Cloud Scanner Service",
    description="Authorized Web Application Vulnerability & Logic Scanner API",
    version=VERSION,
)

REPORTS_DIR = os.path.abspath(os.environ.get("WEBPROBE_REPORTS_DIR", "reports"))
os.makedirs(REPORTS_DIR, exist_ok=True)

# In-memory scan registry: scan_id -> dict
SCANS: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    url: str = Field(..., description="Target URL (e.g. https://example.com)")
    profile: str = Field(default="full", description="Scan profile (quick, recon, auth, injection, authz, business, config, owasp, api, full)")
    rate_limit: float = Field(default=3.0, ge=0.5, le=20.0, description="Requests per second")
    aimd: bool = Field(default=True, description="Enable adaptive rate limiting")
    redact: bool = Field(default=True, description="Redact sensitive data and PII from evidence")
    cookie: Optional[str] = Field(default="", description="Authenticated session cookie header string")
    secondary_cookie: Optional[str] = Field(default="", description="Secondary user cookie for IDOR checks")
    admin_cookie: Optional[str] = Field(default="", description="Admin account cookie for authz checks")
    webhook_callback: Optional[str] = Field(default=None, description="Optional webhook URL to notify on completion")


def _send_webhook_notification(callback_url: str, payload: Dict[str, Any]) -> None:
    """Best-effort notification to callback webhook."""
    try:
        import urllib.request
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            callback_url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": f"webprobe-service/{VERSION}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception:
        pass


def _run_scanner_job(scan_id: str, req_data: Dict[str, Any]) -> None:
    """Background task worker that executes the scanner subprocess."""
    entry = SCANS[scan_id]
    entry["status"] = "running"
    entry["started_at"] = time.time()

    url = req_data["url"]
    profile = req_data.get("profile", "full")
    rate_limit = req_data.get("rate_limit", 3.0)
    aimd = req_data.get("aimd", True)
    redact = req_data.get("redact", True)
    cookie = req_data.get("cookie", "")
    secondary_cookie = req_data.get("secondary_cookie", "")
    admin_cookie = req_data.get("admin_cookie", "")
    callback = req_data.get("webhook_callback")

    json_path = os.path.join(REPORTS_DIR, f"{scan_id}.json")
    md_path = os.path.join(REPORTS_DIR, f"{scan_id}.md")
    sarif_path = os.path.join(REPORTS_DIR, f"{scan_id}.sarif")
    log_path = os.path.join(REPORTS_DIR, f"{scan_id}.log")

    cmd = [
        sys.executable,
        "webprobe.py",
        url,
        "--profile", profile,
        "--rate-limit", str(rate_limit),
        "--json",
        "-o", json_path,
        "--md", md_path,
        "--sarif",
        "--sarif-path", sarif_path,
    ]

    if aimd:
        cmd.append("--aimd")
    if redact:
        cmd.append("--redact")
    if cookie:
        cmd.extend(["--cookie", cookie])
    if secondary_cookie:
        cmd.extend(["--secondary-cookie", secondary_cookie])
    if admin_cookie:
        cmd.extend(["--admin-cookie", admin_cookie])

    try:
        import subprocess
        with open(log_path, "w", encoding="utf-8") as log_file:
            proc = subprocess.run(
                cmd,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=os.path.dirname(os.path.abspath(__file__)),
            )

        entry["ended_at"] = time.time()
        entry["duration_seconds"] = round(entry["ended_at"] - entry["started_at"], 2)

        if proc.returncode == 0 and os.path.exists(json_path):
            entry["status"] = "completed"
            try:
                with open(json_path, "r", encoding="utf-8") as jf:
                    report_data = json.load(jf)
                findings = report_data.get("findings", [])
                entry["findings_count"] = len(findings)
                entry["severity_summary"] = {
                    "critical": sum(1 for f in findings if f.get("severity") == "critical"),
                    "high": sum(1 for f in findings if f.get("severity") == "high"),
                    "medium": sum(1 for f in findings if f.get("severity") == "medium"),
                    "low": sum(1 for f in findings if f.get("severity") == "low"),
                    "info": sum(1 for f in findings if f.get("severity") == "info"),
                }
            except Exception:
                entry["findings_count"] = 0
        else:
            entry["status"] = "failed"
            entry["exit_code"] = proc.returncode

    except Exception as exc:
        entry["status"] = "error"
        entry["error"] = str(exc)
        entry["ended_at"] = time.time()

    if callback:
        _send_webhook_notification(callback, {
            "scan_id": scan_id,
            "target": url,
            "status": entry["status"],
            "findings_count": entry.get("findings_count", 0),
            "severity_summary": entry.get("severity_summary", {}),
            "duration_seconds": entry.get("duration_seconds", 0),
        })


@app.get("/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    """Cloud health probe endpoint."""
    return {
        "status": "healthy",
        "service": "webprobe",
        "version": VERSION,
        "total_checks": len(ALL_CHECKS),
        "profiles": list(PROFILES.keys()),
    }


@app.get("/profiles", tags=["Configuration"])
def list_profiles() -> Dict[str, Any]:
    """Catalog of all scanning profiles and check sets."""
    return {
        prof: {
            "count": len(checks),
            "checks": checks,
        }
        for prof, checks in PROFILES.items()
    }


@app.post("/scan", status_code=status.HTTP_202_ACCEPTED, tags=["Scans"])
def start_scan(req: ScanRequest, bg_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Trigger a web security assessment scan against a target URL."""
    # Basic URL validation
    parsed = urlsplit(req.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL scheme. Must start with http:// or https://",
        )

    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = {
        "scan_id": scan_id,
        "url": req.url,
        "profile": req.profile,
        "status": "queued",
        "created_at": time.time(),
        "findings_count": 0,
        "severity_summary": {},
    }

    bg_tasks.add_task(_run_scanner_job, scan_id, req.model_dump())

    return {
        "scan_id": scan_id,
        "target": req.url,
        "profile": req.profile,
        "status": "queued",
        "status_url": f"/scan/{scan_id}",
        "report_url": f"/scan/{scan_id}/report?format=json",
    }


@app.get("/scan/{scan_id}", tags=["Scans"])
def get_scan_status(scan_id: str) -> Dict[str, Any]:
    """Retrieve execution status, elapsed time, and summary findings count."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return SCANS[scan_id]


@app.get("/scan/{scan_id}/report", tags=["Reports"])
def get_scan_report(scan_id: str, format: str = Query("json", enum=["json", "md", "sarif", "log"])):
    """Retrieve the full scan report in JSON, Markdown, SARIF, or console log format."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    entry = SCANS[scan_id]
    if entry["status"] in ("queued", "running"):
        return JSONResponse(
            status_code=202,
            content={"status": entry["status"], "message": "Scan is still in progress"},
        )

    ext_map = {"json": ".json", "md": ".md", "sarif": ".sarif", "log": ".log"}
    file_path = os.path.join(REPORTS_DIR, f"{scan_id}{ext_map[format]}")

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Report file for format '{format}' not found")

    if format == "json":
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    elif format in ("md", "log"):
        with open(file_path, "r", encoding="utf-8") as f:
            return PlainTextResponse(f.read())
    else:
        return FileResponse(file_path, media_type="application/json", filename=f"webprobe_{scan_id}.sarif")


@app.get("/scans", tags=["Scans"])
def list_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """List recent scans."""
    items = list(SCANS.values())
    items.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return items[:limit]
