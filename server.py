"""
WebProbe Cloud API Service
FastAPI wrapper to execute webprobe vulnerability and logic scans on-demand.
Includes CORS support for Cloudflare Pages and optional Cloudflare R2 report persistence.
"""

import json
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Literal, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, BackgroundTasks, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from webprobe.checks import ALL_CHECKS, PROFILES
from webprobe.cli import VERSION

app = FastAPI(
    title="WebProbe Cloud Scanner Service",
    description="Authorized Web Application Vulnerability & Logic Scanner API",
    version=VERSION,
)
api = APIRouter()

# Enable CORS for Cloudflare Pages, local dev, and custom frontend domains
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REPORTS_DIR = os.path.abspath(os.environ.get("WEBPROBE_REPORTS_DIR", "reports"))
os.makedirs(REPORTS_DIR, exist_ok=True)

# Cloudflare R2 configuration (optional free-tier report persistence)
R2_ACCOUNT_ID = os.environ.get("R2_ACCOUNT_ID")
R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY")
R2_BUCKET_NAME = os.environ.get("R2_BUCKET_NAME")

# In-memory scan registry: scan_id -> dict
SCANS: Dict[str, Dict[str, Any]] = {}
_SCAN_LOCK = threading.RLock()
_PROCESSES: Dict[str, subprocess.Popen] = {}
FRONTEND_DIR = Path(__file__).resolve().parent / "frontend" / "dist"


def _get_r2_client():
    """Returns a boto3 S3 client configured for Cloudflare R2, or None."""
    if not (R2_ACCOUNT_ID and R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY and R2_BUCKET_NAME):
        return None
    try:
        import boto3
        return boto3.client(
            "s3",
            endpoint_url=f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com",
            aws_access_key_id=R2_ACCESS_KEY_ID,
            aws_secret_access_key=R2_SECRET_ACCESS_KEY,
            region_name="auto",
        )
    except Exception:
        return None


def _upload_to_r2(local_path: str, r2_key: str) -> bool:
    """Uploads a local report file to Cloudflare R2 bucket."""
    s3 = _get_r2_client()
    if not s3:
        return False
    try:
        s3.upload_file(local_path, R2_BUCKET_NAME, r2_key)
        return True
    except Exception as exc:
        print(f"[!] Cloudflare R2 upload error for {r2_key}: {exc}")
        return False


def _download_from_r2(r2_key: str, local_path: str) -> bool:
    """Downloads a report file from Cloudflare R2 bucket if missing locally."""
    s3 = _get_r2_client()
    if not s3:
        return False
    try:
        s3.download_file(R2_BUCKET_NAME, r2_key, local_path)
        return True
    except Exception:
        return False


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
    with _SCAN_LOCK:
        entry = SCANS[scan_id]
        # An assessment can be cancelled before the background worker starts.
        if entry["status"] == "aborted":
            return
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
        "-u",  # Make the console log available while the subprocess is running.
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
    cmd.append("--redact" if redact else "--no-redact")
    if cookie:
        cmd.extend(["--cookie", cookie])
    if secondary_cookie:
        cmd.extend(["--secondary-cookie", secondary_cookie])
    if admin_cookie:
        cmd.extend(["--admin-cookie", admin_cookie])

    try:
        with open(log_path, "w", encoding="utf-8") as log_file:
            with _SCAN_LOCK:
                if entry["status"] == "aborted":
                    return
                proc = subprocess.Popen(
                    cmd,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=os.path.dirname(os.path.abspath(__file__)),
                )
                _PROCESSES[scan_id] = proc
            returncode = proc.wait()

        # Keep the process registered until its final status has been recorded.
        # This prevents an abort racing with an already-finished subprocess.
        success = returncode == 0 and os.path.exists(json_path)
        findings = []
        if success:
            with open(json_path, "r", encoding="utf-8") as jf:
                findings = json.load(jf).get("findings", [])
            summary = {
                severity: sum(1 for finding in findings if finding.get("severity", "").lower() == severity)
                for severity in ("critical", "high", "medium", "low", "info")
            }

        with _SCAN_LOCK:
            _PROCESSES.pop(scan_id, None)
            entry["ended_at"] = time.time()
            entry["duration_seconds"] = round(entry["ended_at"] - entry["started_at"], 2)
            if entry["status"] == "aborted":
                completed = False
            elif success:
                entry["status"] = "completed"
                entry["findings_count"] = len(findings)
                entry["severity_summary"] = summary
                completed = True
            else:
                entry["status"] = "failed"
                entry["exit_code"] = returncode
                completed = False

        if completed:
            # Backup reports to Cloudflare R2 if configured.
            _upload_to_r2(json_path, f"reports/{scan_id}.json")
            _upload_to_r2(md_path, f"reports/{scan_id}.md")
            _upload_to_r2(sarif_path, f"reports/{scan_id}.sarif")
            _upload_to_r2(log_path, f"reports/{scan_id}.log")

    except Exception as exc:
        with _SCAN_LOCK:
            _PROCESSES.pop(scan_id, None)
            if entry["status"] != "aborted":
                entry["status"] = "error"
                entry["error"] = str(exc)
            entry["ended_at"] = time.time()
            entry["duration_seconds"] = round(entry["ended_at"] - entry["started_at"], 2)

    if callback:
        _send_webhook_notification(callback, {
            "scan_id": scan_id,
            "target": url,
            "status": entry["status"],
            "findings_count": entry.get("findings_count", 0),
            "severity_summary": entry.get("severity_summary", {}),
            "duration_seconds": entry.get("duration_seconds", 0),
        })


@api.get("/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    """Cloud health probe endpoint."""
    return {
        "status": "healthy",
        "service": "webprobe",
        "version": VERSION,
        "total_checks": len(ALL_CHECKS),
        "profiles": list(PROFILES.keys()),
        "r2_storage_enabled": bool(R2_ACCOUNT_ID and R2_BUCKET_NAME),
    }


@api.get("/profiles", tags=["Configuration"])
def list_profiles() -> Dict[str, Any]:
    """Catalog of all scanning profiles and check sets."""
    return {
        prof: {
            "count": len(checks),
            "checks": checks,
        }
        for prof, checks in PROFILES.items()
    }


@api.post("/scan", status_code=status.HTTP_202_ACCEPTED, tags=["Scans"])
def start_scan(req: ScanRequest, bg_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Trigger a web security assessment scan against a target URL."""
    # Basic URL validation
    try:
        parsed = urlsplit(req.url)
        valid_url = parsed.scheme in ("http", "https") and bool(parsed.hostname) and not parsed.username and not parsed.password
    except ValueError:
        valid_url = False
    if not valid_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL scheme. Must start with http:// or https://",
        )

    if req.profile not in PROFILES:
        raise HTTPException(status_code=400, detail="Unknown scan profile")

    scan_id = str(uuid.uuid4())
    with _SCAN_LOCK:
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


@api.get("/scan/{scan_id}", tags=["Scans"])
def get_scan_status(scan_id: str) -> Dict[str, Any]:
    """Retrieve execution status, elapsed time, and summary findings count."""
    with _SCAN_LOCK:
        if scan_id not in SCANS:
            raise HTTPException(status_code=404, detail="Scan ID not found")
        return dict(SCANS[scan_id])


@api.post("/scan/{scan_id}/abort", tags=["Scans"])
def abort_scan(scan_id: str) -> Dict[str, Any]:
    """Stop a queued or running scanner subprocess, if it is still active."""
    with _SCAN_LOCK:
        entry = SCANS.get(scan_id)
        if not entry:
            raise HTTPException(status_code=404, detail="Scan ID not found")
        if entry["status"] not in ("queued", "running"):
            raise HTTPException(status_code=409, detail="Scan is no longer running")
        proc = _PROCESSES.get(scan_id)
        if proc and proc.poll() is not None:
            raise HTTPException(status_code=409, detail="Scan is already finishing")
        if proc:
            try:
                proc.terminate()
            except ProcessLookupError:
                raise HTTPException(status_code=409, detail="Scan is already finishing")
        entry["status"] = "aborted"
        entry["ended_at"] = time.time()
        if entry.get("started_at"):
            entry["duration_seconds"] = round(entry["ended_at"] - entry["started_at"], 2)
        return {"scan_id": scan_id, "status": "aborted"}


@api.get("/scan/{scan_id}/report", tags=["Reports"])
def get_scan_report(scan_id: str, format: Literal["json", "md", "sarif", "log"] = Query("json")):
    """Retrieve the full scan report in JSON, Markdown, SARIF, or console log format."""
    if scan_id in SCANS:
        entry = SCANS[scan_id]
        if entry["status"] in ("queued", "running") and format != "log":
            return JSONResponse(
                status_code=202,
                content={"status": entry["status"], "message": "Scan is still in progress"},
            )

    ext_map = {"json": ".json", "md": ".md", "sarif": ".sarif", "log": ".log"}
    file_path = os.path.join(REPORTS_DIR, f"{scan_id}{ext_map[format]}")

    # The worker may not have created its log yet; an empty log is not an error.
    if format == "log" and scan_id in SCANS and SCANS[scan_id]["status"] in ("queued", "running") and not os.path.exists(file_path):
        return PlainTextResponse("")

    # If missing locally (e.g. after Render container sleep), attempt pull from Cloudflare R2
    if not os.path.exists(file_path):
        _download_from_r2(f"reports/{scan_id}{ext_map[format]}", file_path)

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


@api.get("/scans", tags=["Scans"])
def list_scans(request: Request, limit: int = Query(50, ge=1, le=1000)) -> Any:
    """List recent scans."""
    # Preserve the legacy JSON endpoint while allowing browser refreshes on the
    # frontend's /scans route when the built UI is served by this process.
    index = FRONTEND_DIR / "index.html"
    if request.url.path == "/scans" and "text/html" in request.headers.get("accept", "") and index.is_file():
        return FileResponse(index)
    with _SCAN_LOCK:
        items = [dict(item) for item in SCANS.values()]
    items.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return items[:limit]


# The browser uses same-origin /api URLs. Keep the original endpoints for CLI
# clients and deployments that already depend on them.
app.include_router(api, prefix="/api")
app.include_router(api)

if (FRONTEND_DIR / "index.html").is_file():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="frontend-assets")

    @app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    def frontend(path: str):
        if path == "api" or path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not found")
        candidate = (FRONTEND_DIR / path).resolve()
        if FRONTEND_DIR.resolve() in candidate.parents and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(FRONTEND_DIR / "index.html")
