"""
WebProbe Cloud API Service
FastAPI wrapper to execute webprobe vulnerability and logic scans on-demand.
Includes CORS support for Cloudflare Pages and optional Cloudflare R2 report persistence.
"""

import hmac
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, Literal, Optional
from urllib.parse import urlsplit

import engines

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request, status
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

ALLOWED_ORIGINS = [o.strip() for o in os.environ.get(
    "WEBPROBE_ALLOWED_ORIGINS",
    "https://jailbreaks.coccoder999.workers.dev,http://localhost:5173",
).split(",") if o.strip()]

API_KEY = os.environ.get("WEBPROBE_API_KEY", "")
ALLOW_UNAUTHENTICATED_LOCAL = os.environ.get("WEBPROBE_ALLOW_UNAUTHENTICATED_LOCAL", "") == "1"

if not API_KEY and ALLOW_UNAUTHENTICATED_LOCAL:
    print("[!] WARNING: WebProbe API running without an API key (local dev only)")

# CORS is enforced by the browser from these backend headers: only the
# origins in WEBPROBE_ALLOWED_ORIGINS may call the API cross-origin.
# Methods and headers are the exact ones the dashboard uses — no
# wildcards, no cookies (auth is the X-API-Key header, not a cookie).
# Set on Render as: WEBPROBE_ALLOWED_ORIGINS=https://jailbreaks.coccoder999.workers.dev,http://localhost:5173
print(f"[*] CORS allowed origins: {ALLOWED_ORIGINS or '(none — same-origin only)'}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key", "Accept"],
)


def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    if API_KEY:
        if x_api_key != API_KEY:
            raise HTTPException(status_code=401, detail="Invalid or missing API key")
        return
    if ALLOW_UNAUTHENTICATED_LOCAL:
        return
    raise HTTPException(status_code=401, detail="API key not configured")


_BLOCKED_NETWORKS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "::/128", "::1/128",
    "fc00::/7", "fe80::/10",
)]


def _is_public_hostname(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if any(ip in net for net in _BLOCKED_NETWORKS):
            return False
    return True


def validate_public_url(raw_url: str) -> None:
    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid URL")
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Invalid URL scheme. Must start with http:// or https://")
    if not _is_public_hostname(parsed.hostname):
        raise HTTPException(status_code=400, detail="URL resolves to a private or loopback address")

_BASE_DIR = Path(__file__).resolve().parent
_FRONTEND_CANDIDATES = [_BASE_DIR.parent / "frontend" / "dist", _BASE_DIR / "frontend" / "dist"]
FRONTEND_DIR = next((p for p in _FRONTEND_CANDIDATES if (p / "index.html").is_file()), _FRONTEND_CANDIDATES[0])
WEBPROBE_CLI = _BASE_DIR / "webprobe.py"

def _resolve_reports_dir() -> str:
    env_dir = os.environ.get("WEBPROBE_REPORTS_DIR", "").strip()
    if env_dir:
        return os.path.abspath(env_dir)
    project_scans = _BASE_DIR.parent / "reports" / "scans"
    if project_scans.parent.is_dir():
        return str(project_scans.resolve())
    return str((_BASE_DIR / "reports" / "scans").resolve())

REPORTS_DIR = _resolve_reports_dir()
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


def _persist_scan_entry(scan_id: str) -> None:
    """Save scan metadata entry to REPORTS_DIR / {scan_id}.meta.json."""
    try:
        with _SCAN_LOCK:
            entry = SCANS.get(scan_id)
            if not entry:
                return
            data = dict(entry)
        meta_path = os.path.join(REPORTS_DIR, f"{scan_id}.meta.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def _load_persisted_scans() -> None:
    """Discover and load saved scan records from REPORTS_DIR into SCANS memory."""
    if not os.path.isdir(REPORTS_DIR):
        return

    with _SCAN_LOCK:
        # 1. Load *.meta.json files
        for fname in os.listdir(REPORTS_DIR):
            if fname.endswith(".meta.json"):
                scan_id = fname[:-10]
                meta_path = os.path.join(REPORTS_DIR, fname)
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    if isinstance(meta, dict) and "scan_id" in meta:
                        SCANS[scan_id] = meta
                except Exception:
                    continue

        # 2. Discover any report JSON files (*.json) that lack a meta file
        for fname in os.listdir(REPORTS_DIR):
            if fname.endswith(".json") and not fname.endswith(".meta.json") and not fname.endswith(".sarif.json"):
                scan_id = fname[:-5]
                if scan_id in SCANS:
                    continue
                json_path = os.path.join(REPORTS_DIR, fname)
                try:
                    with open(json_path, "r", encoding="utf-8") as f:
                        report_data = json.load(f)
                    if not isinstance(report_data, dict):
                        continue
                    findings = report_data.get("findings", [])
                    metadata = report_data.get("metadata", {})
                    summary = {
                        sev: sum(1 for finding in findings if finding.get("severity", "").lower() == sev)
                        for sev in ("critical", "high", "medium", "low", "info")
                    }
                    mtime = os.path.getmtime(json_path)
                    SCANS[scan_id] = {
                        "scan_id": scan_id,
                        "url": metadata.get("target") or report_data.get("target", "unknown"),
                        "profile": metadata.get("profile", "full"),
                        "engine": report_data.get("engine", "webprobe"),
                        "status": "completed",
                        "findings_count": len(findings),
                        "severity_summary": summary,
                        "created_at": mtime,
                        "started_at": mtime,
                        "ended_at": mtime,
                        "duration_seconds": report_data.get("duration", 0),
                    }
                    _persist_scan_entry(scan_id)
                except Exception:
                    continue


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
    url: str = Field(default="", description="Target URL (e.g. https://example.com). Required for URL engines; empty for engine=argus")
    repo: str = Field(default="", description="Code target for engine=argus: a git URL (cloned shallow) or a directory path on this host")
    profile: str = Field(default="full", description="Scan profile (quick, recon, auth, injection, authz, business, config, owasp, api, full)")
    engine: Literal["webprobe", "kagesec", "openosint", "argus", "all"] = Field(
        default="webprobe",
        description="Scanning engine. kagesec/openosint run only when installed on this host; argus scans a repo, not a URL; all runs the installed URL engines in sequence, plus argus when repo is given",
    )
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
        validate_public_url(callback_url)
    except HTTPException:
        return
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


def _run_kagesec(scan_id: str, url: str, log_file, redact: bool):
    """Run `kagesec scan` in a per-scan workdir; return (findings, ok)."""
    binary = engines.engine_binary("kagesec")
    workdir = os.path.join(REPORTS_DIR, f"{scan_id}-kagesec")
    os.makedirs(workdir, exist_ok=True)
    cmd = [
        binary, "scan", url, "--no-ai", "--output", "json",
        "--max-pages", "10", "--depth", "2", "--timeout", "600",
        # KageSec skips unchanged pages on repeat scans (delta mode,
        # ~/.kagesec/crawl_state). A dashboard scan must report the
        # target as it is now, so force a full scan every time.
        "--full",
    ]
    if not engines.kagesec_browser_available():
        cmd.append("--no-browser")
    with _SCAN_LOCK:
        _PROCESSES[scan_id] = subprocess.Popen(
            cmd, stdout=log_file, stderr=subprocess.STDOUT, text=True, cwd=workdir
        )
        proc = _PROCESSES[scan_id]
    returncode = proc.wait()
    raw_path = os.path.join(workdir, "reports", "kagesec_report.json")
    if returncode == 0 and os.path.exists(raw_path):
        with open(raw_path, "r", encoding="utf-8") as f:
            return engines.normalize_kagesec(json.load(f), redact=redact), True
    return [], False


def _run_openosint(scan_id: str, url: str, log_file):
    """Run OpenOSINT direct tools (no AI, no key) for a domain; return (findings, ok)."""
    binary = engines.engine_binary("openosint")
    host = urlsplit(url).hostname or url
    outputs = []
    for subcommand in ("dns", "whois", "rdap", "exposure", "dorks"):
        try:
            proc = subprocess.run(
                [binary, "--json", subcommand, host],
                capture_output=True, text=True, timeout=120,
            )
        except Exception as exc:
            log_file.write(f"[openosint] {subcommand} failed: {exc}\n")
            continue
        log_file.write(proc.stdout or "")
        log_file.write(proc.stderr or "")
        data = engines._openosint_json(proc.stdout or "")
        if data:
            outputs.append(data)
    return engines.normalize_openosint(outputs), bool(outputs)


def _resolve_argus_target(repo: str, scan_id: str, log_file):
    """Return (path, cloned_dir_or_None) for an argus repo input.

    A git URL is cloned shallow into a per-scan dir (deleted by the caller).
    A local path must already exist and be a directory; system dirs are refused.
    """
    repo = (repo or "").strip()
    if repo.startswith(("http://", "https://")):
        clone_dir = os.path.join(REPORTS_DIR, f"{scan_id}-argus-repo")
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", repo, clone_dir],
            capture_output=True, text=True, timeout=120,
            env=engines.argus_scan_env(),
        )
        log_file.write(proc.stdout or "")
        log_file.write(proc.stderr or "")
        if proc.returncode != 0 or not os.path.isdir(clone_dir):
            raise RuntimeError(f"Could not clone repo: {repo}")
        return clone_dir, clone_dir
    path = os.path.abspath(os.path.expanduser(repo))
    if path in ("/", "/proc", "/sys", "/dev", "/etc"):
        raise RuntimeError(f"Refused repo path: {repo}")
    if not os.path.isdir(path):
        raise RuntimeError(f"Repo path does not exist or is not a directory: {repo}")
    return path, None


def _run_argus(scan_id: str, repo: str, log_file):
    """Run `argus scan all` on a repo; return (findings, ok)."""
    binary = engines.engine_binary("argus")
    workdir = os.path.join(REPORTS_DIR, f"{scan_id}-argus")
    os.makedirs(workdir, exist_ok=True)
    sarif_path = os.path.join(workdir, "argus.sarif")
    target_path, clone_dir = _resolve_argus_target(repo, scan_id, log_file)
    try:
        cmd = [binary, "scan", "all", target_path, "--format", "sarif", "-o", sarif_path, "--fail-on", "never"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=engines.argus_scan_env())
        log_file.write(proc.stdout or "")
        log_file.write(proc.stderr or "")
        if proc.returncode == 0 and os.path.exists(sarif_path):
            with open(sarif_path, "r", encoding="utf-8") as f:
                findings = engines.normalize_sarif(json.load(f), engine="argus")
            # Bandit B101 ("assert used") fires on every assert in the test
            # files and drowns the report (5,998 of 7,802 on our own backend).
            # Asserts in tests are not a finding; the raw SARIF is kept in
            # the scan workdir for anyone who wants the full list.
            kept = [f for f in findings if f.get("extra", {}).get("rule_id") != "bandit/B101"]
            log_file.write(f"[argus] {len(findings) - len(kept)} bandit/B101 (assert-used) findings excluded as noise.\n")
            return kept, True
        return [], False
    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)


def _run_scanner_job(scan_id: str, req_data: Dict[str, Any]) -> None:
    """Background task worker: dispatch to one engine, or all installed URL engines in sequence."""
    engine = req_data.get("engine", "webprobe")
    if engine == "webprobe":
        _run_webprobe_job(scan_id, req_data)
        return
    if engine == "all":
        names = [name for name in ("webprobe", "kagesec", "openosint") if engines.engine_available(name)]
        if req_data.get("repo") and engines.engine_available("argus"):
            names.append("argus")
    else:
        names = [engine]

    with _SCAN_LOCK:
        entry = SCANS[scan_id]
        if entry["status"] == "aborted":
            return
        entry["status"] = "running"
        entry["started_at"] = time.time()
        _persist_scan_entry(scan_id)

    url = req_data["url"]
    repo = req_data.get("repo", "")
    target = url or repo
    profile = req_data.get("profile", "full")
    redact = req_data.get("redact", True)
    callback = req_data.get("webhook_callback")
    json_path = os.path.join(REPORTS_DIR, f"{scan_id}.json")
    md_path = os.path.join(REPORTS_DIR, f"{scan_id}.md")
    sarif_path = os.path.join(REPORTS_DIR, f"{scan_id}.sarif")
    log_path = os.path.join(REPORTS_DIR, f"{scan_id}.log")
    findings: list = []
    ran: list = []
    ok = False
    try:
        # WebProbe first, on its own: it opens the log in "w" mode itself,
        # so a second "w" handle from this function would truncate its output.
        if "webprobe" in names:
            with _SCAN_LOCK:
                if SCANS[scan_id]["status"] != "aborted":
                    _run_webprobe_job(scan_id, {**req_data, "engine": "webprobe", "webhook_callback": None})
                    if os.path.exists(json_path):
                        with open(json_path, "r", encoding="utf-8") as f:
                            webprobe_findings = json.load(f).get("findings", [])
                        for finding in webprobe_findings:
                            finding.setdefault("engine", "webprobe")
                        findings.extend(webprobe_findings)
                        ran.append("webprobe")
                        ok = True
        with open(log_path, "a", encoding="utf-8") as log_file:
            for name in names:
                if name == "webprobe":
                    continue
                with _SCAN_LOCK:
                    if SCANS[scan_id]["status"] == "aborted":
                        break
                if name == "kagesec":
                    found, succeeded = _run_kagesec(scan_id, url, log_file, redact)
                    if succeeded:
                        findings.extend(found)
                        ran.append(name)
                        ok = True
                elif name == "openosint":
                    found, succeeded = _run_openosint(scan_id, url, log_file)
                    if succeeded:
                        findings.extend(found)
                        ran.append(name)
                        ok = True
                elif name == "argus":
                    found, succeeded = _run_argus(scan_id, repo, log_file)
                    if succeeded:
                        findings.extend(found)
                        ran.append(name)
                        ok = True
        findings = engines.dedupe_findings(findings)
        duration = round(time.time() - SCANS[scan_id]["started_at"], 2)
        report = engines.webprobe_report(target, engine, ran, findings, duration)
        report["metadata"]["profile"] = profile
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(engines.markdown_summary(target, engine, findings))
        with open(sarif_path, "w", encoding="utf-8") as f:
            json.dump(engines.sarif_from_findings(findings, target), f, indent=2)
        summary = {
            severity: sum(1 for finding in findings if finding.get("severity", "").lower() == severity)
            for severity in ("critical", "high", "medium", "low", "info")
        }
        with _SCAN_LOCK:
            _PROCESSES.pop(scan_id, None)
            entry["ended_at"] = time.time()
            entry["duration_seconds"] = duration
            if entry["status"] == "aborted":
                completed = False
            elif ok:
                entry["status"] = "completed"
                entry["findings_count"] = len(findings)
                entry["severity_summary"] = summary
                completed = True
            else:
                entry["status"] = "failed"
                completed = False
            _persist_scan_entry(scan_id)
        if completed:
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
            _persist_scan_entry(scan_id)
    if callback:
        _send_webhook_notification(callback, {
            "scan_id": scan_id,
            "target": target,
            "status": entry["status"],
            "findings_count": entry.get("findings_count", 0),
            "severity_summary": entry.get("severity_summary", {}),
            "duration_seconds": entry.get("duration_seconds", 0),
        })


def _run_webprobe_job(scan_id: str, req_data: Dict[str, Any]) -> None:
    """Background task worker that executes the WebProbe scanner subprocess."""
    with _SCAN_LOCK:
        entry = SCANS[scan_id]
        # An assessment can be cancelled before the background worker starts.
        if entry["status"] == "aborted":
            return
        entry["status"] = "running"
        entry["started_at"] = time.time()
        _persist_scan_entry(scan_id)

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
        str(WEBPROBE_CLI),
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
            _persist_scan_entry(scan_id)

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
            _persist_scan_entry(scan_id)

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
        "engines": [name for name in engines.ENGINES if engines.engine_available(name)],
        "r2_storage_enabled": bool(R2_ACCOUNT_ID and R2_BUCKET_NAME),
    }


@api.get("/engines", tags=["Configuration"])
def list_engines() -> Dict[str, Any]:
    """Which scan engines are installed on this host. Public like /health:
    it only names installed tools, and the frontend has no API-key wiring yet."""
    return engines.engine_status()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):  # type: ignore[override]
        raise RuntimeError("redirect refused, verify the endpoint")


def _instabox_call(method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """One authenticated call to the InstaBox API. Keys come from Render
    env only (INSTABOX_API_KEY); nothing here is ever logged or returned."""
    base = os.environ.get("INSTABOX_API_BASE", "https://api.instabox.sh").rstrip("/")
    api_key = os.environ.get("INSTABOX_API_KEY", "")
    if not api_key:
        raise RuntimeError("InstaBox API key is not configured")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("X-API-Key", api_key)
    if data is not None:
        req.add_header("Content-Type", "application/json")
        req.add_header("Idempotency-Key", str(uuid.uuid4()))
    try:
        with urllib.request.build_opener(_NoRedirect()).open(req, timeout=15) as resp:
            if resp.status == 204:
                return {}
            return json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"InstaBox HTTP {exc.code} on {method} {path}") from exc


def _instabox_machine() -> Dict[str, Any]:
    wanted = os.environ.get("INSTABOX_BOX6_MACHINE_ID", "")
    machines = _instabox_call("GET", "/v1/machines").get("machines", [])
    if wanted:
        for machine in machines:
            if machine.get("id") == wanted:
                return machine
        raise RuntimeError("Configured InstaBox machine id was not found")
    if len(machines) == 1:
        return machines[0]
    for machine in machines:
        if machine.get("name") == "box6":
            return machine
    raise RuntimeError("No single InstaBox machine found for box6")


def _machine_ready(machine: Dict[str, Any]) -> bool:
    return machine.get("state") == "running" and bool(
        machine.get("ready") or (machine.get("runtime") or {}).get("ready")
    )


def _wake_box6() -> Dict[str, Any]:
    """Resume box6 if suspended, then poll until it is running+ready.
    Max ~90s total. No keepalive timer anywhere: this runs only when a
    scan actually needs box6. Returns {"ready": bool, "state": str}."""
    deadline = time.time() + 90
    machine = _instabox_machine()
    machine_id = machine.get("id")
    woke = False
    if machine.get("state") == "suspended":
        result = _instabox_call("POST", f"/v1/machines/{machine_id}/resume", {})
        operation_id = result.get("id")
        if operation_id:
            while time.time() < deadline:
                operation = _instabox_call("GET", f"/v1/operations/{operation_id}")
                if operation.get("state") in ("succeeded", "failed"):
                    break
                time.sleep(5)
        woke = True
    while time.time() < deadline:
        machine = _instabox_call("GET", f"/v1/machines/{machine_id}")
        if _machine_ready(machine):
            return {"ready": True, "state": machine.get("state", "running"), "woke": woke}
        time.sleep(5)
    return {"ready": False, "state": machine.get("state", "unknown"), "woke": woke}


@api.post("/wake/box6", tags=["System"])
def wake_box6(request: Request) -> Dict[str, Any]:
    """Wake box6 on demand for the Workers proxy. Protected by a shared
    secret (WAKE_SECRET, Render env only) sent as X-Wake-Secret — this is
    NOT the WebProbe API key and it is never exposed to the browser.
    If WAKE_SECRET / INSTABOX_API_KEY are not configured, wake is
    unavailable (503) and the proxy falls back or asks for a retry."""
    secret = os.environ.get("WAKE_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="Wake service is not configured")
    presented = request.headers.get("X-Wake-Secret", "")
    if not presented or not hmac.compare_digest(presented, secret):
        raise HTTPException(status_code=401, detail="Invalid wake secret")
    try:
        result = _wake_box6()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if result["ready"]:
        return result
    return JSONResponse(
        status_code=202,
        content={**result, "note": "Box6 is still waking; retry in about 30 seconds."},
    )


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
def start_scan(req: ScanRequest, bg_tasks: BackgroundTasks, _key: None = Depends(require_api_key)) -> Dict[str, Any]:
    """Trigger a scan: a URL for the URL engines, a repo for engine=argus."""
    if req.webhook_callback:
        validate_public_url(req.webhook_callback)

    if req.engine == "argus":
        if not req.repo.strip():
            raise HTTPException(status_code=400, detail="Engine 'argus' scans code: pass 'repo' as a git URL or a directory path on this host.")
        if req.repo.strip().startswith(("http://", "https://")):
            validate_public_url(req.repo.strip())
        elif not os.path.isdir(os.path.abspath(os.path.expanduser(req.repo.strip()))):
            raise HTTPException(status_code=400, detail=f"Repo path does not exist or is not a directory: {req.repo.strip()}")
        if not engines.engine_available("argus"):
            binary = engines.engine_binary("argus")
            raise HTTPException(status_code=400, detail=f"Engine 'argus' is not installed on this host (binary '{binary}' not found).")
    else:
        if not req.url.strip():
            raise HTTPException(status_code=400, detail="Pass 'url' for this engine (engine=argus takes 'repo' instead).")
        validate_public_url(req.url)
        if req.engine != "webprobe" and req.engine != "all" and not engines.engine_available(req.engine):
            binary = engines.engine_binary(req.engine)
            raise HTTPException(
                status_code=400,
                detail=f"Engine '{req.engine}' is not installed on this host (binary '{binary}' not found).",
            )
    if req.engine in ("webprobe", "all") and req.profile not in PROFILES:
        raise HTTPException(status_code=400, detail="Unknown scan profile")

    target = req.url.strip() or req.repo.strip()
    scan_id = str(uuid.uuid4())
    with _SCAN_LOCK:
        SCANS[scan_id] = {
            "scan_id": scan_id,
            "url": target,
            "profile": req.profile,
            "engine": req.engine,
            "status": "queued",
            "created_at": time.time(),
            "findings_count": 0,
            "severity_summary": {},
        }
        _persist_scan_entry(scan_id)

    bg_tasks.add_task(_run_scanner_job, scan_id, req.model_dump())

    return {
        "scan_id": scan_id,
        "target": target,
        "profile": req.profile,
        "engine": req.engine,
        "status": "queued",
        "status_url": f"/scan/{scan_id}",
        "report_url": f"/scan/{scan_id}/report?format=json",
    }


@api.get("/scan/{scan_id}", tags=["Scans"])
def get_scan_status(scan_id: str, _key: None = Depends(require_api_key)) -> Dict[str, Any]:
    """Retrieve execution status, elapsed time, and summary findings count."""
    with _SCAN_LOCK:
        if scan_id not in SCANS:
            raise HTTPException(status_code=404, detail="Scan ID not found")
        return dict(SCANS[scan_id])


@api.post("/scan/{scan_id}/abort", tags=["Scans"])
def abort_scan(scan_id: str, _key: None = Depends(require_api_key)) -> Dict[str, Any]:
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
        _persist_scan_entry(scan_id)
        return {"scan_id": scan_id, "status": "aborted"}


@api.get("/scan/{scan_id}/report", tags=["Reports"])
def get_scan_report(scan_id: str, format: Literal["json", "md", "sarif", "log"] = Query("json"), _key: None = Depends(require_api_key)):
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
def list_scans(request: Request, limit: int = Query(50, ge=1, le=1000), x_api_key: Optional[str] = Header(default=None)) -> Any:
    """List recent scans."""
    # Preserve the legacy JSON endpoint while allowing browser refreshes on the
    # frontend's /scans route when the built UI is served by this process.
    index = FRONTEND_DIR / "index.html"
    if request.url.path == "/scans" and "text/html" in request.headers.get("accept", "") and index.is_file():
        return FileResponse(index)
    require_api_key(x_api_key)
    with _SCAN_LOCK:
        items = [dict(item) for item in SCANS.values()]
    items.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return items[:limit]


@app.on_event("startup")
def _startup():
    _load_persisted_scans()

_load_persisted_scans()

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
