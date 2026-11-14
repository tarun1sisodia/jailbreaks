"""Contracts used by the WebProbe workspace, without making external requests."""

import json
import os
import subprocess
import sys
import time

os.environ["WEBPROBE_API_KEY"] = "test-key"

import pytest
from fastapi.testclient import TestClient

import server

KEY = {"X-API-Key": "test-key"}


@pytest.fixture(autouse=True)
def isolated_server(monkeypatch, tmp_path):
    server.SCANS.clear()
    server.REMOTE_SCANS.clear()
    server._PROCESSES.clear()
    monkeypatch.setattr(server, "REPORTS_DIR", str(tmp_path))
    yield
    for process in list(server._PROCESSES.values()):
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
    server._PROCESSES.clear()
    server.SCANS.clear()
    server.REMOTE_SCANS.clear()


def test_prefixed_and_legacy_api_routes():
    client = TestClient(server.app)
    assert client.get("/api/health").json() == client.get("/health").json()
    assert client.get("/api/scans", headers=KEY).json() == []
    assert client.get("/scans", headers={"accept": "application/json", **KEY}).json() == []
    assert "quick" in client.get("/api/profiles").json()


def test_scans_browser_refresh_returns_ui_without_breaking_json(monkeypatch, tmp_path):
    (tmp_path / "index.html").write_text("<html>WebProbe</html>")
    monkeypatch.setattr(server, "FRONTEND_DIR", tmp_path)
    client = TestClient(server.app)
    assert "WebProbe" in client.get("/scans", headers={"accept": "text/html"}).text
    assert client.get("/scans", headers={"accept": "application/json", **KEY}).json() == []
    assert client.get("/api/scans", headers={"accept": "text/html", **KEY}).json() == []


def test_launch_validates_url_and_profile_and_preserves_request(monkeypatch):
    captured = []
    monkeypatch.setattr(server, "_run_scanner_job", lambda scan_id, data: captured.append((scan_id, data)))
    client = TestClient(server.app)
    assert client.post("/api/scan", json={"url": "http://["}, headers=KEY).status_code == 400
    assert client.post("/api/scan", json={"url": "https://example.com", "profile": "missing"}, headers=KEY).status_code == 400
    response = client.post("/api/scan", json={"url": "https://example.com", "profile": "quick", "rate_limit": 2, "redact": False, "cookie": "session=fixture"}, headers=KEY)
    assert response.status_code == 202
    scan_id = response.json()["scan_id"]
    assert captured[0][0] == scan_id
    assert captured[0][1]["cookie"] == "session=fixture"
    assert captured[0][1]["redact"] is False
    assert client.get(f"/api/scan/{scan_id}", headers=KEY).json()["status"] == "queued"


def test_running_log_is_readable_but_report_waits(tmp_path):
    server.SCANS["test-id"] = {"scan_id": "test-id", "status": "running"}
    client = TestClient(server.app)
    assert client.get("/api/scan/test-id/report?format=log", headers=KEY).text == ""
    (tmp_path / "test-id.log").write_text("scanner started\n")
    log = client.get("/api/scan/test-id/report?format=log", headers=KEY)
    assert log.status_code == 200
    assert log.text == "scanner started\n"
    assert client.get("/api/scan/test-id/report?format=json", headers=KEY).status_code == 202
    assert client.get("/api/scan/test-id/report?format=other", headers=KEY).status_code == 422


def test_abort_queued_scan_prevents_worker_from_starting(monkeypatch):
    server.SCANS["queued"] = {"scan_id": "queued", "status": "queued", "created_at": time.time()}
    client = TestClient(server.app)
    assert client.post("/api/scan/queued/abort", headers=KEY).json()["status"] == "aborted"
    monkeypatch.setattr(server.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("Worker must not start"))
    server._run_scanner_job("queued", {"url": "https://example.com"})
    assert server.SCANS["queued"]["status"] == "aborted"
    assert client.post("/api/scan/queued/abort", headers=KEY).status_code == 409


def test_abort_running_process_and_reject_finished_process():
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    server.SCANS["running"] = {"scan_id": "running", "status": "running", "started_at": time.time()}
    server._PROCESSES["running"] = process
    client = TestClient(server.app)
    assert client.post("/api/scan/running/abort", headers=KEY).json()["status"] == "aborted"
    assert process.wait(timeout=5) != 0
    assert client.get("/api/scan/running", headers=KEY).json()["status"] == "aborted"

    server.SCANS["finishing"] = {"scan_id": "finishing", "status": "running", "started_at": time.time()}
    server._PROCESSES["finishing"] = process
    assert client.post("/api/scan/finishing/abort", headers=KEY).status_code == 409


def test_worker_summarizes_actual_report_and_honors_redact(monkeypatch):
    command = []

    class FakeProcess:
        def __init__(self, cmd, **_kwargs):
            command.extend(cmd)
            with open(cmd[cmd.index("-o") + 1], "w", encoding="utf-8") as report:
                json.dump({"findings": [{"severity": "critical"}, {"severity": "high"}, {"severity": "high"}]}, report)

        def wait(self):
            return 0

    monkeypatch.setattr(server.subprocess, "Popen", FakeProcess)
    monkeypatch.setattr(server, "_upload_to_r2", lambda *_args: False)
    server.SCANS["complete"] = {"scan_id": "complete", "status": "queued", "created_at": time.time()}
    server._run_scanner_job("complete", {"url": "https://example.com", "profile": "quick", "redact": False})
    scan = server.SCANS["complete"]
    assert scan["status"] == "completed"
    assert scan["findings_count"] == 3
    assert scan["severity_summary"]["critical"] == 1
    assert scan["severity_summary"]["high"] == 2
    assert "-u" in command and "--no-redact" in command
    assert "complete" not in server._PROCESSES


def test_scan_routes_require_api_key():
    client = TestClient(server.app)
    assert client.post("/api/scan", json={"url": "https://example.com"}).status_code == 401
    assert client.post("/api/scan", json={"url": "https://example.com"}, headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/scans").status_code == 401
    assert client.get("/api/remote-scans").status_code == 401
    assert client.post("/api/scans/mirror", json={"scan_id": "abc"}).status_code == 401
    assert client.get("/api/scan/abc").status_code == 401
    assert client.get("/api/scan/abc/report").status_code == 401
    assert client.post("/api/scan/abc/abort").status_code == 401
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/profiles").status_code == 200


def test_scan_rejects_private_targets_and_webhooks():
    client = TestClient(server.app)
    assert client.post("/api/scan", json={"url": "http://127.0.0.1/"}, headers=KEY).status_code == 400
    assert client.post("/api/scan", json={"url": "http://10.0.0.5/"}, headers=KEY).status_code == 400
    assert client.post("/api/scan", json={"url": "http://169.254.169.254/latest/meta-data/"}, headers=KEY).status_code == 400
    assert client.post("/api/scan", json={"url": "https://example.com", "webhook_callback": "http://192.168.1.1/hook"}, headers=KEY).status_code == 400
    assert client.post("/api/scan", json={"url": "https://example.com", "webhook_callback": "ftp://example.com/hook"}, headers=KEY).status_code == 400


def test_proxy_fallback_metadata_persists_in_scan_and_report(monkeypatch):
    captured = {}

    def fake_job(scan_id, data):
        captured["scan_id"] = scan_id
        captured["data"] = data

    monkeypatch.setattr(server, "_run_scanner_job", fake_job)
    client = TestClient(server.app)
    response = client.post("/api/scan", json={
        "url": "https://example.com",
        "profile": "quick",
        "engine": "webprobe",
        "requested_engine": "all",
        "fallback": True,
        "fallback_note": "Full engines were asleep, ran WebProbe only.",
    }, headers=KEY)
    assert response.status_code == 202
    started = response.json()
    assert started["fallback"] is True
    assert started["engine_used"] == "webprobe"
    assert started["requested_engine"] == "all"
    assert "WebProbe only" in started["note"]

    scan_id = started["scan_id"]
    scan = client.get(f"/api/scan/{scan_id}", headers=KEY).json()
    assert scan["fallback"] is True
    assert scan["requested_engine"] == "all"
    assert "WebProbe only" in scan["note"]
    listed = client.get("/api/scans", headers=KEY).json()
    assert listed[0]["scan_id"] == scan_id
    assert listed[0]["fallback"] is True

    class FakeProcess:
        def __init__(self, cmd, **_kwargs):
            with open(cmd[cmd.index("-o") + 1], "w", encoding="utf-8") as report:
                json.dump({"metadata": {"target": "https://example.com"}, "findings": []}, report)

        def wait(self):
            return 0

    monkeypatch.setattr(server.subprocess, "Popen", FakeProcess)
    monkeypatch.setattr(server, "_upload_to_r2", lambda *_args: False)
    server._run_webprobe_job(scan_id, captured["data"])

    completed = client.get(f"/api/scan/{scan_id}", headers=KEY).json()
    assert completed["status"] == "completed"
    assert completed["fallback"] is True
    assert completed["requested_engine"] == "all"
    report = client.get(f"/api/scan/{scan_id}/report?format=json", headers=KEY).json()
    assert report["metadata"]["fallback"] is True
    assert report["metadata"]["engine_used"] == "webprobe"
    assert report["metadata"]["requested_engine"] == "all"
    assert "WebProbe only" in report["metadata"]["note"]


def test_remote_scan_mirror_is_listed_without_shadowing_status():
    client = TestClient(server.app)
    scan_id = "box6-scan-123"
    record = {
        "scan_id": scan_id,
        "target": "https://example.com",
        "url": "https://example.com",
        "profile": "quick",
        "engine": "all",
        "status": "queued",
        "created_at": 1700000000.0,
        "findings_count": 0,
        "severity_summary": {},
    }
    response = client.post("/api/scans/mirror", json=record, headers=KEY)
    assert response.status_code == 200
    assert response.json()["remote"] == "box6"

    remote = client.get("/api/remote-scans", headers=KEY).json()
    assert [item["scan_id"] for item in remote] == [scan_id]
    assert remote[0]["engine"] == "all"
    # Mirrored metadata is history-only: local /scans must not include it and
    # GET /scan/{id} must stay 404 so the proxy fetches the real box6 record.
    assert client.get("/api/scans", headers=KEY).json() == []
    status_response = client.get(f"/api/scan/{scan_id}", headers=KEY)
    assert status_response.status_code == 404
    assert status_response.json()["remote"] == "box6"
    report_response = client.get(f"/api/scan/{scan_id}/report?format=json", headers=KEY)
    assert report_response.status_code == 404
    assert report_response.json()["remote"] == "box6"

    # The mirror survives a Render restart.
    server.REMOTE_SCANS.clear()
    server._load_persisted_remote_scans()
    assert scan_id in server.REMOTE_SCANS

    updated = client.post("/api/scans/mirror", json={
        "scan_id": scan_id,
        "status": "completed",
        "findings_count": 2,
        "severity_summary": {"high": 2},
    }, headers=KEY)
    assert updated.status_code == 200
    assert updated.json()["status"] == "completed"
    assert updated.json()["created_at"] == record["created_at"]
    assert updated.json()["target"] == record["target"]


def test_remote_scan_mirror_validates_ids_and_status():
    client = TestClient(server.app)
    assert client.post("/api/scans/mirror", json={"scan_id": "../escape"}, headers=KEY).status_code == 400
    assert client.post("/api/scans/mirror", json={"scan_id": "ok", "status": "made-up"}, headers=KEY).status_code == 400
