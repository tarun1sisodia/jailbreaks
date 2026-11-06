"""Contracts used by the WebProbe workspace, without making external requests."""

import json
import subprocess
import sys
import time

import pytest
from fastapi.testclient import TestClient

import server


@pytest.fixture(autouse=True)
def isolated_server(monkeypatch, tmp_path):
    server.SCANS.clear()
    server._PROCESSES.clear()
    monkeypatch.setattr(server, "REPORTS_DIR", str(tmp_path))
    yield
    for process in list(server._PROCESSES.values()):
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
    server._PROCESSES.clear()
    server.SCANS.clear()


def test_prefixed_and_legacy_api_routes():
    client = TestClient(server.app)
    assert client.get("/api/health").json() == client.get("/health").json()
    assert client.get("/api/scans").json() == []
    assert client.get("/scans", headers={"accept": "application/json"}).json() == []
    assert "quick" in client.get("/api/profiles").json()


def test_scans_browser_refresh_returns_ui_without_breaking_json(monkeypatch, tmp_path):
    (tmp_path / "index.html").write_text("<html>WebProbe</html>")
    monkeypatch.setattr(server, "FRONTEND_DIR", tmp_path)
    client = TestClient(server.app)
    assert "WebProbe" in client.get("/scans", headers={"accept": "text/html"}).text
    assert client.get("/scans", headers={"accept": "application/json"}).json() == []
    assert client.get("/api/scans", headers={"accept": "text/html"}).json() == []


def test_launch_validates_url_and_profile_and_preserves_request(monkeypatch):
    captured = []
    monkeypatch.setattr(server, "_run_scanner_job", lambda scan_id, data: captured.append((scan_id, data)))
    client = TestClient(server.app)
    assert client.post("/api/scan", json={"url": "http://["}).status_code == 400
    assert client.post("/api/scan", json={"url": "https://example.com", "profile": "missing"}).status_code == 400
    response = client.post("/api/scan", json={"url": "https://example.com", "profile": "quick", "rate_limit": 2, "redact": False, "cookie": "session=fixture"})
    assert response.status_code == 202
    scan_id = response.json()["scan_id"]
    assert captured[0][0] == scan_id
    assert captured[0][1]["cookie"] == "session=fixture"
    assert captured[0][1]["redact"] is False
    assert client.get(f"/api/scan/{scan_id}").json()["status"] == "queued"


def test_running_log_is_readable_but_report_waits(tmp_path):
    server.SCANS["test-id"] = {"scan_id": "test-id", "status": "running"}
    client = TestClient(server.app)
    assert client.get("/api/scan/test-id/report?format=log").text == ""
    (tmp_path / "test-id.log").write_text("scanner started\n")
    log = client.get("/api/scan/test-id/report?format=log")
    assert log.status_code == 200
    assert log.text == "scanner started\n"
    assert client.get("/api/scan/test-id/report?format=json").status_code == 202
    assert client.get("/api/scan/test-id/report?format=other").status_code == 422


def test_abort_queued_scan_prevents_worker_from_starting(monkeypatch):
    server.SCANS["queued"] = {"scan_id": "queued", "status": "queued", "created_at": time.time()}
    client = TestClient(server.app)
    assert client.post("/api/scan/queued/abort").json()["status"] == "aborted"
    monkeypatch.setattr(server.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("Worker must not start"))
    server._run_scanner_job("queued", {"url": "https://example.com"})
    assert server.SCANS["queued"]["status"] == "aborted"
    assert client.post("/api/scan/queued/abort").status_code == 409


def test_abort_running_process_and_reject_finished_process():
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    server.SCANS["running"] = {"scan_id": "running", "status": "running", "started_at": time.time()}
    server._PROCESSES["running"] = process
    client = TestClient(server.app)
    assert client.post("/api/scan/running/abort").json()["status"] == "aborted"
    assert process.wait(timeout=5) != 0
    assert client.get("/api/scan/running").json()["status"] == "aborted"

    server.SCANS["finishing"] = {"scan_id": "finishing", "status": "running", "started_at": time.time()}
    server._PROCESSES["finishing"] = process
    assert client.post("/api/scan/finishing/abort").status_code == 409


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
