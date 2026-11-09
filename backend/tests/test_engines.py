"""Engine normalizers and /api/engines + /api/scan engine validation.

No network, no real binaries: normalizers run on saved sample outputs,
and the API tests stub the job runner like test_server_ui.py does.
"""

import os

os.environ["WEBPROBE_API_KEY"] = "test-key"

import engines
import server
from fastapi.testclient import TestClient

KEY = {"X-API-Key": "test-key"}


def test_normalize_kagesec_maps_verified_fields():
    data = {
        "summary": {"target": "https://example.com", "total_findings": 1},
        "findings": [{
            "title": "Reflected XSS",
            "severity": "high",
            "owasp_category": "A03:2021",
            "url": "https://example.com/?q=1",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "evidence": "payload reflected",
            "verified": True,
            "confidence": 0.9,
            "cwe": "CWE-79",
            "cvss": 7.5,
            "remediation": "Encode output.",
            "poc_curl": "curl https://example.com/?q=1",
        }],
    }
    findings = engines.normalize_kagesec(data, redact=True)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["title"] == "Reflected XSS"
    assert finding["severity"] == "high"
    assert finding["cvss_score"] == 7.5
    assert finding["engine"] == "kagesec"
    assert "payload" not in finding["extra"]
    assert engines.normalize_kagesec(data, redact=False)[0]["extra"]["payload"] == "<script>alert(1)</script>"


def test_normalize_sarif_maps_level_and_score():
    data = {
        "runs": [{
            "tool": {"driver": {"rules": [{"id": "R1", "name": "Hardcoded secret", "help": {"text": "Remove it."}}]}},
            "results": [{
                "ruleId": "R1", "level": "error",
                "message": {"text": "Secret in code"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}],
                "properties": {"security-severity": "9.1"},
            }],
        }]
    }
    findings = engines.normalize_sarif(data, engine="argus")
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["cvss_score"] == 9.1
    assert findings[0]["endpoint"] == "app.py"


def test_normalize_openosint_is_info_intel_not_vulns():
    outputs = [
        {"tool": "search_dns", "target": "example.com",
         "results": ["[DNS] Domain: example.com", "[!] No SPF record found"], "error": None},
        {"tool": "search_whois", "target": "example.com",
         "results": ["Scan error: WHOIS query failed"], "error": None},
        {"domain": "example.com", "grade": "C", "score": 52,
         "findings": [{"id": "hsts_missing", "category": "http_headers", "severity": "low",
                       "title": "HSTS header missing", "evidence": "no header",
                       "recommendation": "Add HSTS."}]},
    ]
    findings = engines.normalize_openosint(outputs)
    assert len(findings) == 3
    assert findings[0]["severity"] == "low"
    assert findings[0]["engine"] == "openosint"
    assert findings[1]["severity"] == "info"
    assert findings[2]["title"] == "HSTS header missing"
    assert findings[2]["remediation"] == "Add HSTS."


def test_dedupe_and_report_shape():
    findings = engines.dedupe_findings([
        {"title": "X", "url": "https://example.com", "parameter": ""},
        {"title": "X", "url": "https://example.com", "parameter": ""},
        {"title": "Y", "url": "https://example.com", "parameter": ""},
    ])
    assert len(findings) == 2
    report = engines.webprobe_report("https://example.com", "all", ["webprobe"], findings, 1.5)
    assert report["metadata"]["engine"] == "all"
    assert report["findings"][0]["id"] == "finding-0"


def test_engines_endpoint_reports_availability(monkeypatch):
    monkeypatch.setattr(engines, "engine_available", lambda name: name == "webprobe")
    monkeypatch.setattr(engines, "engine_version", lambda name: "built-in" if name == "webprobe" else None)
    client = TestClient(server.app)
    # /api/engines is public like /health: it only names installed tools.
    assert client.get("/api/engines").status_code == 200
    body = client.get("/api/engines", headers=KEY).json()
    assert body["webprobe"]["available"] is True
    assert body["kagesec"]["available"] is False
    assert body["argus"]["url_scan"] is False


def test_scan_rejects_missing_engine_and_argus(monkeypatch):
    monkeypatch.setattr(server, "_run_scanner_job", lambda scan_id, data: None)
    client = TestClient(server.app)
    assert client.post("/api/scan", json={"url": "https://example.com", "engine": "kagesec"}, headers=KEY).status_code == 400
    response = client.post("/api/scan", json={"url": "https://example.com", "engine": "webprobe", "profile": "quick"}, headers=KEY)
    assert response.status_code == 202
    assert response.json()["engine"] == "webprobe"


def test_scan_argus_needs_repo(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_run_scanner_job", lambda scan_id, data: None)
    monkeypatch.setattr(engines, "engine_available", lambda name: True)
    client = TestClient(server.app)
    # No repo at all.
    assert client.post("/api/scan", json={"engine": "argus"}, headers=KEY).status_code == 400
    # Repo path that does not exist.
    assert client.post("/api/scan", json={"engine": "argus", "repo": "/no/such/dir"}, headers=KEY).status_code == 400
    # A URL is not a repo for argus.
    assert client.post("/api/scan", json={"engine": "argus", "url": "https://example.com"}, headers=KEY).status_code == 400
    # An existing directory is accepted.
    response = client.post("/api/scan", json={"engine": "argus", "repo": str(tmp_path)}, headers=KEY)
    assert response.status_code == 202
    assert response.json()["target"] == str(tmp_path)


def test_run_argus_parses_sarif_from_fake_binary(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import os\nos.system('ls')\n")
    fake = tmp_path / "argus"
    fake.write_text(
        "#!/bin/sh\n"
        "out=''\n"
        "prev=''\n"
        "for a in \"$@\"; do if [ \"$prev\" = '-o' ]; then out=\"$a\"; fi; prev=\"$a\"; done\n"
        "cat > \"$out\" <<'SARIF'\n"
        "{\"runs\": [{\"tool\": {\"driver\": {\"rules\": [{\"id\": \"B602\", \"name\": \"subprocess_popen_with_shell_equals_true\"}]}}, \"results\": [{\"ruleId\": \"B602\", \"level\": \"warning\", \"message\": {\"text\": \"subprocess call\"}, \"locations\": [{\"physicalLocation\": {\"artifactLocation\": {\"uri\": \"app.py\"}}}]}]}]}\n"
        "SARIF\n"
    )
    fake.chmod(0o755)
    monkeypatch.setenv("ARGUS_BIN", str(fake))
    monkeypatch.setattr(server, "REPORTS_DIR", str(tmp_path / "reports"))
    import io
    findings, ok = server._run_argus("test-scan", str(repo), io.StringIO())
    assert ok is True
    assert len(findings) == 1
    assert findings[0]["engine"] == "argus"
    assert findings[0]["endpoint"] == "app.py"
    assert findings[0]["severity"] == "medium"
