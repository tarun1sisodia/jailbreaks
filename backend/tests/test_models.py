"""Phase 3 tests: Models validation (CVSS, taxonomy enrichment, Response timestamp, PoC)."""

from webprobe.core.models import Finding, Response


def test_finding_has_cvss_attached():
    f = Finding(
        category="sqli",
        severity="critical",
        title="SQL Injection Detected",
        url="http://127.0.0.1/search?id=1",
    )
    assert "cvss" in f.extra
    assert f.extra["cvss"]["score"] is not None
    assert f.extra["cvss"]["score"] >= 9.0
    assert "taxonomy" in f.extra
    assert "cwe" in f.extra["taxonomy"]
    assert f.extra["taxonomy"]["cwe"] == "CWE-89"


def test_response_received_at_populated():
    r = Response(
        status=200,
        url="http://127.0.0.1/",
        headers={"content-type": "text/html"},
        raw_headers=[("Content-Type", "text/html")],
        body=b"OK",
    )
    assert r.received_at > 0.0
    assert r.content_type == "text/html"
