"""Phase 2 tests: Injection checks (positive + negative assertions)."""

import urllib.parse
from webprobe.checks.phase3_injection import (
    check_blind_time,
    check_unicode_desync,
    check_xss_ast,
)
from webprobe.core.models import Point


def test_blind_time_positive(mock_server, ctx_factory, monkeypatch):
    base_url, routes, _, _ = mock_server
    routes["GET /search?q=1"] = (200, "OK", {"Content-Type": "text/html"})

    # Simulate fast responses for baseline and slow for sleep probes
    current_time = [100.0]

    def mock_monotonic():
        current_time[0] += 0.01
        return current_time[0]

    # Hook point send or time.monotonic
    orig_point_send = Point.send

    def _timed_send(self, http, value):
        if "sleep" in value.lower() or "waitfor" in value.lower():
            current_time[0] += 5.2
        return orig_point_send(self, http, value)

    monkeypatch.setattr("webprobe.checks.phase3_injection.time.monotonic", mock_monotonic)
    monkeypatch.setattr(Point, "send", _timed_send)

    ctx = ctx_factory({"time_based": True})
    point = Point(url=f"{base_url}/search", method="GET", param="q", param_type="query", orig_value="1")
    findings = check_blind_time(ctx, point)
    assert len(findings) >= 1
    assert any("blind" in f.title.lower() for f in findings)


def test_blind_time_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /search?q=1"] = (200, "OK", {"Content-Type": "text/html"})
    ctx = ctx_factory({"time_based": False})  # Not enabled
    point = Point(url=f"{base_url}/search", method="GET", param="q", param_type="query", orig_value="1")
    findings = check_blind_time(ctx, point)
    assert findings == []


def test_xss_ast_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server

    def _reflect(handler):
        query = urllib.parse.urlsplit(handler.path).query
        params = urllib.parse.parse_qs(query)
        q = params.get("q", [""])[0]
        body = f"<html><body><div>Search results: {q}</div></body></html>".encode("utf-8")
        handler.send_response(200)
        handler.send_header("Content-Type", "text/html")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    routes["GET /search"] = _reflect

    ctx = ctx_factory()
    point = Point(url=f"{base_url}/search", method="GET", param="q", param_type="query", orig_value="test")
    findings = check_xss_ast(ctx, point)
    assert len(findings) >= 1
    assert any(f.category == "xss_ast" for f in findings)
    assert any("html_body" in f.title for f in findings)


def test_xss_ast_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server

    def _escape_reflect(handler):
        import html
        query = urllib.parse.urlsplit(handler.path).query
        params = urllib.parse.parse_qs(query)
        q = params.get("q", [""])[0]
        escaped = html.escape(q)
        body = f"<html><body><div>Search results: {escaped}</div></body></html>".encode("utf-8")
        handler.send_response(200)
        handler.send_header("Content-Type", "text/html")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    routes["GET /search"] = _escape_reflect

    ctx = ctx_factory()
    point = Point(url=f"{base_url}/search", method="GET", param="q", param_type="query", orig_value="test")
    findings = check_xss_ast(ctx, point)
    assert findings == []


def test_unicode_desync_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server

    def _reflect_unicode(handler):
        query = urllib.parse.urlsplit(handler.path).query
        params = urllib.parse.parse_qs(query)
        q = params.get("q", [""])[0]
        # Backend reflects unicode probe, and document has <script> tag
        body = f"<html><head><script>var x=1;</script></head><body>{q}</body></html>".encode("utf-8")
        handler.send_response(200)
        handler.send_header("Content-Type", "text/html")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    routes["GET /filter"] = _reflect_unicode

    ctx = ctx_factory()
    point = Point(url=f"{base_url}/filter", method="GET", param="q", param_type="query", orig_value="test")
    findings = check_unicode_desync(ctx, point)
    assert len(findings) >= 1
    assert any("unicode" in f.title.lower() for f in findings)


def test_unicode_desync_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    # Safe server rejects or does not reflect raw unicode probe
    routes["GET /filter"] = (200, "<html><body>Safe</body></html>", {"Content-Type": "text/html"})
    ctx = ctx_factory()
    point = Point(url=f"{base_url}/filter", method="GET", param="q", param_type="query", orig_value="test")
    findings = check_unicode_desync(ctx, point)
    assert findings == []
