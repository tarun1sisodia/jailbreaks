"""Phase 2 tests: Infrastructure checks (positive + negative assertions)."""

from webprobe.checks.phase6_infra import (
    check_cache_deception,
    check_cookie_flags,
    check_cors_dynamic,
    check_debug_flags,
)


def test_cors_dynamic_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server

    def _cors_reflect(handler):
        origin = handler.headers.get("Origin", "")
        handler.send_response(200)
        handler.send_header("Access-Control-Allow-Origin", origin)
        handler.send_header("Access-Control-Allow-Credentials", "true")
        handler.send_header("Content-Length", "2")
        handler.end_headers()
        handler.wfile.write(b"OK")

    routes["GET /"] = _cors_reflect

    ctx = ctx_factory()
    findings = check_cors_dynamic(ctx)
    assert len(findings) >= 1
    assert any("cors" in f.category.lower() for f in findings)


def test_cors_dynamic_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    # Strict CORS: no credentials or fixed allowed origin only
    routes["GET /"] = (200, "OK", {
        "Access-Control-Allow-Origin": base_url,
        "Access-Control-Allow-Credentials": "false",
    })

    ctx = ctx_factory()
    findings = check_cors_dynamic(ctx)
    assert findings == []


def test_cache_deception_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    body = "<html><body>User Profile: user@example.com, Account #98765</body></html>"
    routes["GET /profile/test.css"] = (200, body, {
        "Content-Type": "text/html",
        "X-Cache": "HIT",
        "Age": "3600",
    })

    ctx = ctx_factory({"cookie": "sess=user1"})
    ctx.discovered = [f"{base_url}/profile"]
    findings = check_cache_deception(ctx)
    assert len(findings) >= 1
    assert any(f.category == "cache_deception" for f in findings)


def test_cache_deception_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /profile/test.css"] = (404, "Not Found", {"Content-Type": "text/plain"})

    ctx = ctx_factory({"cookie": "sess=user1"})
    ctx.discovered = [f"{base_url}/profile"]
    findings = check_cache_deception(ctx)
    assert findings == []


def test_cookie_flags_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "OK", {
        "Set-Cookie": "sess=abc; Domain=.example.com; Path=/",
    })

    ctx = ctx_factory()
    findings = check_cookie_flags(ctx)
    assert len(findings) >= 1
    assert any(f.category == "cookie" for f in findings)


def test_cookie_flags_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "OK", {
        "Set-Cookie": "sess=abc; Path=/; Secure; HttpOnly; SameSite=Strict",
    })

    ctx = ctx_factory()
    findings = check_cookie_flags(ctx)
    assert findings == []


def test_debug_flags_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "OK", {
        "X-Debug-Token": "d3b4970k3n",
    })

    ctx = ctx_factory()
    findings = check_debug_flags(ctx)
    assert len(findings) >= 1
    assert any(f.category == "debug" for f in findings)


def test_debug_flags_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "Normal Clean Production Page", {"Content-Type": "text/html"})

    ctx = ctx_factory()
    findings = check_debug_flags(ctx)
    assert findings == []
