"""Phase 2 tests: Reconnaissance checks (positive + negative assertions)."""

from webprobe.checks.phase1_recon import (
    check_graphql_js_schema,
    check_manifest_routes,
    check_robots,
    check_security_txt,
)


def test_robots_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /robots.txt"] = (200, "User-agent: *\nDisallow: /admin\nDisallow: /secret\n", {"Content-Type": "text/plain"})
    ctx = ctx_factory()
    findings = check_robots(ctx)
    assert len(findings) >= 1
    assert any(f.category in ("robots", "recon") for f in findings)


def test_robots_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /robots.txt"] = (404, "Not Found", {"Content-Type": "text/plain"})
    ctx = ctx_factory()
    findings = check_robots(ctx)
    assert findings == []


def test_security_txt_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /.well-known/security.txt"] = (
        200,
        "Contact: mailto:security@example.com\nPolicy: https://example.com/policy\nExpires: 2027-01-01T00:00:00Z\n",
        {"Content-Type": "text/plain"},
    )
    ctx = ctx_factory()
    findings = check_security_txt(ctx)
    assert len(findings) >= 1
    assert any(f.category in ("recon", "security_txt") for f in findings)


def test_security_txt_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /.well-known/security.txt"] = (404, "Not Found", {"Content-Type": "text/plain"})
    routes["GET /security.txt"] = (404, "Not Found", {"Content-Type": "text/plain"})
    ctx = ctx_factory()
    findings = check_security_txt(ctx)
    assert findings == []


def test_manifest_routes_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    build_id = "testbuild123"
    routes["GET /"] = (200, f'<html><script src="/_next/static/{build_id}/_buildManifest.js"></script></html>', {"Content-Type": "text/html"})
    manifest_js = 'self.__BUILD_MANIFEST = {"/":["static/chunks/pages/index.js"],"/admin":["static/chunks/pages/admin.js"],"/profile":["static/chunks/pages/profile.js"]};'
    routes[f"GET /_next/static/{build_id}/_buildManifest.js"] = (200, manifest_js, {"Content-Type": "application/javascript"})
    
    ctx = ctx_factory()
    ctx.pages = [{"url": base_url + "/", "html": routes["GET /"][1], "scripts": [f"{base_url}/_next/static/{build_id}/_buildManifest.js"]}]
    findings = check_manifest_routes(ctx)
    assert len(findings) >= 1
    assert any("routes" in f.title.lower() for f in findings)


def test_manifest_routes_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "<html><head><title>Clean Site</title></head><body><h1>Hello</h1></body></html>", {"Content-Type": "text/html"})
    ctx = ctx_factory()
    ctx.pages = [{"url": base_url + "/", "html": routes["GET /"][1], "scripts": []}]
    findings = check_manifest_routes(ctx)
    assert findings == []


def test_graphql_js_schema_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    js_content = """
    const USER_MUTATION = mutation UpdateUserProfile($id: ID!, $email: String!) {
        updateUser(id: $id, email: $email) { id email }
    };
    const USER_QUERY = query GetUser { user { id name } };
    """
    routes["GET /app.js"] = (200, js_content, {"Content-Type": "application/javascript"})
    ctx = ctx_factory()
    ctx.pages = [{"url": base_url + "/", "scripts": [f"{base_url}/app.js"]}]
    findings = check_graphql_js_schema(ctx)
    assert len(findings) >= 1
    assert any(f.category == "graphql" for f in findings)


def test_graphql_js_schema_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /plain.js"] = (200, "console.log('hello world');", {"Content-Type": "application/javascript"})
    ctx = ctx_factory()
    ctx.pages = [{"url": base_url + "/", "scripts": [f"{base_url}/plain.js"]}]
    findings = check_graphql_js_schema(ctx)
    assert findings == []
