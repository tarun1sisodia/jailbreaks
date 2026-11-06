"""Phase 2 tests: Authorization checks (positive + negative assertions)."""

import json
from webprobe.checks.phase4_authorization import (
    check_graphql_resolver,
    check_idor_resources,
    check_mass_assign_schema,
    check_rbac_matrix,
)


def test_idor_resources_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    # Resource body length must be > 100 bytes
    resource_body = "User Booking Details: Booking ID #12345. Name: John Doe. Address: 123 Main St, New York, NY. Total: $450.00. Status: Confirmed. Secret Note: VIP Customer."
    routes["GET /api/booking?id=12345"] = (200, resource_body, {"Content-Type": "application/json"})

    ctx = ctx_factory({"cookie": "sess=user1", "secondary_cookie": "sess=user2"})
    ctx.discovered = [f"{base_url}/api/booking?id=12345"]
    findings = check_idor_resources(ctx)
    assert len(findings) >= 1
    assert any("idor" in f.title.lower() for f in findings)


def test_idor_resources_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server

    def _route(handler):
        cookie = handler.headers.get("Cookie", "")
        if "sess=user2" in cookie:
            handler.send_response(403)
            body = b"Forbidden"
        else:
            handler.send_response(200)
            body = b"User Booking Details: Booking ID #12345. Name: John Doe." + b" " * 150
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    routes["GET /api/booking?id=12345"] = _route

    ctx = ctx_factory({"cookie": "sess=user1", "secondary_cookie": "sess=user2"})
    ctx.discovered = [f"{base_url}/api/booking?id=12345"]
    findings = check_idor_resources(ctx)
    assert findings == []


def test_mass_assign_schema_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /api/profile"] = (200, {"username": "user1", "role": "user", "is_admin": False}, {"Content-Type": "application/json"})
    routes["PATCH /api/profile"] = (200, {"username": "user1", "role": "admin", "is_admin": True}, {"Content-Type": "application/json"})

    ctx = ctx_factory({"cookie": "sess=user1"})
    ctx.discovered = [f"{base_url}/api/profile"]
    findings = check_mass_assign_schema(ctx)
    assert len(findings) >= 1
    assert any("mass assignment" in f.title.lower() for f in findings)


def test_mass_assign_schema_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /api/profile"] = (200, {"username": "user1", "bio": "hello"}, {"Content-Type": "application/json"})
    routes["PATCH /api/profile"] = (400, {"error": "Invalid field"}, {"Content-Type": "application/json"})

    ctx = ctx_factory({"cookie": "sess=user1"})
    ctx.discovered = [f"{base_url}/api/profile"]
    findings = check_mass_assign_schema(ctx)
    assert findings == []


def test_rbac_matrix_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    # Unauthenticated user and customer both see identical 200 response on dashboard
    body = "<html><body>Account Dashboard: Secret Information Account 999</body></html>"
    routes["GET /dashboard"] = (200, body, {"Content-Type": "text/html"})

    ctx = ctx_factory({"cookie": "sess=cust1", "secondary_cookie": "sess=cust2"})
    ctx.discovered = [f"{base_url}/dashboard"]
    findings = check_rbac_matrix(ctx)
    assert len(findings) >= 1
    assert any(f.category == "authz" for f in findings)


def test_rbac_matrix_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server

    def _dash(handler):
        cookie = handler.headers.get("Cookie", "")
        if "sess=cust1" in cookie:
            body = b'{"id": "cust1", "data": "Alice Private Data"}'
            handler.send_response(200)
        elif "sess=cust2" in cookie:
            body = b'{"id": "cust2", "data": "Bob Private Data"}'
            handler.send_response(200)
        else:
            body = b'{"error": "unauthorized"}'
            handler.send_response(401)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    routes["GET /dashboard"] = _dash

    ctx = ctx_factory({"cookie": "sess=cust1", "secondary_cookie": "sess=cust2"})
    ctx.discovered = [f"{base_url}/dashboard"]
    findings = check_rbac_matrix(ctx)
    assert findings == []


def test_graphql_resolver_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    intro = {
        "data": {
            "__schema": {
                "types": [
                    {
                        "name": "User",
                        "fields": [
                            {"name": "id"},
                            {"name": "email"},
                            {"name": "password_hash"}
                        ]
                    }
                ]
            }
        }
    }

    def _gql(handler):
        length = int(handler.headers.get("Content-Length", 0))
        body = handler.rfile.read(length).decode("utf-8")
        if "__schema" in body:
            resp = json.dumps(intro).encode("utf-8")
        else:
            resp = json.dumps({"data": {"users": [{"email": "admin@example.com", "password_hash": "hash123"}]}}).encode("utf-8")
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(resp)))
        handler.end_headers()
        handler.wfile.write(resp)

    routes["POST /graphql"] = _gql

    ctx = ctx_factory({"cookie": "sess=user1"})
    ctx.endpoints = ["/graphql"]
    findings = check_graphql_resolver(ctx)
    assert len(findings) >= 1
    assert any("sensitive" in f.title.lower() for f in findings)


def test_graphql_resolver_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    intro = {
        "data": {
            "__schema": {
                "types": [
                    {
                        "name": "PublicPage",
                        "fields": [
                            {"name": "title"},
                            {"name": "content"}
                        ]
                    }
                ]
            }
        }
    }
    routes["POST /graphql"] = (200, intro, {"Content-Type": "application/json"})

    ctx = ctx_factory({"cookie": "sess=user1"})
    ctx.endpoints = ["/graphql"]
    findings = check_graphql_resolver(ctx)
    assert findings == []
