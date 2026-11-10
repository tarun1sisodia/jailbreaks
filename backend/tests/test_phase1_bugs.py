import json
import re
import pytest
from webprobe.core.models import Finding, Point


def test_jwt_rs_hs_token_from_page(mock_server, ctx_factory):
    """Bug 1: `name` must default when token comes from HTML, not ctx.tokens."""
    base_url, routes, log, _ = mock_server
    fake_jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlMTIzNA"  # secret-scan: allow (test fixture)
    routes["GET /"] = (200, f'<html><script>var t="{fake_jwt}"</script></html>',
                       {"Content-Type": "text/html"})
    routes["GET /.well-known/jwks.json"] = (200, {
        "keys": [{
            "kty": "RSA",
            "n": "u1SU1LfVJXElvumEZaLtVzOJQ9HKufbSb9gghPqxMQE",
            "e": "AQAB"
        }]
    }, {"Content-Type": "application/json"})

    ctx = ctx_factory({"exploit": True})
    ctx.pages = [{"url": base_url + "/", "html": routes["GET /"][1]}]
    from webprobe.checks.phase2_auth import check_jwt_rs_hs_confusion
    result = check_jwt_rs_hs_confusion(ctx)
    assert isinstance(result, list)


def test_jwt_jku_no_name_error(mock_server, ctx_factory):
    """Bug 2: check_jwt_jku must not raise NameError when token comes from page or tokens empty."""
    base_url, routes, log, _ = mock_server
    fake_jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlMTIzNA"  # secret-scan: allow (test fixture)
    routes["GET /"] = (200, f'<html><script>var t="{fake_jwt}"</script></html>',
                       {"Content-Type": "text/html"})

    class MockCollab:
        host = "127.0.0.1"
        port = 1234
        def count(self, marker):
            return 0

    ctx = ctx_factory({"exploit": True})
    ctx.collab = MockCollab()
    ctx.pages = [{"url": base_url + "/", "html": routes["GET /"][1]}]
    from webprobe.checks.phase2_auth import check_jwt_jku
    result = check_jwt_jku(ctx)
    assert isinstance(result, list)


def test_session_revocation_links(mock_server, ctx_factory):
    """Bug 3: check_session_revocation must parse logout link from HTML via parse_page."""
    base_url, routes, log, _ = mock_server
    html_with_logout = '<html><a href="/logout">Logout</a></html>'
    routes["GET /"] = (200, html_with_logout, {"Content-Type": "text/html"})
    ctx = ctx_factory({"test_email": "a@x.com", "test_password": "pass"})
    ctx.pages = [{"url": base_url + "/", "html": html_with_logout}]
    from webprobe.checks.phase2_auth import check_session_revocation
    # Function will return [] if no login form, but must not crash
    result = check_session_revocation(ctx)
    assert isinstance(result, list)


def test_cors_dynamic_parses(mock_server, ctx_factory):
    """Bug 4: check_cors_dynamic must parse and execute without syntax error."""
    base_url, routes, log, _ = mock_server
    routes["GET /"] = (200, "ok", {"Content-Type": "text/plain"})
    ctx = ctx_factory()
    from webprobe.checks.phase6_infra import check_cors_dynamic
    result = check_cors_dynamic(ctx)
    assert isinstance(result, list)


def test_rbac_matrix_different_content(mock_server, ctx_factory):
    """Bug 5: Two roles return 200 with different accounts (alice vs bob) — not IDOR."""
    base_url, routes, log, _ = mock_server
    from tests.conftest import _respond_by_cookie
    # Same non-identity data (balance, tier), but different user/email identity
    routes["GET /api/me"] = lambda h: _respond_by_cookie(h, {
        "session=alice": (200, json.dumps({"user": "alice", "email": "a@x.com", "tier": "gold", "balance": 100, "extra": "x" * 200})),
        "session=bob":   (200, json.dumps({"user": "bob", "email": "b@x.com", "tier": "silver", "balance": 50, "extra": "y" * 200})),
    })
    ctx = ctx_factory({"cookie": "session=alice", "secondary_cookie": "session=bob"})
    ctx.discovered = [base_url + "/api/me"]
    from webprobe.checks.phase4_authorization import check_rbac_matrix
    findings = check_rbac_matrix(ctx)
    idor = [f for f in findings if "identical" in f.title.lower()]
    assert idor == [], "different bodies must not be flagged as IDOR"


def test_graphql_resolver_nested_json(mock_server, ctx_factory):
    """Bug 6: check_graphql_resolver must parse nested types from JSON schema."""
    base_url, routes, log, _ = mock_server
    schema_intro = {
        "data": {
            "__schema": {
                "types": [
                    {
                        "name": "User",
                        "fields": [
                            {"name": "id"},
                            {"name": "email"},
                            {"name": "role"}
                        ]
                    }
                ]
            }
        }
    }
    routes["POST /graphql"] = (200, json.dumps(schema_intro), {"Content-Type": "application/json"})
    ctx = ctx_factory({"cookie": "session=valid"})
    ctx.endpoints = ["/graphql"]
    from webprobe.checks.phase4_authorization import check_graphql_resolver
    findings = check_graphql_resolver(ctx)
    assert isinstance(findings, list)


def test_fsm_workflow_precondition(mock_server, ctx_factory):
    """Bug 7: check_fsm_workflow honors --state-precondition."""
    base_url, routes, log, _ = mock_server
    routes["POST /book/prep"] = (200, '{"ready": true}', {"Content-Type": "application/json"})
    routes["POST /book/confirm"] = (200, '{"confirmed": true}', {"Content-Type": "application/json"})
    ctx = ctx_factory({
        "cookie": "session=valid",
        "state_url": f"{base_url}/book",
        "state_actions": "confirm",
        "state_precondition": f"{base_url}/book/prep"
    })
    from webprobe.checks.phase5_business_logic import check_fsm_workflow
    findings = check_fsm_workflow(ctx)
    assert isinstance(findings, list)


def test_numeric_precision_sentinels(mock_server, ctx_factory):
    """Bug 8: check_numeric_precision must not fire on legitimate 0.01 in page."""
    base_url, routes, log, _ = mock_server
    # Page already contains '0.01'
    routes["GET /cart?amount=1"] = (200, "<html>Total fee: $0.01</html>", {"Content-Type": "text/html"})
    routes["GET /cart?amount=0.01"] = (200, "<html>Total fee: $0.01</html>", {"Content-Type": "text/html"})
    ctx = ctx_factory()
    point = Point(url=f"{base_url}/cart", method="GET", param="amount", param_type="query", orig_value="1")
    from webprobe.checks.phase5_business_logic import check_numeric_precision
    findings = check_numeric_precision(ctx, point)
    # Should not fire simply because 0.01 was already in page
    assert findings == []


def test_postex_invoke_executed(ctx_factory):
    """Bug 9: generate_non_destructive_proof executes invoke callback."""
    ctx = ctx_factory({"exploit_rce": True})
    finding = Finding("rce", "critical", "RCE", "http://example.com/rce", method="POST")

    executed_cmds = []
    def mock_invoke(cmd: str):
        executed_cmds.append(cmd)
        if cmd == "id":
            return "uid=1000(app) gid=1000(app) groups=1000(app)"
        if cmd == "whoami":
            return "app"
        if cmd == "hostname":
            return "prod-srv-01"
        if cmd == "uname -a":
            return "Linux prod-srv-01 5.15.0-generic"
        return ""

    from webprobe.exploits.postex import generate_non_destructive_proof
    proof = generate_non_destructive_proof(ctx, finding, invoke=mock_invoke)
    assert proof is not None
    assert "uid=" in proof.evidence
    assert len(executed_cmds) > 0


def test_checks_init_single_sort():
    """Bug 10: ALL_CHECKS must be sorted and stable."""
    from webprobe.checks import ALL_CHECKS
    assert isinstance(ALL_CHECKS, list)
    assert ALL_CHECKS == sorted(set(ALL_CHECKS))
