"""Phase 2 tests: Authentication checks (positive + negative assertions)."""

import base64
import json
import urllib.parse
from unittest.mock import MagicMock

from webprobe.checks.phase2_auth import (
    check_enumeration,
    check_jwt_jku,
    check_jwt_rs_hs_confusion,
    check_oauth_audit,
)


def test_enumeration_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    login_html = '''
    <html>
      <form action="/login" method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
        <button type="submit">Login</button>
      </form>
    </html>
    '''
    routes["GET /login"] = (200, login_html, {"Content-Type": "text/html"})

    def _login(handler):
        length = int(handler.headers.get("Content-Length", 0))
        body = handler.rfile.read(length).decode("utf-8")
        params = urllib.parse.parse_qs(body)
        uname = params.get("username", [""])[0]
        if uname == "admin@example.com":
            resp = b"User exists: Incorrect password supplied for account" + b" " * 160
            handler.send_response(200)
        else:
            resp = b"Account does not exist"
            handler.send_response(404)
        handler.send_header("Content-Type", "text/plain")
        handler.send_header("Content-Length", str(len(resp)))
        handler.end_headers()
        handler.wfile.write(resp)

    routes["POST /login"] = _login
    ctx = ctx_factory({"test_email": "admin@example.com"})
    form_def = {
        "action": f"{base_url}/login",
        "method": "POST",
        "inputs": {"username": "", "password": ""},
    }
    ctx.pages = [{"url": f"{base_url}/login", "html": login_html, "forms": [form_def]}]

    findings = check_enumeration(ctx)
    assert len(findings) >= 1
    assert any("enumeration" in f.title.lower() for f in findings)


def test_enumeration_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    login_html = '''
    <html>
      <form action="/login" method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </html>
    '''
    routes["GET /login"] = (200, login_html, {"Content-Type": "text/html"})
    routes["POST /login"] = (200, "Invalid credentials.", {"Content-Type": "text/plain"})

    ctx = ctx_factory({"test_email": "admin@example.com"})
    form_def = {
        "action": f"{base_url}/login",
        "method": "POST",
        "inputs": {"username": "", "password": ""},
    }
    ctx.pages = [{"url": f"{base_url}/login", "html": login_html, "forms": [form_def]}]

    findings = check_enumeration(ctx)
    assert findings == []


def test_jwt_rs_hs_confusion_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    hdr = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(b'{"sub":"user123","role":"admin"}').rstrip(b"=").decode()
    token = f"{hdr}.{payload}.fake_rs_sig"

    jwks = {
        "keys": [{
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fTrUOEIgK_69D_a6g_80kq9jiZET1GWNeHn634204559LqUP1324",
            "e": "AQAB"
        }]
    }
    routes["GET /.well-known/jwks.json"] = (200, jwks, {"Content-Type": "application/json"})

    def _auth_route(handler):
        cookie = handler.headers.get("Cookie", "")
        if "token=" in cookie and "deadbeef" not in cookie:
            body = b"Welcome Admin! Privileged data."
        else:
            body = b"Welcome Guest."
        handler.send_response(200)
        handler.send_header("Content-Type", "text/html")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    routes["GET /"] = _auth_route

    ctx = ctx_factory({"exploit": True})
    ctx.tokens = [("token", token)]
    findings = check_jwt_rs_hs_confusion(ctx)
    assert len(findings) >= 1
    assert any("confusion" in f.title.lower() for f in findings)


def test_jwt_rs_hs_confusion_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "Normal page with no tokens", {"Content-Type": "text/html"})
    ctx = ctx_factory({"exploit": True})
    ctx.tokens = []
    ctx.pages = [{"url": f"{base_url}/", "html": "Normal page"}]
    findings = check_jwt_rs_hs_confusion(ctx)
    assert findings == []


def test_jwt_jku_callback_positive(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    hdr = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(b'{"sub":"admin"}').rstrip(b"=").decode()
    token = f"{hdr}.{payload}.fake_sig"

    ctx = ctx_factory({"exploit": True})
    ctx.tokens = [("token", token)]
    collab = MagicMock()
    collab.host = "collab.example.org"
    collab.port = 80
    collab.count.side_effect = [0, 1]
    ctx.collab = collab

    routes["GET /"] = (200, "OK", {"Content-Type": "text/html"})

    findings = check_jwt_jku(ctx)
    assert len(findings) >= 1
    assert any("jku" in f.title.lower() for f in findings)


def test_jwt_jku_callback_negative(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    hdr = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(b'{"sub":"admin"}').rstrip(b"=").decode()
    token = f"{hdr}.{payload}.fake_sig"

    ctx = ctx_factory({"exploit": True})
    ctx.tokens = [("token", token)]
    collab = MagicMock()
    collab.host = "collab.example.org"
    collab.port = 80
    collab.count.return_value = 0
    ctx.collab = collab

    routes["GET /"] = (200, "OK", {"Content-Type": "text/html"})

    findings = check_jwt_jku(ctx)
    assert findings == []


def test_oauth_audit_positive(mock_server, ctx_factory):
    base_url, _, _, _ = mock_server
    oauth_url = f"{base_url}/oauth/authorize?client_id=myclient&response_type=code&redirect_uri={base_url}/callback"
    ctx = ctx_factory({"oauth_test": True})
    ctx.discovered = [oauth_url]

    findings = check_oauth_audit(ctx)
    assert len(findings) >= 1
    assert any(f.category == "oauth" for f in findings)
    assert any("state" in f.evidence for f in findings)


def test_oauth_audit_negative(mock_server, ctx_factory):
    base_url, _, _, _ = mock_server
    secure_oauth = f"{base_url}/oauth/authorize?client_id=myclient&response_type=code&state=random_state_123&code_challenge=xyz789&redirect_uri={base_url}/callback"
    ctx = ctx_factory({"oauth_test": True})
    ctx.discovered = [secure_oauth]

    findings = check_oauth_audit(ctx)
    assert findings == []
