"""Pytest fixtures: hermetic mock HTTP servers for each vulnerability class."""

import atexit
import json
import os
import shutil
import socket
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Optional

import pytest

# server.py resolves REPORTS_DIR at import time. Point it at a throwaway
# directory before any test module imports the server so a test run can never
# load or create artifacts in the project's real reports/scans directory.
_REPORTS_DIR = tempfile.mkdtemp(prefix="webprobe-pytest-reports-")
os.environ["WEBPROBE_REPORTS_DIR"] = _REPORTS_DIR
atexit.register(lambda: shutil.rmtree(_REPORTS_DIR, ignore_errors=True))


class MockHandler(BaseHTTPRequestHandler):
    routes: Dict = {}
    log: list = []
    delay_ms: float = 0.0

    def _handle(self):
        MockHandler.log.append({
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
        })
        if MockHandler.delay_ms:
            time.sleep(MockHandler.delay_ms / 1000.0)

        key = f"{self.command} {self.path}"
        route = MockHandler.routes.get(key)
        if route is None:
            route = MockHandler.routes.get(self.path)
        if route is None:
            import urllib.parse
            unquoted = urllib.parse.unquote(self.path)
            route = MockHandler.routes.get(f"{self.command} {unquoted}") or MockHandler.routes.get(unquoted)
        if route is None and self.command == "GET":
            route = MockHandler.routes.get("GET " + self.path.split("?")[0])
        if route is None:
            self.send_response(404)
            self.end_headers()
            return

        if callable(route):
            route(self)
            return

        status, body, headers = route if isinstance(route, tuple) else (200, route, {})
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_OPTIONS = _handle

    def log_message(self, *args):
        pass


@pytest.fixture
def mock_server(request):
    """Yields (base_url, routes_dict, log_list, delay_setter)."""
    MockHandler.routes = {}
    MockHandler.log = []
    MockHandler.delay_ms = 0.0

    srv = ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    host, port = srv.server_address
    base_url = f"http://{host}:{port}"

    def set_delay(ms: float):
        MockHandler.delay_ms = ms

    yield base_url, MockHandler.routes, MockHandler.log, set_delay
    srv.shutdown()


@pytest.fixture
def http_client():
    from webprobe.core.http import HttpClient
    return HttpClient(timeout=5, insecure=True)


@pytest.fixture
def ctx_factory(mock_server, http_client):
    from webprobe.core.models import Ctx

    def _make(extra_args: Optional[dict] = None):
        base_url = mock_server[0]

        class _Args:
            cookie = ""
            secondary_cookie = ""
            staff_cookie = ""
            admin_cookie = ""
            test_email = ""
            test_password = ""
            time_based = False
            exploit = False
            exploit_rce = False
            rce_command = "id"
            race_url = ""
            race_count = 20
            race_expect = None
            webhook_url = ""
            max_js = 10
            threads = 2
            insecure = True

        for k, v in (extra_args or {}).items():
            setattr(_Args, k, v)

        return Ctx(
            http=http_client,
            args=_Args(),
            base_url=base_url,
            root=base_url,
        )

    return _make


def _respond_by_cookie(handler, responses):
    cookie_hdr = handler.headers.get("Cookie", "")
    for cookie_pattern, resp in responses.items():
        if cookie_pattern in cookie_hdr:
            status = resp[0] if isinstance(resp, tuple) else 200
            body = resp[1] if isinstance(resp, tuple) else resp
            headers = resp[2] if isinstance(resp, tuple) and len(resp) > 2 else {"Content-Type": "application/json"}
            body_bytes = body.encode() if isinstance(body, str) else json.dumps(body).encode() if isinstance(body, (dict, list)) else body
            handler.send_response(status)
            for k, v in headers.items():
                handler.send_header(k, v)
            handler.send_header("Content-Length", str(len(body_bytes)))
            handler.end_headers()
            handler.wfile.write(body_bytes)
            return
    handler.send_response(404)
    handler.end_headers()
