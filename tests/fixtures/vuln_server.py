"""
Deliberately vulnerable HTTP test fixture server for webprobe Phase 4 smoke tests.
Runs on http://127.0.0.1:8765.
"""

import argparse
import html
import json
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class VulnServerHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence standard HTTP access logging in tests
        pass

    def _send_response_data(self, status: int, body: bytes, content_type: str = "text/html", extra_headers: dict = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Intentionally insecure cookie: no HttpOnly, no Secure, wildcard domain or missing attributes
        self.send_header("Set-Cookie", "session_id=probe_sess_12345; Path=/")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. Robots.txt
        if path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin\nDisallow: /private\nDisallow: /backup\n"
            self._send_response_data(200, body, "text/plain")
            return

        # 2. Security.txt
        if path in ("/.well-known/security.txt", "/security.txt"):
            body = (
                b"Contact: mailto:security@example.com\n"
                b"Policy: https://example.com/security-policy\n"
                b"Expires: 2027-12-31T23:59:59Z\n"
            )
            self._send_response_data(200, body, "text/plain")
            return

        # 3. JavaScript assets
        if path == "/app.js":
            body = b"""
            // Client application routes
            const API_USER = "/api/me";
            const ADMIN_DASH = "/admin";
            console.log("App initialized");
            """
            self._send_response_data(200, body, "application/javascript")
            return

        # 4. Search endpoint (Reflected XSS & SQLi)
        if path == "/search":
            q_val = query.get("q", [""])[0]
            # Check for SQL injection quote probe
            if "'" in q_val or "--" in q_val or "UNION" in q_val.upper():
                body = b"500 Internal Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
                self._send_response_data(500, body, "text/html")
                return
            # Reflected XSS vulnerability: unescaped reflection
            body = f"""<!DOCTYPE html>
            <html>
            <head><title>Search Results</title></head>
            <body>
              <h1>Search</h1>
              <div id="results">Results for: {q_val}</div>
            </body>
            </html>""".encode("utf-8")
            self._send_response_data(200, body, "text/html")
            return

        # 5. IDOR resource endpoint
        if path == "/api/me":
            user_id = query.get("id", ["1"])[0]
            resp_obj = {
                "user_id": user_id,
                "email": f"customer_{user_id}@example.com",
                "role": "customer",
                "account_id": f"acc_{user_id}",
                "balance": 1500.0,
                "name": f"Test Customer {user_id}",
                "bio": "Detailed customer profile information with sufficient padding to exceed 120 bytes for scanner detection.",
            }
            body = json.dumps(resp_obj).encode("utf-8")
            self._send_response_data(200, body, "application/json", {"Access-Control-Allow-Origin": "*"})
            return

        # 6. Admin endpoint (Missing authentication / authorization)
        if path in ("/admin", "/admin/dashboard", "/admin/users"):
            body = b"""<!DOCTYPE html>
            <html>
            <head><title>Admin Console</title></head>
            <body>
              <h1>Administrator Portal</h1>
              <p>Welcome admin. System configurations and user management.</p>
            </body>
            </html>"""
            self._send_response_data(200, body, "text/html")
            return

        # 7. Login page (Login CSRF - no anti-CSRF token)
        if path == "/login":
            body = b"""<!DOCTYPE html>
            <html>
            <head><title>Login</title></head>
            <body>
              <form action="/login" method="POST">
                <input type="text" name="username" placeholder="Username">
                <input type="password" name="password" placeholder="Password">
                <button type="submit">Sign In</button>
              </form>
            </body>
            </html>"""
            self._send_response_data(200, body, "text/html")
            return

        # 8. Root homepage with links and forms
        body = b"""<!DOCTYPE html>
        <html>
        <head>
          <title>Vulnerable Testbed Application</title>
          <script src="/app.js"></script>
        </head>
        <body>
          <h1>Welcome to Vulnerable Localhost Fixture</h1>
          <nav>
            <a href="/search?q=test">Search Catalog</a>
            <a href="/api/me?id=1">My Profile</a>
            <a href="/admin">Administrative Dashboard</a>
            <a href="/login">User Login</a>
          </nav>
          <form action="/search" method="GET">
            <input type="text" name="q" value="initial">
            <button type="submit">Search</button>
          </form>
          <form action="/login" method="POST">
            <input type="text" name="username">
            <input type="password" name="password">
            <button type="submit">Login</button>
          </form>
        </body>
        </html>"""
        self._send_response_data(200, body, "text/html")

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path

        length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(length).decode("utf-8", errors="replace")

        if "'" in post_data or "--" in post_data:
            body = b"500 Database Error: You have an error in your SQL syntax; check the manual near ''"
            self._send_response_data(500, body, "text/html")
            return

        if path == "/login":
            body = b'{"status": "ok", "message": "logged in"}'
            self._send_response_data(200, body, "application/json")
            return

        body = b'{"status": "received"}'
        self._send_response_data(200, body, "application/json")


def run_server(port: int = 8765):
    server = ThreadingHTTPServer(("127.0.0.1", port), VulnServerHandler)
    print(f"[*] VulnServer listening on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765, help="Port to listen on (default: 8765)")
    args = parser.parse_args()
    run_server(args.port)
