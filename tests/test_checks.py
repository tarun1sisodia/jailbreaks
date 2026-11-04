"""Real assertions that each check fires on vulnerabilities and stays quiet on clean apps."""

import json
import pytest

from webprobe.checks.phase1_recon import check_robots, check_security_txt
from webprobe.checks.phase3_injection import check_sqli, check_ssti, check_xss
from webprobe.checks.phase6_infra import check_headers
from webprobe.core.models import Finding


def test_robots_true_positive(mock_server, ctx_factory):
    base_url, routes, log, _ = mock_server
    routes["GET /robots.txt"] = (200, "User-agent: *\nDisallow: /admin\nDisallow: /internal\n",
                                 {"Content-Type": "text/plain"})
    ctx = ctx_factory()
    findings = check_robots(ctx)
    assert len(findings) >= 1
    assert any(f.category in ("robots", "recon") for f in findings)


def test_robots_false_positive_no_file(mock_server, ctx_factory):
    base_url, routes, log, _ = mock_server
    routes["GET /robots.txt"] = (404, "Not Found", {"Content-Type": "text/plain"})
    ctx = ctx_factory()
    findings = check_robots(ctx)
    assert findings == []


def test_security_txt_true_positive(mock_server, ctx_factory):
    base_url, routes, log, _ = mock_server
    routes["/.well-known/security.txt"] = (
        200,
        "Contact: mailto:security@example.com\nPolicy: https://example.com/policy\n"
        "Expires: 2027-01-01T00:00:00Z\n",
        {"Content-Type": "text/plain"},
    )
    ctx = ctx_factory()
    findings = check_security_txt(ctx)
    assert len(findings) >= 1


def test_sqli_true_positive(mock_server, ctx_factory):
    base_url, routes, log, _ = mock_server

    body = "You have an error in your SQL syntax; check the manual"
    routes["GET /search?id=1"] = (200, "<html>results for 1</html>", {"Content-Type": "text/html"})
    routes["GET /search?id=1'"] = (500, body, {"Content-Type": "text/html"})
    routes["GET /search?id='"] = (500, body, {"Content-Type": "text/html"})

    from webprobe.core.models import Point
    ctx = ctx_factory()
    point = Point(url=f"{base_url}/search", method="GET",
                 param="id", param_type="query", orig_value="1")
    findings = check_sqli(ctx, point)
    assert any(f.category == "sqli" for f in findings)


def test_ssti_no_false_positive_on_49(mock_server, ctx_factory):
    """Regression: page contains '49' (e.g. price ₹49, page 49) but no SSTI."""
    base_url, routes, log, _ = mock_server
    routes["GET /book?x=1"] = (200, "<html>Price: ₹49. Page 49 of 100. "
                                     "Phone 4912345</html>",
                              {"Content-Type": "text/html"})
    routes["GET /book?x={{7*7}}"] = (200, "<html>Price: ₹49. Page 49 of 100. "
                                          "Phone 4912345</html>",
                                    {"Content-Type": "text/html"})

    from webprobe.core.models import Point
    ctx = ctx_factory()
    point = Point(url=f"{base_url}/book", method="GET",
                 param="x", param_type="query", orig_value="1")
    findings = check_ssti(ctx, point)
    assert findings == [], "SSTI should not fire on '49' in page content"


def test_ssti_true_positive_on_prime(mock_server, ctx_factory):
    """Regression: unique arithmetic 7391*8231=60835321 must fire."""
    base_url, routes, log, _ = mock_server
    a, b = 7391, 8231
    c, d = 6173, 5749
    routes["GET /tpl?x=1"] = (200, "<html>value: 1</html>",
                             {"Content-Type": "text/html"})
    routes["GET /tpl?x={{7391*8231}}"] = (200, f"<html>value: {a*b}</html>",
                                         {"Content-Type": "text/html"})
    routes["GET /tpl?x={{6173*5749}}"] = (200, f"<html>value: {c*d}</html>",
                                         {"Content-Type": "text/html"})

    from webprobe.core.models import Point
    ctx = ctx_factory()
    point = Point(url=f"{base_url}/tpl", method="GET",
                 param="x", param_type="query", orig_value="1")
    findings = check_ssti(ctx, point)
    assert any(f.category == "ssti" for f in findings)


def test_xss_true_positive(mock_server, ctx_factory):
    base_url, routes, log, _ = mock_server

    def _reflect(handler):
        import urllib.parse
        path = handler.path
        payload = urllib.parse.unquote(path.split("=", 1)[1]) if "=" in path else ""
        body = f"<html>You searched for: {payload}</html>".encode()
        handler.send_response(200)
        handler.send_header("Content-Type", "text/html")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    routes["GET /search"] = _reflect

    from webprobe.core.models import Point
    ctx = ctx_factory()
    point = Point(url=f"{base_url}/search", method="GET",
                 param="q", param_type="query", orig_value="x")
    findings = check_xss(ctx, point)
    assert any(f.category == "xss" for f in findings)


def test_headers_true_positive(mock_server, ctx_factory):
    base_url, routes, log, _ = mock_server
    routes["GET /"] = (200, "<html>ok</html>", {"Content-Type": "text/html"})
    ctx = ctx_factory()
    findings = check_headers(ctx)
    titles = [f.title for f in findings]
    assert any("X-Frame-Options" in t for t in titles)
    assert any("X-Content-Type-Options" in t for t in titles)


def test_headers_false_positive_when_all_set(mock_server, ctx_factory):
    base_url, routes, log, _ = mock_server
    routes["GET /"] = (200, "<html>ok</html>", {
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    })
    ctx = ctx_factory()
    findings = check_headers(ctx)
    # No findings about the ones we set
    bad = [f for f in findings if "X-Frame-Options" in f.title
           or "HSTS" in f.title or "X-Content-Type-Options" in f.title]
    assert bad == []
