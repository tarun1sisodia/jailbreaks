"""Phase 3 tests: Crawler validation (CDP headless merge + formfiller synthesis)."""

from unittest.mock import MagicMock
from webprobe.core.crawler import build_points, crawl


def test_crawl_headless_merges(mock_server, ctx_factory, monkeypatch):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "<html><a href='/about'>About</a></html>", {"Content-Type": "text/html"})
    routes["GET /about"] = (200, "<html>About Page</html>", {"Content-Type": "text/html"})

    ctx = ctx_factory({"headless": True, "cdp_port": 9222})

    # Stub cdp module
    import webprobe.core.cdp as cdp_mod
    monkeypatch.setattr(cdp_mod, "headless_available", lambda port=9222: True)
    monkeypatch.setattr(cdp_mod, "auto_crawl", lambda c: [{"url": f"{base_url}/cdp_page", "links": [], "forms": [], "scripts": [], "html": "CDP Rendered"}])

    pages, discovered = crawl(ctx.http, base_url, max_depth=1, ctx=ctx)
    assert any(p["url"] == f"{base_url}/cdp_page" for p in pages)


def test_build_points_synthesizes_form_values():
    forms = [{
        "action": "http://127.0.0.1/contact",
        "method": "POST",
        "inputs": {"email": "", "message": "", "phone": ""}
    }]
    pages = [{"url": "http://127.0.0.1/contact", "forms": forms}]
    points = build_points(pages, [])
    assert len(points) == 3
    # Check that orig_value was populated by formfiller
    email_pt = next(p for p in points if p.param == "email")
    assert "@" in email_pt.orig_value
