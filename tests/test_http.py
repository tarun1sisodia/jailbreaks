"""Verify HttpClient behaviour, redirects, rate limiting, and abort."""

import time


def test_http_client_fetches(mock_server, http_client):
    base_url, routes, log, _ = mock_server
    routes["GET /"] = (200, "hello", {"Content-Type": "text/plain"})
    r = http_client.fetch(base_url + "/")
    assert r is not None
    assert r.status == 200
    assert r.text == "hello"


def test_http_client_follows_redirects(mock_server, http_client):
    base_url, routes, log, _ = mock_server
    routes["GET /"] = (302, "", {"Location": "/landing"})
    routes["GET /landing"] = (200, "landed", {"Content-Type": "text/plain"})
    r = http_client.fetch(base_url + "/", follow=True)
    assert r.status == 200
    assert "landed" in r.text


def test_http_client_no_follow(mock_server, http_client):
    base_url, routes, log, _ = mock_server
    routes["GET /"] = (302, "", {"Location": "/landing"})
    r = http_client.fetch(base_url + "/", follow=False)
    assert r.status == 302


def test_http_client_rate_limit(mock_server, http_client):
    base_url, routes, log, _ = mock_server
    routes["GET /"] = (200, "ok", {"Content-Type": "text/plain"})
    http_client.rps = 5.0
    http_client.min_interval = 1.0 / 5.0
    t0 = time.monotonic()
    for _ in range(5):
        http_client.fetch(base_url + "/")
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.7  # 5 requests at 5 rps ≥ 0.8s


def test_http_client_abort(mock_server, http_client):
    base_url, routes, log, _ = mock_server
    routes["GET /"] = (200, "ok", {"Content-Type": "text/plain"})
    http_client._abort_fn = lambda: True
    import pytest
    with pytest.raises(SystemExit):
        http_client.fetch(base_url + "/")
