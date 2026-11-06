def test_jwt_rs_hs_token_from_page(mock_server, ctx_factory):
    """Regression: `name` must default when token comes from HTML, not ctx.tokens."""
    base_url, routes, log, _ = mock_server
    fake_jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlMTIzNA"
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
    """Regression: check_jwt_jku must not raise NameError when token comes from page or tokens empty."""
    base_url, routes, log, _ = mock_server
    fake_jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlMTIzNA"
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
