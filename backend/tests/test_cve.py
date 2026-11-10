"""Tests for passive CVE fingerprinting (positive + negative)."""

from webprobe.checks.phase6_infra import check_cve


def _find(findings, cve):
    return [f for f in findings if cve in (f.evidence or "")]


def test_cve_detects_apache_2449(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "<html>ok</html>", {"Server": "Apache/2.4.49 (Unix)"})

    findings = check_cve(ctx_factory())
    assert _find(findings, "CVE-2021-41773")
    assert any(f.severity == "critical" for f in findings)


def test_cve_ignores_apache_2451(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "<html>ok</html>", {"Server": "Apache/2.4.51 (Unix)"})

    findings = check_cve(ctx_factory())
    assert not _find(findings, "CVE-2021-41773")
    assert not _find(findings, "CVE-2021-42013")


def test_cve_detects_php_8212(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "<html>ok</html>", {"X-Powered-By": "PHP/8.2.12"})

    findings = check_cve(ctx_factory())
    assert _find(findings, "CVE-2024-4577")


def test_cve_ignores_php_8320(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "<html>ok</html>", {"X-Powered-By": "PHP/8.3.20"})

    findings = check_cve(ctx_factory())
    assert not _find(findings, "CVE-2024-4577")


def test_cve_detects_jquery_341(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, '<script src="/js/jquery-3.4.1.min.js"></script>',
                       {"Content-Type": "text/html"})

    findings = check_cve(ctx_factory())
    assert _find(findings, "CVE-2020-11022")


def test_cve_ignores_jquery_350(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, '<script src="/js/jquery-3.5.0.min.js"></script>',
                       {"Content-Type": "text/html"})

    findings = check_cve(ctx_factory())
    assert not _find(findings, "CVE-2020-11022")


def test_cve_detects_jenkins_2440(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "<html>Jenkins</html>", {"X-Jenkins": "2.440"})

    findings = check_cve(ctx_factory())
    assert _find(findings, "CVE-2024-23897")


def test_cve_ignores_jenkins_2442(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "<html>Jenkins</html>", {"X-Jenkins": "2.442"})

    findings = check_cve(ctx_factory())
    assert not _find(findings, "CVE-2024-23897")


def test_cve_detects_nginx_1180(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "<html>ok</html>", {"Server": "nginx/1.18.0"})

    findings = check_cve(ctx_factory())
    assert _find(findings, "CVE-2021-23017")


def test_cve_ignores_nginx_1201(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "<html>ok</html>", {"Server": "nginx/1.20.1"})

    findings = check_cve(ctx_factory())
    assert not _find(findings, "CVE-2021-23017")


def test_cve_detects_tomcat_9030(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "<html>ok</html>", {"Server": "Apache Tomcat/9.0.30"})

    findings = check_cve(ctx_factory())
    assert _find(findings, "CVE-2020-1938")


def test_cve_detects_wordpress_582(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    body = '<meta name="generator" content="WordPress 5.8.2" />'
    routes["GET /"] = (200, body, {"Content-Type": "text/html"})

    findings = check_cve(ctx_factory())
    assert _find(findings, "CVE-2022-21661")


def test_cve_ignores_wordpress_583(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    body = '<meta name="generator" content="WordPress 5.8.3" />'
    routes["GET /"] = (200, body, {"Content-Type": "text/html"})

    findings = check_cve(ctx_factory())
    assert not _find(findings, "CVE-2022-21661")


def test_cve_detects_openssl_heartbleed(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "<html>ok</html>", {"Server": "OpenSSL/1.0.1f"})

    findings = check_cve(ctx_factory())
    assert _find(findings, "CVE-2014-0160")


def test_cve_ignores_openssl_101g(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, "<html>ok</html>", {"Server": "OpenSSL/1.0.1g"})

    findings = check_cve(ctx_factory())
    assert not _find(findings, "CVE-2014-0160")


def test_cve_detects_jira_822(mock_server, ctx_factory):
    base_url, routes, _, _ = mock_server
    routes["GET /"] = (200, 'jira.version = "8.2.2";', {"Content-Type": "text/html"})

    findings = check_cve(ctx_factory())
    assert _find(findings, "CVE-2019-11581")
