"""Schema and coverage tests for the passive CVE fingerprint database."""

import json
import re

from webprobe.checks.phase6_infra import (
    CVE_DB_PATH,
    CVE_FINGERPRINTS,
    _range_tuple,
)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
SEVERITIES = {"critical", "high", "medium", "low", "info"}


def test_db_file_exists_and_loads():
    assert CVE_DB_PATH.exists(), f"missing CVE database: {CVE_DB_PATH}"
    payload = json.loads(CVE_DB_PATH.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert len(payload["fingerprints"]) == len(CVE_FINGERPRINTS)
    assert len(CVE_FINGERPRINTS) >= 20


def test_each_fingerprint_has_required_fields():
    for fp in CVE_FINGERPRINTS:
        assert fp["product"], fp
        assert fp["source"] in {"headers", "body"}, fp
        re.compile(fp["regex"])
        assert isinstance(fp["rules"], list) and fp["rules"], fp


def test_each_rule_has_valid_metadata_and_ranges():
    for fp in CVE_FINGERPRINTS:
        seen = set()
        for rule in fp["rules"]:
            ids = CVE_RE.findall(rule["cve"])
            assert ids, f"{fp['product']}: no CVE ID in {rule['cve']!r}"
            for cve in ids:
                assert cve not in seen, f"{fp['product']}: duplicate {cve}"
                seen.add(cve)
            assert rule["severity"] in SEVERITIES, rule
            assert rule["title"] and rule["remediation"], rule
            assert isinstance(rule["ranges"], list) and rule["ranges"], rule
            for rng in rule["ranges"]:
                assert isinstance(rng, dict), rng
                low = _range_tuple(rng.get("low", []))
                high = _range_tuple(rng.get("high", []))
                assert low <= high, f"{rule['cve']}: low {low} > high {high}"
                for flag in ("low_exclusive", "high_exclusive"):
                    if flag in rng:
                        assert isinstance(rng[flag], bool), rng


def test_known_products_are_covered():
    products = {fp["product"] for fp in CVE_FINGERPRINTS}
    required = {
        "Apache HTTP Server", "PHP", "Jenkins", "jQuery", "Bootstrap",
        "GitLab", "Confluence", "TeamCity", "GeoServer",
        "nginx", "Apache Tomcat", "WordPress", "Drupal", "Joomla",
        "AngularJS", "lodash", "Moment.js", "Handlebars", "Axios",
        "DOMPurify", "OpenSSL", "Atlassian Jira",
        "Next.js", "ASP.NET Core", ".NET",
    }
    assert required <= products, f"missing products: {required - products}"


def test_cve_id_count():
    ids = set()
    for fp in CVE_FINGERPRINTS:
        for rule in fp["rules"]:
            ids.update(CVE_RE.findall(rule["cve"]))
    assert len(ids) >= 45, f"only {len(ids)} CVE IDs in the database"
