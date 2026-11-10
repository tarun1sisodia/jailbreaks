"""Tests for the repository secret-hygiene scanner."""

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "secret_scan", REPO_ROOT / "scripts" / "secret_scan.py"
)
secret_scan = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(secret_scan)


def test_flags_aws_access_key():
    findings = secret_scan.scan_text("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP", "x.py")  # secret-scan: allow (test fixture)
    assert any(f.rule == "aws-access-key" for f in findings)


def test_flags_private_key():
    findings = secret_scan.scan_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n", "id_rsa"  # secret-scan: allow (test fixture)
    )
    assert any(f.rule == "private-key" for f in findings)


def test_flags_generic_quoted_assignment():
    findings = secret_scan.scan_text('password = "Sup3rS3cretValue123"', "x.py")  # secret-scan: allow (test fixture)
    assert any(f.rule == "generic-secret-assignment" for f in findings)


def test_flags_json_assignment():
    findings = secret_scan.scan_text(
        '{"password": "Sup3rS3cretValue123"}', "config.json"  # secret-scan: allow (test fixture)
    )
    assert any(f.rule == "generic-secret-assignment" for f in findings)


def test_ignores_placeholders():
    text = (
        'password = "changeme-please-now"\n'
        'api_key = "${WEBPROBE_API_KEY}"\n'
        'secret = "example-value-not-real"\n'
    )
    assert secret_scan.scan_text(text, "config.example.json") == []


def test_permissions_finding(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("TOKEN=value\n", encoding="utf-8")
    env_file.chmod(0o644)

    findings = secret_scan.check_sensitive_permissions(tmp_path, tracked=set())
    assert any(f.rule == "secret-file-permissions" for f in findings)

    env_file.chmod(0o600)
    assert secret_scan.check_sensitive_permissions(tmp_path, tracked=set()) == []


def test_tracked_secret_file_finding(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("TOKEN=value\n", encoding="utf-8")
    env_file.chmod(0o600)

    findings = secret_scan.check_sensitive_permissions(tmp_path, tracked={".env"})
    assert any(f.rule == "tracked-secret-file" for f in findings)


def test_repository_is_clean():
    assert secret_scan.scan_repo(REPO_ROOT) == []
    assert secret_scan.check_sensitive_permissions(REPO_ROOT) == []
