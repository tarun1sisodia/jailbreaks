"""Tests for env-backed scan configuration handling."""

from webprobe.cli import apply_env_overrides, expand_env_placeholders


def test_expand_env_placeholder(monkeypatch):
    monkeypatch.setenv("WEBPROBE_TEST_PASSWORD", "s3cret-value")
    assert expand_env_placeholders("${WEBPROBE_TEST_PASSWORD}") == "s3cret-value"


def test_missing_env_placeholder_becomes_empty_and_is_reported():
    missing = set()
    assert expand_env_placeholders("${WEBPROBE_NOT_SET}", missing) == ""
    assert "WEBPROBE_NOT_SET" in missing


def test_non_string_values_are_unchanged():
    assert expand_env_placeholders(42) == 42
    assert expand_env_placeholders(None) is None


def test_env_override_only_applies_to_credential_keys(monkeypatch):
    monkeypatch.setenv("WEBPROBE_COOKIE", "sess=abc")
    monkeypatch.setenv("WEBPROBE_URL", "https://attacker.invalid")

    cfg = {"cookie": "${WEBPROBE_COOKIE}", "url": "https://target.invalid"}
    apply_env_overrides(cfg)

    assert cfg["cookie"] == "sess=abc"
    assert cfg["url"] == "https://target.invalid"
