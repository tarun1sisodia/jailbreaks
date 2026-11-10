"""Tests for private runtime-config writes."""

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "refresh_session", REPO_ROOT / "backend" / "scripts" / "refresh_session.py"
)
refresh_session = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(refresh_session)


def test_write_private_json_uses_private_permissions(tmp_path):
    target = tmp_path / "nested" / "runtime.json"
    out = refresh_session.write_private_json(target, {"cookie": "test-value"})

    assert out == target.resolve()
    assert out.stat().st_mode & 0o777 == 0o600
    assert out.parent.stat().st_mode & 0o777 == 0o700
    assert out.read_text(encoding="utf-8").strip().startswith("{")
