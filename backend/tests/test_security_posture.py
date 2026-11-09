"""Regression tests for repository-level security posture.

These tests do not need a running target. They guard against credentials
being committed back into the Workers proxy or Wrangler config.
"""

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKER = REPO_ROOT / "frontend" / "worker.js"
WRANGLER = REPO_ROOT / "frontend" / "wrangler.jsonc"

SECRET_NAMES = ("RENDER_API_KEY", "BOX6_API_KEY", "WAKE_SECRET")
SECRET_ASSIGNMENT = re.compile(
    r"(?m)^\s*(RENDER_API_KEY|BOX6_API_KEY|WAKE_SECRET)\s*:\s*['\"][^'\"]+['\"]"
)
QUOTED_SECRET_KEY = re.compile(
    r'"(RENDER_API_KEY|BOX6_API_KEY|WAKE_SECRET)"\s*:'
)


def test_worker_has_no_hardcoded_backend_secrets():
    text = WORKER.read_text(encoding="utf-8")
    matches = SECRET_ASSIGNMENT.findall(text)
    assert not matches, f"hardcoded Worker secret(s) found: {matches}"


def test_wrangler_vars_do_not_contain_secret_values():
    text = WRANGLER.read_text(encoding="utf-8")
    matches = QUOTED_SECRET_KEY.findall(text)
    assert not matches, f"secret key(s) found in wrangler vars: {matches}"
