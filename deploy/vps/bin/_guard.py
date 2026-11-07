#!/usr/bin/env python3
"""
Scope Enforcement Guardrail for WebProbe & Ecosystem Security Tools.
Rejects any target not explicitly defined in /opt/mcp/config/scope.toml.
Exit codes:
  0 = In-scope (authorized)
  2 = Out-of-scope (rejected / denied)
  1 = Configuration or usage error
"""
import sys
import urllib.parse
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        tomllib = None

# Default path on VPS, with local fallback for local development/testing
DEFAULT_SCOPE_PATH = Path("/opt/mcp/config/scope.toml")
LOCAL_SCOPE_PATH = Path(__file__).resolve().parent.parent / "config" / "scope.toml"


def get_scope_file(custom_path: Path = None) -> Path:
    if custom_path and custom_path.exists():
        return custom_path
    if DEFAULT_SCOPE_PATH.exists():
        return DEFAULT_SCOPE_PATH
    if LOCAL_SCOPE_PATH.exists():
        return LOCAL_SCOPE_PATH
    return DEFAULT_SCOPE_PATH


def _parse_toml_minimal(text: str) -> dict:
    """Fallback parser for scope.toml if tomllib/tomli is not installed."""
    result = {"scope": {"allowed_hosts": [], "deny": {"hosts": []}}}
    current_section = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip()
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                items = [
                    item.strip().strip("\"'")
                    for item in v[1:-1].split(",")
                    if item.strip().strip("\"'")
                ]
                if current_section == "scope" and k == "allowed_hosts":
                    result["scope"]["allowed_hosts"] = items
                elif current_section in ("scope.deny", "scope.deny.hosts") and k == "hosts":
                    result["scope"]["deny"]["hosts"] = items
    return result


def load_scope_config(path: Path) -> dict:
    if not path.exists():
        return {"scope": {"allowed_hosts": [], "deny": {"hosts": []}}}
    if tomllib:
        with open(path, "rb") as f:
            return tomllib.load(f)
    else:
        with open(path, "r", encoding="utf-8") as f:
            return _parse_toml_minimal(f.read())


def normalize_host(url_or_host: str) -> str:
    target = (url_or_host or "").strip()
    if not target:
        return ""
    if "://" in target:
        parsed = urllib.parse.urlsplit(target)
        host = parsed.hostname or ""
        return host.lower()
    # Hostname, IP, or path
    host = target.split("/")[0].split(":")[0]
    return host.lower()


def in_scope(url_or_host: str, scope_path: Path = None) -> bool:
    host = normalize_host(url_or_host)
    if not host:
        return False

    cfg_path = get_scope_file(scope_path)
    cfg = load_scope_config(cfg_path).get("scope", {})

    # 1. Deny patterns take strict precedence
    for deny in cfg.get("deny", {}).get("hosts", []):
        pattern = deny.lower().lstrip("*.")
        if host == pattern or host.endswith("." + pattern):
            return False

    # 2. Allow patterns
    for allowed in cfg.get("allowed_hosts", []):
        pattern = allowed.lower().lstrip("*.")
        if host == pattern or host.endswith("." + pattern):
            return True

    return False


def require(target: str, scope_path: Path = None) -> None:
    if not in_scope(target, scope_path):
        cfg_path = get_scope_file(scope_path)
        sys.stderr.write(
            f"[!] OUT OF SCOPE: Target '{target}' is not permitted by scope policy ({cfg_path}).\n"
        )
        sys.exit(2)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="WebProbe Target Scope Guardrail")
    parser.add_argument("--check", required=True, help="Target URL or hostname to validate")
    parser.add_argument("--scope-file", default="", help="Custom scope.toml path")
    args = parser.parse_args()

    custom_scope = Path(args.scope_file) if args.scope_file else None
    require(args.check, custom_scope)
    print(f"[+] IN SCOPE: {normalize_host(args.check)}")
    sys.exit(0)

