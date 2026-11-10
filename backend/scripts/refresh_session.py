"""
Session Token Refresher for webprobe.

Reads Supabase credentials from the process environment or the repository
``.env``, obtains fresh Supabase JWTs, and writes a private runtime scan
config outside the repository (mode 0600). It never writes tokens back into
the repository working tree.
"""

import argparse
import json
import os
import ssl
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_PATHS = (REPO_ROOT / ".env", REPO_ROOT / "backend" / ".env")
BASE_CONFIG = REPO_ROOT / "backend" / "config" / "agraskbagheltourandtravels.json"
DEFAULT_OUT = (
    Path.home() / ".secrets" / "jailbreaks" / "agraskbagheltourandtravels.runtime.json"
)


def load_env(paths=ENV_PATHS) -> None:
    """Load .env files without overriding variables already in the process."""
    for env_path in paths:
        if not env_path.exists():
            continue
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):]
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def write_private_json(path: Path, data: dict) -> Path:
    """Write JSON with 0600 permissions, creating a 0700 parent directory."""
    path = path.expanduser().resolve()
    if not path.parent.exists():
        path.parent.mkdir(parents=True, mode=0o700)
        path.parent.chmod(0o700)
    tmp = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()
    path.chmod(0o600)
    return path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Refresh Supabase JWTs into a private runtime config")
    parser.add_argument(
        "--out",
        default=os.environ.get("WEBPROBE_RUNTIME_CONFIG", str(DEFAULT_OUT)),
        help="Private runtime config path (default: ~/.secrets/jailbreaks/agraskbagheltourandtravels.runtime.json)",
    )
    parser.add_argument(
        "--base",
        default=str(BASE_CONFIG),
        help="Base scan config to copy non-secret settings from",
    )
    args = parser.parse_args(argv)

    load_env()

    supabase_url = os.environ.get("SUPABASE_URL", "").rstrip("/")
    service_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    if not supabase_url or not service_key:
        print("[!] Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY")
        return 1

    ctx = ssl.create_default_context()

    def get_token(email: str, password: str) -> str:
        url = f"{supabase_url}/auth/v1/token?grant_type=password"
        payload = json.dumps({"email": email, "password": password}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "apikey": service_key,
                "Authorization": f"Bearer {service_key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("access_token", "")
        except Exception as e:
            print(f"[!] Error authenticating {email}: {e}")
            return ""

    admin_email = os.environ.get("SUPABASE_ADMIN_EMAIL", "skbagheltravels@gmail.com")
    test_email = os.environ.get(
        "SUPABASE_TEST_EMAIL", "test.customer@agraskbagheltourandtravels.com"
    )
    test2_email = os.environ.get(
        "SUPABASE_TEST2_EMAIL", "test.customer2@agraskbagheltourandtravels.com"
    )
    admin_password = os.environ.get("SUPABASE_ADMIN_PASSWORD", "")
    test_password = os.environ.get("SUPABASE_TEST_PASSWORD", "")
    test2_password = os.environ.get("SUPABASE_TEST2_PASSWORD", "")
    if not admin_password or not test_password or not test2_password:
        print(
            "[!] Missing SUPABASE_ADMIN_PASSWORD, SUPABASE_TEST_PASSWORD "
            "or SUPABASE_TEST2_PASSWORD"
        )
        return 1

    base_path = Path(args.base).expanduser()
    if not base_path.exists():
        print(f"[!] Base config file not found at {base_path}")
        return 1
    cfg = json.loads(base_path.read_text(encoding="utf-8"))

    print("[*] Refreshing Supabase authentication tokens...")
    admin_token = get_token(admin_email, admin_password)
    cust1_token = get_token(test_email, test_password)
    cust2_token = get_token(test2_email, test2_password)

    creds = cfg.setdefault("credentials", {})
    refreshed = 0
    if cust1_token:
        creds["cookie"] = f"sb-access-token={cust1_token}; token={cust1_token}"
        creds["test_email"] = test_email
        creds.pop("test_password", None)
        refreshed += 1
        print("[+] Primary customer token refreshed.")
    if cust2_token:
        creds["secondary_cookie"] = f"sb-access-token={cust2_token}; token={cust2_token}"
        refreshed += 1
        print("[+] Secondary customer token refreshed.")
    if admin_token:
        creds["admin_cookie"] = f"sb-access-token={admin_token}; token={admin_token}"
        refreshed += 1
        print("[+] Admin token refreshed.")

    if refreshed == 0:
        print("[!] No tokens were refreshed; runtime config not written.")
        return 1

    out_path = write_private_json(Path(args.out), cfg)
    print(f"[+] Wrote private runtime config to {out_path} (mode 600)")
    print(f"[*] Use it with: python webprobe.py --config {out_path} <url>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
