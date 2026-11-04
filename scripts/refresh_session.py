"""
Session Token Refresher for webprobe.
Reads environment credentials from .env, obtains fresh Supabase JWTs,
and updates config/agraskbagheltourandtravels.json automatically.
"""

import json
import os
import ssl
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"
CONFIG_PATH = ROOT / "config" / "agraskbagheltourandtravels.json"

def load_env(env_path: Path):
    env_vars = {}
    if not env_path.exists():
        return env_vars
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env_vars[k.strip()] = v.strip().strip("\"'")
    return env_vars

def main():
    env = load_env(ENV_PATH)
    supabase_url = env.get("SUPABASE_URL", "https://uwtcawvtchrqqojoekxf.supabase.co")
    service_key = env.get("SUPABASE_SERVICE_ROLE_KEY", "")

    if not service_key:
        print("[!] Missing SUPABASE_SERVICE_ROLE_KEY in .env")
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
                "Content-Type": "application/json"
            }
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("access_token", "")
        except Exception as e:
            print(f"[!] Error authenticating {email}: {e}")
            return ""

    print("[*] Refreshing Supabase authentication tokens...")
    admin_token = get_token("skbagheltravels@gmail.com", "***REMOVED***")
    cust1_token = get_token("test.customer@agraskbagheltourandtravels.com", "***REMOVED***")
    cust2_token = get_token("test.customer2@agraskbagheltourandtravels.com", "***REMOVED***")

    if not CONFIG_PATH.exists():
        print(f"[!] Config file not found at {CONFIG_PATH}")
        return 1

    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    creds = cfg.setdefault("credentials", {})
    if cust1_token:
        creds["cookie"] = f"sb-access-token={cust1_token}; token={cust1_token}"
        creds["test_email"] = "test.customer@agraskbagheltourandtravels.com"
        creds["test_password"] = "***REMOVED***"
        print("[+] Primary customer token refreshed.")
    if cust2_token:
        creds["secondary_cookie"] = f"sb-access-token={cust2_token}; token={cust2_token}"
        print("[+] Secondary customer token refreshed.")
    if admin_token:
        creds["admin_cookie"] = f"sb-access-token={admin_token}; token={admin_token}"
        print("[+] Admin token refreshed.")

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    print(f"[+] Successfully refreshed credentials in {CONFIG_PATH}")
    return 0

if __name__ == "__main__":
    sys.exit(main())

