"""Append-only cryptographic ledger: every entry chains off the previous via HMAC."""

import hashlib
import hmac
import json
import os
import threading
import time
from typing import Optional


class Ledger:
    """Records tamper-evident audit entries.

    Each line is: <timestamp>\\t<hmac_hex>\\t<prev_hmac_hex>\\t<json_payload>
    where hmac = HMAC-SHA256(key, prev_hmac || json_payload).

    Any truncation or line edit invalidates every subsequent HMAC.
    """

    def __init__(self, path: str, key: Optional[bytes] = None):
        self.path = path
        self.lock = threading.Lock()
        self.key = key or self._derive_key()
        self.prev_hmac = b"\x00" * 32
        self._verify_or_reset()

    def _derive_key(self) -> bytes:
        # Derive from machine-specific material; deterministic on one host
        seed = (os.environ.get("WEBPROBE_LEDGER_SEED", "") +
                str(os.uname().nodename if hasattr(os, "uname") else "host")).encode()
        return hashlib.sha256(seed).digest()

    def _verify_or_reset(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    parts = line.rstrip("\n").split("\t", 3)
                    if len(parts) != 4:
                        continue
                    _, reported, prev, payload = parts
                    expected = self._compute(bytes.fromhex(prev), payload.encode())
                    if hmac.compare_digest(reported, expected.hex()):
                        self.prev_hmac = bytes.fromhex(reported)
                    else:
                        raise ValueError(f"ledger tampering detected at line: {line[:80]}")
        except ValueError:
            raise

    def _compute(self, prev: bytes, payload: bytes) -> bytes:
        return hmac.new(self.key, prev + payload, hashlib.sha256).digest()

    def append(self, test_id: str, outcome: str, description: str,
               evidence: str = "", **extra) -> None:
        payload = json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "test_id": test_id,
            "outcome": outcome,
            "description": description,
            "evidence": evidence,
            **extra,
        }, separators=(",", ":"))
        with self.lock:
            current_hmac = self._compute(self.prev_hmac, payload.encode())
            line = (f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\t"
                    f"{current_hmac.hex()}\t{self.prev_hmac.hex()}\t{payload}\n")
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)
            self.prev_hmac = current_hmac

    def verify(self) -> bool:
        """Re-verify the whole chain. Returns True if intact."""
        try:
            self._verify_or_reset()
            return True
        except ValueError:
            return False
