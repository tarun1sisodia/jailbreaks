"""Out-of-band callback listener. Uses webhook.site (default) or a user-supplied listener.

For blind vulnerabilities: emit a unique URL; the target's server calls it; poll
for the callback. No external dependencies.
"""

import json
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional


USER_AGENT = "webprobe-oast/1.0"


class OASTBridge:
    """Abstract OAST listener. Two backends: webhook.site (public) and custom."""

    def __init__(self, backend: str = "webhooksite",
                 poll_interval: float = 3.0,
                 timeout: float = 300.0):
        self.backend = backend
        self.poll_interval = poll_interval
        self.timeout = timeout
        self.token: Optional[str] = None
        self.base_url: Optional[str] = None
        self._hits: List[Dict] = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "OASTBridge":
        if self.backend == "webhooksite":
            self._start_webhooksite()
        elif self.backend == "custom":
            raise ValueError("custom backend: set base_url manually and call start_custom()")
        return self

    def _start_webhooksite(self) -> None:
        req = urllib.request.Request(
            "https://webhook.site/token",
            method="POST",
            data=b"{}",
            headers={"User-Agent": USER_AGENT,
                     "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
            self.token = data["uuid"]
            self.base_url = f"https://webhook.site/{self.token}"
        self._thread = threading.Thread(target=self._poll_webhooksite, daemon=True)
        self._thread.start()

    def _poll_webhooksite(self) -> None:
        url = f"https://webhook.site/token/{self.token}/requests"
        seen_ids = set()
        deadline = time.monotonic() + self.timeout
        while not self._stop.is_set() and time.monotonic() < deadline:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=10) as r:
                    data = json.loads(r.read())
                for item in data.get("data", []):
                    rid = item.get("uuid")
                    if rid and rid not in seen_ids:
                        seen_ids.add(rid)
                        self._hits.append(item)
            except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
                pass
            time.sleep(self.poll_interval)

    def payload_url(self, marker: str) -> str:
        """Return a URL that will call home with `marker` in the path."""
        if not self.base_url:
            raise RuntimeError("call start() first")
        return f"{self.base_url}/{marker}"

    def hits(self, marker: Optional[str] = None) -> List[Dict]:
        if marker is None:
            return list(self._hits)
        return [h for h in self._hits
                if marker in (h.get("url", "") + json.dumps(h))]

    def wait_for(self, marker: str, wait_seconds: float = 15.0) -> bool:
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            if self.hits(marker):
                return True
            time.sleep(self.poll_interval)
        return False

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
