"""
Safety, operational gates, and circuit breakers for webprobe.
"""

import os
import re
import threading
import time
from typing import Any, Dict, Optional


def in_testing_window(window: str) -> bool:
    """Check if the current local time falls within the allowed testing window (HH:MM-HH:MM)."""
    if not window:
        return True
    m = re.match(r"^\s*(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s*$", window)
    if not m:
        return True
    sh, sm, eh, em = map(int, m.groups())
    cur = time.localtime()
    c = cur.tm_hour * 60 + cur.tm_min
    start, end = sh * 60 + sm, eh * 60 + em
    return start <= c <= end if start <= end else (c >= start or c <= end)


class InstabilityMonitor:
    """Monitors 5xx error rates over HTTP responses to halt/backoff on server instability."""

    def __init__(self, threshold: float = 0.20, min_samples: int = 20):
        self.total = 0
        self.errors = 0
        self.threshold = threshold
        self.min_samples = min_samples
        self.lock = threading.Lock()
        self.aborted = False
        self._aimd: Optional[Any] = None

    @property
    def aimd(self) -> Any:
        if self._aimd is None:
            from webprobe.core.aimd import AIMD
            self._aimd = AIMD()
        return self._aimd

    @aimd.setter
    def aimd(self, val: Any) -> None:
        self._aimd = val

    def observe(self, status: int) -> None:
        with self.lock:
            self.total += 1
            if status >= 500:
                self.errors += 1
            if self.total >= self.min_samples and (self.errors / self.total) > self.threshold:
                self.aborted = True

    def error_rate(self) -> float:
        with self.lock:
            return (self.errors / self.total) if self.total > 0 else 0.0


_ABORT_CACHE: Dict[str, float] = {}


def check_abort_file(path: str) -> bool:
    """Returns True if the abort file exists and logs a warning on first detection."""
    if not path:
        return False
    if os.path.exists(path):
        mtime = os.path.getmtime(path)
        if _ABORT_CACHE.get(path) != mtime:
            _ABORT_CACHE[path] = mtime
            print(f"\n[!] Emergency abort file detected: {path} (mtime {mtime})")
        return True
    return False


def aborted(ctx: Any) -> bool:
    """Returns True if either the abort file exists or the target server instability threshold was crossed."""
    abort_path = getattr(ctx.args, "abort_file", "webprobe.abort")
    if check_abort_file(abort_path):
        return True
    inst = getattr(ctx, "instability", None)
    if inst is not None and inst.aborted:
        return True
    return False


def scrub(text: str) -> str:
    """Scrub PII, tokens, and secrets from text."""
    from webprobe.core.redact import redact_text
    return redact_text(text)
