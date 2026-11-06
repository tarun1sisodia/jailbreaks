"""AIMD rate regulator: additive increase on healthy RTT, multiplicative decrease on degradation."""

import threading
import time
from collections import deque
from typing import Deque


class AIMD:
    """Closed-loop concurrency regulator.

    - Samples RTT for every request.
    - On healthy window (median RTT < threshold_p95): additively increase rate.
    - On degradation (median RTT > threshold_p95): multiply rate by 0.5.
    """

    def __init__(
        self,
        initial_rps: float = 5.0,
        min_rps: float = 0.5,
        max_rps: float = 50.0,
        window: int = 20,
        increase_step: float = 0.5,
        decrease_factor: float = 0.5,
        rtt_ceiling_ms: float = 2000.0,
    ):
        self.rps = initial_rps
        self.min_rps = min_rps
        self.max_rps = max_rps
        self.window = window
        self.increase_step = increase_step
        self.decrease_factor = decrease_factor
        self.rtt_ceiling_ms = rtt_ceiling_ms

        self._rtts: Deque[float] = deque(maxlen=window)
        self._lock = threading.Lock()
        self._last = 0.0
        self.adjustments = 0

    def observe(self, rtt_seconds: float) -> None:
        with self._lock:
            self._rtts.append(rtt_seconds * 1000.0)
            if len(self._rtts) < self.window:
                return
            sorted_rtts = sorted(self._rtts)
            median = sorted_rtts[len(sorted_rtts) // 2]
            if median > self.rtt_ceiling_ms:
                new_rps = max(self.min_rps, self.rps * self.decrease_factor)
            else:
                new_rps = min(self.max_rps, self.rps + self.increase_step)
            if abs(new_rps - self.rps) > 0.05:
                self.rps = new_rps
                self.adjustments += 1
                self._rtts.clear()

    def throttle(self) -> None:
        """Sleep so we respect current rate."""
        with self._lock:
            interval = 1.0 / max(self.rps, 0.01)
            now = time.monotonic()
            wait = self._last + interval - now
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "rps": round(self.rps, 2),
                "samples": len(self._rtts),
                "adjustments": self.adjustments,
            }
