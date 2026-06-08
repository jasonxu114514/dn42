"""A tiny dependency-free sliding-window rate limiter for the public looking glass.

Keyed by client identity (usually IP). Process-local: when running multiple workers each
keeps its own counters, which is acceptable for the looking glass abuse-prevention use case.
"""

import threading
import time
from collections import defaultdict, deque


class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window = float(window_seconds)
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Record a hit for ``key`` and return whether it is within the limit."""
        if self.limit <= 0 or self.window <= 0:
            return True
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            self._prune(cutoff)
            return True

    def _prune(self, cutoff: float) -> None:
        """Drop buckets with no recent activity so memory stays bounded under many IPs."""
        if len(self._hits) <= 2048:
            return
        stale = [key for key, hits in self._hits.items() if not hits or hits[-1] < cutoff]
        for key in stale:
            del self._hits[key]
