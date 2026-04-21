"""HTTP and rate-limiter helpers."""

from __future__ import annotations

import asyncio
import time

import httpx


class AsyncRateLimiter:
    """Cooperative async limiter with fixed minimum interval."""

    def __init__(self, requests_per_second: float) -> None:
        self._interval = 1.0 / requests_per_second if requests_per_second > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_allowed_at = 0.0

    async def acquire(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.perf_counter()
            wait_for = self._next_allowed_at - now
            if wait_for > 0:
                await asyncio.sleep(wait_for)
                now = time.perf_counter()
            self._next_allowed_at = now + self._interval


def make_client(timeout: float) -> httpx.AsyncClient:
    """Create a standard async HTTP client for scans."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=True,
        headers={"User-Agent": "SecScan/1.0 (authorized testing only)"},
    )
