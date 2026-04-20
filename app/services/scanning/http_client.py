"""HTTP request building/sending helpers used by scan plugins."""

from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from app.core.config import settings
from app.services.crawler import AttackTarget
from app.services.scanning.context import get_scan_context

logger = logging.getLogger(__name__)


class AsyncRateLimiter:
    """Simple async rate limiter using a minimum interval between requests."""

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


_RATE_LIMITER = AsyncRateLimiter(settings.scanner_requests_per_second)


def inject_query_param(url: str, parameter: str, value: str) -> str:
    """Return a copy of *url* with a mutated query value for *parameter*."""
    parsed = urlparse(url)
    existing = parse_qs(parsed.query, keep_blank_values=True)
    existing[parameter] = [value]
    new_query = urlencode(existing, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def build_probe_request(
    target: AttackTarget,
    parameter: str,
    payload: str,
) -> tuple[str, str, dict[str, dict[str, str]]]:
    """Build an HTTP request tuple (method, url, kwargs) from an attack target."""
    method = target.method.upper()
    base_payload = {name: "1" for name in target.params}
    base_payload[parameter] = payload

    if target.content_type == "query" or method == "GET":
        if target.content_type == "query":
            url = inject_query_param(target.url, parameter, payload)
            return method, url, {}
        return method, target.url, {"params": base_payload}

    if target.content_type == "json":
        return method, target.url, {"json": base_payload}

    return method, target.url, {"data": base_payload}


async def send_probe(
    client: httpx.AsyncClient,
    target: AttackTarget,
    parameter: str,
    payload: str,
) -> tuple[httpx.Response | None, float]:
    """Send one probe request and return (response, elapsed_seconds)."""
    method, url, kwargs = build_probe_request(target, parameter, payload)
    max_attempts = max(1, settings.scanner_max_retries + 1)
    context = get_scan_context()

    for attempt in range(1, max_attempts + 1):
        await _RATE_LIMITER.acquire()
        started = time.perf_counter()

        logger.debug(
            "Scanner request attempt",
            extra={
                **context,
                "url": url,
                "method": method,
                "parameter": parameter,
                "attempt": attempt,
            },
        )

        try:
            response = await client.request(method, url, **kwargs)
            elapsed = time.perf_counter() - started
            return response, elapsed
        except (httpx.RequestError, httpx.TimeoutException) as exc:
            if attempt >= max_attempts:
                logger.warning(
                    "Probe request failed after retries",
                    extra={
                        **context,
                        "plugin_context": "http_client",
                        "target_url": target.url,
                        "url": url,
                        "method": method,
                        "parameter": parameter,
                        "attempt": attempt,
                        "error": str(exc),
                    },
                )
                return None, 0.0

            delay = settings.scanner_retry_backoff_seconds * (2 ** (attempt - 1))
            await asyncio.sleep(delay)

    return None, 0.0


async def send_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    **kwargs,
) -> httpx.Response | None:
    """Send a generic scanner request with retry/backoff and shared rate limiting."""
    max_attempts = max(1, settings.scanner_max_retries + 1)
    method = method.upper()

    for attempt in range(1, max_attempts + 1):
        await _RATE_LIMITER.acquire()
        try:
            return await client.request(method, url, **kwargs)
        except (httpx.RequestError, httpx.TimeoutException) as exc:
            if attempt >= max_attempts:
                logger.warning(
                    "Scanner request failed after retries",
                    extra={
                        **get_scan_context(),
                        "url": url,
                        "method": method,
                        "attempt": attempt,
                        "error": str(exc),
                    },
                )
                return None

            delay = settings.scanner_retry_backoff_seconds * (2 ** (attempt - 1))
            await asyncio.sleep(delay)

    return None
