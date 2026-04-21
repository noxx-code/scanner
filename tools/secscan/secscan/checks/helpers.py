"""Shared helpers used by check plugins."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx


async def safe_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    **kwargs: Any,
) -> httpx.Response | None:
    """Execute a request and convert HTTP/network failures to None."""
    try:
        return await client.request(method.upper(), url, **kwargs)
    except (httpx.HTTPError, httpx.TimeoutException):
        return None


def inject_query_param(url: str, parameter: str, value: str) -> str:
    """Return URL with one query parameter replaced by value."""
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[parameter] = [value]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def external_redirect_target(response: httpx.Response, target_host: str) -> str | None:
    """Return redirect target if response/history leads off-site."""
    for historic in response.history:
        location = historic.headers.get("location", "")
        if is_external(location, target_host):
            return location

    location = response.headers.get("location", "")
    if is_external(location, target_host):
        return location

    final_url = str(response.url)
    if is_external(final_url, target_host):
        return final_url

    return None


def is_external(url: str, target_host: str) -> bool:
    """Return True when URL host differs from target host."""
    if not url:
        return False
    host = (urlparse(url).hostname or "").lower()
    return bool(host and host != target_host)
