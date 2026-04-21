"""Async web crawler for target mapping."""

from __future__ import annotations

from collections import deque
import logging
from urllib.parse import urljoin, urlparse

import httpx

from backend.secscan.crawler.extractor import extract_api_paths_from_text, extract_forms, extract_js_files, extract_links, extract_query_endpoints
from backend.secscan.crawler.robots import load_policy
from backend.secscan.utils.config import ScanConfig
from backend.secscan.utils.http import AsyncRateLimiter, make_client
from backend.secscan.utils.models import CrawlResult, Endpoint

logger = logging.getLogger(__name__)


class WebCrawler:
    """Breadth-first crawler with safe scope and pacing controls."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._rate_limiter = AsyncRateLimiter(config.rate_limit)

    async def crawl(self) -> CrawlResult:
        """Crawl configured target and return discovered attack surfaces."""
        result = CrawlResult(base_url=self.config.target_url)
        start = self._normalize_url(self.config.target_url)
        base_host = (urlparse(start).hostname or "").lower()

        queue: deque[tuple[str, int]] = deque([(start, 0)])
        visited: set[str] = set()
        queued: set[str] = {start}
        endpoint_keys: set[tuple[str, str, tuple[str, ...], str]] = set()

        async with make_client(self.config.request_timeout) as client:
            robots = await load_policy(
                client=client,
                base_url=start,
                enabled=self.config.respect_robots_txt,
                user_agent="SecScan/1.0",
            )

            while queue:
                url, depth = queue.popleft()
                queued.discard(url)

                normalized = self._normalize_url(url)
                if normalized in visited:
                    continue
                if depth > self.config.depth:
                    continue
                if not self._within_scope(normalized, base_host):
                    continue
                if not robots.allows(normalized):
                    continue

                visited.add(normalized)
                result.urls.append(normalized)

                for endpoint in extract_query_endpoints(normalized):
                    self._add_endpoint(result, endpoint, endpoint_keys)

                if depth == self.config.depth:
                    continue

                response = await self._get(client, normalized)
                if response is None:
                    continue

                content_type = response.headers.get("content-type", "").lower()
                if "html" not in content_type and "javascript" not in content_type:
                    continue

                body = response.text
                links = extract_links(body, normalized)
                forms, form_endpoints = extract_forms(body, normalized)
                js_files = extract_js_files(body, normalized)
                api_paths = extract_api_paths_from_text(body)

                result.forms.extend(forms)
                for endpoint in form_endpoints:
                    self._add_endpoint(result, endpoint, endpoint_keys)

                for js_url in js_files:
                    if js_url not in result.js_files:
                        result.js_files.append(js_url)

                for path in sorted(api_paths):
                    if path not in result.discovered_api_paths:
                        result.discovered_api_paths.append(path)
                    absolute = urljoin(start, path)
                    api_endpoint = Endpoint(
                        url=absolute,
                        method="GET",
                        params=("q", "id", "search"),
                        source="api-discovered",
                        content_type="query",
                    )
                    self._add_endpoint(result, api_endpoint, endpoint_keys)

                for link in links:
                    link_norm = self._normalize_url(link)
                    if link_norm in visited or link_norm in queued:
                        continue
                    queue.append((link_norm, depth + 1))
                    queued.add(link_norm)

        logger.info("Crawl complete", extra={"pages": len(result.urls), "endpoints": len(result.endpoints)})
        return result

    async def _get(self, client: httpx.AsyncClient, url: str) -> httpx.Response | None:
        await self._rate_limiter.acquire()
        try:
            return await client.get(url)
        except (httpx.HTTPError, httpx.TimeoutException):
            logger.debug("Skipping unreachable URL", extra={"url": url})
            return None

    def _within_scope(self, url: str, base_host: str) -> bool:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not self.config.same_domain_only:
            return True
        return host == base_host

    @staticmethod
    def _normalize_url(url: str) -> str:
        parsed = urlparse(url)
        if not parsed.scheme:
            parsed = urlparse("http://" + url)

        path = parsed.path or "/"
        if path != "/":
            path = path.rstrip("/") or "/"

        normalized = parsed._replace(fragment="", path=path)
        return normalized.geturl()

    @staticmethod
    def _add_endpoint(result: CrawlResult, endpoint: Endpoint, seen: set[tuple[str, str, tuple[str, ...], str]]) -> None:
        key = (
            endpoint.url,
            endpoint.method.upper(),
            tuple(dict.fromkeys(endpoint.params)),
            endpoint.content_type,
        )
        if key in seen:
            return
        seen.add(key)
        result.endpoints.append(
            Endpoint(
                url=endpoint.url,
                method=endpoint.method.upper(),
                params=key[2],
                source=endpoint.source,
                content_type=endpoint.content_type,
            )
        )
