"""
Web crawler service.

Given a starting URL, the crawler discovers:
  - Internal page URLs (links found in <a href="...">)
  - Query parameters present in those URLs (GET parameters)

The crawl is breadth-first and respects a configurable maximum depth.
External domains are skipped to keep the scope focused.
"""

import asyncio
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs

import httpx
from bs4 import BeautifulSoup

from app.core.config import settings


class CrawlResult:
    """Container returned by the crawler."""

    def __init__(self) -> None:
        # All internal URLs visited or discovered
        self.pages: list[str] = []
        # Mapping of {url: [param_name, ...]} for URLs that carry query params
        self.params: dict[str, list[str]] = {}


async def crawl(target_url: str, depth: int = settings.default_crawl_depth) -> CrawlResult:
    """
    Crawl *target_url* up to *depth* levels deep.

    :param target_url: The starting URL (must be absolute, e.g. https://example.com).
    :param depth: Maximum link-following depth (1 = only the start page).
    :return: CrawlResult with discovered pages and parameters.
    """
    result = CrawlResult()
    base_domain = urlparse(target_url).netloc

    # BFS queue: (url, current_depth)
    queue: deque[tuple[str, int]] = deque([(target_url, 0)])
    visited: set[str] = set()

    async with httpx.AsyncClient(
        timeout=settings.crawl_timeout,
        follow_redirects=True,
        # Pretend to be a regular browser to avoid trivial bot-blocks
        headers={"User-Agent": "SecurityScanner/1.0 (educational use)"},
    ) as client:
        while queue:
            url, current_depth = queue.popleft()

            # Normalise URL (strip fragment)
            url = url.split("#")[0].rstrip("/") or url
            if url in visited:
                continue
            visited.add(url)

            # Only crawl pages within the same domain
            if urlparse(url).netloc != base_domain:
                continue

            result.pages.append(url)

            # Record any query parameters carried by this URL
            parsed = urlparse(url)
            if parsed.query:
                params = list(parse_qs(parsed.query).keys())
                result.params[url] = params

            # Stop descending beyond the requested depth
            if current_depth >= depth:
                continue

            # Fetch the page and extract child links
            try:
                response = await client.get(url)
                if "text/html" not in response.headers.get("content-type", ""):
                    continue
                links = _extract_links(response.text, url)
            except (httpx.RequestError, httpx.HTTPStatusError):
                # Non-fatal: just skip unreachable pages
                continue

            for link in links:
                if link not in visited:
                    queue.append((link, current_depth + 1))

    return result


def _extract_links(html: str, base_url: str) -> list[str]:
    """
    Parse *html* and return absolute internal links found in <a href="...">.

    :param html: Raw HTML content of the page.
    :param base_url: Used to resolve relative hrefs.
    :return: List of absolute URL strings.
    """
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    base_domain = urlparse(base_url).netloc

    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        # Skip non-HTTP schemes (mailto, javascript, etc.)
        if href.startswith(("mailto:", "javascript:", "tel:", "#")):
            continue
        absolute = urljoin(base_url, href).split("#")[0]
        # Only keep links in the same domain
        if urlparse(absolute).netloc == base_domain:
            links.append(absolute)

    return links
