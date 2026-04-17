"""
Web crawler service.

Given a starting URL, the crawler discovers:
    - Internal page URLs (links found in <a href="...">)
    - Query parameters present in those URLs (GET parameters)
    - HTML form inputs (<form>, <input>, <textarea>, <select>)
    - Common API endpoints for JSON-aware scanning

The crawl is breadth-first and respects a configurable maximum depth.
External domains are skipped to keep the scope focused.
"""

from collections import deque
from dataclasses import dataclass
import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse, parse_qs

import httpx
from bs4 import BeautifulSoup, Tag

from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AttackTarget:
    """A structured input surface that can be fuzzed by the scanner."""

    url: str
    method: str
    params: tuple[str, ...]
    content_type: str  # query | form | json
    source: str  # link-query | html-form | api-common | api-bruteforce | api-discovered


class CrawlResult:
    """Container returned by the crawler."""

    def __init__(self) -> None:
        # All internal URLs visited or discovered
        self.pages: list[str] = []
        # Mapping of {url: [param_name, ...]} for URLs that carry query params
        self.params: dict[str, list[str]] = {}
        # Rich attack surfaces discovered during crawling
        self.targets: list[AttackTarget] = []


async def crawl(
    target_url: str,
    depth: int = settings.default_crawl_depth,
    include_api: bool = True,
    brute_force_api: bool = False,
    api_paths: list[str] | None = None,
    scan_id: int | None = None,
) -> CrawlResult:
    """
    Crawl *target_url* up to *depth* levels deep.

    :param target_url: The starting URL (must be absolute, e.g. https://example.com).
    :param depth: Maximum link-following depth (1 = only the start page).
    :return: CrawlResult with discovered pages and parameters.
    """
    result = CrawlResult()
    base_domain = urlparse(target_url).netloc
    crawl_context = {"scan_id": scan_id, "target_url": target_url}
    logger.info("Crawler started", extra=crawl_context)

    # BFS queue: (url, current_depth)
    queue: deque[tuple[str, int]] = deque([(target_url, 0)])
    visited: set[str] = set()
    target_keys: set[tuple[str, str, tuple[str, ...], str]] = set()
    discovered_api_paths: set[str] = set()

    # Seed common API endpoints (configurable + optional brute-force additions)
    if include_api:
        configured_paths = api_paths or _parse_config_api_paths(settings.api_common_endpoints)
        for path in configured_paths:
            discovered_api_paths.add(path)
        if brute_force_api:
            discovered_api_paths.update(_default_api_bruteforce_paths())

    timeout = httpx.Timeout(settings.crawl_timeout)
    async with httpx.AsyncClient(
        timeout=timeout,
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
                _add_target(
                    result,
                    target_keys,
                    AttackTarget(
                        url=url,
                        method="GET",
                        params=tuple(params),
                        content_type="query",
                        source="link-query",
                    ),
                )

            # Stop descending beyond the requested depth
            if current_depth >= depth:
                continue

            # Fetch the page and extract child links
            try:
                response = await _get_with_retries(client, url, scan_id=scan_id, target_url=target_url)
                if "text/html" not in response.headers.get("content-type", ""):
                    continue
                links = _extract_links(response.text, url)
                forms = _extract_forms(response.text, url)
                discovered_api_paths.update(_discover_api_paths(response.text))
            except (httpx.RequestError, httpx.HTTPStatusError, httpx.TimeoutException):
                # Non-fatal: just skip unreachable pages
                logger.warning(
                    "Crawler skipped unreachable page",
                    extra={"scan_id": scan_id, "target_url": target_url, "url": url},
                )
                continue

            for link in links:
                if link not in visited:
                    queue.append((link, current_depth + 1))

            for form_target in forms:
                _add_target(result, target_keys, form_target)
                if form_target.method == "GET":
                    # Keep backwards-compatible map used by older scan code paths.
                    result.params.setdefault(form_target.url, list(form_target.params))

    if include_api:
        for api_target in _build_api_targets(target_url, discovered_api_paths, brute_force_api):
            _add_target(result, target_keys, api_target)

    logger.info(
        "Crawler finished",
        extra={
            "scan_id": scan_id,
            "target_url": target_url,
            "pages": len(result.pages),
            "targets": len(result.targets),
        },
    )
    return result


async def _get_with_retries(
    client: httpx.AsyncClient,
    url: str,
    scan_id: int | None,
    target_url: str,
) -> httpx.Response:
    """GET with retry/backoff to avoid transient failures aborting crawl."""
    max_attempts = max(1, settings.crawl_max_retries + 1)
    for attempt in range(1, max_attempts + 1):
        logger.debug(
            "Crawler request attempt",
            extra={
                "scan_id": scan_id,
                "target_url": target_url,
                "url": url,
                "attempt": attempt,
            },
        )
        try:
            response = await client.get(url)
            return response
        except (httpx.RequestError, httpx.TimeoutException, httpx.HTTPStatusError) as exc:
            if attempt >= max_attempts:
                logger.error(
                    "Crawler request failed after retries",
                    extra={
                        "scan_id": scan_id,
                        "target_url": target_url,
                        "url": url,
                        "attempt": attempt,
                        "error": str(exc),
                    },
                )
                raise
            delay = settings.crawl_retry_backoff_seconds * (2 ** (attempt - 1))
            await asyncio.sleep(delay)


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
        if not isinstance(tag, Tag):
            continue
        href = _attr_as_str(tag, "href").strip()
        if not href:
            continue
        # Skip non-HTTP schemes (mailto, javascript, etc.)
        if href.startswith(("mailto:", "javascript:", "tel:", "#")):
            continue
        absolute = urljoin(base_url, href).split("#")[0]
        # Only keep links in the same domain
        if urlparse(absolute).netloc == base_domain:
            links.append(absolute)

    return links


def _extract_forms(html: str, page_url: str) -> list[AttackTarget]:
    """Parse HTML forms and build form attack targets."""
    soup = BeautifulSoup(html, "html.parser")
    targets: list[AttackTarget] = []

    for form in soup.find_all("form"):
        if not isinstance(form, Tag):
            continue

        action = _attr_as_str(form, "action").strip()
        method = (_attr_as_str(form, "method") or "GET").upper()
        if method not in {"GET", "POST"}:
            method = "POST"

        target_url = urljoin(page_url, action) if action else page_url
        params: list[str] = []

        for field in form.find_all(["input", "textarea", "select"]):
            if not isinstance(field, Tag):
                continue
            name = _attr_as_str(field, "name").strip()
            if name:
                params.append(name)

        deduped = tuple(dict.fromkeys(params))
        if not deduped:
            continue

        targets.append(
            AttackTarget(
                url=target_url,
                method=method,
                params=deduped,
                content_type="form",
                source="html-form",
            )
        )

    return targets


def _discover_api_paths(html: str) -> set[str]:
    """Extract API-like paths from inline scripts and HTML attributes."""
    # Conservative path matcher: /api, /rest, /search, /v1/items etc.
    pattern = re.compile(r'(["\'])(/(?:api|rest|search|graphql|v\d+)[^"\'\s<>]*)\1', re.IGNORECASE)
    discovered: set[str] = set()
    for match in pattern.finditer(html):
        path = match.group(2).strip()
        if path:
            discovered.add(path)
    return discovered


def _parse_config_api_paths(raw_paths: str) -> list[str]:
    """Parse comma-separated endpoint seeds from settings."""
    parsed: list[str] = []
    for piece in raw_paths.split(","):
        p = piece.strip()
        if not p:
            continue
        parsed.append(p if p.startswith("/") else f"/{p}")
    return parsed


def _default_api_bruteforce_paths() -> set[str]:
    """Small endpoint wordlist used when brute-force mode is enabled."""
    return {
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/search",
        "/api/products",
        "/api/users",
        "/api/login",
        "/rest",
        "/rest/products/search",
        "/rest/user/login",
        "/search",
        "/graphql",
    }


def _build_api_targets(
    base_url: str,
    api_paths: set[str],
    brute_force_enabled: bool,
) -> list[AttackTarget]:
    """Create GET/POST-JSON attack targets from discovered API paths."""
    base_domain = urlparse(base_url).netloc
    targets: list[AttackTarget] = []

    for path in api_paths:
        absolute = urljoin(base_url, path)
        if urlparse(absolute).netloc != base_domain:
            continue

        source = "api-bruteforce" if brute_force_enabled and path in _default_api_bruteforce_paths() else "api-common"
        if path not in _default_api_bruteforce_paths() and path not in _parse_config_api_paths(settings.api_common_endpoints):
            source = "api-discovered"

        # Query-style probing
        targets.append(
            AttackTarget(
                url=absolute,
                method="GET",
                params=("q", "search", "id", "term"),
                content_type="query",
                source=source,
            )
        )

        # JSON body probing
        if settings.scan_json_endpoints:
            targets.append(
                AttackTarget(
                    url=absolute,
                    method="POST",
                    params=("q", "search", "id", "email", "password"),
                    content_type="json",
                    source=source,
                )
            )

    return targets


def _add_target(
    result: CrawlResult,
    seen: set[tuple[str, str, tuple[str, ...], str]],
    target: AttackTarget,
) -> None:
    """Deduplicate targets while preserving insertion order."""
    params = tuple(dict.fromkeys(target.params))
    key = (target.method, target.url, params, target.content_type)
    if key in seen or not params:
        return
    seen.add(key)
    result.targets.append(
        AttackTarget(
            url=target.url,
            method=target.method,
            params=params,
            content_type=target.content_type,
            source=target.source,
        )
    )


def _attr_as_str(tag: Tag, name: str) -> str:
    """Read a BeautifulSoup attribute as a normalized string."""
    value = tag.get(name)
    if value is None:
        return ""
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    return str(value)
