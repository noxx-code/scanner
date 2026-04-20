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
import time
from urllib import robotparser
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup, Tag

from app.core.config import settings

logger = logging.getLogger(__name__)

SKIP_SCHEMES = ("mailto:", "javascript:", "tel:")
STATIC_ASSET_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".css",
    ".js",
    ".mjs",
    ".map",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".pdf",
    ".zip",
    ".rar",
    ".7z",
    ".mp4",
    ".mp3",
    ".avi",
    ".mov",
}


class AsyncRateLimiter:
    """Simple async rate limiter based on minimum interval pacing."""

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


class RobotsPolicy:
    """robots.txt policy helper used by the crawler."""

    def __init__(self, parser: robotparser.RobotFileParser | None, enabled: bool, user_agent: str) -> None:
        self._parser = parser
        self._enabled = enabled
        self._user_agent = user_agent

    def allows(self, url: str) -> bool:
        if not self._enabled or self._parser is None:
            return True
        return self._parser.can_fetch(self._user_agent, url)


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
    respect_robots_txt: bool = settings.crawl_respect_robots_txt,
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
    normalized_start_url = _normalize_url(target_url)
    start_parsed = urlparse(normalized_start_url)
    base_domain = (start_parsed.hostname or "").lower()
    if not base_domain:
        logger.warning(
            "Crawler aborted due to invalid start URL",
            extra={"scan_id": scan_id, "target_url": target_url},
        )
        return result

    crawl_context = {"scan_id": scan_id, "target_url": target_url}
    logger.info("Crawler started", extra={**crawl_context, "base_domain": base_domain, "max_depth": depth})

    # BFS queue: (url, current_depth)
    queue: deque[tuple[str, int]] = deque([(normalized_start_url, 0)])
    queued: set[str] = {normalized_start_url}
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
    rate_limiter = AsyncRateLimiter(settings.crawl_requests_per_second)
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        # Pretend to be a regular browser to avoid trivial bot-blocks
        headers={"User-Agent": settings.scanner_user_agent},
    ) as client:
        robots_policy = await _load_robots_policy(
            client=client,
            start_url=normalized_start_url,
            user_agent=settings.scanner_user_agent,
            enabled=respect_robots_txt,
            scan_id=scan_id,
            target_url=target_url,
        )

        while queue:
            url, current_depth = queue.popleft()
            queued.discard(url)
            logger.debug(
                "Crawler dequeued URL",
                extra={
                    "scan_id": scan_id,
                    "target_url": target_url,
                    "url": url,
                    "depth": current_depth,
                    "queue_size": len(queue),
                },
            )

            if current_depth > depth:
                logger.debug(
                    "Crawler skipped URL",
                    extra={
                        "scan_id": scan_id,
                        "target_url": target_url,
                        "url": url,
                        "depth": current_depth,
                        "reason": "exceeds max depth",
                    },
                )
                continue

            url = _normalize_url(url)
            if url in visited:
                logger.debug(
                    "Crawler skipped URL",
                    extra={
                        "scan_id": scan_id,
                        "target_url": target_url,
                        "url": url,
                        "depth": current_depth,
                        "reason": "already visited",
                    },
                )
                continue

            skip_reason = _skip_reason(url, base_domain)
            if skip_reason:
                logger.debug(
                    "Crawler skipped URL",
                    extra={
                        "scan_id": scan_id,
                        "target_url": target_url,
                        "url": url,
                        "depth": current_depth,
                        "reason": skip_reason,
                    },
                )
                continue

            if not robots_policy.allows(url):
                logger.debug(
                    "Crawler skipped URL",
                    extra={
                        "scan_id": scan_id,
                        "target_url": target_url,
                        "url": url,
                        "depth": current_depth,
                        "reason": "blocked by robots.txt",
                    },
                )
                continue

            if len(result.pages) >= settings.crawl_max_pages:
                logger.info(
                    "Crawler reached max page cap",
                    extra={
                        "scan_id": scan_id,
                        "target_url": target_url,
                        "max_pages": settings.crawl_max_pages,
                    },
                )
                break

            visited.add(url)

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
                response = await _get_with_retries(
                    client,
                    url,
                    scan_id=scan_id,
                    target_url=target_url,
                    rate_limiter=rate_limiter,
                )
                if 300 <= response.status_code < 400:
                    logger.debug(
                        "Crawler skipped URL",
                        extra={
                            "scan_id": scan_id,
                            "target_url": target_url,
                            "url": url,
                            "depth": current_depth,
                            "reason": "redirect response not followed",
                            "status_code": response.status_code,
                            "location": response.headers.get("location", ""),
                        },
                    )
                    continue

                content_type = response.headers.get("content-type", "").lower()
                if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                    logger.debug(
                        "Crawler skipped URL",
                        extra={
                            "scan_id": scan_id,
                            "target_url": target_url,
                            "url": url,
                            "depth": current_depth,
                            "reason": "non-html response",
                            "content_type": content_type,
                        },
                    )
                    continue

                links = _extract_links(response.text, url, base_domain)
                forms = _extract_forms(response.text, url)
                discovered_api_paths.update(_discover_api_paths(response.text))
            except (httpx.RequestError, httpx.HTTPStatusError, httpx.TimeoutException):
                # Non-fatal: just skip unreachable pages
                logger.warning(
                    "Crawler skipped unreachable page",
                    extra={
                        "scan_id": scan_id,
                        "target_url": target_url,
                        "url": url,
                        "depth": current_depth,
                    },
                )
                continue

            for link in links:
                if current_depth + 1 > depth:
                    logger.debug(
                        "Crawler skipped URL",
                        extra={
                            "scan_id": scan_id,
                            "target_url": target_url,
                            "url": link,
                            "depth": current_depth + 1,
                            "reason": "would exceed max depth",
                        },
                    )
                    continue

                if link in visited or link in queued:
                    logger.debug(
                        "Crawler skipped URL",
                        extra={
                            "scan_id": scan_id,
                            "target_url": target_url,
                            "url": link,
                            "depth": current_depth + 1,
                            "reason": "already visited or queued",
                        },
                    )
                    continue

                queue.append((link, current_depth + 1))
                queued.add(link)
                logger.debug(
                    "Crawler queued URL",
                    extra={
                        "scan_id": scan_id,
                        "target_url": target_url,
                        "url": link,
                        "depth": current_depth + 1,
                        "queue_size": len(queue),
                    },
                )

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
    rate_limiter: AsyncRateLimiter,
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
            await rate_limiter.acquire()
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


async def _load_robots_policy(
    client: httpx.AsyncClient,
    start_url: str,
    user_agent: str,
    enabled: bool,
    scan_id: int | None,
    target_url: str,
) -> RobotsPolicy:
    """Load robots.txt and build an allow/deny policy for crawling."""
    if not enabled:
        logger.info(
            "Crawler robots.txt enforcement disabled",
            extra={"scan_id": scan_id, "target_url": target_url},
        )
        return RobotsPolicy(parser=None, enabled=False, user_agent=user_agent)

    parsed = urlparse(start_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    rp = robotparser.RobotFileParser()
    rp.set_url(robots_url)

    try:
        response = await client.get(robots_url)
        if response.status_code >= 400:
            logger.info(
                "robots.txt not available; crawler continuing",
                extra={"scan_id": scan_id, "target_url": target_url, "robots_url": robots_url},
            )
            return RobotsPolicy(parser=None, enabled=False, user_agent=user_agent)
        rp.parse(response.text.splitlines())
        logger.info(
            "robots.txt loaded",
            extra={"scan_id": scan_id, "target_url": target_url, "robots_url": robots_url},
        )
        return RobotsPolicy(parser=rp, enabled=True, user_agent=user_agent)
    except (httpx.RequestError, httpx.TimeoutException):
        logger.info(
            "robots.txt fetch failed; crawler continuing",
            extra={"scan_id": scan_id, "target_url": target_url, "robots_url": robots_url},
        )
        return RobotsPolicy(parser=None, enabled=False, user_agent=user_agent)


def _extract_links(html: str, base_url: str, base_domain: str) -> list[str]:
    """
    Parse *html* and return absolute internal links found in <a href="...">.

    :param html: Raw HTML content of the page.
    :param base_url: Used to resolve relative hrefs.
    :return: List of absolute URL strings.
    """
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    for tag in soup.find_all("a", href=True):
        if not isinstance(tag, Tag):
            continue
        href = _attr_as_str(tag, "href").strip()
        if not href:
            continue

        if href.startswith("#"):
            continue
        if href.lower().startswith(SKIP_SCHEMES):
            continue

        absolute = _normalize_url(urljoin(base_url, href))
        skip_reason = _skip_reason(absolute, base_domain)
        if skip_reason:
            continue
        links.append(absolute)

    return links


def _normalize_url(url: str) -> str:
    """Normalize URL for stable deduplication and queue management."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        return url.split("#", 1)[0].rstrip("/")

    default_port = 80 if scheme == "http" else 443 if scheme == "https" else None
    if parsed.port and parsed.port != default_port:
        netloc = f"{hostname}:{parsed.port}"
    else:
        netloc = hostname

    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"

    normalized = parsed._replace(scheme=scheme, netloc=netloc, path=path, fragment="")
    return normalized.geturl()


def _skip_reason(url: str, base_domain: str) -> str | None:
    """Return skip reason for URLs outside crawl scope; otherwise None."""
    lowered = url.lower()
    if lowered.startswith(SKIP_SCHEMES):
        return "unsupported URL scheme"

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return "non-http URL"

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return "missing hostname"
    if hostname != base_domain:
        return "external domain"

    path = parsed.path.lower()
    for ext in STATIC_ASSET_EXTENSIONS:
        if path.endswith(ext):
            return "static asset URL"

    return None


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
