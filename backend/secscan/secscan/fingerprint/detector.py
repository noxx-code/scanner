"""Technology fingerprint detector."""

from __future__ import annotations

import logging
import re

import httpx

from backend.secscan.fingerprint.signatures import HEADER_TECH_SIGNATURES, HTML_LIBRARY_PATTERNS, MOCK_VULN_MINIMUMS
from backend.secscan.utils.http import make_client
from backend.secscan.utils.models import CrawlResult, Fingerprint

logger = logging.getLogger(__name__)


class Fingerprinter:
    """Detects server/framework/library technologies and rough versions."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def fingerprint(self, crawl_result: CrawlResult) -> list[Fingerprint]:
        """Fingerprint technologies from crawled URLs and JavaScript files."""
        fingerprints: list[Fingerprint] = []
        seen: set[tuple[str, str, str | None]] = set()

        if not crawl_result.urls:
            return fingerprints

        sample_urls = crawl_result.urls[: min(15, len(crawl_result.urls))]
        sample_js_urls = crawl_result.js_files[: min(25, len(crawl_result.js_files))]

        async with make_client(self.timeout) as client:
            for url in sample_urls:
                response = await self._safe_get(client, url)
                if response is None:
                    continue

                for header_name, (category, tech_name) in HEADER_TECH_SIGNATURES.items():
                    value = response.headers.get(header_name)
                    if not value:
                        continue
                    version = _extract_version(value)
                    fingerprint = Fingerprint(
                        category=category,
                        name=tech_name,
                        version=version,
                        evidence=f"{header_name}: {value}",
                    )
                    self._append_unique(fingerprints, seen, fingerprint)

                self._analyze_blob(
                    fingerprints=fingerprints,
                    seen=seen,
                    blob=response.text[:50000],
                    evidence_source=url,
                )

            for js_url in sample_js_urls:
                js_response = await self._safe_get(client, js_url)
                if js_response is None:
                    continue

                self._analyze_blob(
                    fingerprints=fingerprints,
                    seen=seen,
                    blob=js_response.text[:80000],
                    evidence_source=f"JS file: {js_url}",
                )

        logger.info("Fingerprinting complete", extra={"technologies": len(fingerprints)})
        return fingerprints

    @staticmethod
    def _append_unique(
        fingerprints: list[Fingerprint],
        seen: set[tuple[str, str, str | None]],
        fingerprint: Fingerprint,
    ) -> None:
        key = (fingerprint.category, fingerprint.name.lower(), fingerprint.version)
        if key in seen:
            return
        seen.add(key)
        fingerprints.append(fingerprint)

    @staticmethod
    async def _safe_get(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
        try:
            return await client.get(url)
        except (httpx.HTTPError, httpx.TimeoutException):
            return None

    def _analyze_blob(
        self,
        fingerprints: list[Fingerprint],
        seen: set[tuple[str, str, str | None]],
        blob: str,
        evidence_source: str,
    ) -> None:
        for library, pattern in HTML_LIBRARY_PATTERNS:
            match = pattern.search(blob)
            if not match:
                continue

            version = match.group(1) if match.lastindex else None
            vulnerable, advisory = _mock_vulnerability_check(library, version)
            fingerprint = Fingerprint(
                category="library",
                name=library,
                version=version,
                evidence=f"Pattern detected in {evidence_source}",
                vulnerable=vulnerable,
                advisory=advisory,
            )
            self._append_unique(fingerprints, seen, fingerprint)


def _extract_version(raw: str) -> str | None:
    match = re.search(r"(\\d+\\.\\d+(?:\\.\\d+)?)", raw)
    return match.group(1) if match else None


def _mock_vulnerability_check(name: str, version: str | None) -> tuple[bool, str | None]:
    if version is None:
        return False, None
    min_safe = MOCK_VULN_MINIMUMS.get(name)
    if not min_safe:
        return False, None

    parsed = _parse_version(version)
    if parsed is None:
        return False, None

    if parsed < min_safe:
        return True, f"{name} {version} appears below recommended baseline {'.'.join(str(v) for v in min_safe)}"
    return False, None


def _parse_version(value: str) -> tuple[int, int, int] | None:
    parts = re.findall(r"\\d+", value)
    if not parts:
        return None
    major = int(parts[0])
    minor = int(parts[1]) if len(parts) > 1 else 0
    patch = int(parts[2]) if len(parts) > 2 else 0
    return major, minor, patch
