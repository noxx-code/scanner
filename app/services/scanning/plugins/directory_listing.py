"""Directory listing detection plugin (passive content checks)."""

from __future__ import annotations

import asyncio
from urllib.parse import urljoin, urlparse

import httpx

from app.models.scan import Severity
from app.services.crawler import AttackTarget
from app.services.scanning.contracts import Finding, ScannerPlugin
from app.services.scanning.http_client import send_request

_DIRECTORY_PROBES = ("/", "/uploads/", "/static/", "/assets/", "/backup/")
_LISTING_MARKERS = (
    "<title>index of",
    "directory listing for",
    "parent directory",
)


class DirectoryListingPlugin(ScannerPlugin):
    """Checks for obvious directory index exposure using safe GET requests."""

    name = "directory_listing"

    def __init__(self) -> None:
        self._checked_hosts: set[str] = set()
        self._lock = asyncio.Lock()

    async def run(
        self,
        client: httpx.AsyncClient,
        target: AttackTarget,
        parameter: str,
    ) -> list[Finding]:
        del parameter
        parsed = urlparse(target.url)
        host_root = f"{parsed.scheme}://{parsed.netloc}"

        async with self._lock:
            if host_root in self._checked_hosts:
                return []
            self._checked_hosts.add(host_root)

        findings: list[Finding] = []
        for probe in _DIRECTORY_PROBES:
            probe_url = urljoin(host_root, probe)
            response = await send_request(client, "GET", probe_url)
            if response is None:
                continue

            content_type = response.headers.get("content-type", "").lower()
            if "html" not in content_type:
                continue

            body = response.text[:10000].lower()
            if any(marker in body for marker in _LISTING_MARKERS):
                findings.append(
                    Finding(
                        url=probe_url,
                        parameter="N/A",
                        vuln_type="DirectoryListingEnabled",
                        severity=Severity.medium,
                        detail="Directory index appears enabled and browsable.",
                    )
                )

        return findings
