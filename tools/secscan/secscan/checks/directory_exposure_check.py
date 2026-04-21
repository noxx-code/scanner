"""Directory and sensitive file exposure check plugin."""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

import httpx

from secscan.checks.base import CheckScope, ScanContext
from secscan.checks.helpers import safe_request
from secscan.utils.models import Endpoint, Finding, Severity


class DirectoryExposureCheck:
    """Checks common exposed paths and directory indexing."""

    name = "directory_exposure_check"
    passive = True
    scope = CheckScope.host

    _paths = ("/backup/", "/.git/", "/.env", "/config/", "/admin/", "/uploads/")
    _listing_markers = ("<title>index of", "directory listing", "parent directory")

    async def run(self, client: httpx.AsyncClient, endpoint: Endpoint, context: ScanContext) -> list[Finding]:
        del context
        parsed = urlparse(endpoint.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        findings: list[Finding] = []
        for path in self._paths:
            probe_url = urljoin(base, path)
            response = await safe_request(client, "GET", probe_url)
            if response is None:
                continue

            if response.status_code >= 400:
                continue

            lower = response.text[:10000].lower()
            if path in {"/.env", "/.git/"}:
                findings.append(
                    Finding(
                        url=probe_url,
                        issue_type="Sensitive File/Directory Exposure",
                        severity=Severity.high,
                        evidence=f"Accessible path returned HTTP {response.status_code}",
                        recommendation="Block public access to sensitive files/directories at server level.",
                        check_name=self.name,
                    )
                )
                continue

            if any(marker in lower for marker in self._listing_markers):
                findings.append(
                    Finding(
                        url=probe_url,
                        issue_type="Directory Listing Enabled",
                        severity=Severity.medium,
                        evidence="Directory index markers detected in response body.",
                        recommendation="Disable auto-indexing and enforce explicit index files.",
                        check_name=self.name,
                    )
                )

        return findings
