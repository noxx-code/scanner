"""HTTP security headers validation plugin."""

from __future__ import annotations

import httpx

from backend.secscan.checks.base import CheckScope, ScanContext
from backend.secscan.checks.helpers import safe_request
from backend.secscan.utils.models import Endpoint, Finding, Severity


class HeadersCheck:
    """Detects missing or weak security headers."""

    name = "headers_check"
    passive = True
    scope = CheckScope.endpoint

    _required_headers = (
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
    )

    async def run(self, client: httpx.AsyncClient, endpoint: Endpoint, context: ScanContext) -> list[Finding]:
        del context
        findings: list[Finding] = []

        response = await safe_request(client, "GET", endpoint.url)
        if response is None:
            return findings

        lower_headers = {k.lower() for k in response.headers.keys()}
        missing = [name for name in self._required_headers if name not in lower_headers]
        if not missing:
            return findings

        severity = Severity.medium if len(missing) >= 3 else Severity.low
        findings.append(
            Finding(
                url=endpoint.url,
                issue_type="Missing Security Headers",
                severity=severity,
                evidence=f"Missing headers: {', '.join(missing)}",
                recommendation="Add recommended security headers with hardened values.",
                check_name=self.name,
            )
        )
        return findings
