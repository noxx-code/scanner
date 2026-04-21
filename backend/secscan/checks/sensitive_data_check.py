"""Sensitive data exposure pattern scanner plugin."""

from __future__ import annotations

import re

import httpx

from backend.secscan.checks.base import CheckScope, ScanContext
from backend.secscan.checks.helpers import safe_request
from backend.secscan.utils.models import Endpoint, Finding, Severity


class SensitiveDataExposureCheck:
    """Scans responses for possible secrets, tokens, emails, and internal IPs."""

    name = "sensitive_data_exposure_check"
    passive = True
    scope = CheckScope.endpoint

    _patterns: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("Potential API key", re.compile(r"(?i)(api[_-]?key|secret)[\\s:=\"']+[a-z0-9_\\-]{12,}")),
        ("Potential bearer token", re.compile(r"(?i)bearer\\s+[a-z0-9\\-_.=]{20,}")),
        ("Email address", re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+")),
        ("Internal IP", re.compile(r"\\b(?:10\\.|192\\.168\\.|172\\.(?:1[6-9]|2\\d|3[0-1])\\.)\\d{1,3}\\.\\d{1,3}\\b")),
    )

    async def run(self, client: httpx.AsyncClient, endpoint: Endpoint, context: ScanContext) -> list[Finding]:
        del context
        response = await safe_request(client, "GET", endpoint.url)
        if response is None:
            return []

        body = response.text[:120000]
        findings: list[Finding] = []
        for label, pattern in self._patterns:
            match = pattern.search(body)
            if not match:
                continue
            findings.append(
                Finding(
                    url=endpoint.url,
                    issue_type="Sensitive Data Exposure",
                    severity=Severity.medium,
                    evidence=f"{label}: {match.group(0)[:120]}",
                    recommendation="Remove sensitive values from client responses and logs.",
                    check_name=self.name,
                )
            )

        return findings
