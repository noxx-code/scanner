"""CORS misconfiguration check plugin."""

from __future__ import annotations

import httpx

from secscan.checks.base import CheckScope, ScanContext
from secscan.checks.helpers import safe_request
from secscan.utils.models import Endpoint, Finding, Severity


class CorsMisconfigurationCheck:
    """Checks permissive CORS configurations using safe preflight requests."""

    name = "cors_misconfiguration_check"
    passive = False
    scope = CheckScope.endpoint

    async def run(self, client: httpx.AsyncClient, endpoint: Endpoint, context: ScanContext) -> list[Finding]:
        del context
        headers = {
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
        }

        response = await safe_request(client, "OPTIONS", endpoint.url, headers=headers)
        if response is None:
            return []

        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "")

        findings: list[Finding] = []
        if acao == "*":
            findings.append(
                Finding(
                    url=endpoint.url,
                    issue_type="Overly Permissive CORS",
                    severity=Severity.medium,
                    evidence="Access-Control-Allow-Origin is wildcard (*).",
                    recommendation="Limit Access-Control-Allow-Origin to trusted origins.",
                    check_name=self.name,
                )
            )

        if acao == "*" and acac.lower() == "true":
            findings.append(
                Finding(
                    url=endpoint.url,
                    issue_type="CORS Credentials Misconfiguration",
                    severity=Severity.high,
                    evidence="Wildcard origin used with Access-Control-Allow-Credentials=true.",
                    recommendation="Do not allow credentials with wildcard origins.",
                    check_name=self.name,
                )
            )

        return findings
