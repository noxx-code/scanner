"""Input reflection check (XSS indicator only)."""

from __future__ import annotations

import httpx

from secscan.checks.base import CheckScope, ScanContext
from secscan.checks.helpers import inject_query_param, safe_request
from secscan.utils.models import Endpoint, Finding, Severity


class InputReflectionCheck:
    """Injects harmless canary payload and checks reflection."""

    name = "input_reflection_check"
    passive = False
    scope = CheckScope.endpoint

    _payload = "<test123>"

    async def run(self, client: httpx.AsyncClient, endpoint: Endpoint, context: ScanContext) -> list[Finding]:
        del context
        findings: list[Finding] = []

        for param in endpoint.params:
            probe_url = inject_query_param(endpoint.url, param, self._payload)
            response = await safe_request(client, "GET", probe_url)
            if response is None:
                continue

            if self._payload in response.text:
                findings.append(
                    Finding(
                        url=endpoint.url,
                        issue_type="Input Reflection (XSS Indicator)",
                        severity=Severity.medium,
                        evidence=f"Payload reflected for parameter '{param}'.",
                        recommendation="Apply context-aware output encoding and strict input validation.",
                        check_name=self.name,
                    )
                )
                break

        return findings
