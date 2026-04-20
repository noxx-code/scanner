"""JavaScript analysis plugin for endpoints/secrets/libraries."""

from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

from secscan.checks.base import CheckScope, ScanContext
from secscan.checks.helpers import safe_request
from secscan.utils.models import Endpoint, Finding, Severity


class JavaScriptAnalysisCheck:
    """Analyzes JS assets for potential secrets and endpoint hints."""

    name = "js_analysis_check"
    passive = True
    scope = CheckScope.global_run

    _endpoint_pattern = re.compile(r"['\"](/(?:api|v\d+|auth|user|admin|search)[^'\"\s]*)['\"]", re.IGNORECASE)
    _secret_pattern = re.compile(r"(?i)(api[_-]?key|token|secret)\\s*[:=]\\s*['\"][^'\"]{10,}['\"]")
    _lib_pattern = re.compile(r"(?i)(jquery|react|angular|vue|bootstrap)[^\\d]{0,6}(\\d+\\.\\d+(?:\\.\\d+)?)")

    async def run(self, client: httpx.AsyncClient, endpoint: Endpoint, context: ScanContext) -> list[Finding]:
        base_origin = context.target_origin

        findings: list[Finding] = []
        for js_file in context.js_files[:30]:
            js_url = js_file if js_file.startswith("http") else urljoin(base_origin, js_file)
            response = await safe_request(client, "GET", js_url)
            if response is None:
                continue

            body = response.text[:120000]

            endpoint_match = self._endpoint_pattern.search(body)
            if endpoint_match:
                findings.append(
                    Finding(
                        url=js_url,
                        issue_type="JavaScript Endpoint Disclosure",
                        severity=Severity.low,
                        evidence=f"Endpoint-like path found in JS: {endpoint_match.group(1)}",
                        recommendation="Review front-end exposed endpoints and enforce server-side authorization.",
                        check_name=self.name,
                    )
                )

            secret_match = self._secret_pattern.search(body)
            if secret_match:
                findings.append(
                    Finding(
                        url=js_url,
                        issue_type="JavaScript Secret Exposure",
                        severity=Severity.high,
                        evidence=f"Potential secret assignment in JS: {secret_match.group(0)[:120]}",
                        recommendation="Remove secrets from client-side code and rotate exposed credentials.",
                        check_name=self.name,
                    )
                )

            lib_match = self._lib_pattern.search(body)
            if lib_match:
                findings.append(
                    Finding(
                        url=js_url,
                        issue_type="JavaScript Library Fingerprint",
                        severity=Severity.low,
                        evidence=f"Detected library signature: {lib_match.group(1)} {lib_match.group(2)}",
                        recommendation="Keep front-end libraries updated to patched versions.",
                        check_name=self.name,
                    )
                )

        return findings
