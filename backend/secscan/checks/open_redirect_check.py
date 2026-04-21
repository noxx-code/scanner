"""Open redirect check plugin."""

from __future__ import annotations

import httpx

from backend.secscan.checks.base import CheckScope, ScanContext
from backend.secscan.checks.helpers import external_redirect_target, inject_query_param, safe_request
from backend.secscan.utils.models import Endpoint, Finding, Severity


class OpenRedirectCheck:
    """Tests redirect parameters for external redirect acceptance."""

    name = "open_redirect_check"
    passive = False
    scope = CheckScope.endpoint

    _params = {
        "redirect",
        "redirect_uri",
        "redirect_to",
        "next",
        "url",
        "return",
        "return_url",
        "target",
    }

    async def run(self, client: httpx.AsyncClient, endpoint: Endpoint, context: ScanContext) -> list[Finding]:
        target_host = context.target_host

        for param in endpoint.params:
            if param.lower() not in self._params:
                continue
            probe_url = inject_query_param(endpoint.url, param, "https://example.com")
            response = await safe_request(client, "GET", probe_url)
            if response is None:
                continue

            redirected_to = external_redirect_target(response, target_host)
            if redirected_to:
                return [
                    Finding(
                        url=endpoint.url,
                        issue_type="Open Redirect",
                        severity=Severity.medium,
                        evidence=f"External redirect observed via parameter '{param}' to {redirected_to}",
                        recommendation="Restrict redirect destinations to trusted internal allow-list.",
                        check_name=self.name,
                    )
                ]

        return []
