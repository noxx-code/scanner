"""SQL error exposure check plugin."""

from __future__ import annotations

import httpx

from secscan.checks.base import CheckScope, ScanContext
from secscan.checks.helpers import inject_query_param, safe_request
from secscan.utils.models import Endpoint, Finding, Severity


class SqlErrorExposureCheck:
    """Sends safe malformed input and searches for SQL error signatures."""

    name = "sql_error_exposure_check"
    passive = False
    scope = CheckScope.endpoint

    _error_signatures = (
        "sql syntax",
        "you have an error in your sql syntax",
        "sqlite3.operationalerror",
        "unterminated quoted string",
        "sqlstate",
        "mysql_fetch",
        "odbc sql server",
    )

    async def run(self, client: httpx.AsyncClient, endpoint: Endpoint, context: ScanContext) -> list[Finding]:
        del context
        findings: list[Finding] = []

        for param in endpoint.params:
            probe_url = inject_query_param(endpoint.url, param, "'")
            response = await safe_request(client, "GET", probe_url)
            if response is None:
                continue

            lower = response.text.lower()
            matched = next((sig for sig in self._error_signatures if sig in lower), None)
            if matched:
                findings.append(
                    Finding(
                        url=endpoint.url,
                        issue_type="SQL Error Exposure",
                        severity=Severity.high,
                        evidence=f"Database error signature detected after malformed input: {matched}",
                        recommendation="Handle exceptions server-side and use parameterized queries.",
                        check_name=self.name,
                    )
                )
                break

        return findings
