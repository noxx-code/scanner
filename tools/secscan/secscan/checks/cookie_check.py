"""Cookie security check plugin."""

from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from secscan.checks.base import CheckScope, ScanContext
from secscan.checks.helpers import safe_request
from secscan.utils.models import Endpoint, Finding, Severity


class CookieSecurityCheck:
    """Checks Secure/HttpOnly/SameSite cookie flags and token leakage in URLs."""

    name = "cookie_security_check"
    passive = True
    scope = CheckScope.endpoint

    _token_keys = {"token", "session", "auth", "jwt", "apikey", "api_key"}

    async def run(self, client: httpx.AsyncClient, endpoint: Endpoint, context: ScanContext) -> list[Finding]:
        del context
        findings: list[Finding] = []

        response = await safe_request(client, "GET", endpoint.url)
        if response is None:
            return findings

        for raw_cookie in response.headers.get_list("set-cookie"):
            lower = raw_cookie.lower()
            missing: list[str] = []
            if "secure" not in lower:
                missing.append("Secure")
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if "samesite=" not in lower:
                missing.append("SameSite")
            if not missing:
                continue

            cookie_name = raw_cookie.split("=", 1)[0]
            findings.append(
                Finding(
                    url=endpoint.url,
                    issue_type="Insecure Cookie Flags",
                    severity=Severity.medium if "Secure" in missing or "HttpOnly" in missing else Severity.low,
                    evidence=f"Cookie {cookie_name} missing: {', '.join(missing)}",
                    recommendation="Set Secure, HttpOnly, and SameSite attributes for sensitive cookies.",
                    check_name=self.name,
                )
            )

        parsed = urlparse(endpoint.url)
        query = parsed.query.lower()
        if any(re.search(rf"(^|[?&]){key}=", f"?{query}") for key in self._token_keys):
            findings.append(
                Finding(
                    url=endpoint.url,
                    issue_type="Session Token in URL",
                    severity=Severity.high,
                    evidence="Sensitive token-like parameter found in query string.",
                    recommendation="Avoid placing session tokens or API keys in URLs.",
                    check_name=self.name,
                )
            )

        return findings
