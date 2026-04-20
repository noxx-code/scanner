"""Open redirect detection plugin (non-intrusive)."""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from app.models.scan import Severity
from app.services.crawler import AttackTarget
from app.services.scanning.contracts import Finding, ScannerPlugin
from app.services.scanning.http_client import send_probe

_REDIRECT_PARAMS = {
    "next",
    "url",
    "target",
    "dest",
    "destination",
    "redirect",
    "redirect_to",
    "redirect_uri",
    "return",
    "return_url",
    "continue",
}


class OpenRedirectPlugin(ScannerPlugin):
    """Checks if redirect-style parameters allow off-site redirection."""

    name = "open_redirect"

    async def run(
        self,
        client: httpx.AsyncClient,
        target: AttackTarget,
        parameter: str,
    ) -> list[Finding]:
        if parameter.lower() not in _REDIRECT_PARAMS:
            return []

        payload = "https://example.org/security-scanner-canary"
        response, _ = await send_probe(client, target, parameter, payload)
        if response is None:
            return []

        target_host = (urlparse(target.url).hostname or "").lower()
        redirect_target = _find_external_redirect_target(response, target_host)
        if redirect_target:
            return [
                Finding(
                    url=target.url,
                    parameter=parameter,
                    vuln_type="OpenRedirect",
                    severity=Severity.medium,
                    detail=(
                        "Application accepted an external redirect target in a user-controlled "
                        f"parameter ({parameter}) and redirected to {redirect_target}."
                    ),
                )
            ]

        return []


def _find_external_redirect_target(response: httpx.Response, target_host: str) -> str | None:
    """Return an external redirect location if found in response history/final URL."""
    for historic in response.history:
        location = historic.headers.get("location", "")
        if _is_external(location, target_host):
            return location

    location = response.headers.get("location", "")
    if _is_external(location, target_host):
        return location

    final_url = str(response.url)
    if _is_external(final_url, target_host):
        return final_url

    return None


def _is_external(location: str, target_host: str) -> bool:
    if not location:
        return False
    location_host = (urlparse(location).hostname or "").lower()
    return bool(location_host and location_host != target_host)
