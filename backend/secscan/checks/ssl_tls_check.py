"""SSL/TLS validation plugin."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import socket
import ssl
from urllib.parse import urlparse

import httpx

from backend.secscan.checks.base import CheckScope, ScanContext
from backend.secscan.utils.models import Endpoint, Finding, Severity


class SslTlsCheck:
    """Checks certificate metadata for HTTPS targets."""

    name = "ssl_tls_check"
    passive = True
    scope = CheckScope.host

    async def run(self, client: httpx.AsyncClient, endpoint: Endpoint, context: ScanContext) -> list[Finding]:
        del client, context
        parsed = urlparse(endpoint.url)
        if parsed.scheme.lower() != "https":
            return []

        host = parsed.hostname
        if not host:
            return []

        port = parsed.port or 443

        cert_info = await asyncio.to_thread(_fetch_cert, host, port)
        if cert_info is None:
            return []

        findings: list[Finding] = []

        not_after = cert_info.get("notAfter")
        issuer = cert_info.get("issuer")
        if not_after:
            try:
                expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                if expires <= datetime.now(timezone.utc):
                    findings.append(
                        Finding(
                            url=endpoint.url,
                            issue_type="Expired TLS Certificate",
                            severity=Severity.high,
                            evidence=f"Certificate expired at {expires.isoformat()}",
                            recommendation="Renew TLS certificate immediately.",
                            check_name=self.name,
                        )
                    )
            except ValueError:
                findings.append(
                    Finding(
                        url=endpoint.url,
                        issue_type="TLS Certificate Date Parse Warning",
                        severity=Severity.low,
                        evidence=f"Unable to parse certificate expiration format: {not_after}",
                        recommendation="Review certificate metadata format and monitoring automation.",
                        check_name=self.name,
                    )
                )

        if issuer:
            issuer_text = ", ".join(f"{name}={value}" for attrs in issuer for name, value in attrs)
            if "let's encrypt" not in issuer_text.lower() and "digicert" not in issuer_text.lower():
                findings.append(
                    Finding(
                        url=endpoint.url,
                        issue_type="Unrecognized Certificate Issuer",
                        severity=Severity.low,
                        evidence=f"Issuer: {issuer_text}",
                        recommendation="Validate certificate issuer trust chain and rotation process.",
                        check_name=self.name,
                    )
                )

        return findings


def _fetch_cert(host: str, port: int) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                return tls_sock.getpeercert()
    except OSError:
        return None
