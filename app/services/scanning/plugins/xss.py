"""Reflected XSS scanner plugin."""

from __future__ import annotations

import logging

import httpx

from app.models.scan import Severity
from app.services.crawler import AttackTarget
from app.services.scanning.contracts import Finding, ScannerPlugin
from app.services.scanning.http_client import send_probe

logger = logging.getLogger(__name__)

XSS_PAYLOADS: list[tuple[str, str]] = [
    ("<scannertag>xsstest</scannertag>", "Reflected XSS canary tag"),
    ("'\"><scannertag>", "Reflected XSS quote-break canary"),
    ("<img src=x onerror=alert('xss')>", "HTML attribute injection probe"),
    ("<svg/onload=alert('xss')>", "SVG onload probe"),
    ("</script><script>alert('xss')</script>", "Script context break-out probe"),
]


class XssPlugin(ScannerPlugin):
    """Checks whether payloads are reflected in server responses."""

    name = "xss"

    async def run(
        self,
        client: httpx.AsyncClient,
        target: AttackTarget,
        parameter: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for payload, description in XSS_PAYLOADS:
            response, _ = await send_probe(client, target, parameter, payload)
            if response is None:
                continue

            if payload.lower() in response.text.lower():
                findings.append(
                    Finding(
                        url=target.url,
                        parameter=parameter,
                        vuln_type="XSS",
                        severity=Severity.high,
                        detail=(
                            f"{description}: payload reflected in response. "
                            f"surface={target.content_type} method={target.method} source={target.source}."
                        ),
                    )
                )
                logger.info(
                    "Potential XSS detected",
                    extra={
                        "plugin": self.name,
                        "target_url": target.url,
                        "parameter": parameter,
                    },
                )
                break

        return findings
