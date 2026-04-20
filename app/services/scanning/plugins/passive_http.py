"""Passive HTTP security checks plugin (headers, cookies, technology disclosure)."""

from __future__ import annotations

import asyncio
import re

import httpx

from app.models.scan import Severity
from app.services.crawler import AttackTarget
from app.services.scanning.contracts import Finding, ScannerPlugin
from app.services.scanning.http_client import send_request

_REQUIRED_HEADERS: tuple[str, ...] = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

_TECH_HEADERS: tuple[str, ...] = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-generator",
    "via",
)

_VERSION_PATTERNS: tuple[tuple[str, re.Pattern[str], tuple[int, int, int], Severity], ...] = (
    (
        "jQuery",
        re.compile(r"jquery[^\\d]{0,6}(\\d+\\.\\d+(?:\\.\\d+)?)", re.IGNORECASE),
        (3, 5, 0),
        Severity.medium,
    ),
    (
        "Bootstrap",
        re.compile(r"bootstrap[^\\d]{0,6}(\\d+\\.\\d+(?:\\.\\d+)?)", re.IGNORECASE),
        (4, 6, 0),
        Severity.low,
    ),
    (
        "AngularJS",
        re.compile(r"angular(?:\\.min)?\\.js[^\\d]{0,6}(\\d+\\.\\d+(?:\\.\\d+)?)", re.IGNORECASE),
        (1, 8, 3),
        Severity.medium,
    ),
)


class PassiveHttpPlugin(ScannerPlugin):
    """Run non-intrusive passive checks once per URL."""

    name = "passive_http"

    def __init__(self) -> None:
        self._seen_urls: set[str] = set()
        self._lock = asyncio.Lock()

    async def run(
        self,
        client: httpx.AsyncClient,
        target: AttackTarget,
        parameter: str,
    ) -> list[Finding]:
        del parameter
        async with self._lock:
            if target.url in self._seen_urls:
                return []
            self._seen_urls.add(target.url)

        response = await send_request(client, "GET", target.url)
        if response is None:
            return []

        findings: list[Finding] = []
        findings.extend(self._missing_security_headers(target.url, response.headers))
        findings.extend(self._cookie_security(target.url, response.headers))
        findings.extend(self._tech_disclosure(target.url, response.headers))
        findings.extend(self._outdated_versions(target.url, response, response.headers))
        return findings

    def _missing_security_headers(self, url: str, headers: httpx.Headers) -> list[Finding]:
        lowered = {k.lower(): v for k, v in headers.items()}
        missing = [name for name in _REQUIRED_HEADERS if name not in lowered]
        if not missing:
            return []

        severity = Severity.medium if len(missing) >= 3 else Severity.low
        return [
            Finding(
                url=url,
                parameter="N/A",
                vuln_type="MissingSecurityHeaders",
                severity=severity,
                detail=f"Missing recommended headers: {', '.join(missing)}.",
            )
        ]

    def _cookie_security(self, url: str, headers: httpx.Headers) -> list[Finding]:
        set_cookie_headers = headers.get_list("set-cookie")
        findings: list[Finding] = []

        for raw_cookie in set_cookie_headers:
            cookie_lower = raw_cookie.lower()
            cookie_name = raw_cookie.split("=", 1)[0].strip() or "unknown"
            missing_flags: list[str] = []

            if "secure" not in cookie_lower:
                missing_flags.append("Secure")
            if "httponly" not in cookie_lower:
                missing_flags.append("HttpOnly")
            if "samesite=" not in cookie_lower:
                missing_flags.append("SameSite")

            if not missing_flags:
                continue

            severity = Severity.medium if any(flag in {"Secure", "HttpOnly"} for flag in missing_flags) else Severity.low
            findings.append(
                Finding(
                    url=url,
                    parameter=cookie_name,
                    vuln_type="InsecureCookieFlags",
                    severity=severity,
                    detail=f"Cookie '{cookie_name}' missing: {', '.join(missing_flags)}.",
                )
            )

        return findings

    def _tech_disclosure(self, url: str, headers: httpx.Headers) -> list[Finding]:
        disclosed: list[str] = []
        for name in _TECH_HEADERS:
            value = headers.get(name)
            if value:
                disclosed.append(f"{name}={value}")

        if not disclosed:
            return []

        return [
            Finding(
                url=url,
                parameter="N/A",
                vuln_type="TechnologyDisclosure",
                severity=Severity.low,
                detail=f"Technology details exposed via response headers: {'; '.join(disclosed)}.",
            )
        ]

    def _outdated_versions(self, url: str, response: httpx.Response, headers: httpx.Headers) -> list[Finding]:
        findings: list[Finding] = []

        blob = "\n".join([
            response.text[:40000],
            "\n".join(f"{k}:{v}" for k, v in headers.items()),
        ])

        for product, pattern, min_version, severity in _VERSION_PATTERNS:
            match = pattern.search(blob)
            if not match:
                continue

            version_text = match.group(1)
            parsed = _parse_version(version_text)
            if parsed is None:
                continue

            if parsed < min_version:
                findings.append(
                    Finding(
                        url=url,
                        parameter="N/A",
                        vuln_type="OutdatedSoftware",
                        severity=severity,
                        detail=(
                            f"Detected {product} {version_text}, which may be outdated. "
                            f"Recommended minimum: {'.'.join(str(p) for p in min_version)}."
                        ),
                    )
                )

        return findings


def _parse_version(value: str) -> tuple[int, int, int] | None:
    parts = re.findall(r"\\d+", value)
    if not parts:
        return None

    major = int(parts[0])
    minor = int(parts[1]) if len(parts) > 1 else 0
    patch = int(parts[2]) if len(parts) > 2 else 0
    return major, minor, patch
