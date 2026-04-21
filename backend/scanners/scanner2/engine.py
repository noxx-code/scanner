"""
Refactored Scanner2 - unified interface version.
Implements basic web application security checks.
"""

import re
import time
import logging
import ssl
import socket
from typing import Dict, List, Optional
from urllib.parse import urlparse
import asyncio

try:
    import httpx
except ImportError:
    httpx = None

from backend.scanners.base import BaseScanner, ScanResult, Finding

logger = logging.getLogger(__name__)


class Scanner2(BaseScanner):
    """Simplified security audit implementation with unified interface."""

    def __init__(self, timeout: int = 10):
        """Initialize Scanner2.

        Args:
            timeout: HTTP request timeout in seconds
        """
        super().__init__("scanner2")
        self.timeout = timeout

    def validate_target(self, target: str) -> bool:
        """Validate if target is a valid URL."""
        try:
            result = urlparse(target)
            return all([result.scheme in ("http", "https"), result.netloc])
        except:
            return False

    async def run(self, target: str, **kwargs) -> ScanResult:
        """
        Execute scan on target.

        Args:
            target: Target URL to scan
            **kwargs: Additional options

        Returns:
            ScanResult with findings
        """
        if not self.validate_target(target):
            return self._create_result(
                target,
                status="failed",
                error=f"Invalid target: {target}",
            )

        if not httpx:
            return self._create_result(
                target,
                status="failed",
                error="httpx not installed",
            )

        start_time = time.time()
        findings: List[Finding] = []

        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                # Run all checks
                findings.extend(await self._check_security_headers(client, target))
                findings.extend(await self._check_ssl_tls(target))
                findings.extend(await self._check_cookies(client, target))
                findings.extend(await self._check_framework_disclosure(client, target))
                findings.extend(
                    await self._check_common_vulnerabilities(client, target)
                )

        except Exception as e:
            logger.error(f"Scan error: {e}")
            return self._create_result(
                target,
                status="failed",
                duration=time.time() - start_time,
                error=str(e),
            )

        return self._create_result(
            target,
            findings=findings,
            status="success" if findings else "partial",
            duration=time.time() - start_time,
        )

    async def _check_security_headers(
        self, client: "httpx.AsyncClient", target: str
    ) -> List[Finding]:
        """Check for missing security headers."""
        findings: List[Finding] = []

        required_headers = {
            "X-Frame-Options": "Clickjacking protection",
            "X-Content-Type-Options": "MIME type sniffing protection",
            "Strict-Transport-Security": "HTTPS enforcement",
            "Content-Security-Policy": "XSS protection",
        }

        try:
            response = await client.get(target)

            for header, description in required_headers.items():
                if header not in response.headers:
                    findings.append(
                        Finding(
                            title=f"Missing Security Header: {header}",
                            description=description,
                            severity="medium",
                            type="missing-header",
                            url=target,
                            evidence=f"Header '{header}' not found in response",
                        )
                    )
        except Exception as e:
            logger.debug(f"Header check error: {e}")

        return findings

    async def _check_ssl_tls(self, target: str) -> List[Finding]:
        """Check SSL/TLS configuration."""
        findings: List[Finding] = []

        try:
            hostname = urlparse(target).netloc.split(":")[0]

            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()

                    # Check weak protocols
                    if version in ("SSLv2", "SSLv3", "TLSv1.0"):
                        findings.append(
                            Finding(
                                title=f"Weak SSL/TLS Version: {version}",
                                description="Using outdated SSL/TLS protocol",
                                severity="high",
                                type="weak-ssl",
                                url=target,
                                evidence=version,
                            )
                        )
        except Exception as e:
            logger.debug(f"SSL/TLS check error: {e}")

        return findings

    async def _check_cookies(
        self, client: "httpx.AsyncClient", target: str
    ) -> List[Finding]:
        """Check cookie security."""
        findings: List[Finding] = []

        try:
            response = await client.get(target)

            for cookie_header in response.headers.get_list("Set-Cookie"):
                # Check for secure flag
                if "secure" not in cookie_header.lower() and target.startswith(
                    "https"
                ):
                    findings.append(
                        Finding(
                            title="Insecure Cookie: Missing Secure Flag",
                            description="Cookie transmitted over secure channel without Secure flag",
                            severity="medium",
                            type="insecure-cookie",
                            url=target,
                            evidence=cookie_header[:100],
                        )
                    )

                # Check for HttpOnly flag
                if "httponly" not in cookie_header.lower():
                    findings.append(
                        Finding(
                            title="Insecure Cookie: Missing HttpOnly Flag",
                            description="Cookie accessible to JavaScript (XSS risk)",
                            severity="medium",
                            type="insecure-cookie",
                            url=target,
                            evidence=cookie_header[:100],
                        )
                    )
        except Exception as e:
            logger.debug(f"Cookie check error: {e}")

        return findings

    async def _check_framework_disclosure(
        self, client: "httpx.AsyncClient", target: str
    ) -> List[Finding]:
        """Check for framework/technology disclosure."""
        findings: List[Finding] = []

        disclosure_patterns = {
            "Django": r"django",
            "Flask": r"werkzeug",
            "PHP": r"X-Powered-By:.*php",
            "ASP.NET": r"X-AspNet-Version",
            "Java": r"X-Powered-By:.*java",
        }

        try:
            response = await client.get(target)
            headers_text = "\n".join(
                f"{k}: {v}" for k, v in response.headers.items()
            )
            body = response.text.lower()

            for framework, pattern in disclosure_patterns.items():
                if re.search(pattern, headers_text, re.IGNORECASE) or re.search(
                    pattern, body, re.IGNORECASE
                ):
                    findings.append(
                        Finding(
                            title=f"Technology Disclosure: {framework}",
                            description=f"Application reveals use of {framework}",
                            severity="low",
                            type="disclosure",
                            url=target,
                        )
                    )
        except Exception as e:
            logger.debug(f"Disclosure check error: {e}")

        return findings

    async def _check_common_vulnerabilities(
        self, client: "httpx.AsyncClient", target: str
    ) -> List[Finding]:
        """Check for common vulnerabilities."""
        findings: List[Finding] = []

        checks = {
            "/admin": "Potential admin panel",
            "/config": "Potential configuration file",
            "/.git": "Exposed .git directory",
            "/.env": "Exposed environment file",
        }

        for path, description in checks.items():
            try:
                response = await client.get(target + path)
                if response.status_code in (200, 301, 302):
                    findings.append(
                        Finding(
                            title=f"Potentially Exposed Path: {path}",
                            description=description,
                            severity="medium",
                            type="exposed-path",
                            url=target + path,
                            evidence=str(response.status_code),
                        )
                    )
            except Exception as e:
                logger.debug(f"Vulnerability check error for {path}: {e}")

        return findings
