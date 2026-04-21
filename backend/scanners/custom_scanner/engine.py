"""
Custom Scanner - simple vulnerability scanner.
Performs basic input validation and vulnerability checks.
"""

import re
import time
import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs
import asyncio

try:
    import httpx
except ImportError:
    httpx = None

from backend.scanners.base import BaseScanner, ScanResult, Finding

logger = logging.getLogger(__name__)


class CustomScanner(BaseScanner):
    """Simplified custom vulnerability scanner."""

    def __init__(self, timeout: int = 10):
        """Initialize custom scanner.

        Args:
            timeout: HTTP request timeout in seconds
        """
        super().__init__("custom_scanner")
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
                # Run vulnerability checks
                findings.extend(await self._check_xss(client, target))
                findings.extend(await self._check_sqli(client, target))
                findings.extend(await self._check_path_traversal(client, target))
                findings.extend(await self._check_open_redirect(client, target))

        except asyncio.TimeoutError:
            return self._create_result(
                target,
                status="failed",
                duration=time.time() - start_time,
                error="Scan timeout",
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

    async def _check_xss(
        self, client: "httpx.AsyncClient", target: str
    ) -> List[Finding]:
        """Check for XSS vulnerabilities."""
        findings: List[Finding] = []

        # Check if URL has query parameters
        parsed = urlparse(target)
        if not parsed.query:
            return findings

        params = parse_qs(parsed.query)

        # Test each parameter
        for param_name in params.keys():
            test_payload = f"<script>alert('xss')</script>"
            test_url = f"{target}&{param_name}={test_payload}"

            try:
                response = await client.get(test_url)

                # Check if payload is reflected
                if test_payload in response.text:
                    findings.append(
                        Finding(
                            title="Potential XSS Vulnerability",
                            description=f"Parameter '{param_name}' reflects user input",
                            severity="high",
                            type="xss",
                            url=test_url,
                            parameter=param_name,
                            evidence="Payload reflected in response",
                        )
                    )
            except Exception as e:
                logger.debug(f"XSS check error: {e}")

        return findings

    async def _check_sqli(
        self, client: "httpx.AsyncClient", target: str
    ) -> List[Finding]:
        """Check for SQL injection vulnerabilities."""
        findings: List[Finding] = []

        sql_patterns = [
            r"SQL.*syntax",
            r"mysql_fetch",
            r"Warning: mysql",
            r"ORA-\d+",
            r"PostgreSQL.*error",
        ]

        test_payloads = [
            "' OR '1'='1",
            "1' UNION SELECT NULL--",
            "1' AND '1'='1",
        ]

        # Test with payloads
        for payload in test_payloads:
            test_url = f"{target}{'&' if '?' in target else '?'}id={payload}"

            try:
                response = await client.get(test_url)

                # Check for SQL error messages
                for pattern in sql_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        findings.append(
                            Finding(
                                title="Potential SQL Injection",
                                description="Response contains SQL error message",
                                severity="high",
                                type="sqli",
                                url=test_url,
                                evidence="SQL error detected in response",
                            )
                        )
                        break
            except Exception as e:
                logger.debug(f"SQLi check error: {e}")

        return findings

    async def _check_path_traversal(
        self, client: "httpx.AsyncClient", target: str
    ) -> List[Finding]:
        """Check for path traversal vulnerabilities."""
        findings: List[Finding] = []

        traversal_payloads = [
            "../../etc/passwd",
            "..\\..\\windows\\win.ini",
            "....//....//etc/passwd",
        ]

        for payload in traversal_payloads:
            test_url = f"{target}{'&' if '?' in target else '?'}file={payload}"

            try:
                response = await client.get(test_url)

                # Check for file content
                if "root:" in response.text or "[boot loader]" in response.text:
                    findings.append(
                        Finding(
                            title="Path Traversal Vulnerability",
                            description="Server appears to expose local files",
                            severity="high",
                            type="path-traversal",
                            url=test_url,
                            evidence="File content detected in response",
                        )
                    )
                    break
            except Exception as e:
                logger.debug(f"Path traversal check error: {e}")

        return findings

    async def _check_open_redirect(
        self, client: "httpx.AsyncClient", target: str
    ) -> List[Finding]:
        """Check for open redirect vulnerabilities."""
        findings: List[Finding] = []

        redirect_payload = "http://attacker.com"
        test_url = f"{target}{'&' if '?' in target else '?'}redirect={redirect_payload}"

        try:
            response = await client.get(test_url, follow_redirects=False)

            # Check if redirects to external URL
            location = response.headers.get("Location", "")
            if "attacker.com" in location:
                findings.append(
                    Finding(
                        title="Open Redirect Vulnerability",
                        description="Server redirects to external URL",
                        severity="medium",
                        type="open-redirect",
                        url=test_url,
                        evidence=f"Redirects to: {location}",
                    )
                )
        except Exception as e:
            logger.debug(f"Open redirect check error: {e}")

        return findings
