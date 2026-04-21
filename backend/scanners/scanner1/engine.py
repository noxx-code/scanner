"""
Simplified Python-based template scanner (Scanner1).
Loads templates and performs basic HTTP vulnerability scanning.
"""

import re
import time
import logging
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse
import asyncio

try:
    import httpx
except ImportError:
    httpx = None

from backend.scanners.base import BaseScanner, ScanResult, Finding

logger = logging.getLogger(__name__)

# Default templates directory
TEMPLATES_DIR = Path(__file__).parent / "templates"


class Scanner1(BaseScanner):
    """Simplified Python implementation of template-based vulnerability scanner."""

    def __init__(self, templates_dir: Optional[Path] = None, timeout: int = 10):
        """Initialize Scanner1.

        Args:
            templates_dir: Directory containing YAML templates
            timeout: HTTP request timeout in seconds
        """
        super().__init__("scanner1")
        self.templates_dir = templates_dir or TEMPLATES_DIR
        self.timeout = timeout
        self.templates: Dict[str, Dict] = {}
        self._load_templates()

    def _load_templates(self) -> None:
        """Load all templates from YAML files."""
        if not self.templates_dir.exists():
            logger.warning(f"Templates directory not found: {self.templates_dir}")
            return

        for template_file in self.templates_dir.glob("*.yaml"):
            try:
                with open(template_file) as f:
                    template = yaml.safe_load(f)
                    if template and "id" in template:
                        self.templates[template["id"]] = template
                        logger.debug(f"Loaded template: {template['id']}")
            except Exception as e:
                logger.error(f"Failed to load template {template_file}: {e}")

        logger.info(f"Loaded {len(self.templates)} templates")

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
            **kwargs: Additional options (templates, timeout, etc)

        Returns:
            ScanResult with findings
        """
        if not self.validate_target(target):
            return self._create_result(
                target,
                status="failed",
                error=f"Invalid target format: {target}",
            )

        if not httpx:
            return self._create_result(
                target,
                status="failed",
                error="httpx not installed. Install with: pip install httpx",
            )

        start_time = time.time()
        findings: List[Finding] = []

        try:
            # Run specified templates or all templates
            template_ids = kwargs.get("templates") or list(self.templates.keys())

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                for template_id in template_ids:
                    if template_id not in self.templates:
                        logger.debug(f"Template not found: {template_id}")
                        continue

                    template = self.templates[template_id]
                    template_findings = await self._run_template(
                        client, target, template
                    )
                    findings.extend(template_findings)

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

    async def _run_template(
        self, client: "httpx.AsyncClient", target: str, template: Dict
    ) -> List[Finding]:
        """
        Execute a single template against target.

        Args:
            client: HTTP client
            target: Target URL
            template: Template configuration

        Returns:
            List of findings
        """
        findings: List[Finding] = []

        try:
            # Get requests from template
            requests = template.get("requests", [])
            if not isinstance(requests, list):
                requests = [requests]

            for req in requests:
                req_findings = await self._execute_request(
                    client, target, template, req
                )
                findings.extend(req_findings)

        except Exception as e:
            logger.debug(f"Template execution error: {e}")

        return findings

    async def _execute_request(
        self,
        client: "httpx.AsyncClient",
        target: str,
        template: Dict,
        request: Dict,
    ) -> List[Finding]:
        """
        Execute a single HTTP request and check for matches.

        Args:
            client: HTTP client
            target: Target URL
            template: Template definition
            request: Request configuration

        Returns:
            List of findings
        """
        findings: List[Finding] = []

        try:
            # Build request URL
            path = request.get("path", "/")
            url = urljoin(target, path)

            # Prepare request
            method = request.get("method", "GET").upper()
            headers = request.get("headers", {})
            body = request.get("body")
            params = request.get("params", {})

            # Execute request
            response = await client.request(
                method,
                url,
                headers=headers,
                content=body,
                params=params,
            )

            # Check matchers
            matchers = request.get("matchers", [])
            if not matchers:
                matchers = template.get("matchers", [])

            if not isinstance(matchers, list):
                matchers = [matchers]

            # Evaluate matchers
            for matcher in matchers:
                if self._evaluate_matcher(response, matcher, template):
                    findings.append(
                        Finding(
                            title=template.get("name", "Unknown Vulnerability"),
                            description=template.get("description", ""),
                            severity=template.get("severity", "medium").lower(),
                            type=template.get("id", "unknown"),
                            url=url,
                            evidence=response.text[:500] if response.text else None,
                            metadata={
                                "status_code": response.status_code,
                                "request_method": method,
                                "template_id": template.get("id"),
                            },
                        )
                    )

        except Exception as e:
            logger.debug(f"Request execution error: {e}")

        return findings

    def _evaluate_matcher(
        self, response: "httpx.Response", matcher: Dict, template: Dict
    ) -> bool:
        """
        Evaluate if response matches the matcher criteria.

        Args:
            response: HTTP response
            matcher: Matcher configuration
            template: Template (for context)

        Returns:
            True if matches, False otherwise
        """
        try:
            # Status code matcher
            if "status" in matcher:
                expected_statuses = (
                    matcher["status"]
                    if isinstance(matcher["status"], list)
                    else [matcher["status"]]
                )
                if response.status_code not in expected_statuses:
                    return False

            # Keyword matcher
            if "keywords" in matcher:
                keywords = (
                    matcher["keywords"]
                    if isinstance(matcher["keywords"], list)
                    else [matcher["keywords"]]
                )
                text = response.text.lower()
                for keyword in keywords:
                    if keyword.lower() not in text:
                        return False

            # Regex matcher
            if "regex" in matcher:
                patterns = (
                    matcher["regex"]
                    if isinstance(matcher["regex"], list)
                    else [matcher["regex"]]
                )
                for pattern in patterns:
                    if not re.search(pattern, response.text, re.IGNORECASE):
                        return False

            # Header matcher
            if "headers" in matcher:
                for header_name, header_value in matcher["headers"].items():
                    if response.headers.get(header_name) != header_value:
                        return False

            return True

        except Exception as e:
            logger.debug(f"Matcher evaluation error: {e}")
            return False
