"""
Vulnerability scanner service.

Performs lightweight, non-destructive checks for:

  1. Reflected XSS — injects a harmless canary string into each GET parameter
     and checks whether it appears unescaped in the response HTML.
  2. SQL Injection — injects classic error-triggering payloads and looks for
     database-error keywords in the response.

All payloads are chosen to be *diagnostic only* — they do not modify data.
"""

import asyncio
from urllib.parse import urlencode, urljoin, urlparse, parse_qs, urlunparse

import httpx

from app.models.scan import Severity


# ---------------------------------------------------------------------------
# Payload definitions
# ---------------------------------------------------------------------------

# XSS: a canary string that will appear verbatim in the DOM if not escaped.
# Using a unique tag name reduces false positives.
XSS_PAYLOADS: list[tuple[str, str]] = [
    ("<scannertag>xsstest</scannertag>", "Reflected XSS canary tag"),
    ("'\"><scannertag>", "Reflected XSS quote-break canary"),
]

# SQLi: classic single-quote + boolean payloads that provoke DB errors.
SQLI_PAYLOADS: list[tuple[str, str]] = [
    ("'", "Single-quote SQLi probe"),
    ("1' OR '1'='1", "Boolean-based SQLi probe"),
    ("1; --", "Comment-based SQLi probe"),
]

# Keywords that appear in common database error messages.
SQLI_ERROR_SIGNATURES: list[str] = [
    "sql syntax",
    "syntax error",
    "mysql_fetch",
    "ora-01756",
    "sqlite3.operationalerror",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg::syntaxerror",
    "sqlexception",
]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


class Finding:
    """A single vulnerability finding."""

    def __init__(
        self,
        url: str,
        parameter: str,
        vuln_type: str,
        severity: Severity,
        detail: str,
    ) -> None:
        self.url = url
        self.parameter = parameter
        self.vuln_type = vuln_type
        self.severity = severity
        self.detail = detail


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def scan_targets(
    pages_with_params: dict[str, list[str]],
) -> list[Finding]:
    """
    Scan each URL+parameter combination for XSS and SQL injection.

    :param pages_with_params: Mapping of {url: [param_name, ...]} as returned
                              by the crawler.
    :return: List of Finding objects describing discovered vulnerabilities.
    """
    findings: list[Finding] = []

    async with httpx.AsyncClient(
        timeout=10,
        follow_redirects=True,
        headers={"User-Agent": "SecurityScanner/1.0 (educational use)"},
    ) as client:
        tasks = []
        for url, params in pages_with_params.items():
            for param in params:
                tasks.append(_test_parameter(client, url, param))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)

    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _test_parameter(
    client: httpx.AsyncClient, url: str, param: str
) -> list[Finding]:
    """Run all checks for a single URL + parameter combination."""
    findings: list[Finding] = []
    findings.extend(await _check_xss(client, url, param))
    findings.extend(await _check_sqli(client, url, param))
    return findings


def _inject_param(url: str, param: str, value: str) -> str:
    """
    Return a copy of *url* where *param*'s value has been replaced with *value*.

    Existing values for other parameters are preserved.
    """
    parsed = urlparse(url)
    existing = parse_qs(parsed.query, keep_blank_values=True)
    existing[param] = [value]
    new_query = urlencode(existing, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def _check_xss(
    client: httpx.AsyncClient, url: str, param: str
) -> list[Finding]:
    """
    Test *param* in *url* for reflected XSS.

    Strategy: inject a unique canary string and check whether it appears
    literally (unescaped) in the HTML response.
    """
    findings: list[Finding] = []

    for payload, description in XSS_PAYLOADS:
        test_url = _inject_param(url, param, payload)
        try:
            response = await client.get(test_url)
        except httpx.RequestError:
            continue

        body = response.text
        # The canary appears unescaped → likely reflected XSS
        if payload.lower() in body.lower():
            findings.append(
                Finding(
                    url=url,
                    parameter=param,
                    vuln_type="XSS",
                    severity=Severity.high,
                    detail=f"{description}: payload '{payload}' reflected in response.",
                )
            )
            # One confirmed finding per param is enough — stop testing more payloads
            break

    return findings


async def _check_sqli(
    client: httpx.AsyncClient, url: str, param: str
) -> list[Finding]:
    """
    Test *param* in *url* for SQL injection via error-based detection.

    Strategy: inject payloads that commonly trigger DB error messages, then
    look for those error strings in the response body.
    """
    findings: list[Finding] = []

    for payload, description in SQLI_PAYLOADS:
        test_url = _inject_param(url, param, payload)
        try:
            response = await client.get(test_url)
        except httpx.RequestError:
            continue

        body_lower = response.text.lower()
        for signature in SQLI_ERROR_SIGNATURES:
            if signature in body_lower:
                findings.append(
                    Finding(
                        url=url,
                        parameter=param,
                        vuln_type="SQLi",
                        severity=Severity.high,
                        detail=(
                            f"{description}: error signature '{signature}' "
                            f"found in response after injecting payload '{payload}'."
                        ),
                    )
                )
                return findings  # Stop at first confirmed SQLi for this param

    return findings
