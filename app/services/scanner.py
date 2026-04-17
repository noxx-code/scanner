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
import time
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx

from app.core.config import settings
from app.models.scan import Severity
from app.services.crawler import AttackTarget


# ---------------------------------------------------------------------------
# Payload definitions
# ---------------------------------------------------------------------------

# XSS: a canary string that will appear verbatim in the DOM if not escaped.
# Using a unique tag name reduces false positives.
XSS_PAYLOADS: list[tuple[str, str]] = [
    ("<scannertag>xsstest</scannertag>", "Reflected XSS canary tag"),
    ("'\"><scannertag>", "Reflected XSS quote-break canary"),
    ("<img src=x onerror=alert('xss')>", "HTML attribute injection probe"),
    ("<svg/onload=alert('xss')>", "SVG onload probe"),
    ("</script><script>alert('xss')</script>", "Script context break-out probe"),
]

# SQLi: classic single-quote + boolean payloads that provoke DB errors.
SQLI_PAYLOADS: list[tuple[str, str]] = [
    ("'", "Single-quote SQLi probe"),
    ("1' OR '1'='1", "Boolean-based SQLi probe"),
    ("1; --", "Comment-based SQLi probe"),
    ("' OR 1=1--", "Classic auth bypass style probe"),
    ("') OR ('1'='1", "Parenthesis balance probe"),
]

SQLI_TIME_PAYLOADS: list[tuple[str, str, float]] = [
    ("1' OR SLEEP(5)--", "MySQL time-based probe", 5.0),
    ("1'; WAITFOR DELAY '0:0:5'--", "MSSQL time-based probe", 5.0),
    ("1' OR pg_sleep(5)--", "PostgreSQL time-based probe", 5.0),
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
    "you have an error in your sql syntax",
    "sqlstate",
    "pdoexception",
    "database error",
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
    targets: list[AttackTarget] | dict[str, list[str]],
) -> list[Finding]:
    """
    Scan each URL+parameter combination for XSS and SQL injection.

    :param targets: List of AttackTarget objects discovered by crawler.
                    Legacy dict input is still supported for compatibility.
    :return: List of Finding objects describing discovered vulnerabilities.
    """
    findings: list[Finding] = []

    prepared_targets = _normalise_targets(targets)

    async with httpx.AsyncClient(
        timeout=settings.scanner_timeout,
        follow_redirects=True,
        headers={"User-Agent": "SecurityScanner/1.0 (educational use)"},
    ) as client:
        tasks = []
        for target in prepared_targets:
            for param in target.params:
                tasks.append(_test_parameter(client, target, param))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)

    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _test_parameter(
    client: httpx.AsyncClient, target: AttackTarget, param: str
) -> list[Finding]:
    """Run all checks for a single URL + parameter combination."""
    findings: list[Finding] = []
    findings.extend(await _check_xss(client, target, param))
    findings.extend(await _check_sqli(client, target, param))
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


def _normalise_targets(targets: list[AttackTarget] | dict[str, list[str]]) -> list[AttackTarget]:
    """Convert legacy crawler output to rich attack targets when needed."""
    if isinstance(targets, dict):
        return [
            AttackTarget(
                url=url,
                method="GET",
                params=tuple(params),
                content_type="query",
                source="legacy-query",
            )
            for url, params in targets.items()
        ]
    return targets


def _build_base_payload(target: AttackTarget) -> dict[str, str]:
    """Create a baseline payload map with neutral values for all params."""
    return {name: "1" for name in target.params}


def _build_probe_request(
    target: AttackTarget,
    param: str,
    payload: str,
) -> tuple[str, str, dict[str, dict[str, str]]]:
    """Build request method/url/kwargs based on target content type."""
    method = target.method.upper()
    base_payload = _build_base_payload(target)
    base_payload[param] = payload

    if target.content_type == "query" or method == "GET":
        if target.content_type == "query":
            url = _inject_param(target.url, param, payload)
            return method, url, {}
        return method, target.url, {"params": base_payload}

    if target.content_type == "json":
        return method, target.url, {"json": base_payload}

    return method, target.url, {"data": base_payload}


async def _send_probe(
    client: httpx.AsyncClient,
    target: AttackTarget,
    param: str,
    payload: str,
) -> tuple[httpx.Response | None, float]:
    """Send one probe and return (response, elapsed_seconds)."""
    method, url, kwargs = _build_probe_request(target, param, payload)
    started = time.perf_counter()
    try:
        response = await client.request(method, url, **kwargs)
    except httpx.RequestError:
        return None, 0.0
    elapsed = time.perf_counter() - started
    return response, elapsed


async def _check_xss(
    client: httpx.AsyncClient, target: AttackTarget, param: str
) -> list[Finding]:
    """
    Test *param* in *url* for reflected XSS.

    Strategy: inject a unique canary string and check whether it appears
    literally (unescaped) in the HTML response.
    """
    findings: list[Finding] = []

    for payload, description in XSS_PAYLOADS:
        response, _ = await _send_probe(client, target, param, payload)
        if response is None:
            continue

        body = response.text
        # The canary appears unescaped → likely reflected XSS
        if payload.lower() in body.lower():
            findings.append(
                Finding(
                    url=target.url,
                    parameter=param,
                    vuln_type="XSS",
                    severity=Severity.high,
                    detail=(
                        f"{description}: payload reflected in response. "
                        f"surface={target.content_type} method={target.method} source={target.source}."
                    ),
                )
            )
            # One confirmed finding per param is enough — stop testing more payloads
            break

    return findings


async def _check_sqli(
    client: httpx.AsyncClient, target: AttackTarget, param: str
) -> list[Finding]:
    """
    Test *param* in *url* for SQL injection via error-based detection.

    Strategy: inject payloads that commonly trigger DB error messages, then
    look for those error strings in the response body. Also perform a basic
    time-based check using common database delay functions.
    """
    findings: list[Finding] = []

    # Baseline latency for this target/parameter pair.
    _, baseline_elapsed = await _send_probe(client, target, param, "1")

    for payload, description in SQLI_PAYLOADS:
        response, _ = await _send_probe(client, target, param, payload)
        if response is None:
            continue

        body_lower = response.text.lower()
        for signature in SQLI_ERROR_SIGNATURES:
            if signature in body_lower:
                findings.append(
                    Finding(
                        url=target.url,
                        parameter=param,
                        vuln_type="SQLi",
                        severity=Severity.high,
                        detail=(
                            f"{description}: error signature '{signature}' "
                            f"found after payload injection. "
                            f"surface={target.content_type} method={target.method} source={target.source}."
                        ),
                    )
                )
                return findings  # Stop at first confirmed SQLi for this param

    # Time-based SQLi check.
    for payload, description, expected_delay in SQLI_TIME_PAYLOADS:
        response, elapsed = await _send_probe(client, target, param, payload)
        if response is None:
            continue

        if elapsed - baseline_elapsed >= min(expected_delay * 0.6, settings.sqli_time_threshold_seconds):
            findings.append(
                Finding(
                    url=target.url,
                    parameter=param,
                    vuln_type="SQLi",
                    severity=Severity.medium,
                    detail=(
                        f"{description}: potential time-based SQLi. "
                        f"baseline={baseline_elapsed:.2f}s probe={elapsed:.2f}s "
                        f"surface={target.content_type} method={target.method} source={target.source}."
                    ),
                )
            )
            return findings

    return findings
