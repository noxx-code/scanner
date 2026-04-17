"""SQL injection scanner plugin (error-based + basic time-based checks)."""

from __future__ import annotations

import logging

import httpx

from app.core.config import settings
from app.models.scan import Severity
from app.services.crawler import AttackTarget
from app.services.scanning.contracts import Finding, ScannerPlugin
from app.services.scanning.http_client import send_probe

logger = logging.getLogger(__name__)

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


class SqliPlugin(ScannerPlugin):
    """Performs SQLi probes and signature/latency-based checks."""

    name = "sqli"

    async def run(
        self,
        client: httpx.AsyncClient,
        target: AttackTarget,
        parameter: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        _, baseline_elapsed = await send_probe(client, target, parameter, "1")

        for payload, description in SQLI_PAYLOADS:
            response, _ = await send_probe(client, target, parameter, payload)
            if response is None:
                continue

            body_lower = response.text.lower()
            for signature in SQLI_ERROR_SIGNATURES:
                if signature in body_lower:
                    findings.append(
                        Finding(
                            url=target.url,
                            parameter=parameter,
                            vuln_type="SQLi",
                            severity=Severity.high,
                            detail=(
                                f"{description}: error signature '{signature}' found after payload injection. "
                                f"surface={target.content_type} method={target.method} source={target.source}."
                            ),
                        )
                    )
                    logger.info(
                        "Potential SQLi detected (error-based)",
                        extra={
                            "plugin": self.name,
                            "target_url": target.url,
                            "parameter": parameter,
                            "signature": signature,
                        },
                    )
                    return findings

        for payload, description, expected_delay in SQLI_TIME_PAYLOADS:
            response, elapsed = await send_probe(client, target, parameter, payload)
            if response is None:
                continue

            threshold = min(expected_delay * 0.6, settings.sqli_time_threshold_seconds)
            if elapsed - baseline_elapsed >= threshold:
                findings.append(
                    Finding(
                        url=target.url,
                        parameter=parameter,
                        vuln_type="SQLi",
                        severity=Severity.medium,
                        detail=(
                            f"{description}: potential time-based SQLi. "
                            f"baseline={baseline_elapsed:.2f}s probe={elapsed:.2f}s "
                            f"surface={target.content_type} method={target.method} source={target.source}."
                        ),
                    )
                )
                logger.info(
                    "Potential SQLi detected (time-based)",
                    extra={
                        "plugin": self.name,
                        "target_url": target.url,
                        "parameter": parameter,
                        "elapsed": f"{elapsed:.2f}",
                    },
                )
                return findings

        return findings
