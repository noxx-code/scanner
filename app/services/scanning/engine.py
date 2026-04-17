"""Scanning engine that orchestrates plugin execution safely."""

from __future__ import annotations

import asyncio
import logging

import httpx

from app.core.config import settings
from app.services.crawler import AttackTarget
from app.services.scanning.contracts import Finding, ScannerPlugin
from app.services.scanning.context import get_scan_context

logger = logging.getLogger(__name__)


class ScanEngine:
    """Coordinates scanning over targets with pluggable checks."""

    def __init__(
        self,
        plugins: list[ScannerPlugin],
        max_concurrency: int = 30,
    ) -> None:
        self._plugins = plugins
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def scan(self, targets: list[AttackTarget]) -> list[Finding]:
        """Run all plugins across all target/parameter combinations."""
        findings: list[Finding] = []
        if not targets:
            return findings

        logger.info("Scan engine started", extra={**get_scan_context(), "targets": len(targets)})

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.scanner_timeout),
            follow_redirects=True,
            headers={"User-Agent": "SecurityScanner/1.0 (educational use)"},
        ) as client:
            tasks = [
                self._scan_target_parameter(client, target, parameter)
                for target in targets
                for parameter in target.params
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.exception("Target scan task failed", exc_info=result, extra=get_scan_context())
                continue
            findings.extend(result)

        logger.info("Scan engine completed", extra={**get_scan_context(), "findings": len(findings)})
        return findings

    async def _scan_target_parameter(
        self,
        client: httpx.AsyncClient,
        target: AttackTarget,
        parameter: str,
    ) -> list[Finding]:
        """Run all plugins for one parameter, isolating plugin failures."""
        findings: list[Finding] = []

        async with self._semaphore:
            logger.debug(
                "Scanning target parameter",
                extra={**get_scan_context(), "url": target.url, "parameter": parameter},
            )
            for plugin in self._plugins:
                try:
                    plugin_findings = await plugin.run(client, target, parameter)
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "Plugin failed for target parameter",
                        exc_info=exc,
                        extra={
                            **get_scan_context(),
                            "plugin": plugin.name,
                            "target_url": target.url,
                            "parameter": parameter,
                        },
                    )
                    continue

                if plugin_findings:
                    findings.extend(plugin_findings)

        return findings
