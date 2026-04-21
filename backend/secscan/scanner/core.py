"""Scanner core with async queue-based check execution."""

from __future__ import annotations

import asyncio
import logging
from typing import Iterable
from urllib.parse import urlparse

import httpx

from backend.secscan.checks import default_checks
from backend.secscan.checks.base import CheckScope, ScanContext, SecurityCheck
from backend.secscan.utils.config import ScanConfig
from backend.secscan.utils.http import AsyncRateLimiter, make_client
from backend.secscan.utils.models import Endpoint, Finding

logger = logging.getLogger(__name__)


class ScannerCore:
    """Runs passive and light-active checks against discovered endpoints."""

    def __init__(self, config: ScanConfig, checks: list[SecurityCheck] | None = None) -> None:
        self.config = config
        self.checks = checks or default_checks()
        self._rate_limiter = AsyncRateLimiter(config.rate_limit)

    async def scan(self, endpoints: list[Endpoint], context: ScanContext) -> list[Finding]:
        """Execute check plugins across endpoints in parallel."""
        deduped_endpoints = _dedupe_endpoints(endpoints)
        if not deduped_endpoints:
            return []

        passive_checks = [check for check in self.checks if getattr(check, "passive", False)]
        active_checks = [check for check in self.checks if not getattr(check, "passive", False)]

        async with make_client(self.config.request_timeout) as client:
            findings: list[Finding] = []
            findings.extend(await self._run_phase(client, passive_checks, deduped_endpoints, context))
            findings.extend(await self._run_phase(client, active_checks, deduped_endpoints, context))

        unique_findings = _dedupe_findings(findings)
        logger.info(
            "Scanner finished",
            extra={"findings": len(unique_findings), "endpoints": len(deduped_endpoints)},
        )
        return unique_findings

    async def _run_phase(
        self,
        client: httpx.AsyncClient,
        checks: list[SecurityCheck],
        endpoints: list[Endpoint],
        context: ScanContext,
    ) -> list[Finding]:
        if not checks:
            return []

        queue: asyncio.Queue[tuple[SecurityCheck, Endpoint]] = asyncio.Queue()
        findings: list[Finding] = []
        lock = asyncio.Lock()
        scheduled: set[tuple[str, str]] = set()

        for endpoint in endpoints:
            for check in checks:
                job_key = _build_job_key(check, endpoint)
                key = (check.name, job_key)
                if key in scheduled:
                    continue
                scheduled.add(key)
                queue.put_nowait((check, endpoint))

        workers = [
            asyncio.create_task(self._worker(queue, client, context, findings, lock))
            for _ in range(max(1, self.config.threads))
        ]

        await queue.join()

        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        return findings

    async def _worker(
        self,
        queue: asyncio.Queue[tuple[SecurityCheck, Endpoint]],
        client,
        context: ScanContext,
        findings: list[Finding],
        lock: asyncio.Lock,
    ) -> None:
        while True:
            check, endpoint = await queue.get()
            try:
                await self._rate_limiter.acquire()
                check_findings = await check.run(client, endpoint, context)
                if check_findings:
                    async with lock:
                        findings.extend(check_findings)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Check failed", extra={"check": getattr(check, "name", "unknown"), "url": endpoint.url, "error": str(exc)})
            finally:
                queue.task_done()


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str]] = set()
    output: list[Finding] = []

    for finding in findings:
        key = (finding.url, finding.issue_type, finding.check_name, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        output.append(finding)

    return output


def _dedupe_endpoints(endpoints: Iterable[Endpoint]) -> list[Endpoint]:
    seen: set[tuple[str, str, tuple[str, ...], str]] = set()
    output: list[Endpoint] = []

    for endpoint in endpoints:
        key = (endpoint.url, endpoint.method.upper(), endpoint.params, endpoint.content_type)
        if key in seen:
            continue
        seen.add(key)
        output.append(endpoint)

    return output


def _build_job_key(check: SecurityCheck, endpoint: Endpoint) -> str:
    scope = getattr(check, "scope", CheckScope.endpoint)

    if scope == CheckScope.global_run:
        return "global"

    if scope == CheckScope.host:
        parsed = urlparse(endpoint.url)
        host = (parsed.hostname or "").lower()
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        return f"{parsed.scheme.lower()}://{host}:{port}"

    return f"{endpoint.method.upper()} {endpoint.url} {endpoint.content_type} {'|'.join(endpoint.params)}"
