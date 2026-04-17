"""Compatibility facade for the modular scanning subsystem."""

from __future__ import annotations

import asyncio
from collections import defaultdict
import logging
from typing import Awaitable, Callable
from urllib.parse import urlparse, urlunparse

import httpx

from app.core.config import settings
from app.services.crawler import AttackTarget
from app.services.scanning import http_client as scan_http_client
from app.services.scanning import Finding, ScanEngine
from app.services.scanning.context import get_scan_context, reset_scan_context, set_scan_context
from app.services.scanning.plugins import default_plugins
from app.services.scanning.plugins import sqli as sqli_plugin_module
from app.services.scanning.plugins import xss as xss_plugin_module

logger = logging.getLogger(__name__)
_PLUGIN_PATCH_LOCK = asyncio.Lock()


ProbeSender = Callable[
    [httpx.AsyncClient, AttackTarget, str, str],
    Awaitable[tuple[httpx.Response | None, float]],
]


def _canonical_endpoint(url: str) -> str:
    """Normalize endpoint identity for dedupe/caps across payload variants."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    hostname = (parsed.hostname or "").lower()

    default_port = 80 if scheme == "http" else 443 if scheme == "https" else None
    if parsed.port and parsed.port != default_port:
        netloc = f"{hostname}:{parsed.port}"
    else:
        netloc = hostname

    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"

    return urlunparse((scheme, netloc, path, "", "", ""))


class _ScanRequestController:
    """Controls probe volume and suppresses repeated redundant endpoint scans."""

    def __init__(self, base_send_probe: ProbeSender) -> None:
        self._base_send_probe = base_send_probe
        self._lock = asyncio.Lock()

        self.max_payloads_per_endpoint = max(1, int(getattr(settings, "scanner_max_payloads_per_endpoint", 8)))
        self.max_requests_per_endpoint = max(1, int(getattr(settings, "scanner_max_requests_per_endpoint", 40)))
        self.max_total_requests = max(1, int(getattr(settings, "scanner_max_total_requests", 500)))
        self.injection_delay_seconds = max(0.0, float(getattr(settings, "scanner_injection_delay_seconds", 0.1)))
        self.endpoint_failure_threshold = max(1, int(getattr(settings, "scanner_endpoint_failure_threshold", 3)))

        self._request_keys_seen: set[tuple[str, str, str]] = set()
        self._endpoint_payloads: dict[str, set[str]] = defaultdict(set)
        self._endpoint_request_count: dict[str, int] = defaultdict(int)
        self._total_request_count = 0

        self._post_disallowed_endpoints: set[str] = set()
        self._redirect_ignored_endpoints: set[tuple[str, str]] = set()
        self._failed_endpoints: set[str] = set()
        self._endpoint_failures: dict[str, int] = defaultdict(int)

    async def send_probe(
        self,
        client: httpx.AsyncClient,
        target: AttackTarget,
        parameter: str,
        payload: str,
    ) -> tuple[httpx.Response | None, float]:
        method, url, _ = scan_http_client.build_probe_request(target, parameter, payload)
        method = method.upper()
        endpoint = _canonical_endpoint(url)
        request_key = (endpoint, method, payload)

        async with self._lock:
            if self._total_request_count >= self.max_total_requests:
                logger.info(
                    "Probe skipped due to total request limit",
                    extra={
                        **get_scan_context(),
                        "url": endpoint,
                        "method": method,
                        "limit": self.max_total_requests,
                    },
                )
                return None, 0.0

            if endpoint in self._failed_endpoints:
                logger.info(
                    "Probe skipped due to endpoint failure suppression",
                    extra={**get_scan_context(), "url": endpoint, "method": method, "reason": "repeated failures"},
                )
                return None, 0.0

            if method == "POST" and endpoint in self._post_disallowed_endpoints:
                logger.info(
                    "Probe skipped due to method disallowed",
                    extra={
                        **get_scan_context(),
                        "url": endpoint,
                        "method": method,
                        "reason": "405 Method Not Allowed",
                    },
                )
                return None, 0.0

            if (method, endpoint) in self._redirect_ignored_endpoints:
                logger.info(
                    "Probe skipped due to redirect suppression",
                    extra={**get_scan_context(), "url": endpoint, "method": method},
                )
                return None, 0.0

            if request_key in self._request_keys_seen:
                logger.debug(
                    "Probe skipped due to duplication",
                    extra={**get_scan_context(), "url": endpoint, "method": method, "parameter": parameter},
                )
                return None, 0.0

            endpoint_payloads = self._endpoint_payloads[endpoint]
            if payload not in endpoint_payloads and len(endpoint_payloads) >= self.max_payloads_per_endpoint:
                logger.info(
                    "Probe skipped due to payload limit",
                    extra={
                        **get_scan_context(),
                        "url": endpoint,
                        "method": method,
                        "limit": self.max_payloads_per_endpoint,
                        "parameter": parameter,
                    },
                )
                return None, 0.0

            if self._endpoint_request_count[endpoint] >= self.max_requests_per_endpoint:
                logger.info(
                    "Probe skipped due to endpoint request cap",
                    extra={
                        **get_scan_context(),
                        "url": endpoint,
                        "method": method,
                        "limit": self.max_requests_per_endpoint,
                    },
                )
                return None, 0.0

            self._request_keys_seen.add(request_key)
            endpoint_payloads.add(payload)
            self._endpoint_request_count[endpoint] += 1
            self._total_request_count += 1

        if self.injection_delay_seconds > 0:
            await asyncio.sleep(self.injection_delay_seconds)

        response, elapsed = await self._base_send_probe(client, target, parameter, payload)

        async with self._lock:
            if response is None:
                self._endpoint_failures[endpoint] += 1
                if self._endpoint_failures[endpoint] >= self.endpoint_failure_threshold:
                    self._failed_endpoints.add(endpoint)
                    logger.warning(
                        "Endpoint ignored after repeated failure",
                        extra={
                            **get_scan_context(),
                            "url": endpoint,
                            "method": method,
                            "failures": self._endpoint_failures[endpoint],
                        },
                    )
                return None, elapsed

            # Successful response resets failure accumulation.
            self._endpoint_failures.pop(endpoint, None)

            if method == "POST" and response.status_code == 405:
                self._post_disallowed_endpoints.add(endpoint)
                logger.info(
                    "Endpoint marked POST-disallowed after 405",
                    extra={**get_scan_context(), "url": endpoint, "method": method},
                )

            if self._response_has_redirect(response):
                self._redirect_ignored_endpoints.add((method, endpoint))
                redirected_endpoint = _canonical_endpoint(str(response.url))
                self._redirect_ignored_endpoints.add((method, redirected_endpoint))
                logger.info(
                    "Endpoint redirect detected and suppressed",
                    extra={
                        **get_scan_context(),
                        "url": endpoint,
                        "method": method,
                        "redirected_to": redirected_endpoint,
                    },
                )

        return response, elapsed

    @staticmethod
    def _response_has_redirect(response: httpx.Response) -> bool:
        if response.status_code in {301, 302, 303, 307, 308}:
            return True
        return any(h.status_code in {301, 302, 303, 307, 308} for h in response.history)

def _normalise_targets(targets: list[AttackTarget] | dict[str, list[str]]) -> list[AttackTarget]:
    """Convert legacy dict input to attack targets for backwards compatibility."""
    if isinstance(targets, dict):
        source_targets = [
            AttackTarget(
                url=url,
                method="GET",
                params=tuple(params),
                content_type="query",
                source="legacy-query",
            )
            for url, params in targets.items()
        ]
    else:
        source_targets = targets

    deduped: list[AttackTarget] = []
    seen: set[tuple[str, str, tuple[str, ...], str]] = set()

    for target in source_targets:
        canonical_url = _canonical_endpoint(target.url)
        normalized_url = target.url.split("#", 1)[0]
        canonical_params = tuple(dict.fromkeys(target.params))
        key = (target.method.upper(), canonical_url, canonical_params, target.content_type)
        if key in seen:
            logger.debug(
                "Target skipped during normalization due to duplication",
                extra={"url": canonical_url, "method": target.method.upper()},
            )
            continue
        seen.add(key)
        deduped.append(
            AttackTarget(
                url=normalized_url,
                method=target.method,
                params=canonical_params,
                content_type=target.content_type,
                source=target.source,
            )
        )

    return deduped


async def scan_targets(
    targets: list[AttackTarget] | dict[str, list[str]],
    scan_id: int | None = None,
    target_url: str | None = None,
) -> list[Finding]:
    """Public scanner API used by routes; now backed by the modular engine."""
    normalised = _normalise_targets(targets)
    engine = ScanEngine(plugins=default_plugins(), max_concurrency=settings.scanner_max_concurrency)
    controller = _ScanRequestController(base_send_probe=scan_http_client.send_probe)

    original_xss_send_probe = xss_plugin_module.send_probe
    original_sqli_send_probe = sqli_plugin_module.send_probe

    tokens = set_scan_context(scan_id=scan_id, target_url=target_url)
    logger.info(
        "Starting scan",
        extra={"scan_id": scan_id, "target_url": target_url, "target_count": len(normalised)},
    )

    try:
        async with _PLUGIN_PATCH_LOCK:
            # Patch plugin probe sender for this scan run only.
            xss_plugin_module.send_probe = controller.send_probe
            sqli_plugin_module.send_probe = controller.send_probe
            findings = await engine.scan(normalised)
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "Scan orchestration failed",
            exc_info=exc,
            extra={"scan_id": scan_id, "target_url": target_url},
        )
        return []
    finally:
        xss_plugin_module.send_probe = original_xss_send_probe
        sqli_plugin_module.send_probe = original_sqli_send_probe
        reset_scan_context(tokens)

    logger.info(
        "Scan completed",
        extra={"scan_id": scan_id, "target_url": target_url, "finding_count": len(findings)},
    )
    return findings
