"""Compatibility facade for the modular scanning subsystem."""

from __future__ import annotations

import logging

from app.services.crawler import AttackTarget
from app.services.scanning import Finding, ScanEngine
from app.services.scanning.context import reset_scan_context, set_scan_context
from app.services.scanning.plugins import default_plugins

logger = logging.getLogger(__name__)


def _normalise_targets(targets: list[AttackTarget] | dict[str, list[str]]) -> list[AttackTarget]:
    """Convert legacy dict input to attack targets for backwards compatibility."""
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


async def scan_targets(
    targets: list[AttackTarget] | dict[str, list[str]],
    scan_id: int | None = None,
    target_url: str | None = None,
) -> list[Finding]:
    """Public scanner API used by routes; now backed by the modular engine."""
    normalised = _normalise_targets(targets)
    engine = ScanEngine(plugins=default_plugins())

    tokens = set_scan_context(scan_id=scan_id, target_url=target_url)
    logger.info(
        "Starting scan",
        extra={"scan_id": scan_id, "target_url": target_url, "target_count": len(normalised)},
    )

    try:
        findings = await engine.scan(normalised)
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "Scan orchestration failed",
            exc_info=exc,
            extra={"scan_id": scan_id, "target_url": target_url},
        )
        return []
    finally:
        reset_scan_context(tokens)

    logger.info(
        "Scan completed",
        extra={"scan_id": scan_id, "target_url": target_url, "finding_count": len(findings)},
    )
    return findings
