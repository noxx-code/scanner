"""Contracts and shared types for the scanning engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx

from app.models.scan import Severity
from app.services.crawler import AttackTarget


@dataclass(slots=True)
class Finding:
    """A single vulnerability finding returned by a scanner plugin."""

    url: str
    parameter: str
    vuln_type: str
    severity: Severity
    detail: str


class ScannerPlugin(Protocol):
    """Contract implemented by all vulnerability-check plugins."""

    name: str

    async def run(
        self,
        client: httpx.AsyncClient,
        target: AttackTarget,
        parameter: str,
    ) -> list[Finding]:
        """Run this plugin against one target parameter."""
