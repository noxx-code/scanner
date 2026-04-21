"""Plugin contract for scan checks."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol
from urllib.parse import urlparse

import httpx

from backend.secscan.utils.models import Endpoint, Finding


class CheckScope(str, Enum):
    """Execution scope for check scheduling and deduplication."""

    endpoint = "endpoint"
    host = "host"
    global_run = "global"


@dataclass(slots=True)
class ScanContext:
    """Runtime context passed to checks."""

    target_url: str
    target_host: str
    target_origin: str
    js_files: list[str]

    @classmethod
    def from_target(cls, target_url: str, js_files: list[str]) -> "ScanContext":
        parsed = urlparse(target_url)
        host = (parsed.hostname or "").lower()
        origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else target_url
        return cls(target_url=target_url, target_host=host, target_origin=origin, js_files=js_files)


class SecurityCheck(Protocol):
    """Plugin protocol for security checks."""

    name: str
    passive: bool
    scope: CheckScope

    async def run(self, client: httpx.AsyncClient, endpoint: Endpoint, context: ScanContext) -> list[Finding]:
        """Execute check against one endpoint."""
