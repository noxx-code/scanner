"""Configuration types for scanner runtime."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import urlparse


@dataclass(slots=True)
class ScanConfig:
    """User-supplied scan configuration."""

    target_url: str
    depth: int = 2
    threads: int = 20
    rate_limit: float = 5.0
    same_domain_only: bool = True
    respect_robots_txt: bool = True
    request_timeout: float = 10.0
    output_dir: Path = Path("reports")
    output_basename: str = "scan_report"

    def __post_init__(self) -> None:
        parsed = urlparse(self.target_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("target_url must be an absolute http/https URL")

        self.depth = max(1, int(self.depth))
        self.threads = max(1, int(self.threads))
        self.rate_limit = max(0.1, float(self.rate_limit))
        self.request_timeout = max(1.0, float(self.request_timeout))
        self.output_basename = _safe_basename(self.output_basename)


def _safe_basename(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]", "_", value).strip("._")
    return cleaned or "scan_report"
