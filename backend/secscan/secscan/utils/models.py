"""Data models shared across scanner modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    """Severity levels for findings."""

    low = "Low"
    medium = "Medium"
    high = "High"


@dataclass(slots=True)
class FormInput:
    """Form input descriptor."""

    name: str
    input_type: str = "text"
    required: bool = False


@dataclass(slots=True)
class FormDescriptor:
    """Form metadata extracted by crawler."""

    source_url: str
    action: str
    method: str
    inputs: list[FormInput]


@dataclass(slots=True)
class Endpoint:
    """Endpoint surface discovered during crawl."""

    url: str
    method: str = "GET"
    params: tuple[str, ...] = ()
    source: str = "link"
    content_type: str = "query"


@dataclass(slots=True)
class CrawlResult:
    """Crawler output used by scanner core."""

    base_url: str
    urls: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    forms: list[FormDescriptor] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    discovered_api_paths: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Fingerprint:
    """Technology fingerprint result."""

    category: str
    name: str
    version: str | None
    evidence: str
    vulnerable: bool = False
    advisory: str | None = None


@dataclass(slots=True)
class Finding:
    """Security finding output from a check plugin."""

    url: str
    issue_type: str
    severity: Severity
    evidence: str
    recommendation: str
    check_name: str


@dataclass(slots=True)
class ScanMetadata:
    """Top-level run metadata."""

    target_url: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: datetime | None = None

    def finish(self) -> None:
        self.ended_at = datetime.now(timezone.utc)

    @property
    def duration_seconds(self) -> float:
        if self.ended_at is None:
            return 0.0
        return (self.ended_at - self.started_at).total_seconds()


@dataclass(slots=True)
class ScanSession:
    """Persistable session object for resume support."""

    metadata: ScanMetadata
    crawl_result: CrawlResult
    fingerprints: list[Fingerprint]
    findings: list[Finding]

    def to_dict(self) -> dict:
        from backend.secscan.utils.serialization import crawl_result_to_dict, finding_to_dict, fingerprint_to_dict, metadata_to_dict

        return {
            "metadata": metadata_to_dict(self.metadata),
            "crawl_result": crawl_result_to_dict(self.crawl_result),
            "fingerprints": [fingerprint_to_dict(fingerprint) for fingerprint in self.fingerprints],
            "findings": [finding_to_dict(finding) for finding in self.findings],
        }
