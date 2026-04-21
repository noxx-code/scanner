"""Serialization helpers for reports and persisted sessions."""

from __future__ import annotations

from dataclasses import asdict

from secscan.utils.models import CrawlResult, Finding, Fingerprint, ScanMetadata, Severity


def metadata_to_dict(metadata: ScanMetadata) -> dict:
    """Convert scan metadata to a serializable dictionary."""
    return {
        "target_url": metadata.target_url,
        "started_at": metadata.started_at.isoformat(),
        "ended_at": metadata.ended_at.isoformat() if metadata.ended_at else None,
        "duration_seconds": round(metadata.duration_seconds, 2),
    }


def fingerprint_to_dict(fingerprint: Fingerprint) -> dict:
    """Convert a fingerprint object to dictionary."""
    return asdict(fingerprint)


def finding_to_dict(finding: Finding) -> dict:
    """Convert a finding object to dictionary."""
    data = asdict(finding)
    data["severity"] = finding.severity.value
    return data


def crawl_result_to_dict(crawl_result: CrawlResult) -> dict:
    """Convert crawler output to dictionary."""
    return {
        "base_url": crawl_result.base_url,
        "urls": list(crawl_result.urls),
        "endpoints": [asdict(endpoint) for endpoint in crawl_result.endpoints],
        "forms": [asdict(form) for form in crawl_result.forms],
        "js_files": list(crawl_result.js_files),
        "discovered_api_paths": list(crawl_result.discovered_api_paths),
    }


def summarize_findings(findings: list[Finding]) -> dict[str, int]:
    """Build severity summary for report headers."""
    counts = {"total": len(findings), "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        key = finding.severity.value.lower()
        if key in counts:
            counts[key] += 1
    return counts


def severity_from_string(value: str) -> Severity:
    """Parse serialized severity into enum value."""
    return Severity(value)
