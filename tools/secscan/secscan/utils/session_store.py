"""Session persistence for resume support."""

from __future__ import annotations

import json
from pathlib import Path

from secscan.utils.models import CrawlResult, Endpoint, Finding, Fingerprint, FormDescriptor, FormInput, ScanMetadata, ScanSession
from secscan.utils.serialization import crawl_result_to_dict, finding_to_dict, fingerprint_to_dict, metadata_to_dict, severity_from_string


class SessionStore:
    """Stores and loads scan session snapshots."""

    def __init__(self, root: Path = Path(".secscan_sessions")) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, name: str, session: ScanSession) -> Path:
        path = self.root / f"{name}.json"
        payload = {
            "metadata": metadata_to_dict(session.metadata),
            "crawl_result": crawl_result_to_dict(session.crawl_result),
            "fingerprints": [fingerprint_to_dict(fp) for fp in session.fingerprints],
            "findings": [finding_to_dict(finding) for finding in session.findings],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def load(self, name: str) -> ScanSession:
        path = self.root / f"{name}.json"
        data = json.loads(path.read_text(encoding="utf-8"))

        metadata = ScanMetadata(target_url=data["metadata"]["target_url"])
        metadata.started_at = _parse_dt(data["metadata"]["started_at"])
        metadata.ended_at = _parse_dt(data["metadata"]["ended_at"]) if data["metadata"]["ended_at"] else None

        crawl = data["crawl_result"]
        crawl_result = CrawlResult(base_url=crawl["base_url"])
        crawl_result.urls = list(crawl["urls"])
        crawl_result.endpoints = [Endpoint(**endpoint) for endpoint in crawl["endpoints"]]
        crawl_result.forms = [
            FormDescriptor(
                source_url=form["source_url"],
                action=form["action"],
                method=form["method"],
                inputs=[FormInput(**field) for field in form["inputs"]],
            )
            for form in crawl["forms"]
        ]
        crawl_result.js_files = list(crawl["js_files"])
        crawl_result.discovered_api_paths = list(crawl["discovered_api_paths"])

        fingerprints = [Fingerprint(**fingerprint) for fingerprint in data["fingerprints"]]
        findings = [
            Finding(
                url=finding["url"],
                issue_type=finding["issue_type"],
                severity=severity_from_string(finding["severity"]),
                evidence=finding["evidence"],
                recommendation=finding["recommendation"],
                check_name=finding["check_name"],
            )
            for finding in data["findings"]
        ]

        return ScanSession(
            metadata=metadata,
            crawl_result=crawl_result,
            fingerprints=fingerprints,
            findings=findings,
        )


def _parse_dt(value: str):
    from datetime import datetime

    return datetime.fromisoformat(value)
