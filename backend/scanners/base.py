"""
Unified scanner interface and base classes for all scanners.
All scanners must inherit from BaseScanner and implement run().
"""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Represents a single security finding."""
    title: str
    description: str
    severity: str  # high, medium, low
    type: str  # vulnerability type
    url: str
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Unified result format for all scanners."""
    scan_id: str
    scanner_name: str
    target: str
    status: str  # success, failed, partial
    findings: List[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def findings_count(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def severity_breakdown(self) -> Dict[str, int]:
        """Count findings by severity."""
        breakdown = {"high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            sev = finding.severity.lower()
            if sev in breakdown:
                breakdown[sev] += 1
        return breakdown

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "scanner_name": self.scanner_name,
            "target": self.target,
            "status": self.status,
            "findings": [asdict(f) for f in self.findings],
            "findings_count": self.findings_count,
            "severity_breakdown": self.severity_breakdown,
            "duration_seconds": self.duration_seconds,
            "timestamp": self.timestamp,
            "error_message": self.error_message,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


class BaseScanner(ABC):
    """
    Abstract base class for all scanners.
    Scanners must inherit from this and implement validate_target() and run().
    """

    def __init__(self, name: str):
        """Initialize scanner.
        
        Args:
            name: Scanner name (e.g., 'nuclei', 'secscan')
        """
        self.name = name
        logger.info(f"Initialized {name} scanner")

    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """
        Validate if target format is supported by this scanner.

        Args:
            target: Target URL or identifier

        Returns:
            True if valid for this scanner, False otherwise
        """
        pass

    @abstractmethod
    async def run(self, target: str, **kwargs) -> ScanResult:
        """
        Execute scan on target.

        Args:
            target: Target to scan (URL, domain, etc)
            **kwargs: Scanner-specific options

        Returns:
            ScanResult with findings
        """
        pass

    def _create_result(
        self,
        target: str,
        findings: Optional[List[Finding]] = None,
        status: str = "success",
        duration: float = 0.0,
        error: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> ScanResult:
        """
        Helper to create a ScanResult.

        Args:
            target: Target that was scanned
            findings: List of findings
            status: Result status (success, failed, partial)
            duration: Scan duration in seconds
            error: Error message if failed
            metadata: Additional metadata

        Returns:
            Configured ScanResult
        """
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            scanner_name=self.name,
            target=target,
            status=status,
            findings=findings or [],
            duration_seconds=duration,
            error_message=error,
            metadata=metadata or {},
        )
