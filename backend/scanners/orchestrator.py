"""
Scanner Orchestrator - coordinates all scanners and combines results.
"""

import logging
import asyncio
import time
from typing import Dict, List, Optional, Any
from enum import Enum

from backend.scanners.base import BaseScanner, ScanResult, Finding
from backend.scanners.scanner1.engine import Scanner1
from backend.scanners.scanner2.engine import Scanner2
from backend.scanners.custom_scanner.engine import CustomScanner

logger = logging.getLogger(__name__)


class ScannerType(Enum):
    """Available scanner types."""
    SCANNER1 = "scanner1"
    SCANNER2 = "scanner2"
    CUSTOM_SCANNER = "custom_scanner"


class ScanOrchestrator:
    """
    Central coordinator for all security scanners.
    Runs scanners sequentially or concurrently and combines results.
    """

    def __init__(self):
        """Initialize orchestrator with all scanners."""
        self.scanners: Dict[str, BaseScanner] = {
            "scanner1": Scanner1(),
            "scanner2": Scanner2(),
            "custom_scanner": CustomScanner(),
        }
        logger.info(f"Initialized orchestrator with {len(self.scanners)} scanners")

    def get_available_scanners(self) -> Dict[str, Dict[str, Any]]:
        """
        Get list of available scanners with metadata.

        Returns:
            Dict mapping scanner names to their info
        """
        info = {
            "scanner1": {
                "name": "Scanner1",
                "description": "Template-based vulnerability scanner",
                "available": "scanner1" in self.scanners,
            },
            "scanner2": {
                "name": "Scanner2",
                "description": "Security header and configuration scanner",
                "available": "scanner2" in self.scanners,
            },
            "custom_scanner": {
                "name": "Custom Scanner",
                "description": "Input validation and basic vulnerability scanner",
                "available": "custom_scanner" in self.scanners,
            },
        }
        return info

    async def run_single(
        self,
        scanner_name: str,
        target: str,
        **kwargs
    ) -> ScanResult:
        """
        Run a single scanner on target.

        Args:
            scanner_name: Name of scanner to run
            target: Target to scan
            **kwargs: Additional options for scanner

        Returns:
            ScanResult from the scanner
        """
        if scanner_name not in self.scanners:
            return ScanResult(
                scan_id="error",
                scanner_name=scanner_name,
                target=target,
                status="failed",
                error_message=f"Scanner not found: {scanner_name}",
            )

        scanner = self.scanners[scanner_name]

        if not scanner.validate_target(target):
            return scanner._create_result(
                target,
                status="failed",
                error=f"Invalid target format for {scanner_name}",
            )

        logger.info(f"Running {scanner_name} on {target}")
        return await scanner.run(target, **kwargs)

    async def run_all(
        self,
        target: str,
        concurrent: bool = True,
        **kwargs
    ) -> List[ScanResult]:
        """
        Run all scanners on target.

        Args:
            target: Target to scan
            concurrent: Whether to run scanners in parallel
            **kwargs: Additional options for scanners

        Returns:
            List of ScanResults from all scanners
        """
        logger.info(f"Running all scanners on {target} (concurrent={concurrent})")

        if concurrent:
            # Run all scanners in parallel
            tasks = [
                self.run_single(name, target, **kwargs)
                for name in self.scanners.keys()
            ]
            results = await asyncio.gather(*tasks, return_exceptions=False)
            return results
        else:
            # Run scanners sequentially
            results = []
            for scanner_name in self.scanners.keys():
                result = await self.run_single(scanner_name, target, **kwargs)
                results.append(result)
            return results

    async def run_selected(
        self,
        target: str,
        scanner_names: List[str],
        concurrent: bool = True,
        **kwargs
    ) -> List[ScanResult]:
        """
        Run specific scanners on target.

        Args:
            target: Target to scan
            scanner_names: List of scanner names to run
            concurrent: Whether to run in parallel
            **kwargs: Additional options

        Returns:
            List of ScanResults
        """
        logger.info(f"Running selected scanners on {target}: {scanner_names}")

        if concurrent:
            tasks = [
                self.run_single(name, target, **kwargs)
                for name in scanner_names
                if name in self.scanners
            ]
            results = await asyncio.gather(*tasks, return_exceptions=False)
            return results
        else:
            results = []
            for scanner_name in scanner_names:
                if scanner_name not in self.scanners:
                    continue
                result = await self.run_single(scanner_name, target, **kwargs)
                results.append(result)
            return results

    @staticmethod
    def aggregate_results(
        results: List[ScanResult],
        deduplicate: bool = True
    ) -> Dict[str, Any]:
        """
        Aggregate results from multiple scanners.

        Args:
            results: List of ScanResults
            deduplicate: Whether to remove duplicate findings

        Returns:
            Aggregated result dictionary
        """
        total_findings: List[Finding] = []
        total_duration = 0.0
        errors = []
        successful_count = 0

        # Aggregate findings
        for result in results:
            total_findings.extend(result.findings)
            total_duration += result.duration_seconds

            if result.status == "success" or result.status == "partial":
                successful_count += 1
            else:
                if result.error_message:
                    errors.append(f"{result.scanner_name}: {result.error_message}")

        # Deduplicate findings (optional)
        if deduplicate:
            unique_findings = {}
            for finding in total_findings:
                # Create key from finding attributes
                key = (finding.title, finding.url, finding.type)
                if key not in unique_findings:
                    unique_findings[key] = finding

            total_findings = list(unique_findings.values())

        # Count by severity
        severity_breakdown = {"high": 0, "medium": 0, "low": 0}
        for finding in total_findings:
            sev = finding.severity.lower()
            if sev in severity_breakdown:
                severity_breakdown[sev] += 1

        return {
            "total_scanners": len(results),
            "successful_scanners": successful_count,
            "total_findings": len(total_findings),
            "findings": [
                {
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "type": f.type,
                    "url": f.url,
                    "parameter": f.parameter,
                    "evidence": f.evidence,
                    "metadata": f.metadata,
                }
                for f in total_findings
            ],
            "severity_breakdown": severity_breakdown,
            "total_duration_seconds": round(total_duration, 2),
            "errors": errors,
        }
