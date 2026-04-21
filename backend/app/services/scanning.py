"""Service layer for scanning operations."""
import logging
import time
from typing import Dict, List, Any, Optional
from uuid import uuid4

from backend.scanners.orchestrator import ScanOrchestrator
from backend.scanners.base import ScanResult, Finding

logger = logging.getLogger(__name__)


class ScanningService:
    """High-level scanning service for API and business logic."""
    
    def __init__(self, config=None):
        """Initialize scanning service.
        
        Args:
            config: Application configuration (optional)
        """
        self.config = config
        # Initialize orchestrator - now it handles all setup internally
        self.orchestrator = ScanOrchestrator()
        logger.info("ScanningService initialized with Python-based scanners")
    
    async def scan_target(
        self,
        target: str,
        scanner_name: Optional[str] = None,
        **options
    ) -> Dict[str, Any]:
        """Scan a target with specified or all scanners.
        
        Args:
            target: Target URL to scan
            scanner_name: Specific scanner to use (None = all)
            **options: Scanner-specific options
            
        Returns:
            Dictionary with scan results
        """
        scan_id = str(uuid4())
        logger.info(f"Starting scan {scan_id} for {target} with scanner={scanner_name}")
        
        # Validate target
        if not target.startswith(('http://', 'https://')):
            return {
                'scan_id': scan_id,
                'status': 'error',
                'error': 'Target must start with http:// or https://',
                'available_scanners': self.get_available_scanners()
            }
        
        try:
            if scanner_name:
                # Run specific scanner
                result = await self.orchestrator.run_single(
                    scanner_name,
                    target,
                    **options
                )
                return self._format_result(result, scan_id, target)
            else:
                # Run all scanners concurrently
                results = await self.orchestrator.run_all(target, concurrent=True, **options)
                return self._aggregate_results(results, target, scan_id)
        
        except Exception as e:
            logger.exception(f"Scan error: {e}")
            return {
                'scan_id': scan_id,
                'status': 'error',
                'error': str(e),
                'available_scanners': self.get_available_scanners()
            }
    
    def get_available_scanners(self) -> List[Dict[str, Any]]:
        """Get list of available scanners with metadata.
        
        Returns:
            List of scanner info dictionaries
        """
        scanner_info = self.orchestrator.get_available_scanners()
        result = []
        
        for name, info in scanner_info.items():
            result.append({
                'name': name,
                'display_name': info.get('name', name),
                'description': info.get('description', ''),
                'available': info.get('available', True)
            })
        
        return result
    
    @staticmethod
    def _format_result(
        result: ScanResult,
        scan_id: str,
        target: str
    ) -> Dict[str, Any]:
        """Format a single scanner result.
        
        Args:
            result: ScanResult from scanner
            scan_id: Scan ID
            target: Target URL
            
        Returns:
            Formatted result dictionary
        """
        findings_data = []
        for finding in result.findings:
            findings_data.append({
                'title': finding.title,
                'description': finding.description,
                'severity': finding.severity,
                'type': finding.type,
                'url': finding.url,
                'parameter': finding.parameter,
                'evidence': finding.evidence,
                'metadata': finding.metadata
            })
        
        return {
            'scan_id': scan_id,
            'target': target,
            'scanner': result.scanner_name,
            'status': result.status,
            'findings': findings_data,
            'findings_count': len(findings_data),
            'severity_breakdown': result.severity_breakdown,
            'duration_seconds': result.duration_seconds,
            'timestamp': result.timestamp,
            'error': result.error_message
        }
    
    @staticmethod
    def _aggregate_results(
        results: List[ScanResult],
        target: str,
        scan_id: str
    ) -> Dict[str, Any]:
        """Aggregate results from multiple scanners.
        
        Args:
            results: List of ScanResults
            target: Target that was scanned
            scan_id: Scan ID
            
        Returns:
            Aggregated results dictionary
        """
        all_findings = []
        errors = []
        successful_count = 0
        total_duration = 0.0
        scanner_results = []
        
        for result in results:
            total_duration += result.duration_seconds
            
            findings_data = []
            for finding in result.findings:
                findings_data.append({
                    'title': finding.title,
                    'description': finding.description,
                    'severity': finding.severity,
                    'type': finding.type,
                    'url': finding.url,
                    'parameter': finding.parameter,
                    'evidence': finding.evidence,
                    'metadata': finding.metadata
                })
                all_findings.append(finding)
            
            if result.status in ("success", "partial"):
                successful_count += 1
            else:
                if result.error_message:
                    errors.append({
                        'scanner': result.scanner_name,
                        'error': result.error_message
                    })
            
            scanner_results.append({
                'scanner': result.scanner_name,
                'status': result.status,
                'findings_count': len(findings_data),
                'duration_seconds': result.duration_seconds,
                'error': result.error_message
            })
        
        # Deduplicate findings by creating keys
        unique_findings = {}
        for finding in all_findings:
            key = (finding.title, finding.url, finding.type)
            if key not in unique_findings:
                unique_findings[key] = finding
        
        # Format deduplicated findings
        findings_data = []
        for finding in unique_findings.values():
            findings_data.append({
                'title': finding.title,
                'description': finding.description,
                'severity': finding.severity,
                'type': finding.type,
                'url': finding.url,
                'parameter': finding.parameter,
                'evidence': finding.evidence,
                'metadata': finding.metadata
            })
        
        # Count by severity
        severity_breakdown = {"high": 0, "medium": 0, "low": 0}
        for finding in findings_data:
            sev = finding.get('severity', 'low').lower()
            if sev in severity_breakdown:
                severity_breakdown[sev] += 1
        
        return {
            'scan_id': scan_id,
            'target': target,
            'total_scanners': len(results),
            'successful_scanners': successful_count,
            'total_findings': len(findings_data),
            'unique_findings': findings_data,
            'severity_breakdown': severity_breakdown,
            'total_duration_seconds': round(total_duration, 2),
            'scanner_results': scanner_results,
            'errors': errors,
            'status': 'completed'
        }
