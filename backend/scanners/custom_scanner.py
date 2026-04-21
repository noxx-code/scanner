"""Custom scanner runner adapter."""
import sys
import logging
from pathlib import Path
from typing import Dict, Any
import json
import time

from .base import BaseRunner, ScanResult

logger = logging.getLogger(__name__)


class CustomScannerRunner(BaseRunner):
    """Adapter for custom/vuln_scanner vulnerability scanner."""
    
    def __init__(self, assets_dir: Path, scanner_path: Path):
        """Initialize custom scanner runner.
        
        Args:
            assets_dir: Root assets directory
            scanner_path: Path to custom scanner package directory
        """
        super().__init__("custom_scanner", assets_dir)
        self.scanner_path = Path(scanner_path)
        
        # Add to path for imports
        if str(self.scanner_path) not in sys.path:
            sys.path.insert(0, str(self.scanner_path))
    
    def validate_target(self, target: str) -> bool:
        """Validate target is a valid URL."""
        return target.startswith(('http://', 'https://'))
    
    async def run(self, target: str, **kwargs) -> ScanResult:
        """Run custom scanner.
        
        Args:
            target: Target URL to scan
            **kwargs: Scanner options (timeout, etc.)
            
        Returns:
            ScanResult with findings
        """
        start_time = time.time()
        scan_id = kwargs.get('scan_id', 'default')
        output_file = self.get_output_path(scan_id)
        log_file = self.get_log_path(scan_id)
        
        # Validate target
        if not self.validate_target(target):
            return ScanResult(
                scanner_name=self.scanner_name,
                target=target,
                status="error",
                findings=[],
                duration_seconds=0,
                timestamp=str(time.time()),
                error_message="Invalid target: must start with http:// or https://"
            )
        
        try:
            # Use subprocess to run custom scanner
            cmd = [sys.executable, "-m", "cli", "scan", target]
            
            timeout = kwargs.get('timeout', 300)
            stdout, stderr, returncode = await self.run_subprocess(cmd, timeout)
            
            # Log output
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write(f"STDOUT:\n{stdout}\n")
                if stderr:
                    f.write(f"\nSTDERR:\n{stderr}\n")
            
            # Parse results
            findings = []
            try:
                result = json.loads(stdout)
                if isinstance(result, list):
                    findings = result
                elif isinstance(result, dict):
                    if 'findings' in result:
                        findings = result['findings']
                    elif 'vulnerabilities' in result:
                        findings = result['vulnerabilities']
                    elif 'results' in result:
                        findings = result['results']
                    else:
                        findings = [result]
                else:
                    findings = [result]
            except json.JSONDecodeError:
                if stdout:
                    logger.info(f"Custom scanner raw output: {stdout[:200]}")
            
            duration = time.time() - start_time
            status = "success" if returncode == 0 or len(findings) > 0 else "error"
            
            return ScanResult(
                scanner_name=self.scanner_name,
                target=target,
                status=status,
                findings=findings,
                duration_seconds=duration,
                timestamp=str(time.time()),
                error_message=stderr if returncode != 0 else None,
                raw_output=stdout
            )
            
        except Exception as e:
            logger.exception(f"CustomScannerRunner error: {e}")
            duration = time.time() - start_time
            return ScanResult(
                scanner_name=self.scanner_name,
                target=target,
                status="error",
                findings=[],
                duration_seconds=duration,
                timestamp=str(time.time()),
                error_message=str(e)
            )
