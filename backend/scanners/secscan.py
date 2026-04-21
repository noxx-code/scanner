"""SecScan Python scanner runner adapter."""
import sys
import logging
from pathlib import Path
from typing import Dict, Any
import json
import time

from .base import BaseRunner, ScanResult

logger = logging.getLogger(__name__)


class SecscanRunner(BaseRunner):
    """Adapter for SecScan vulnerability scanner."""
    
    def __init__(self, assets_dir: Path, secscan_path: Path):
        """Initialize Secscan runner.
        
        Args:
            assets_dir: Root assets directory
            secscan_path: Path to secscan package directory
        """
        super().__init__("secscan", assets_dir)
        self.secscan_path = Path(secscan_path)
        
        # Add secscan to path for imports
        if str(self.secscan_path) not in sys.path:
            sys.path.insert(0, str(self.secscan_path))
    
    def validate_target(self, target: str) -> bool:
        """Validate target is a valid URL."""
        return target.startswith(('http://', 'https://'))
    
    async def run(self, target: str, **kwargs) -> ScanResult:
        """Run SecScan.
        
        Args:
            target: Target URL to scan
            **kwargs: SecScan options (timeout, etc.)
            
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
            # Try to import and run secscan
            try:
                # Use subprocess to run secscan as CLI
                cmd = [sys.executable, "-m", "secscan.cli", "scan", "--url", target]
                
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
                    # Try to parse as JSON
                    result = json.loads(stdout)
                    if isinstance(result, list):
                        findings = result
                    elif isinstance(result, dict):
                        if 'findings' in result:
                            findings = result['findings']
                        elif 'vulnerabilities' in result:
                            findings = result['vulnerabilities']
                        else:
                            findings = [result]
                    else:
                        findings = [result]
                except json.JSONDecodeError:
                    # If not JSON, log raw output
                    if stdout:
                        logger.info(f"SecScan raw output: {stdout[:200]}")
                
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
                logger.error(f"SecscanCLI error: {e}")
                raise
        
        except Exception as e:
            logger.exception(f"SecscanRunner error: {e}")
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
