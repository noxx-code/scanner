"""Nuclei scanner runner adapter."""
import sys
import logging
from pathlib import Path
from typing import Dict, Any
import json
import time

from .base import BaseRunner, ScanResult

logger = logging.getLogger(__name__)


class NucleiRunner(BaseRunner):
    """Adapter for Nuclei vulnerability scanner."""
    
    def __init__(self, assets_dir: Path, nuclei_bin_path: Path):
        """Initialize Nuclei runner.
        
        Args:
            assets_dir: Root assets directory
            nuclei_bin_path: Path to nuclei binary or script
        """
        super().__init__("nuclei", assets_dir)
        self.nuclei_bin = Path(nuclei_bin_path)
        
        if not self.nuclei_bin.exists():
            logger.warning(f"Nuclei binary not found at {nuclei_bin_path}")
    
    def validate_target(self, target: str) -> bool:
        """Validate target is a valid URL."""
        return target.startswith(('http://', 'https://'))
    
    async def run(self, target: str, **kwargs) -> ScanResult:
        """Run Nuclei scan.
        
        Args:
            target: Target URL to scan
            **kwargs: Nuclei options (templates, severity, timeout, etc.)
            
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
            # Build command
            cmd = [str(self.nuclei_bin), "-u", target, "-json", "-o", str(output_file)]
            
            # Add optional parameters
            if kwargs.get('templates'):
                cmd.extend(["-t", kwargs['templates']])
            if kwargs.get('severity'):
                cmd.extend(["-severity", kwargs['severity']])
            if kwargs.get('tags'):
                cmd.extend(["-tags", kwargs['tags']])
            
            timeout = kwargs.get('timeout', 300)
            
            # Run nuclei
            stdout, stderr, returncode = await self.run_subprocess(cmd, timeout)
            
            # Log output
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write(f"STDOUT:\n{stdout}\n")
                if stderr:
                    f.write(f"\nSTDERR:\n{stderr}\n")
            
            # Parse results
            findings = []
            if output_file.exists() and output_file.stat().st_size > 0:
                try:
                    with open(output_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    findings.append(json.loads(line))
                                except json.JSONDecodeError:
                                    pass
                except Exception as e:
                    logger.error(f"Error reading Nuclei output: {e}")
            
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
            logger.exception(f"Nuclei runner error: {e}")
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
