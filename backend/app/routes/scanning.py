"""Scanner API routes - REST endpoints for vulnerability scanning."""
try:
    from fastapi import APIRouter, HTTPException, Query, Depends
    from typing import Optional
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    APIRouter = None

import logging

logger = logging.getLogger(__name__)

if HAS_FASTAPI:
    router = APIRouter(prefix="/api/scan", tags=["scanning"])
    
    # Dependency injection helper
    def get_scanning_service():
        """Get scanning service instance."""
        try:
            from backend.app.services.scanning import ScanningService
            return ScanningService()
        except Exception as e:
            logger.error(f"Failed to initialize scanning service: {e}")
            raise
    
    @router.get("/scanners")
    async def list_scanners(service = Depends(get_scanning_service)):
        """List available scanners.
        
        Returns:
            List of available scanner information with descriptions
        """
        try:
            scanners = service.get_available_scanners()
            return {
                'status': 'success',
                'scanners': scanners
            }
        except Exception as e:
            logger.error(f"Error listing scanners: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @router.get("/run")
    async def run_scan(
        target: str = Query(..., description="Target URL to scan (http:// or https://)"),
        scanner: Optional[str] = Query(None, description="Specific scanner to use (scanner1/scanner2/custom_scanner)"),
        timeout: Optional[int] = Query(30, description="Timeout in seconds per request"),
        service = Depends(get_scanning_service)
    ):
        """Run security scan on target.
        
        Execute vulnerability scan using specified scanner or all scanners.
        
        Args:
            target: Target URL (must be http:// or https://)
            scanner: Optional specific scanner name. If not provided, runs all scanners
            timeout: HTTP request timeout in seconds
            
        Returns:
            Scan results with findings, severity breakdown, and scanner details
            
        Examples:
            - GET /api/scan/run?target=https://example.com
            - GET /api/scan/run?target=https://example.com&scanner=scanner1
        """
        # Validate target format
        if not target.startswith(('http://', 'https://')):
            raise HTTPException(
                status_code=400,
                detail="Target must start with http:// or https://"
            )
        
        try:
            logger.info(f"Starting scan on {target} with scanner={scanner}")
            result = await service.scan_target(
                target,
                scanner_name=scanner,
                timeout=timeout
            )
            
            if result.get('status') == 'error':
                raise HTTPException(status_code=400, detail=result.get('error'))
            
            return result
        
        except HTTPException:
            raise
        except Exception as e:
            logger.exception(f"Scan error: {e}")
            raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    
    @router.get("/status/{scan_id}")
    async def get_scan_status(scan_id: str):
        """Get status of a scan.
        
        Note: Full implementation with scan history storage requires database integration.
        
        Args:
            scan_id: Scan ID to check
            
        Returns:
            Scan status information
        """
        return {
            'scan_id': scan_id,
            'status': 'completed',
            'note': 'Scan history requires database integration for persistence'
        }
    
    @router.get("/health")
    async def health_check(service = Depends(get_scanning_service)):
        """Health check endpoint - verify scanners are available.
        
        Returns:
            Health status with available scanners
        """
        try:
            scanners = service.get_available_scanners()
            available_count = sum(1 for s in scanners if s.get('available'))
            
            return {
                'status': 'healthy',
                'scanners_available': available_count,
                'scanners': [s['name'] for s in scanners if s.get('available')]
            }
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

else:
    router = None
    logger.warning("FastAPI not available - scanner routes not registered")
