"""
Scan routes.

Endpoints
---------
POST /scan              — start a new scan (runs in background)
GET  /scan/{scan_id}    — retrieve a scan and its vulnerabilities
"""

import asyncio
from datetime import datetime, timezone
import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, HttpUrl, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.db.database import AsyncSessionLocal, get_db
from app.models.scan import Scan, ScanStatus, Severity, Vulnerability
from app.models.user import User
from app.routes.dependencies import get_current_user
from app.services.crawler import crawl
from app.services.scanner import scan_targets

router = APIRouter(prefix="/scan", tags=["scan"])
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target_url: HttpUrl
    depth: int = settings.default_crawl_depth

    @field_validator("depth")
    @classmethod
    def depth_range(cls, v: int) -> int:
        if v < 1 or v > 5:
            raise ValueError("Depth must be between 1 and 5.")
        return v


class VulnerabilityOut(BaseModel):
    id: int
    url: str
    parameter: str
    vuln_type: str
    severity: str
    detail: str | None

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: int
    target_url: str
    depth: int
    status: str
    created_at: datetime
    completed_at: datetime | None
    error_message: str | None = None
    vulnerabilities: list[VulnerabilityOut] = []

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Background task
# ---------------------------------------------------------------------------


async def _run_scan(scan_id: int) -> None:
    """
    Execute crawl + vulnerability scan for *scan_id*.

    This runs as a FastAPI BackgroundTask so the POST /scan endpoint
    returns immediately while the scan proceeds asynchronously.
    """
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            return

        # Mark as running
        scan.status = ScanStatus.running
        await db.commit()

        try:
            logger.info("Scan job started", extra={"scan_id": scan.id, "target_url": scan.target_url})
            # Step 1: Crawl
            crawl_result = await crawl(
                scan.target_url,
                depth=scan.depth,
                include_api=True,
                brute_force_api=settings.api_bruteforce_enabled,
                scan_id=scan.id,
            )

            # Step 2: Scan discovered attack surfaces for vulnerabilities
            findings = await scan_targets(
                crawl_result.targets,
                scan_id=scan.id,
                target_url=scan.target_url,
            )

            # Step 3: Persist findings
            for finding in findings:
                vuln = Vulnerability(
                    scan_id=scan_id,
                    url=finding.url,
                    parameter=finding.parameter,
                    vuln_type=finding.vuln_type,
                    severity=finding.severity,
                    detail=finding.detail,
                )
                db.add(vuln)

            scan.status = ScanStatus.completed
            logger.info(
                "Scan job completed",
                extra={"scan_id": scan.id, "target_url": scan.target_url, "findings": len(findings)},
            )
        except Exception as exc:  # noqa: BLE001
            scan.status = ScanStatus.failed
            scan.error_message = str(exc)
            logger.exception(
                "Scan job failed",
                exc_info=exc,
                extra={"scan_id": scan.id, "target_url": scan.target_url},
            )

        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
async def start_scan(
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Start a new scan. Returns immediately; scan runs in the background."""
    scan = Scan(
        target_url=str(payload.target_url),
        depth=payload.depth,
        owner_id=current_user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(_run_scan, scan.id)

    # Build response manually — no vulnerabilities yet for a brand-new scan
    return ScanOut(
        id=scan.id,
        target_url=scan.target_url,
        depth=scan.depth,
        status=scan.status,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        error_message=None,
        vulnerabilities=[],
    )


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get scan details and its discovered vulnerabilities."""
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if scan is None or scan.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan
