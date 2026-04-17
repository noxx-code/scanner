"""
Report routes.

Endpoints
---------
GET /reports            — list all scans belonging to the current user
GET /reports/{scan_id}  — detailed report for a single scan (alias for GET /scan/{id})
DELETE /reports/{scan_id} — delete one report and related vulnerabilities
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.database import get_db
from app.models.scan import Scan
from app.models.user import User
from app.routes.dependencies import get_current_user
from app.routes.scan import ScanOut

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("", response_model=list[ScanOut])
async def list_reports(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return a list of all scans created by the current user (newest first)."""
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.owner_id == current_user.id)
        .order_by(Scan.created_at.desc())
    )
    return list(result.scalars().all())


@router.get("/{scan_id}", response_model=ScanOut)
async def get_report(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return the full report for a single scan including all vulnerabilities."""
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if scan is None or scan.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    return scan


@router.delete("/{scan_id}")
async def delete_report(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete one report. Returns 403 if it belongs to another user."""
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    if scan.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden.")

    await db.delete(scan)
    await db.commit()
    return {"detail": "Report deleted."}
