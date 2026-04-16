"""
Scan-related ORM models.

Two tables:
- Scan         — one row per scan job triggered by a user.
- Vulnerability — one row per vulnerability found during a scan.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class ScanStatus(str, enum.Enum):
    """Lifecycle states for a scan job."""

    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class Severity(str, enum.Enum):
    """Vulnerability severity levels."""

    low = "low"
    medium = "medium"
    high = "high"


class Scan(Base):
    """Represents a single scan job."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    depth: Mapped[int] = mapped_column(Integer, default=2)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.pending, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Foreign key to the user who triggered the scan
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    owner: Mapped["User"] = relationship("User", back_populates="scans")  # noqa: F821

    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="scan", cascade="all, delete-orphan"
    )


class Vulnerability(Base):
    """A single vulnerability discovered during a scan."""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    parameter: Mapped[str] = mapped_column(String(256), nullable=False)
    vuln_type: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "XSS", "SQLi"
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="vulnerabilities")
