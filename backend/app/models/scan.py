"""Scan database model."""

from sqlalchemy import Column, Integer, String, DateTime, JSON, Float, Enum as SQLEnum, ForeignKey, Text
from datetime import datetime
from backend.app.models.user import Base
import enum


class ScanStatus(str, enum.Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, enum.Enum):
    """Severity levels for vulnerabilities."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Scan(Base):
    """Scan model for storing scan results."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), unique=True, nullable=False, index=True)
    target = Column(String(2048), nullable=False)
    scanner_name = Column(String(255), nullable=False)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING)
    findings_count = Column(Integer, default=0)
    severity_breakdown = Column(JSON, default={})
    duration_seconds = Column(Float, default=0.0)
    error_message = Column(String(1024), nullable=True)
    results = Column(JSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Scan(id={self.id}, scan_id={self.scan_id}, target={self.target})>"


class Vulnerability(Base):
    """Vulnerability findings model."""

    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    url = Column(String(2048), nullable=False)
    parameter = Column(String(255), nullable=True)
    vuln_type = Column(String(255), nullable=False)
    severity = Column(SQLEnum(Severity), default=Severity.MEDIUM)
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Vulnerability(id={self.id}, type={self.vuln_type}, severity={self.severity})>"
