"""
Report routes.

Endpoints
---------
GET /reports                 — list all scans belonging to the current user
GET /reports/{scan_id}       — detailed report for a single scan
GET /reports/{scan_id}/json  — structured JSON export with summary and remediation
GET /reports/{scan_id}/html  — HTML export suitable for sharing
DELETE /reports/{scan_id}    — delete one report and related vulnerabilities
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from html import escape

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.db.database import get_db
from backend.app.models.scan import Scan, Severity, Vulnerability
from backend.app.models.user import User
from backend.app.routes.dependencies import get_current_user

router = APIRouter(prefix="/reports", tags=["reports"])

_OWASP_CATEGORY_MAP: dict[str, str] = {
    "XSS": "A03:2021 - Injection",
    "SQLi": "A03:2021 - Injection",
    "OpenRedirect": "A10:2021 - Server-Side Request Forgery",
    "MissingSecurityHeaders": "A05:2021 - Security Misconfiguration",
    "TechnologyDisclosure": "A05:2021 - Security Misconfiguration",
    "OutdatedSoftware": "A06:2021 - Vulnerable and Outdated Components",
    "DirectoryListingEnabled": "A05:2021 - Security Misconfiguration",
    "InsecureCookieFlags": "A02:2021 - Cryptographic Failures",
    "InjectionPoint": "A01:2021 - Broken Access Control (surface discovery)",
}

_REMEDIATION_MAP: dict[str, str] = {
    "XSS": "Contextually encode output, apply input validation, and enforce a strict Content Security Policy.",
    "SQLi": "Use parameterized queries/prepared statements and server-side allow-list validation.",
    "OpenRedirect": "Restrict redirect targets to an allow-list of trusted internal destinations.",
    "MissingSecurityHeaders": "Add CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.",
    "TechnologyDisclosure": "Remove or minimize banner headers like Server and X-Powered-By.",
    "OutdatedSoftware": "Upgrade to currently supported framework/library versions and patch regularly.",
    "DirectoryListingEnabled": "Disable auto-indexing for web directories and block direct listing paths.",
    "InsecureCookieFlags": "Set Secure, HttpOnly, and SameSite on session and sensitive cookies.",
    "InjectionPoint": "Apply centralized input validation and server-side parameter constraints.",
}


def _severity_rank(severity: Severity | str) -> int:
    value = severity.value if isinstance(severity, Severity) else severity
    order = {"high": 3, "medium": 2, "low": 1}
    return order.get(value, 0)


def _build_summary(scan: Scan) -> dict:
    severities = Counter(v.severity.value for v in scan.vulnerabilities)
    by_type = Counter(v.vuln_type for v in scan.vulnerabilities)

    highest = "low"
    if severities.get("high", 0):
        highest = "high"
    elif severities.get("medium", 0):
        highest = "medium"

    return {
        "total_findings": len(scan.vulnerabilities),
        "severity_counts": {
            "high": severities.get("high", 0),
            "medium": severities.get("medium", 0),
            "low": severities.get("low", 0),
        },
        "highest_severity": highest,
        "findings_by_type": dict(by_type),
    }


def _finding_to_dict(vuln: Vulnerability) -> dict:
    vuln_type = vuln.vuln_type
    return {
        "id": vuln.id,
        "url": vuln.url,
        "parameter": vuln.parameter,
        "vulnerability_type": vuln_type,
        "severity": vuln.severity.value,
        "owasp_category": _OWASP_CATEGORY_MAP.get(vuln_type, "Uncategorized"),
        "detail": vuln.detail,
        "remediation": _REMEDIATION_MAP.get(vuln_type, "Review application logic and apply secure coding controls."),
    }


def _scan_to_json_report(scan: Scan) -> dict:
    sorted_vulns = sorted(scan.vulnerabilities, key=lambda v: _severity_rank(v.severity), reverse=True)
    return {
        "scan": {
            "id": scan.id,
            "target_url": scan.target_url,
            "depth": scan.depth,
            "status": scan.status.value,
            "created_at": scan.created_at.isoformat() if isinstance(scan.created_at, datetime) else str(scan.created_at),
            "completed_at": (
                scan.completed_at.isoformat()
                if isinstance(scan.completed_at, datetime)
                else (str(scan.completed_at) if scan.completed_at else None)
            ),
            "error_message": scan.error_message,
        },
        "summary": _build_summary(scan),
        "findings": [_finding_to_dict(v) for v in sorted_vulns],
    }


def _scan_to_html_report(scan: Scan) -> str:
    report = _scan_to_json_report(scan)
    summary = report["summary"]

    finding_rows = []
    for finding in report["findings"]:
        finding_rows.append(
            "<tr>"
            f"<td>{escape(finding['severity'].upper())}</td>"
            f"<td>{escape(finding['vulnerability_type'])}</td>"
            f"<td>{escape(finding['url'])}</td>"
            f"<td>{escape(finding['parameter'])}</td>"
            f"<td>{escape((finding['detail'] or '')[:300])}</td>"
            f"<td>{escape(finding['remediation'])}</td>"
            "</tr>"
        )

    findings_table = (
        "".join(finding_rows)
        if finding_rows
        else "<tr><td colspan='6'>No vulnerabilities were detected during this scan.</td></tr>"
    )

    return f"""<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>Security Scan Report #{scan.id}</title>
  <style>
    :root {{
      --bg: #f4f7fb;
      --fg: #152238;
      --muted: #4b5d79;
      --card: #ffffff;
      --border: #d8e1ef;
      --high: #b71c1c;
      --medium: #ef6c00;
      --low: #1565c0;
    }}
    body {{ background: var(--bg); color: var(--fg); font-family: Segoe UI, Tahoma, sans-serif; margin: 0; }}
    .wrap {{ max-width: 1120px; margin: 24px auto; padding: 0 16px; }}
    .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
    h1, h2 {{ margin: 0 0 12px 0; }}
    .meta {{ color: var(--muted); font-size: 14px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 12px; }}
    .kpi {{ border: 1px solid var(--border); border-radius: 8px; padding: 10px; background: #fbfdff; }}
    .kpi b {{ display: block; font-size: 22px; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ border: 1px solid var(--border); padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5fb; }}
    .sev-high {{ color: var(--high); font-weight: 700; }}
    .sev-medium {{ color: var(--medium); font-weight: 700; }}
    .sev-low {{ color: var(--low); font-weight: 700; }}
  </style>
</head>
<body>
  <div class='wrap'>
    <div class='card'>
      <h1>Security Scan Report #{scan.id}</h1>
      <div class='meta'>Target: {escape(scan.target_url)}</div>
      <div class='meta'>Status: {escape(scan.status.value)} | Depth: {scan.depth}</div>
      <div class='meta'>Created: {escape(str(scan.created_at))} | Completed: {escape(str(scan.completed_at or 'N/A'))}</div>
    </div>

    <div class='card'>
      <h2>Summary</h2>
      <div class='grid'>
        <div class='kpi'>Total Findings <b>{summary['total_findings']}</b></div>
        <div class='kpi'>High <b class='sev-high'>{summary['severity_counts']['high']}</b></div>
        <div class='kpi'>Medium <b class='sev-medium'>{summary['severity_counts']['medium']}</b></div>
        <div class='kpi'>Low <b class='sev-low'>{summary['severity_counts']['low']}</b></div>
      </div>
    </div>

    <div class='card'>
      <h2>Findings</h2>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Type</th>
            <th>URL</th>
            <th>Parameter</th>
            <th>Detail</th>
            <th>Remediation</th>
          </tr>
        </thead>
        <tbody>
          {findings_table}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""


async def _get_owned_scan_or_404(db: AsyncSession, scan_id: int, current_user: User) -> Scan:
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if scan is None or scan.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    return scan


@router.get("", response_model=list)
async def list_reports(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return all scans created by current user (newest first)."""
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.owner_id == current_user.id)
        .order_by(Scan.created_at.desc())
    )
    return list(result.scalars().all())


@router.get("/{scan_id}")
async def get_report(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return one scan report including all findings."""
    return await _get_owned_scan_or_404(db, scan_id, current_user)


@router.get("/{scan_id}/json")
async def get_report_json(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Export report in structured JSON format with summary and remediation guidance."""
    scan = await _get_owned_scan_or_404(db, scan_id, current_user)
    return JSONResponse(content=_scan_to_json_report(scan))


@router.get("/{scan_id}/html", response_class=HTMLResponse)
async def get_report_html(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Export report as printable HTML."""
    scan = await _get_owned_scan_or_404(db, scan_id, current_user)
    return HTMLResponse(content=_scan_to_html_report(scan))


@router.delete("/{scan_id}")
async def delete_report(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete one report and all related findings."""
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    if scan.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden.")

    await db.delete(scan)
    await db.commit()
    return {"detail": "Report deleted."}
