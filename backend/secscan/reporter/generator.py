"""Report generation utilities for JSON, HTML, and CSV."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from backend.secscan.utils.models import Finding, Fingerprint, ScanMetadata
from backend.secscan.utils.serialization import finding_to_dict, fingerprint_to_dict, metadata_to_dict, summarize_findings


class ReportGenerator:
    """Builds structured JSON and HTML reports plus CSV export."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write_json(
        self,
        basename: str,
        metadata: ScanMetadata,
        findings: list[Finding],
        fingerprints: list[Fingerprint],
    ) -> Path:
        """Write JSON report file."""
        metadata_payload = metadata_to_dict(metadata)
        payload = {
            "scan_metadata": {
                "target": metadata_payload["target_url"],
                "started_at": metadata_payload["started_at"],
                "ended_at": metadata_payload["ended_at"],
                "duration_seconds": metadata_payload["duration_seconds"],
            },
            "summary": summarize_findings(findings),
            "fingerprints": [fingerprint_to_dict(fp) for fp in fingerprints],
            "findings": [finding_to_dict(finding) for finding in findings],
        }

        path = self.output_dir / f"{basename}.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def write_html(
        self,
        basename: str,
        metadata: ScanMetadata,
        findings: list[Finding],
        fingerprints: list[Fingerprint],
    ) -> Path:
        """Write HTML dashboard report file."""
        summary = summarize_findings(findings)
        rows = "\n".join(
            "<tr data-severity='{}'><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                finding.severity.value,
                _escape(finding.severity.value),
                _escape(finding.issue_type),
                _escape(finding.url),
                _escape(finding.evidence),
                _escape(finding.recommendation),
            )
            for finding in findings
        ) or "<tr><td colspan='5'>No findings detected.</td></tr>"

        tech_rows = "\n".join(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                _escape(fp.category),
                _escape(fp.name),
                _escape(fp.version or "N/A"),
                _escape(fp.advisory or "N/A"),
            )
            for fp in fingerprints
        ) or "<tr><td colspan='4'>No technology fingerprints.</td></tr>"

        html = f"""<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>SecScan Report</title>
  <style>
    body {{ font-family: Segoe UI, Tahoma, sans-serif; margin: 0; background: #f3f6fb; color: #172a45; }}
    .wrap {{ max-width: 1200px; margin: 24px auto; padding: 0 16px; }}
    .banner {{ background: #fee7c7; color: #7a4c00; border: 1px solid #f2d29b; padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; }}
    .card {{ background: #fff; border: 1px solid #d5deea; border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 10px; }}
    .kpi {{ border: 1px solid #dce5f0; border-radius: 8px; padding: 8px; background: #fafcff; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ border: 1px solid #dce5f0; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #ecf2fa; }}
    .controls {{ margin-bottom: 12px; }}
    .btn {{ border: 1px solid #6886af; background: #fff; padding: 6px 10px; border-radius: 6px; cursor: pointer; margin-right: 8px; }}
  </style>
</head>
<body>
  <div class='wrap'>
    <div class='banner'>Authorized testing only. Do not scan systems without explicit permission.</div>

    <div class='card'>
      <h2>Scan Metadata</h2>
      <p>Target: {_escape(metadata.target_url)}</p>
      <p>Started: {_escape(metadata.started_at.isoformat())}</p>
      <p>Ended: {_escape(metadata.ended_at.isoformat() if metadata.ended_at else 'N/A')}</p>
      <p>Duration: {metadata.duration_seconds:.2f}s</p>
    </div>

    <div class='card'>
      <h2>Summary</h2>
      <div class='grid'>
        <div class='kpi'>Total Findings<br><b>{summary['total']}</b></div>
        <div class='kpi'>High<br><b>{summary['high']}</b></div>
        <div class='kpi'>Medium<br><b>{summary['medium']}</b></div>
        <div class='kpi'>Low<br><b>{summary['low']}</b></div>
      </div>
    </div>

    <div class='card'>
      <h2>Vulnerabilities</h2>
      <div class='controls'>
        <button class='btn' onclick="filterRows('All')">All</button>
        <button class='btn' onclick="filterRows('High')">High</button>
        <button class='btn' onclick="filterRows('Medium')">Medium</button>
        <button class='btn' onclick="filterRows('Low')">Low</button>
      </div>
      <table>
        <thead><tr><th>Severity</th><th>Issue</th><th>URL</th><th>Evidence</th><th>Recommendation</th></tr></thead>
        <tbody id='findings-body'>{rows}</tbody>
      </table>
    </div>

    <div class='card'>
      <h2>Technology Fingerprints</h2>
      <table>
        <thead><tr><th>Category</th><th>Name</th><th>Version</th><th>Advisory</th></tr></thead>
        <tbody>{tech_rows}</tbody>
      </table>
    </div>
  </div>

  <script>
    function filterRows(sev) {{
      const rows = document.querySelectorAll('#findings-body tr');
      rows.forEach((row) => {{
        if (sev === 'All') {{
          row.style.display = '';
          return;
        }}
        row.style.display = row.dataset.severity === sev ? '' : 'none';
      }});
    }}
  </script>
</body>
</html>
"""

        path = self.output_dir / f"{basename}.html"
        path.write_text(html, encoding="utf-8")
        return path

    def write_csv(self, basename: str, findings: list[Finding]) -> Path:
        """Write CSV findings export."""
        path = self.output_dir / f"{basename}.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["url", "issue_type", "severity", "evidence", "recommendation", "check_name"])
            for finding in findings:
                writer.writerow(
                    [
                        finding.url,
                        finding.issue_type,
                        finding.severity.value,
                        finding.evidence,
                        finding.recommendation,
                        finding.check_name,
                    ]
                )
        return path


def _escape(value: str) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
