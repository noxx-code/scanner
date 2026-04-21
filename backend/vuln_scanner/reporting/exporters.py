"""
Result exporters for different output formats.
"""

import json
from typing import List, Optional
from pathlib import Path
from loguru import logger

from ..core.models import Result


class JSONExporter:
    """Export results to JSON format."""
    
    def __init__(self, output_file: Optional[str] = None):
        self.output_file = output_file
        self.results: List[Result] = []
    
    def add_result(self, result: Result) -> None:
        """Add a result to export."""
        self.results.append(result)
    
    def export(self) -> str:
        """Export results to JSON string."""
        output = {
            "scanner": "VulnerabilityScanner/1.0",
            "results_count": len(self.results),
            "results": [r.to_dict() for r in self.results],
        }
        
        json_str = json.dumps(output, indent=2)
        
        if self.output_file:
            Path(self.output_file).write_text(json_str)
            logger.info(f"Results exported to {self.output_file}")
        
        return json_str


class JSONLExporter:
    """Export results to JSONL format (one JSON per line)."""
    
    def __init__(self, output_file: Optional[str] = None):
        self.output_file = output_file
        self.results: List[Result] = []
    
    def add_result(self, result: Result) -> None:
        """Add a result to export."""
        self.results.append(result)
    
    def export(self) -> str:
        """Export results to JSONL string."""
        lines = [json.dumps(r.to_dict()) for r in self.results]
        jsonl_str = "\n".join(lines)
        
        if self.output_file:
            Path(self.output_file).write_text(jsonl_str)
            logger.info(f"Results exported to {self.output_file}")
        
        return jsonl_str


class CSVExporter:
    """Export results to CSV format."""
    
    def __init__(self, output_file: Optional[str] = None):
        self.output_file = output_file
        self.results: List[Result] = []
    
    def add_result(self, result: Result) -> None:
        """Add a result to export."""
        self.results.append(result)
    
    def export(self) -> str:
        """Export results to CSV string."""
        import csv
        from io import StringIO
        
        output = StringIO()
        
        if not self.results:
            return ""
        
        # Get all unique field names
        fieldnames = set()
        for result in self.results:
            fieldnames.update(result.to_dict().keys())
        
        fieldnames = sorted(list(fieldnames))
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for result in self.results:
            writer.writerow(result.to_dict())
        
        csv_str = output.getvalue()
        
        if self.output_file:
            Path(self.output_file).write_text(csv_str)
            logger.info(f"Results exported to {self.output_file}")
        
        return csv_str


class HTMLExporter:
    """Export results to HTML report."""
    
    def __init__(self, output_file: Optional[str] = None):
        self.output_file = output_file
        self.results: List[Result] = []
    
    def add_result(self, result: Result) -> None:
        """Add a result to export."""
        self.results.append(result)
    
    def export(self) -> str:
        """Export results to HTML string."""
        
        html = self._generate_html()
        
        if self.output_file:
            Path(self.output_file).write_text(html)
            logger.info(f"Results exported to {self.output_file}")
        
        return html
    
    def _generate_html(self) -> str:
        """Generate HTML report."""
        
        # Count results by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        
        for result in self.results:
            if result.matched and result.severity:
                severity_counts[result.severity.value] += 1
        
        # Generate HTML
        html_parts = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<title>Vulnerability Scan Report</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; margin: 20px; }",
            "h1 { color: #333; }",
            ".summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }",
            ".critical { color: #dc3545; font-weight: bold; }",
            ".high { color: #fd7e14; font-weight: bold; }",
            ".medium { color: #ffc107; font-weight: bold; }",
            ".low { color: #28a745; font-weight: bold; }",
            ".info { color: #17a2b8; }",
            "table { width: 100%; border-collapse: collapse; margin-top: 20px; }",
            "th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }",
            "th { background-color: #f9f9f9; }",
            ".error { color: #dc3545; }",
            "pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }",
            "</style>",
            "</head>",
            "<body>",
            "<h1>Vulnerability Scan Report</h1>",
            "<div class='summary'>",
            f"<p><strong>Total Results:</strong> {len([r for r in self.results if r.matched])}</p>",
            f"<p><strong class='critical'>Critical:</strong> {severity_counts['critical']}</p>",
            f"<p><strong class='high'>High:</strong> {severity_counts['high']}</p>",
            f"<p><strong class='medium'>Medium:</strong> {severity_counts['medium']}</p>",
            f"<p><strong class='low'>Low:</strong> {severity_counts['low']}</p>",
            f"<p><strong class='info'>Info:</strong> {severity_counts['info']}</p>",
            "</div>",
            "<table>",
            "<tr>",
            "<th>Severity</th>",
            "<th>Template</th>",
            "<th>Target</th>",
            "<th>Status</th>",
            "<th>Extracted Data</th>",
            "</tr>",
        ]
        
        # Add results table
        for result in self.results:
            if result.matched:
                severity_class = f"class='{result.severity.value}'"
                status = "✓ Vulnerable" if result.matched else "✗ Safe"
                extracted_json = json.dumps(result.extracted_data, indent=2) if result.extracted_data else ""
                
                html_parts.extend([
                    "<tr>",
                    f"<td {severity_class}>{result.severity.value.upper()}</td>",
                    f"<td>{result.template_name}</td>",
                    f"<td><a href='{result.request_url}'>{result.target}</a></td>",
                    f"<td>{status}</td>",
                    f"<td><pre>{extracted_json}</pre></td>",
                    "</tr>",
                ])
        
        html_parts.extend([
            "</table>",
            "</body>",
            "</html>",
        ])
        
        return "\n".join(html_parts)


class ExporterFactory:
    """Factory for creating exporters."""
    
    EXPORTERS = {
        "json": JSONExporter,
        "jsonl": JSONLExporter,
        "csv": CSVExporter,
        "html": HTMLExporter,
    }
    
    @classmethod
    def create(cls, format: str, output_file: Optional[str] = None):
        """
        Create an exporter instance.
        
        Args:
            format: Export format (json, jsonl, csv, html)
            output_file: Output file path
        
        Returns:
            Exporter instance
        """
        exporter_class = cls.EXPORTERS.get(format)
        
        if not exporter_class:
            raise ValueError(f"Unknown export format: {format}")
        
        return exporter_class(output_file)
