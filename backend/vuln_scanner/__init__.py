"""
Vulnerability scanner package.
"""

__version__ = "1.0.0"
__author__ = "Security Team"

from .core.models import Template, Result, ScannerOptions, Severity
from .core.template_loader import TemplateLoader
from .core.engine import ScanningEngine
from .protocols.http_executor import HTTPExecutor
from .operators.matchers import MatcherEngine
from .operators.extractors import ExtractorEngine
from .reporting.exporters import ExporterFactory

__all__ = [
    "Template",
    "Result",
    "ScannerOptions",
    "Severity",
    "TemplateLoader",
    "ScanningEngine",
    "HTTPExecutor",
    "MatcherEngine",
    "ExtractorEngine",
    "ExporterFactory",
]
