"""
Core data models for vulnerability scanner templates and results.
"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SeverityRank:
    """Map severity to numeric rank for sorting."""
    RANK = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }


@dataclass
class TemplateInfo:
    """Metadata about a template."""
    name: str
    author: str
    description: str
    severity: Severity
    tags: List[str] = field(default_factory=list)
    reference: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "author": self.author,
            "description": self.description,
            "severity": self.severity.value,
            "tags": self.tags,
            "reference": self.reference,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
        }


@dataclass
class HTTPRequest:
    """HTTP request specification."""
    name: Optional[str] = None
    method: str = "GET"
    path: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    auth: Optional[Dict[str, Any]] = None
    redirects: int = 5
    timeout: int = 10
    payloads: Dict[str, Any] = field(default_factory=dict)
    matchers: List[Dict[str, Any]] = field(default_factory=list)
    matchers_condition: str = "and"
    extractors: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class DNSRequest:
    """DNS query specification."""
    name: Optional[str] = None
    type: str = "A"
    class_: str = "IN"
    resolvers: List[str] = field(default_factory=list)
    matchers: List[Dict[str, Any]] = field(default_factory=list)
    matchers_condition: str = "and"
    extractors: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class NetworkRequest:
    """TCP/Network request specification."""
    name: Optional[str] = None
    host: str = ""
    port: int = 0
    input_data: Optional[str] = None
    matchers: List[Dict[str, Any]] = field(default_factory=list)
    matchers_condition: str = "and"
    extractors: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class SSLRequest:
    """SSL/TLS certificate check specification."""
    name: Optional[str] = None
    address: str = ""
    min_version: str = "tls12"
    matchers: List[Dict[str, Any]] = field(default_factory=list)
    matchers_condition: str = "and"
    extractors: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class Template:
    """Complete vulnerability scanner template."""
    id: str
    info: TemplateInfo
    http: List[HTTPRequest] = field(default_factory=list)
    dns: List[DNSRequest] = field(default_factory=list)
    network: List[NetworkRequest] = field(default_factory=list)
    ssl: List[SSLRequest] = field(default_factory=list)
    flow: Optional[str] = None
    
    @property
    def cache_key(self) -> str:
        """Generate cache key for this template."""
        content = f"{self.id}:{self.info.name}:{len(self.http)}{len(self.dns)}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "info": self.info.to_dict(),
            "http": [self._request_to_dict(r) for r in self.http],
            "dns": [self._request_to_dict(r) for r in self.dns],
            "network": [self._request_to_dict(r) for r in self.network],
            "ssl": [self._request_to_dict(r) for r in self.ssl],
            "flow": self.flow,
        }
    
    @staticmethod
    def _request_to_dict(request: Any) -> Dict[str, Any]:
        """Convert request object to dict."""
        return {k: v for k, v in request.__dict__.items() if v}


@dataclass
class Response:
    """HTTP/Protocol response."""
    status_code: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_bytes: bytes = b""
    cookies: Dict[str, str] = field(default_factory=dict)
    request_url: Optional[str] = None
    request_method: str = "GET"
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    duration_ms: float = 0.0
    error: Optional[str] = None
    protocol: str = "http"
    
    @property
    def is_error(self) -> bool:
        """Check if response represents an error."""
        return self.error is not None or self.status_code is None


@dataclass
class Result:
    """Scanning result/finding."""
    template_id: str
    target: str
    matched: bool
    severity: Severity = Severity.INFO
    response: Optional[Response] = None
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    request_url: Optional[str] = None
    match_string: Optional[str] = None
    error: Optional[str] = None
    template_name: str = ""
    template_info: Optional[TemplateInfo] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting."""
        return {
            "template_id": self.template_id,
            "template_name": self.template_name,
            "severity": self.severity.value,
            "target": self.target,
            "matched": self.matched,
            "extracted_data": self.extracted_data,
            "timestamp": self.timestamp.isoformat(),
            "error": self.error,
            "url": self.request_url,
        }
    
    def get_dedup_key(self) -> str:
        """Get deduplication key for this result."""
        extracted_keys = ",".join(sorted(self.extracted_data.keys())) if self.matched else ""
        content = f"{self.template_id}:{self.target}:{self.matched}:{extracted_keys}"
        return hashlib.sha256(content.encode()).hexdigest()


@dataclass
class ExecutionContext:
    """Context for template execution."""
    target: str
    target_url: str
    template_id: str
    variables: Dict[str, Any] = field(default_factory=dict)
    previous_results: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 10
    retries: int = 3
    proxy: Optional[str] = None
    rate_limiter: Optional[Any] = None


@dataclass
class ScannerOptions:
    """Configuration options for scanner."""
    templates_path: str
    targets: List[str]
    concurrency: int = 10
    timeout: int = 10
    retries: int = 3
    verify_ssl: bool = True
    proxy: Optional[str] = None
    user_agent: str = "VulnerabilityScanner/1.0"
    rate_limit: float = 0.0  # 0 = unlimited, >0 = requests per second
    include_tags: List[str] = field(default_factory=list)
    exclude_tags: List[str] = field(default_factory=list)
    output_file: Optional[str] = None
    output_format: str = "json"  # json, html, csv, jsonl
    deduplicate: bool = True
    max_results: Optional[int] = None
    verbose: bool = False
    debug: bool = False
