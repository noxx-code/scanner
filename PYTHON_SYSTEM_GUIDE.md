# Python-Based Security Scanning System - Complete Implementation Guide

## Overview

This is a **clean, fully Python-based security scanning system** that consolidates multiple vulnerability scanners under a unified interface. It replaces the previous subprocess-based approach with direct Python implementations of scanning engines.

### Key Principles
- **Pure Python**: No external binaries or Go code dependencies
- **Unified Interface**: All scanners implement `BaseScanner` abstract class
- **Template-Based Configuration**: Vulnerability patterns defined in YAML
- **Async/Await**: Native Python async/await for concurrent scanning
- **Simple & Readable**: Prioritizes clarity over complexity

---

## Architecture Overview

### Directory Structure
```
backend/
├── scanners/
│   ├── base.py                      # Unified scanner interface
│   ├── orchestrator.py              # Coordinates all scanners
│   ├── nuclei/
│   │   ├── engine.py               # Simplified Python nuclei implementation
│   │   ├── __init__.py
│   │   └── templates/
│   │       └── default.yaml        # Vulnerability detection templates
│   ├── secscan/
│   │   ├── engine.py               # Security header/config scanner
│   │   └── __init__.py
│   └── custom_scanner/
│       ├── engine.py               # Input validation scanner
│       └── __init__.py
├── app/
│   ├── services/
│   │   └── scanning.py             # High-level scanning service
│   └── routes/
│       └── scanning.py             # FastAPI REST endpoints
```

### Component Responsibilities

#### 1. **Base Scanner Interface** (`backend/scanners/base.py`)
Defines the contract that all scanners must implement.

**Key Classes:**
- `Finding` - Dataclass representing a single vulnerability finding
  - `title`: Vulnerability name
  - `description`: Detailed description
  - `severity`: high/medium/low
  - `type`: Category (xss, sqli, etc.)
  - `url`: Affected URL
  - `parameter`: Affected parameter (if applicable)
  - `evidence`: Proof of vulnerability
  - `metadata`: Additional context

- `ScanResult` - Dataclass for complete scan results
  - `scan_id`: Unique scan identifier
  - `scanner_name`: Name of scanner used
  - `target`: Target URL
  - `status`: success/partial/failed
  - `findings`: List of Finding objects
  - `duration_seconds`: Scan duration
  - `timestamp`: When scan executed
  - `error_message`: Error details if failed

- `BaseScanner` - Abstract base class
  - `validate_target(target)`: Validates URL format
  - `run(target)`: Main async scanning method
  - `_create_result()`: Factory for creating results
  - `severity_breakdown`: Property with finding counts by severity

#### 2. **Nuclei Scanner** (`backend/scanners/nuclei/`)
Template-based vulnerability detection engine.

**How It Works:**
1. Loads YAML templates from `templates/` directory
2. For each template, constructs HTTP requests
3. Evaluates matchers against responses:
   - Status code matching
   - Keyword detection (case-insensitive)
   - Regex pattern matching
   - Header inspection
4. Collects findings and returns aggregated results

**Supported Matchers:**
- **status**: Match HTTP status codes (200, 301, 404, etc.)
- **keywords**: Match strings in response body (case-insensitive)
- **regex**: Match regex patterns in response
- **headers**: Match specific HTTP headers

#### 3. **Secscan Scanner** (`backend/scanners/secscan/`)
Security-focused vulnerability detector.

**Checks Performed:**
- Missing security headers (X-Frame-Options, CSP, etc.)
- Weak SSL/TLS configuration
- Insecure cookie flags
- Framework/technology disclosure
- Exposed paths and admin panels

#### 4. **Custom Scanner** (`backend/scanners/custom_scanner/`)
Input validation and basic vulnerability detector.

**Checks Performed:**
- Reflected XSS in query parameters
- SQL injection indicators
- Path traversal attempts
- Open redirect vulnerabilities

#### 5. **Orchestrator** (`backend/scanners/orchestrator.py`)
Coordinates all scanners and aggregates results.

**Key Methods:**
- `run_single(scanner_name, target)` - Run one scanner
- `run_all(target, concurrent=True)` - Run all scanners
- `run_selected(target, scanner_names)` - Run specific scanners
- `aggregate_results(results)` - Combine and deduplicate findings

#### 6. **Scanning Service** (`backend/app/services/scanning.py`)
High-level business logic layer for API and orchestration.

**Key Methods:**
- `scan_target(target, scanner_name)` - Main entry point
- `get_available_scanners()` - List available scanners
- `_format_result()` - Format for API response
- `_aggregate_results()` - Combine multiple scanner results

#### 7. **API Routes** (`backend/app/routes/scanning.py`)
FastAPI REST endpoints for HTTP access.

---

## Usage Examples

### 1. Running Scans via REST API

**Get Available Scanners**
```bash
GET /api/scan/scanners

Response:
{
  "status": "success",
  "scanners": [
    {
      "name": "nuclei",
      "display_name": "Nuclei",
      "description": "Template-based vulnerability scanner",
      "available": true
    },
    {
      "name": "secscan",
      "display_name": "SecScan",
      "description": "Security header and configuration scanner",
      "available": true
    },
    {
      "name": "custom_scanner",
      "display_name": "Custom Scanner",
      "description": "Input validation and basic vulnerability scanner",
      "available": true
    }
  ]
}
```

**Run All Scanners**
```bash
GET /api/scan/run?target=https://example.com&timeout=30

Response:
{
  "scan_id": "abc123...",
  "target": "https://example.com",
  "total_scanners": 3,
  "successful_scanners": 3,
  "total_findings": 5,
  "unique_findings": [
    {
      "title": "Missing Security Headers",
      "description": "X-Frame-Options header missing",
      "severity": "medium",
      "type": "missing-header",
      "url": "https://example.com",
      "evidence": "Header not found"
    }
  ],
  "severity_breakdown": {
    "high": 1,
    "medium": 3,
    "low": 1
  },
  "total_duration_seconds": 15.3,
  "status": "completed"
}
```

**Run Specific Scanner**
```bash
GET /api/scan/run?target=https://example.com&scanner=nuclei

Response:
{
  "scan_id": "def456...",
  "target": "https://example.com",
  "scanner": "nuclei",
  "status": "success",
  "findings": [...],
  "findings_count": 3,
  "severity_breakdown": {"high": 1, "medium": 2, "low": 0},
  "duration_seconds": 8.5,
  "timestamp": "2024-01-15T10:30:45"
}
```

**Health Check**
```bash
GET /api/scan/health

Response:
{
  "status": "healthy",
  "scanners_available": 3,
  "scanners": ["nuclei", "secscan", "custom_scanner"]
}
```

### 2. Using Scanners Programmatically

**Run Single Scanner**
```python
import asyncio
from backend.scanners.nuclei.engine import NucleiScanner

async def main():
    scanner = NucleiScanner()
    result = await scanner.run("https://example.com")
    
    print(f"Findings: {len(result.findings)}")
    print(f"Status: {result.status}")
    for finding in result.findings:
        print(f"  - {finding.title} ({finding.severity})")

asyncio.run(main())
```

**Run All Scanners**
```python
import asyncio
from backend.scanners.orchestrator import ScanOrchestrator

async def main():
    orchestrator = ScanOrchestrator()
    
    # Run all scanners concurrently
    results = await orchestrator.run_all("https://example.com")
    
    # Aggregate results
    aggregated = orchestrator.aggregate_results(results)
    
    print(f"Total findings: {aggregated['total_findings']}")
    print(f"Severity breakdown: {aggregated['severity_breakdown']}")

asyncio.run(main())
```

**Run Selected Scanners**
```python
import asyncio
from backend.scanners.orchestrator import ScanOrchestrator

async def main():
    orchestrator = ScanOrchestrator()
    
    # Run only nuclei and secscan
    results = await orchestrator.run_selected(
        "https://example.com",
        ["nuclei", "secscan"]
    )
    
    for result in results:
        print(f"{result.scanner_name}: {len(result.findings)} findings")

asyncio.run(main())
```

---

## Creating Custom Vulnerability Templates

Templates are YAML files in `backend/scanners/nuclei/templates/`.

### Template Structure
```yaml
# Basic metadata
id: unique-template-id
name: Display Name
description: What this template detects
severity: high|medium|low
author: your-name

# HTTP requests to execute
requests:
  # First request
  - path: /endpoint
    method: GET
    matchers:
      - status: [200, 301]  # Match status codes
      - keywords:
          - "vulnerable pattern"
          - "error message"
      - regex:
          - "pattern.*to.*match"
      - headers:
          X-Header-Name: expected-value

  # Second request (optional)
  - path: /endpoint?param=value
    method: POST
    matchers:
      - keywords:
          - "confirmed vulnerability"
```

### Complete Example - XSS Detection
```yaml
id: custom-xss
name: Custom XSS Detector
description: Detects reflected XSS in query parameters
severity: high
author: security-team

requests:
  - path: /?search=<img src=x onerror=alert(1)>
    method: GET
    matchers:
      - keywords:
          - "<img src=x onerror=alert(1)>"
```

### Adding to System
1. Create YAML file in `backend/scanners/nuclei/templates/`
2. Restart scanner service (or reload templates)
3. Template automatically included in scans

---

## Creating Custom Scanners

To add a new scanner:

### Step 1: Create Scanner Class
```python
# backend/scanners/my_scanner/engine.py

from backend.scanners.base import BaseScanner, ScanResult, Finding
import asyncio

class MyScanner(BaseScanner):
    def __init__(self, timeout: int = 10):
        super().__init__("my_scanner")
        self.timeout = timeout
    
    def validate_target(self, target: str) -> bool:
        # Validate URL format
        return target.startswith(("http://", "https://"))
    
    async def run(self, target: str, **kwargs) -> ScanResult:
        findings = []
        
        # Perform your scanning logic
        # ... 
        
        return self._create_result(
            target,
            findings=findings,
            status="success"
        )
```

### Step 2: Export Scanner
```python
# backend/scanners/my_scanner/__init__.py

from backend.scanners.my_scanner.engine import MyScanner

__all__ = ["MyScanner"]
```

### Step 3: Register with Orchestrator
Edit `backend/scanners/orchestrator.py`:

```python
from backend.scanners.my_scanner.engine import MyScanner

class ScanOrchestrator:
    def __init__(self):
        self.scanners: Dict[str, BaseScanner] = {
            "nuclei": NucleiScanner(),
            "secscan": SecscanScanner(),
            "custom_scanner": CustomScanner(),
            "my_scanner": MyScanner(),  # Add here
        }
```

---

## Configuration

### Environment Variables
```bash
# Optional: Configure scanner behavior
export NUCLEI_TIMEOUT=30          # Nuclei template timeout
export SECSCAN_TIMEOUT=10         # Secscan timeout
export CUSTOM_SCANNER_TIMEOUT=10  # Custom scanner timeout
```

### Logging Configuration
The system uses Python's standard logging module. Configure via:

```python
import logging
logging.basicConfig(level=logging.INFO)

# Enable debug logging for specific scanner
logging.getLogger("backend.scanners.nuclei").setLevel(logging.DEBUG)
```

---

## Deployment

### Requirements
```
Python 3.8+
FastAPI 0.95+
httpx 0.24+
pyyaml 6.0+
```

### Install Dependencies
```bash
pip install fastapi httpx pyyaml
```

### Run Development Server
```bash
uvicorn backend.app.main:app --reload --port 8000
```

### Run Production Server
```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Docker Deployment
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## Performance Characteristics

### Scan Speed (Approximate)
- **Nuclei**: 5-15 seconds (depends on template count)
- **Secscan**: 3-10 seconds (depends on checks performed)
- **Custom Scanner**: 2-8 seconds (payload-based testing)
- **All Combined**: 5-15 seconds (concurrent execution)

### Resource Usage
- Memory: ~100-200 MB per scan
- CPU: Minimal (mostly waiting for network)
- Network: Varies by target and templates

### Concurrency
- Default: All scanners run concurrently
- Sequential mode available via `concurrent=False`

---

## Troubleshooting

### Scanner Not Starting
**Problem**: ImportError for scanner module
**Solution**: Verify `__init__.py` files exist in all scanner directories

### SSL Certificate Errors
**Problem**: CERTIFICATE_VERIFY_FAILED
**Solution**: 
```python
# Temporarily disable verification (not recommended for production)
async with httpx.AsyncClient(verify=False) as client:
    # scan code
```

### Timeout Issues
**Problem**: Scans hang or timeout
**Solution**: Increase timeout parameter or check target connectivity

### No Findings
**Problem**: Scanner runs but finds nothing
**Possible Causes**:
- Target not vulnerable
- Template patterns don't match
- Response format differs from expectations

---

## Migration from Old System

### Breaking Changes
- No external binaries required (nuclei, secscan executables removed)
- Subprocess calls replaced with direct Python imports
- Scanner configuration simplified (no config files needed)
- Templates now YAML-based (not JSON)

### Migration Path
1. Stop old system
2. Install new Python dependencies
3. Update API clients to use new response format
4. Test with sample targets
5. Deploy new system

---

## Security Considerations

1. **Target Validation**: Always validate input URLs
2. **Rate Limiting**: Implement rate limits on API endpoints
3. **Authentication**: Add API key/JWT authentication
4. **SSL Verification**: Enable SSL verification in production
5. **Logging**: Sanitize sensitive data in logs
6. **Network Segmentation**: Isolate scanner from sensitive systems

---

## Future Enhancements

Potential additions:
- [ ] Database storage for scan results
- [ ] Scheduled/recurring scans
- [ ] Scan result comparisons
- [ ] Custom authentication for target sites
- [ ] Proxy support for scanning
- [ ] Report generation (PDF, HTML)
- [ ] Integration with vulnerability management platforms
- [ ] Machine learning-based finding classification

---

## Support & Contributing

For issues, questions, or contributions:

1. Check existing documentation
2. Review template YAML format
3. Verify scanner implementation follows `BaseScanner` interface
4. Submit detailed logs for debugging

---

## Version History

### v2.0 (Current)
- Pure Python implementation
- Unified scanner interface
- Template-based configuration
- Async/await throughout
- Simplified architecture

### v1.0 (Previous)
- Subprocess-based external tools
- Tool-specific interfaces
- Complex orchestration layer

