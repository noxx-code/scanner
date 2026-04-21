# API Usage Guide - Python Security Scanner

## Quick Start

### Prerequisites
```bash
pip install fastapi uvicorn httpx pyyaml
```

### Start the API Server
```bash
# Development mode
uvicorn backend.app.main:app --reload

# Production mode
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

The API will be available at `http://localhost:8000`

---

## REST Endpoints

### 1. List Available Scanners
**Endpoint**: `GET /api/scan/scanners`

**Description**: Get list of all available vulnerability scanners

**Example**:
```bash
curl -X GET "http://localhost:8000/api/scan/scanners"
```

**Response (200 OK)**:
```json
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

---

### 2. Run Vulnerability Scan
**Endpoint**: `GET /api/scan/run`

**Description**: Execute a vulnerability scan on target URL

**Query Parameters**:
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | Yes | N/A | Target URL (must start with http:// or https://) |
| `scanner` | string | No | None | Specific scanner to use (nuclei/secscan/custom_scanner). If omitted, runs all |
| `timeout` | integer | No | 30 | HTTP request timeout in seconds |

**Examples**:

**Run all scanners on target**:
```bash
curl -X GET "http://localhost:8000/api/scan/run?target=https://httpbin.org"
```

**Run specific scanner (nuclei)**:
```bash
curl -X GET "http://localhost:8000/api/scan/run?target=https://httpbin.org&scanner=nuclei"
```

**Run with custom timeout**:
```bash
curl -X GET "http://localhost:8000/api/scan/run?target=https://httpbin.org&timeout=60"
```

**Response (200 OK) - All Scanners**:
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "target": "https://httpbin.org",
  "total_scanners": 3,
  "successful_scanners": 3,
  "total_findings": 4,
  "unique_findings": [
    {
      "title": "Missing Security Headers",
      "description": "X-Frame-Options header missing",
      "severity": "medium",
      "type": "missing-header",
      "url": "https://httpbin.org",
      "parameter": null,
      "evidence": "Header 'X-Frame-Options' not found in response",
      "metadata": {}
    },
    {
      "title": "Technology Disclosure: Python",
      "description": "Application reveals use of Python",
      "severity": "low",
      "type": "disclosure",
      "url": "https://httpbin.org",
      "parameter": null,
      "evidence": null,
      "metadata": {}
    }
  ],
  "severity_breakdown": {
    "high": 0,
    "medium": 2,
    "low": 2
  },
  "total_duration_seconds": 12.5,
  "scanner_results": [
    {
      "scanner": "nuclei",
      "status": "success",
      "findings_count": 1,
      "duration_seconds": 5.2,
      "error": null
    },
    {
      "scanner": "secscan",
      "status": "success",
      "findings_count": 2,
      "duration_seconds": 4.8,
      "error": null
    },
    {
      "scanner": "custom_scanner",
      "status": "success",
      "findings_count": 1,
      "duration_seconds": 2.5,
      "error": null
    }
  ],
  "errors": [],
  "status": "completed"
}
```

**Response (200 OK) - Single Scanner**:
```json
{
  "scan_id": "660e8400-e29b-41d4-a716-446655440000",
  "target": "https://httpbin.org",
  "scanner": "nuclei",
  "status": "success",
  "findings": [
    {
      "title": "Directory Listing Enabled",
      "description": "Detects enabled directory listing",
      "severity": "medium",
      "type": "directory-listing",
      "url": "https://httpbin.org/uploads",
      "parameter": null,
      "evidence": null,
      "metadata": {}
    }
  ],
  "findings_count": 1,
  "severity_breakdown": {
    "high": 0,
    "medium": 1,
    "low": 0
  },
  "duration_seconds": 5.2,
  "timestamp": "2024-01-15T10:30:45.123456",
  "error": null
}
```

**Error Response (400 Bad Request)**:
```json
{
  "detail": "Target must start with http:// or https://"
}
```

**Error Response (500 Internal Server Error)**:
```json
{
  "detail": "Scan failed: Connection timeout"
}
```

---

### 3. Get Scan Status
**Endpoint**: `GET /api/scan/status/{scan_id}`

**Description**: Get status of a previously executed scan

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `scan_id` | string | Yes | Scan ID from previous scan response |

**Example**:
```bash
curl -X GET "http://localhost:8000/api/scan/status/550e8400-e29b-41d4-a716-446655440000"
```

**Response (200 OK)**:
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "note": "Scan history requires database integration for persistence"
}
```

---

### 4. Health Check
**Endpoint**: `GET /api/scan/health`

**Description**: Verify API and scanner availability

**Example**:
```bash
curl -X GET "http://localhost:8000/api/scan/health"
```

**Response (200 OK)**:
```json
{
  "status": "healthy",
  "scanners_available": 3,
  "scanners": ["nuclei", "secscan", "custom_scanner"]
}
```

**Response (500 Internal Server Error)**:
```json
{
  "detail": "Health check failed: No scanners available"
}
```

---

## Python Client Examples

### Using Python Requests Library

```python
import requests
import json

BASE_URL = "http://localhost:8000/api/scan"

def list_scanners():
    """Get available scanners"""
    response = requests.get(f"{BASE_URL}/scanners")
    return response.json()

def run_scan(target, scanner=None, timeout=30):
    """Run a scan"""
    params = {
        "target": target,
        "timeout": timeout
    }
    if scanner:
        params["scanner"] = scanner
    
    response = requests.get(f"{BASE_URL}/run", params=params)
    return response.json()

def get_scan_status(scan_id):
    """Get scan status"""
    response = requests.get(f"{BASE_URL}/status/{scan_id}")
    return response.json()

# Usage
if __name__ == "__main__":
    # List scanners
    print("Available Scanners:")
    scanners = list_scanners()
    print(json.dumps(scanners, indent=2))
    
    # Run scan
    print("\nRunning scan...")
    result = run_scan("https://httpbin.org", timeout=60)
    print(f"Found {result['total_findings']} vulnerabilities")
    
    # Show results
    for finding in result['unique_findings']:
        print(f"  - {finding['title']} ({finding['severity']})")
```

### Using Python async/await

```python
import asyncio
import httpx

BASE_URL = "http://localhost:8000/api/scan"

async def run_scan_async(target):
    """Run scan asynchronously"""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{BASE_URL}/run",
            params={"target": target}
        )
        return response.json()

# Usage
async def main():
    result = await run_scan_async("https://httpbin.org")
    print(f"Findings: {result['total_findings']}")

asyncio.run(main())
```

---

## Response Field Reference

### Finding Object
```json
{
  "title": "Vulnerability title",
  "description": "Detailed description of the vulnerability",
  "severity": "high|medium|low",
  "type": "vulnerability-type",
  "url": "https://target.com/path",
  "parameter": "parameter-name or null",
  "evidence": "Proof of vulnerability or null",
  "metadata": {}
}
```

### ScanResult Object
```json
{
  "scan_id": "UUID of the scan",
  "target": "https://target.com",
  "status": "success|partial|failed",
  "findings": [/* Array of Finding objects */],
  "findings_count": 5,
  "severity_breakdown": {
    "high": 1,
    "medium": 3,
    "low": 1
  },
  "duration_seconds": 12.5,
  "timestamp": "2024-01-15T10:30:45.123456",
  "error": "Error message if status is failed"
}
```

---

## Error Handling

### Common Error Cases

**400 Bad Request - Invalid Target**
```bash
curl -X GET "http://localhost:8000/api/scan/run?target=invalid"
```
Response:
```json
{
  "detail": "Target must start with http:// or https://"
}
```

**400 Bad Request - Invalid Scanner Name**
```bash
curl -X GET "http://localhost:8000/api/scan/run?target=https://example.com&scanner=nonexistent"
```
Response: Returns error in scan result

**500 Internal Server Error - Connection Failed**
```bash
curl -X GET "http://localhost:8000/api/scan/run?target=https://unreachable-host.example"
```
Response:
```json
{
  "detail": "Scan failed: [Errno -2] Name or service not known"
}
```

---

## Performance Tips

1. **Concurrent Requests**: Run scans in parallel when needed
   ```python
   import asyncio
   
   async def scan_multiple(targets):
       tasks = [run_scan_async(t) for t in targets]
       return await asyncio.gather(*tasks)
   ```

2. **Timeout Settings**: Adjust timeout based on target responsiveness
   - Slow targets: `timeout=60`
   - Normal targets: `timeout=30` (default)
   - Fast targets: `timeout=15`

3. **Single vs All Scanners**: 
   - Single scanner faster but less comprehensive
   - All scanners provide better coverage but take longer

4. **Result Deduplication**: Results already deduplicated by backend

---

## Integration Examples

### Webhook Integration
```python
import requests
import json

def notify_on_scan_complete(webhook_url, scan_result):
    """Send scan results to webhook"""
    payload = {
        "scan_id": scan_result["scan_id"],
        "target": scan_result["target"],
        "severity_breakdown": scan_result["severity_breakdown"],
        "findings_count": scan_result["total_findings"],
        "timestamp": scan_result.get("timestamp")
    }
    requests.post(webhook_url, json=payload)

# Usage
result = run_scan("https://example.com")
notify_on_scan_complete("https://your-webhook.com/scan-complete", result)
```

### CI/CD Pipeline Integration
```bash
#!/bin/bash

TARGET=$1
FAIL_THRESHOLD=5

# Run scan
RESPONSE=$(curl -s "http://localhost:8000/api/scan/run?target=$TARGET")

# Extract findings count
FINDINGS=$(echo $RESPONSE | jq '.total_findings')

# Fail if too many vulnerabilities found
if [ $FINDINGS -gt $FAIL_THRESHOLD ]; then
  echo "❌ Scan failed: $FINDINGS vulnerabilities found"
  exit 1
else
  echo "✓ Scan passed: $FINDINGS vulnerabilities found"
  exit 0
fi
```

---

## Limits & Quotas

Current implementation has no built-in limits. For production, consider:

- **Rate Limiting**: Limit API requests per IP
- **Timeout**: API requests timeout after 30+ seconds
- **Concurrent Scans**: No hard limit, depends on system resources
- **Result Storage**: No database persistence (in-memory only)

---

## Support

For API issues:
1. Check endpoint URLs and parameters
2. Verify target URL format
3. Check /api/scan/health endpoint
4. Review server logs for errors
5. Ensure dependencies are installed
