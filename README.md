# Security Scanner - Restructured Architecture

## Overview

This project has been restructured for clean architecture and modularity. The main components are:

- **Backend API** (`backend/app/`) - FastAPI web application
- **Scanner Orchestration** (`backend/scanners/`) - Unified scanner adapter layer
- **External Tools** (`tools/`) - Isolated scanner tools (not modified)
- **Assets** (`backend/assets/`) - Scan outputs and logs

![Landing Page](https://github.com/user-attachments/assets/903c2d07-ae00-4343-9dd0-175590356e77)

## Features

- **Authentication** — Register, login, logout with bcrypt password hashing and JWT tokens; brute-force protection (account locked after 5 failed attempts in 5 minutes)
- **Web Crawler** — BFS crawler that discovers internal pages, query parameters, HTML forms, and common API endpoints up to a configurable depth (max 5), with robots.txt support (enabled by default, configurable per scan)
- **Vulnerability Scanner** — Non-intrusive checks for reflected XSS, SQLi signatures/time heuristics, open redirects, directory listing exposure, missing security headers, insecure cookies, and technology/version disclosure
- **Rate-Limited Scanning** — Request pacing and retry/backoff controls to reduce load on target systems
- **Reporting Dashboard** — HTML/JS dashboard with scan history, vulnerability details modal, plus JSON and HTML export

### Modular CLI Security Scanner (secscan)

This repository now also includes a standalone modular scanner package for authorized web application testing:

- `secscan/crawler` — BFS crawler with link/form/query/JS endpoint extraction, depth, duplicate filtering, domain scope, robots.txt support, and rate limiting
- `secscan/fingerprint` — server/framework/library detection with version extraction and mock vulnerable-version matching
- `secscan/scanner` — async queue-based scanner core with plugin execution
- `secscan/checks` — plugin checks for OWASP-style findings (passive + light active)
- `secscan/reporter` — JSON/HTML/CSV reporting with summary stats and severity filtering
- `secscan/utils` — shared config, models, logging, HTTP, and session persistence for resume support

Security checks implemented as plugins:

- Headers check
- SSL/TLS certificate check
- Cookie security check
- Input reflection check (XSS indicator)
- SQL error exposure check
- Open redirect check
- Directory and file exposure check
- Sensitive data exposure scan
- JavaScript analysis
- CORS misconfiguration check

---

## Project Structure (Restructured)

```
scanner/
├── backend/                      # Main application
│   ├── app/                     # FastAPI application
│   │   ├── main.py             # App factory and ASGI entry
│   │   ├── core/
│   │   │   └── config.py       # Configuration management
│   │   ├── routes/
│   │   │   ├── __init__.py
│   │   │   ├── scanning.py     # Scanner API routes
│   │   │   ├── auth.py         # Auth routes
│   │   │   └── report.py       # Report routes
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   └── scanning.py     # Scanning service
│   │   ├── models/             # Data models
│   │   ├── db/                 # Database layer
│   │   ├── templates/          # Jinja2 templates
│   │   └── static/             # CSS, JS, images
│   │
│   ├── scanners/               # Core scanner implementations
│   │   ├── __init__.py
│   │   ├── base.py            # BaseScanner interface
│   │   ├── orchestrator.py    # Central coordinator
│   │   ├── scanner1/          # Template-based scanner
│   │   ├── scanner2/          # Security audit scanner
│   │   └── custom_scanner/    # Input validation scanner
│   │
│   ├── secscan/               # Advanced security scanner module
│   │   ├── crawler/           # Web crawling
│   │   ├── fingerprint/       # Tech detection
│   │   ├── checks/            # Security checks
│   │   ├── reporter/          # Report generation
│   │   ├── scanner/           # Scanning engine
│   │   ├── utils/             # Utilities
│   │   ├── cli.py             # CLI interface
│   │   └── __main__.py        # Module entry point
│   │
│   ├── vuln_scanner/          # Template-driven vulnerability scanner
│   │   ├── core/              # Engine & template loader
│   │   ├── dsl/               # Domain-specific language
│   │   ├── operators/         # Matchers & extractors
│   │   ├── protocols/         # HTTP executor
│   │   ├── cache/             # Caching system
│   │   ├── reporting/         # Report exporters
│   │   ├── utils/             # Utilities
│   │   ├── cli.py             # CLI interface
│   │   └── __main__.py        # Module entry point
│   │
│   └── assets/                # Scan outputs and logs
│       ├── outputs/           # Results directory
│       ├── logs/              # Log files
│       └── temp/              # Temporary files
│
├── tools/                      # External tools
│   └── [other tools]           # Not modified
│
├── requirements.txt            # Dependencies
└── README.md                   # This file
```

---

## Architecture

### Layered Design

```
HTTP Request
    ↓
FastAPI Route (/api/scan/run)
    ↓
Scanning Service (Business Logic)
    ↓
Scan Orchestrator (Manages Scanner1, Scanner2, CustomScanner)
    ↓
Individual Scanners:
├── Scanner1 (Template-based: nuclei-like)
├── Scanner2 (Security audit: secscan-like)
├── CustomScanner (Input validation)
├── secscan module (Advanced crawling, fingerprinting, checks)
└── vuln_scanner module (Template-driven engine)
    ↓
Results → backend/assets/outputs/
Logs → backend/assets/logs/
    ↓
HTTP Response (JSON)
```

### Key Components

1. **BaseScanner** (`backend/scanners/base.py`) - Abstract interface for all scanners
2. **ScanOrchestrator** (`backend/scanners/orchestrator.py`) - Coordinates multiple scanners
3. **Scanner Implementations**:
   - Scanner1: Template-based vulnerability detection
   - Scanner2: Security configuration auditing
   - CustomScanner: Input validation testing
4. **Advanced Modules** (integrated from separate directories):
   - secscan: Full-featured security scanner with crawler, fingerprinting, checks
   - vuln_scanner: Template-driven vulnerability engine
5. **Service Layer** (`backend/app/services/scanning.py`) - Business logic
6. **API Routes** (`backend/app/routes/scanning.py`) - HTTP endpoints
7. **Configuration** (`backend/app/core/config.py`) - Centralized settings

---

## Quick Start

### 1. Installation

```bash
# Clone and setup
git clone https://github.com/noxx-code/scanner.git
cd scanner
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

Copy environment template:

```bash
cp .env.example .env
```

Configure paths in `backend/app/core/config.py` if needed:

```python
NUCLEI_BIN = TOOLS_ROOT / "nuclei" / "nuclei-dev" / "nuclei"
SECSCAN_PATH = TOOLS_ROOT / "secscan"
CUSTOM_SCANNER_PATH = TOOLS_ROOT / "custom_scanner"
```

### 3. Run the API Server

```bash
# Using uvicorn
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000

# Or directly
python -m backend.app.main
```

Access API at **http://localhost:8000**

### 4. Check Available Scanners

```bash
curl http://localhost:8000/api/scan/scanners
```

### 5. Run a Scan

```bash
# Single scanner
curl "http://localhost:8000/api/scan/run?target=http://example.com&scanner=nuclei"

# All scanners
curl "http://localhost:8000/api/scan/run?target=http://example.com"
```

---

## API Endpoints

### Scanner Management

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/scan/scanners` | List available scanners |
| `POST` | `/api/scan/run` | Run scan (query params: target, scanner, timeout) |
| `GET` | `/api/scan/status/{scan_id}` | Get scan status |

### Example Request

```bash
curl -X POST "http://localhost:8000/api/scan/run?target=http://example.com&timeout=300"
```

Response:

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "target": "http://example.com",
  "total_scanners": 3,
  "successful_scanners": 3,
  "total_findings": 12,
  "unique_findings": [...],
  "total_duration_seconds": 125.5,
  "scanner_results": {
    "nuclei": {
      "status": "success",
      "findings_count": 5,
      "duration_seconds": 45.2
    },
    "secscan": {
      "status": "success",
      "findings_count": 4,
      "duration_seconds": 32.1
    },
    "custom_scanner": {
      "status": "success",
      "findings_count": 3,
      "duration_seconds": 48.2
    }
  },
  "errors": []
}
```
|---|---|---|---|
| `GET` | `/reports` | Bearer | List all scans for the current user |
| `GET` | `/reports/{id}` | Bearer | Full report for one scan |
| `GET` | `/reports/{id}/json` | Bearer | Structured JSON report with summary, severity counts, and remediation |
| `GET` | `/reports/{id}/html` | Bearer | Printable HTML report export |
| `DELETE` | `/reports/{id}` | Bearer | Delete one scan report and related vulnerabilities |

Interactive docs: **http://localhost:8000/docs**

---

## Adding a New Scanner

To integrate a new scanner:

### 1. Create a Runner

Create `backend/scanners/my_scanner.py`:

```python
from pathlib import Path
from backend.scanners.base import BaseRunner, ScanResult

class MyRunnerRunner(BaseRunner):
    def __init__(self, assets_dir: Path, tool_path: Path):
        super().__init__("my_scanner", assets_dir)
        self.tool_path = Path(tool_path)
    
    def validate_target(self, target: str) -> bool:
        return target.startswith(('http://', 'https://'))
    
    async def run(self, target: str, **kwargs) -> ScanResult:
        # Implement scanning logic
        # Return ScanResult with findings
        pass
```

### 2. Add to Orchestrator

Update `backend/scanners/orchestrator.py`:

```python
from backend.scanners.my_scanner import MyRunnerRunner

# In __init__:
tool_path = getattr(config, 'MY_SCANNER_PATH', None)
if tool_path:
    self.runners[ScannerType.MY_SCANNER] = MyRunnerRunner(self.assets_dir, tool_path)
```

### 3. Update Configuration

Edit `backend/app/core/config.py`:

```python
MY_SCANNER_PATH = TOOLS_ROOT / "my_scanner"
```

### 4. Done!

Scanner is now available via API automatically.

---

## Using Programmatically

```python
from backend.app.core.config import get_config
from backend.app.services.scanning import ScanningService
import asyncio

async def main():
    config = get_config()
    service = ScanningService(config)
    
    # Run specific scanner
    result = await service.scan_target("http://example.com", scanner_name="nuclei")
    
    # Run all scanners
    result = await service.scan_target("http://example.com")
    
    print(f"Findings: {result['findings_count']}")

asyncio.run(main())
```

---

## Configuration

Set environment variables or update `.env`:

```bash
ENVIRONMENT=development      # development, production, testing
LOG_LEVEL=INFO              # INFO, DEBUG, WARNING
SECRET_KEY=your-secret      # Change in production
SCAN_TIMEOUT=300            # Seconds
MAX_CONCURRENT_SCANS=5      # Parallel scans
DATABASE_URL=sqlite:///./scanner.db
```

---

## File Organization

### What's New

- `backend/scanners/` - Adapter layer (isolated from tools)
- `backend/app/services/scanning.py` - Scanning service
- `backend/app/routes/scanning.py` - Scanner API routes
- `backend/assets/` - Structured output/log storage
- `tools/` - Isolated external tools (unchanged)

### What Moved

```
secscan/ → tools/secscan/
vuln_scanner/ → tools/custom_scanner/
nuclei-extracted/ → tools/nuclei/
app/ → backend/app/
```

All external tools are preserved exactly as-is.

---

## Troubleshooting

### Scanners Not Found

Check configuration:

```python
from backend.app.core.config import Config
print(Config.NUCLEI_BIN)
print(Config.SECSCAN_PATH)
print(Config.CUSTOM_SCANNER_PATH)
```

Verify paths exist:

```bash
ls tools/nuclei/
ls tools/secscan/
ls tools/custom_scanner/
```

### Import Errors

Ensure all `__init__.py` files exist:

```bash
find backend -type d -exec touch {}/__init__.py \;
```

### API Not Starting

Install FastAPI:

```bash
pip install fastapi uvicorn[standard]
```

### Empty Scan Results

Check logs in `backend/assets/logs/{scanner}/`:

```bash
cat backend/assets/logs/nuclei/*.log
```

Check tool availability:

```bash
curl http://localhost:8000/api/scan/scanners
```

---

## Design Principles

✅ **Separation of Concerns** - HTTP handling, business logic, tool interaction isolated
✅ **No Tight Coupling** - Tools called via subprocess, easy to replace
✅ **Easy Extension** - Add scanner: inherit BaseRunner, done
✅ **Clean Architecture** - Domain logic independent of frameworks
✅ **Adapter Pattern** - Normalize tool-specific details
✅ **Orchestrator Pattern** - Central coordination point

---

## Security Notes

- **Isolation** - External tools run in separate processes
- **No Modification** - Tool code is never modified
- **Path Validation** - All URLs validated before scanning
- **Timeout** - Scans timeout to prevent hanging
- **Permissions** - Always require explicit permission to scan targets

---

## Original Features

The original application includes:

- **Authentication** - Register, login with JWT tokens
- **Web Crawler** - BFS crawler with form/endpoint discovery
- **Built-in Scanner** - XSS, SQLi, open redirects
- **Dashboard** - Scan history and results
- **Reporting** - HTML/JSON exports

These features are preserved in `backend/app/` and can be accessed as before.

---

## Screenshots

| Register | Dashboard |
|---|---|
| ![Register](https://github.com/user-attachments/assets/8c5fb872-078c-4543-8a09-97f2e7120f0b) | ![Dashboard](https://github.com/user-attachments/assets/6cfaff4c-63a0-4d82-bce3-a1fa74c38295) |

---

## Security Notes

- Passwords are stored as **bcrypt** hashes — plain-text passwords are never persisted.
- JWTs are signed with HS256; the `SECRET_KEY` **must** be changed before deploying.
- Scanner payloads are *diagnostic only* — they do not write, delete, or modify data on the target.
- Always obtain explicit permission before scanning any target.