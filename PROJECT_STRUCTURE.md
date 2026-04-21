# Project Structure Guide - Python Security Scanner System

## Quick Navigation

### Documentation Files (Read These First!)
```
PROJECT_ROOT/
├── PYTHON_SYSTEM_GUIDE.md          ← Start here! Comprehensive guide
├── API_USAGE_GUIDE.md              ← API reference and examples
├── IMPLEMENTATION_SUMMARY.md       ← Project overview and status
├── examples_quick_start.py         ← Runnable code examples
└── README.md                       ← Original project readme
```

### Scanner Implementation
```
backend/scanners/
├── base.py                         ← Unified scanner interface
├── orchestrator.py                 ← Scanner coordinator
├── nuclei/                         ← Template-based scanner
│   ├── __init__.py
│   ├── engine.py
│   └── templates/
│       └── default.yaml            ← 12 vulnerability templates
├── secscan/                        ← Security audit scanner
│   ├── __init__.py
│   └── engine.py
└── custom_scanner/                ← Input validation scanner
    ├── __init__.py
    └── engine.py
```

### API & Service Layer
```
backend/app/
├── services/
│   └── scanning.py                 ← Service layer for scanning
└── routes/
    └── scanning.py                 ← REST API endpoints
```

---

## File Descriptions

### Core Scanner Files

#### `backend/scanners/base.py` (~150 LOC)
**Purpose**: Define unified scanner interface

**Key Classes**:
- `Finding` - Individual vulnerability representation
- `ScanResult` - Complete scan result with findings
- `BaseScanner` - Abstract base class for all scanners

**Important Methods**:
- `validate_target(target)` - Abstract method to validate URL
- `async run(target)` - Abstract method to execute scan
- `_create_result()` - Factory for creating consistent results
- `to_dict()` / `to_json()` - Serialization methods

**Example Usage**:
```python
from backend.scanners.base import BaseScanner

class MyScanner(BaseScanner):
    def validate_target(self, target):
        return target.startswith("http")
    
    async def run(self, target):
        findings = []  # Perform scan
        return self._create_result(target, findings=findings)
```

---

#### `backend/scanners/nuclei/engine.py` (~250 LOC)
**Purpose**: Template-based vulnerability detection

**Key Classes**:
- `NucleiScanner` - Main scanner implementation

**Key Methods**:
- `_load_templates()` - Load YAML templates from disk
- `run(target)` - Async main scanning method
- `_run_template(template)` - Execute single template
- `_execute_request(request)` - HTTP request execution
- `_evaluate_matcher(response, matcher)` - Matcher evaluation

**Supported Matchers**:
- `status: [200, 301, 404]` - HTTP status codes
- `keywords: ["vulnerable", "error"]` - String matching
- `regex: ["pattern.*here"]` - Regex patterns
- `headers: {X-Header: value}` - Header matching

**Template Format** (YAML):
```yaml
id: template-id
name: Template Name
description: What it detects
severity: high|medium|low

requests:
  - path: /endpoint
    method: GET
    matchers:
      - status: [200]
      - keywords: ["vulnerable"]
```

---

#### `backend/scanners/nuclei/templates/default.yaml` (12 templates)
**Purpose**: Built-in vulnerability detection patterns

**Included Templates**:
1. `info-disclosure` - Debug pages
2. `missing-security-headers` - Missing HTTP security headers
3. `known-vuln-response` - Known error patterns
4. `sql-injection-indicators` - SQL errors
5. `open-redirect` - Redirect vulnerabilities
6. `directory-listing` - Directory enumeration
7. `exposed-admin-panel` - Admin path detection
8. `weak-ssl-tls` - SSL/TLS issues
9. `xss-detection` - Reflected XSS
10. `csrf-token-missing` - CSRF token absence
11. `sensitive-data-exposure` - Data leakage patterns
12. `config-exposure` - Config file exposure

---

#### `backend/scanners/secscan/engine.py` (~280 LOC)
**Purpose**: Security header and configuration validation

**Key Classes**:
- `SecscanScanner` - Security scanner implementation

**Checks Performed**:
- Missing security headers (X-Frame-Options, CSP, HSTS)
- SSL/TLS configuration weakness
- Insecure cookie flags
- Technology disclosure
- Exposed paths and admin panels

**Key Methods**:
- `_check_security_headers()` - Header validation
- `_check_ssl_tls()` - SSL/TLS configuration
- `_check_cookies()` - Cookie security
- `_check_framework_disclosure()` - Framework detection
- `_check_common_vulnerabilities()` - Path enumeration

---

#### `backend/scanners/custom_scanner/engine.py` (~280 LOC)
**Purpose**: Input validation and basic vulnerability testing

**Key Classes**:
- `CustomScanner` - Input validation scanner

**Checks Performed**:
- Reflected XSS in query parameters
- SQL injection indicators
- Path traversal attempts
- Open redirect vulnerabilities

**Key Methods**:
- `_check_xss()` - Payload reflection detection
- `_check_sqli()` - SQL error detection
- `_check_path_traversal()` - File access testing
- `_check_open_redirect()` - Redirect chain testing

---

#### `backend/scanners/orchestrator.py` (~200 LOC)
**Purpose**: Coordinate all scanners and aggregate results

**Key Classes**:
- `ScanOrchestrator` - Main coordinator
- `ScannerType` - Enum of scanner types

**Key Methods**:
- `run_single(scanner_name, target)` - Run one scanner
- `run_all(target)` - Run all scanners concurrently
- `run_selected(target, scanner_names)` - Run specific scanners
- `aggregate_results(results)` - Combine findings

**Features**:
- Concurrent execution using asyncio
- Result deduplication
- Error handling
- Severity aggregation

**Usage Example**:
```python
from backend.scanners.orchestrator import ScanOrchestrator

orchestrator = ScanOrchestrator()
results = await orchestrator.run_all("https://example.com")
aggregated = orchestrator.aggregate_results(results)
```

---

### Service & API Files

#### `backend/app/services/scanning.py` (~250 LOC)
**Purpose**: Business logic layer for scanning operations

**Key Classes**:
- `ScanningService` - Main service class

**Key Methods**:
- `scan_target(target, scanner_name)` - Main entry point
- `get_available_scanners()` - List available scanners
- `_format_result(result)` - Format for API
- `_aggregate_results(results)` - Combine multiple results

**Responsibilities**:
- Input validation
- Service instantiation
- Result formatting
- Error handling

**Usage in API**:
```python
service = ScanningService()
result = await service.scan_target("https://example.com")
```

---

#### `backend/app/routes/scanning.py` (~100 LOC)
**Purpose**: REST API endpoints for scanning

**Endpoints**:

1. `GET /api/scan/scanners`
   - List available scanners
   - No parameters
   - Returns: Scanner list with descriptions

2. `GET /api/scan/run`
   - Execute scan
   - Parameters: `target` (required), `scanner` (optional), `timeout` (optional)
   - Returns: Scan results with findings

3. `GET /api/scan/status/{scan_id}`
   - Get scan status
   - Parameter: `scan_id` in path
   - Returns: Status information

4. `GET /api/scan/health`
   - Health check
   - No parameters
   - Returns: Health status and available scanners

**Error Handling**:
- 400: Invalid input (bad URL format, etc.)
- 404: Not found
- 500: Server error during scan

---

### Documentation Files

#### `PYTHON_SYSTEM_GUIDE.md` (~500 lines)
**Contents**:
- Architecture overview
- Component descriptions
- Usage examples (API and programmatic)
- Template creation guide
- Custom scanner development
- Configuration guide
- Deployment instructions
- Troubleshooting
- Future enhancements

**Read When**: Need comprehensive understanding of system

---

#### `API_USAGE_GUIDE.md` (~400 lines)
**Contents**:
- REST endpoint reference
- Request/response examples
- Python client examples
- Error handling patterns
- Integration examples
- Performance tips
- CI/CD integration
- Response field reference

**Read When**: Building API clients or integrating with other systems

---

#### `IMPLEMENTATION_SUMMARY.md` (~400 lines)
**Contents**:
- Project completion status
- Technical architecture overview
- Component breakdown
- Performance benchmarks
- Extensibility guide
- Security considerations
- Dependencies
- Migration path
- Testing recommendations
- Future roadmap

**Read When**: Need project overview or planning enhancements

---

#### `examples_quick_start.py` (~200 lines)
**Contents**:
- 7 runnable example scenarios
- Single scanner usage
- All scanners execution
- Selected scanners
- Scanner availability check
- Target validation
- Result formatting
- Error handling

**Run When**: Want to see practical usage patterns
```bash
python examples_quick_start.py
```

---

## Directory Tree (Complete)

```
scanner/
│
├── Documentation
│   ├── PYTHON_SYSTEM_GUIDE.md           ← Start here!
│   ├── API_USAGE_GUIDE.md
│   ├── IMPLEMENTATION_SUMMARY.md
│   ├── ARCHITECTURE.md                  (old)
│   └── README.md
│
├── Examples & Tests
│   ├── examples_quick_start.py
│   ├── examples/
│   │   └── sample_report.json
│   └── tests/                           (optional)
│
├── Scanner Implementation
│   └── backend/
│       └── scanners/
│           ├── base.py                  (unified interface)
│           ├── orchestrator.py          (coordinator)
│           ├── nuclei/
│           │   ├── __init__.py
│           │   ├── engine.py            (template scanner)
│           │   └── templates/
│           │       └── default.yaml     (12 templates)
│           ├── secscan/
│           │   ├── __init__.py
│           │   └── engine.py            (security checks)
│           └── custom_scanner/
│               ├── __init__.py
│               └── engine.py            (input validation)
│
├── API & Services
│   └── backend/
│       └── app/
│           ├── main.py                  (FastAPI app)
│           ├── services/
│           │   └── scanning.py          (service layer)
│           └── routes/
│               └── scanning.py          (API endpoints)
│
├── Configuration & Dependencies
│   ├── requirements.txt
│   ├── .env                             (optional)
│   └── pyproject.toml                   (optional)
│
├── Legacy (Do Not Use)
│   ├── nuclei-extracted/                (REMOVED)
│   ├── secscan/                         (moved to backend/scanners)
│   ├── vuln_scanner/                    (REMOVED)
│   └── tools/                           (REMOVED)
│
└── Utilities
    ├── .gitignore
    ├── LICENSE
    └── setup.py                         (optional)
```

---

## How to Use This Structure

### For API Users
1. Read: **API_USAGE_GUIDE.md**
2. Start API: `uvicorn backend.app.main:app --reload`
3. Test endpoints: Use curl or Postman
4. Integrate: Follow Python client examples

### For Developers
1. Read: **PYTHON_SYSTEM_GUIDE.md**
2. Review: **base.py** for interface
3. Study: **nuclei/engine.py** for implementation example
4. Run: **examples_quick_start.py** to see usage
5. Extend: Create new scanner inheriting from `BaseScanner`

### For DevOps/Deployment
1. Read: **IMPLEMENTATION_SUMMARY.md**
2. Install: `pip install -r requirements.txt`
3. Configure: Environment variables if needed
4. Deploy: Use Docker or systemd
5. Monitor: Check `/api/scan/health` endpoint

### For Operations/Maintenance
1. Reference: **PYTHON_SYSTEM_GUIDE.md** troubleshooting section
2. Logs: Enable debug logging for diagnostics
3. Templates: Add new YAML files to `templates/` directory
4. Monitoring: Check system health and scan performance

---

## Important Notes

### ⚠️ What Was Removed
- ❌ `nuclei-extracted/` (Go binary)
- ❌ Old `secscan/` and `vuln_scanner/` at root
- ❌ `tools/` directory (external binaries)
- ❌ All subprocess-based execution
- ❌ Config file-based configuration

### ✅ What Was Added
- ✅ Pure Python implementations
- ✅ Unified `BaseScanner` interface
- ✅ Template-based configuration (YAML)
- ✅ Async/concurrent execution
- ✅ Comprehensive documentation
- ✅ Production-ready API

### ⚡ Key Changes from v1.0 to v2.0
- Architecture: Subprocess → Pure Python
- Interface: Tool-specific → Unified BaseScanner
- Execution: Sequential → Concurrent async/await
- Configuration: Config files → Environment variables
- API: Simple endpoints → RESTful with proper status codes

---

## Next Steps

1. **Read Documentation**
   - Start: PYTHON_SYSTEM_GUIDE.md
   - API Details: API_USAGE_GUIDE.md
   - Project Status: IMPLEMENTATION_SUMMARY.md

2. **Run Examples**
   ```bash
   python examples_quick_start.py
   ```

3. **Start API Server**
   ```bash
   uvicorn backend.app.main:app --reload
   ```

4. **Test Endpoints**
   ```bash
   curl http://localhost:8000/api/scan/scanners
   curl "http://localhost:8000/api/scan/run?target=https://example.com"
   ```

5. **Extend System** (optional)
   - Add custom templates to `backend/scanners/nuclei/templates/`
   - Create new scanner by implementing `BaseScanner`
   - Register new scanner in `orchestrator.py`

---

## Support References

| Need | Reference | Location |
|------|-----------|----------|
| General Overview | PYTHON_SYSTEM_GUIDE.md | Root directory |
| API Reference | API_USAGE_GUIDE.md | Root directory |
| Project Status | IMPLEMENTATION_SUMMARY.md | Root directory |
| Code Examples | examples_quick_start.py | Root directory |
| Base Interface | backend/scanners/base.py | Source code |
| Scanner Example | backend/scanners/nuclei/engine.py | Source code |
| Templates | backend/scanners/nuclei/templates/default.yaml | Source code |
| API Endpoints | backend/app/routes/scanning.py | Source code |
| Service Logic | backend/app/services/scanning.py | Source code |

---

**Version**: 2.0  
**Status**: Production Ready  
**Last Updated**: January 2024
# Proposed Project Structure (Tree View)

This is the target structure after complete restructuring (Phase 5).

```
scanner/
│
├── 📦 core/                              # SHARED UTILITIES (Framework-agnostic)
│   ├── __init__.py
│   ├── config.py                         # ✅ Unified configuration (replaces 2)
│   │   └── AppConfig, HttpConfig, CrawlerConfig, ScannerConfig, etc.
│   │
│   ├── models.py                         # ✅ Unified domain models (replaces 3)
│   │   ├── Endpoint
│   │   ├── Finding (single model, used everywhere)
│   │   ├── Scan
│   │   ├── Severity, VulnerabilityType, ScanStatus
│   │   └── to_dict() serialization
│   │
│   ├── http.py                           # ✅ Unified HTTP client (replaces duplicates)
│   │   ├── AsyncRateLimiter (SINGLE implementation)
│   │   ├── HttpClientFactory
│   │   ├── RateLimitedHttpClient
│   │   └── create_http_client(), create_rate_limited_client()
│   │
│   ├── deduplication.py                  # ✅ Centralized dedup (consolidates scattered functions)
│   │   ├── DeduplicationStrategy
│   │   ├── EndpointDeduplicator
│   │   ├── FindingDeduplicator
│   │   └── Deduplicator (unified API)
│   │
│   ├── exceptions.py                     # Custom exceptions
│   │   ├── ScanError
│   │   ├── CrawlError
│   │   ├── PluginError
│   │   └── ValidationError
│   │
│   └── logging.py                        # Centralized logging setup
│       └── get_logger(), setup_logging()
│
│
├── 🧠 domain/                            # PURE BUSINESS LOGIC (No framework imports!)
│   ├── __init__.py
│   │
│   ├── crawler/                          # Web crawling
│   │   ├── __init__.py
│   │   ├── engine.py                    # CrawlerEngine
│   │   │   └── async def crawl(url, config) → list[Endpoint]
│   │   ├── extractor.py                 # LinkExtractor, ParamExtractor
│   │   ├── robots.py                    # robots.txt handling
│   │   └── models.py                    # CrawlerConfig, crawl results
│   │
│   ├── scanner/                          # Vulnerability scanning
│   │   ├── __init__.py
│   │   ├── engine.py                    # ScannerEngine
│   │   │   └── async def scan(endpoints, plugins) → list[Finding]
│   │   ├── plugin.py                    # Plugin base class & interface
│   │   ├── executor.py                  # PluginExecutor (execution strategy)
│   │   ├── deduplicator.py              # FindingDeduplicator
│   │   └── models.py                    # ScannerConfig, results
│   │
│   ├── plugins/                          # Security check plugins (unified interface)
│   │   ├── __init__.py
│   │   ├── base.py                      # Plugin protocol/interface
│   │   ├── registry.py                  # PluginRegistry (auto-discovery)
│   │   │
│   │   ├── xss/
│   │   │   ├── __init__.py
│   │   │   ├── detector.py
│   │   │   ├── payloads.py
│   │   │   └── test_payloads.py
│   │   │
│   │   ├── sqli/
│   │   │   ├── __init__.py
│   │   │   ├── detector.py
│   │   │   ├── payloads.py
│   │   │   └── test_payloads.py
│   │   │
│   │   ├── open_redirect/
│   │   │   ├── __init__.py
│   │   │   ├── detector.py
│   │   │   └── payloads.py
│   │   │
│   │   ├── directory_exposure/
│   │   │   ├── __init__.py
│   │   │   └── detector.py
│   │   │
│   │   ├── insecure_headers/
│   │   │   ├── __init__.py
│   │   │   └── detector.py
│   │   │
│   │   └── ... (other plugins)
│   │
│   ├── reporter/                        # Result processing & reporting
│   │   ├── __init__.py
│   │   ├── engine.py                   # ReporterEngine
│   │   │   ├── aggregate_findings()
│   │   │   ├── generate_report()
│   │   │   └── calculate_severity_distribution()
│   │   │
│   │   ├── exporter.py                 # Exporter interface
│   │   │
│   │   └── exporters/
│   │       ├── __init__.py
│   │       ├── json_exporter.py
│   │       ├── html_exporter.py
│   │       ├── csv_exporter.py
│   │       ├── markdown_exporter.py
│   │       └── sarif_exporter.py
│   │
│   └── job/                            # Scan job lifecycle (async task management)
│       ├── __init__.py
│       ├── models.py                   # ScanJob, JobStatus
│       ├── repository.py               # JobRepository (abstraction for storage)
│       ├── queue.py                    # JobQueue (abstraction for messaging)
│       └── executor.py                 # JobExecutor (orchestration)
│
│
├── 🔌 adapters/                         # FRAMEWORK-SPECIFIC IMPLEMENTATIONS
│   ├── __init__.py
│   │
│   ├── http/                            # HTTP client adapter
│   │   ├── __init__.py
│   │   ├── httpx_client.py             # httpx implementation
│   │   ├── rate_limiter.py             # Rate limiting adapter
│   │   └── middleware.py               # Request/response middleware
│   │
│   ├── database/                        # Data persistence adapter
│   │   ├── __init__.py
│   │   ├── models.py                   # SQLAlchemy ORM models
│   │   │   ├── FindingORM
│   │   │   ├── ScanORM
│   │   │   └── UserORM
│   │   │
│   │   ├── repository.py               # Repository implementations
│   │   │   ├── FindingRepository
│   │   │   ├── ScanRepository
│   │   │   └── UserRepository
│   │   │
│   │   ├── mappers.py                  # ORM ↔ Domain model converters
│   │   │   ├── finding_to_orm()
│   │   │   ├── orm_to_finding()
│   │   │   └── ... (other converters)
│   │   │
│   │   └── migrations/                 # Alembic migrations
│   │       ├── versions/
│   │       └── env.py
│   │
│   ├── fastapi_app.py                  # FastAPI app factory
│   │   └── create_app() → FastAPI
│   │
│   ├── cli_app.py                      # Click CLI app factory
│   │   └── create_cli() → click.Group
│   │
│   └── logging.py                      # Logging adapter
│       └── setup_logging(config)
│
│
├── 🌐 api/                              # FASTAPI HTTP API
│   ├── __init__.py
│   ├── main.py                          # FastAPI app factory & setup
│   │   └── create_app(config: AppConfig) → FastAPI
│   │
│   ├── middleware.py                    # Request/response middleware
│   │   ├── ErrorHandlerMiddleware
│   │   ├── AuthMiddleware
│   │   ├── LoggingMiddleware
│   │   └── CorsMiddleware
│   │
│   ├── dependencies.py                  # FastAPI dependency injection
│   │   ├── get_current_user()
│   │   ├── get_scanner_engine()
│   │   ├── get_crawler_engine()
│   │   └── get_db_session()
│   │
│   ├── schemas.py                       # Pydantic request/response models
│   │   ├── ScanRequestSchema
│   │   ├── ScanResponseSchema
│   │   ├── FindingResponseSchema
│   │   └── ... (other schemas)
│   │
│   └── routes/
│       ├── __init__.py
│       ├── scan.py                      # POST /scan, GET /scan/{id}
│       │   └── scan(), get_scan(), list_scans()
│       │
│       ├── auth.py                      # Authentication endpoints
│       │   └── login(), register(), logout()
│       │
│       ├── reports.py                   # Report endpoints
│       │   └── export_report(), generate_report()
│       │
│       ├── health.py                    # Health check
│       │   └── health_check()
│       │
│       └── templates.py                 # Template endpoints (for vuln_scanner)
│           └── list_templates(), upload_template()
│
│
├── ⌨️  cli/                              # CLICK CLI
│   ├── __init__.py
│   ├── main.py                          # CLI entry point & group
│   │   └── @click.group()
│   │
│   ├── formatters.py                    # Rich output formatters
│   │   ├── format_findings()
│   │   ├── format_scan_progress()
│   │   └── format_report()
│   │
│   └── commands/
│       ├── __init__.py
│       ├── scan.py                      # scan command
│       │   └── @click.command('scan')
│       │
│       ├── template.py                  # template command (vuln_scanner integration)
│       │   ├── list_templates()
│       │   └── validate_template()
│       │
│       ├── config.py                    # config command
│       │   └── show_config(), set_config()
│       │
│       └── report.py                    # report command
│           └── export_report()
│
│
├── 🎨 static/                           # Web UI assets
│   ├── css/
│   │   ├── bootstrap.min.css
│   │   ├── style.css
│   │   └── dashboard.css
│   │
│   ├── js/
│   │   ├── jquery.min.js
│   │   ├── app.js
│   │   ├── dashboard.js
│   │   └── scanner.js
│   │
│   └── images/
│       └── logo.png
│
│
├── 📝 templates/                        # Jinja2 templates
│   ├── base.html
│   ├── dashboard.html
│   ├── scan_detail.html
│   ├── login.html
│   ├── register.html
│   └── report.html
│
│
├── ✅ tests/                            # TEST SUITE
│   ├── __init__.py
│   ├── conftest.py                      # Pytest configuration & fixtures
│   │
│   ├── unit/                            # Unit tests (pure logic, no I/O)
│   │   ├── __init__.py
│   │   ├── test_config.py
│   │   ├── test_models.py
│   │   ├── test_http.py
│   │   ├── test_deduplication.py
│   │   ├── crawler/
│   │   │   ├── test_extractor.py
│   │   │   └── test_robots.py
│   │   ├── scanner/
│   │   │   ├── test_engine.py
│   │   │   ├── test_executor.py
│   │   │   └── test_deduplicator.py
│   │   └── plugins/
│   │       ├── test_xss.py
│   │       ├── test_sqli.py
│   │       └── test_open_redirect.py
│   │
│   ├── integration/                    # Integration tests (domain + adapters)
│   │   ├── __init__.py
│   │   ├── test_crawler_integration.py
│   │   ├── test_scanner_integration.py
│   │   ├── test_plugin_integration.py
│   │   ├── test_api_endpoints.py
│   │   ├── test_cli_commands.py
│   │   └── test_database_layer.py
│   │
│   ├── e2e/                            # End-to-end tests (full workflow)
│   │   ├── __init__.py
│   │   ├── test_scan_workflow.py
│   │   ├── test_api_workflow.py
│   │   └── test_cli_workflow.py
│   │
│   └── fixtures/
│       ├── __init__.py
│       ├── http_server.py               # Mock HTTP server
│       ├── sample_data.py               # Test data
│       ├── payloads.py                  # Test payloads
│       └── mocks.py                     # Mock objects
│
│
├── ⚙️  config/                          # Configuration files
│   ├── settings.base.py                 # Base settings
│   ├── settings.dev.py                  # Development settings
│   ├── settings.prod.py                 # Production settings
│   └── settings.test.py                 # Test settings
│
│
├── 🐳 Docker/                           # Containerization
│   ├── Dockerfile
│   ├── Dockerfile.dev
│   ├── docker-compose.yml
│   ├── docker-compose.dev.yml
│   └── .dockerignore
│
│
├── 📚 Documentation
│   ├── README.md                        # Main README
│   ├── ARCHITECTURE.md                  # Architecture overview
│   ├── API.md                          # API documentation
│   ├── PLUGINS.md                      # Plugin development guide
│   ├── DEPLOYMENT.md                   # Deployment guide
│   ├── CODEBASE_ANALYSIS.md            # Analysis document (this restructuring)
│   ├── PHASE_1_IMPLEMENTATION.md       # Phase 1 implementation guide
│   ├── ARCHITECTURE_DIAGRAMS.md        # Visual architecture
│   └── README_RESTRUCTURING.md         # Executive summary
│
│
├── .env.example                         # Environment variables template
├── .env.test                            # Test environment
├── .gitignore
├── .dockerignore
├── pyproject.toml                       # Project metadata
├── setup.py                             # Installation script
├── setup.cfg                            # Setup configuration
├── Makefile                             # Common commands
├── requirements.txt                     # Production dependencies
├── requirements-dev.txt                 # Development dependencies
├── pytest.ini                           # Pytest configuration
└── LICENSE
```

---

## Key Improvements in New Structure

### 1. **Clear Separation of Concerns**

```
domain/               ← Pure business logic, no framework
adapters/            ← Framework-specific implementations
api/ + cli/          ← Thin controllers/commands
core/                ← Shared utilities
```

### 2. **Eliminates All Duplicates**

```
Before:
  ❌ AsyncRateLimiter in 3 places
  ❌ Crawler logic in 2 places
  ❌ Finding model in 3 places
  ❌ Dedup functions scattered

After:
  ✅ AsyncRateLimiter in core/http.py (used everywhere)
  ✅ CrawlerEngine in domain/crawler/ (single source)
  ✅ Finding in core/models.py (single model)
  ✅ Deduplicator in core/deduplication.py (unified)
```

### 3. **Enables Clean Testing**

```
tests/unit/               ← Test domain logic in isolation (fast)
tests/integration/        ← Test domain + adapters (medium)
tests/e2e/               ← Test full workflows (slow, rare)
tests/fixtures/          ← Shared test utilities
```

### 4. **Dependency Injection Ready**

```
api/dependencies.py      ← FastAPI Depends() providers
cli/commands/            ← Click @pass_obj providers
adapters/               ← Adapter factories
```

### 5. **Plugin System Unified**

```
domain/plugins/          ← All plugins use same interface
domain/plugins/base.py   ← Plugin protocol
registry.py              ← Auto-discovery

Before: SecurityCheck, ScannerPlugin, Finding contracts
After: Single Plugin interface
```

### 6. **Database Abstraction**

```
core/models.py           ← Domain models (no ORM)
adapters/database/models.py  ← ORM models
adapters/database/repository.py ← Data access layer

Before: ORM models in app/models/, business logic tied to DB
After: Domain logic independent, adapters handle persistence
```

---

## File Count Summary

| Category | Before | After | Change |
|----------|--------|-------|--------|
| **Duplicated Files** | 5-7 | 0 | -100% ✅ |
| **Core/Shared** | 2 | 4 | +2 (consolidated) |
| **Domain** | 8 | 12+ | +4 (extracted) |
| **Adapters** | 3 | 6 | +3 (separated) |
| **API** | 5 | 6 | +1 (organized) |
| **CLI** | 2 | 3 | +1 (organized) |
| **Tests** | 3 | 15+ | +12 (comprehensive) |
| **Documentation** | 1 | 7 | +6 (complete) |
| **Total** | ~35 | ~50 | More organized, less duplicate |

---

## Migration Path

### Step 1: Create new structure (already done)
```bash
mkdir -p scanner/{core,domain,adapters,api,cli,tests}
```

### Step 2: Implement core/ (Phase 1)
- Copy shared logic from app/ and secscan/ to core/
- Update imports to use core/
- Run tests to validate

### Step 3: Extract domain/ (Phase 2)
- Copy business logic from app/services/ to domain/
- Create unified plugin interface
- Migrate existing plugins

### Step 4: Create adapters/ (Phase 3)
- Create FastAPI adapter
- Create database adapter
- Create CLI adapter

### Step 5: Migrate routes/commands (Phase 4)
- Migrate api/routes/ to use domain/
- Migrate cli/commands/ to use domain/
- Delete old implementations

### Step 6: Cleanup (Phase 5)
- Delete secscan/ folder
- Delete duplicate code in app/
- Final testing and validation

---

## Files to Delete After Migration

```
OLD IMPLEMENTATIONS (DELETE):
❌ secscan/          (entire folder - replaced by domain/ + cli/)
❌ app/core/config.py        (replaced by core/config.py)
❌ app/services/crawler.py   (replaced by domain/crawler/)
❌ app/services/scanner.py   (replaced by domain/scanner/)
❌ app/services/scanning/    (replaced by domain/)
❌ Duplicate dedup functions (replaced by core/deduplication.py)
❌ Duplicate HTTP clients    (replaced by core/http.py)
```

---

## Usage Examples After Migration

### Python API Usage (Domain Logic)

```python
from scanner.core import get_config, Endpoint, Finding
from scanner.domain.crawler import CrawlerEngine
from scanner.domain.scanner import ScannerEngine
from scanner.domain.plugins import PluginRegistry

config = get_config()

# Crawl a target
crawler = CrawlerEngine(config.crawler)
endpoints = await crawler.crawl("http://target.com")

# Scan with plugins
scanner = ScannerEngine(config.scanner)
plugins = PluginRegistry.load_all()
findings = await scanner.scan(endpoints, plugins)

# Export results
from scanner.domain.reporter import ReporterEngine
reporter = ReporterEngine()
report = reporter.generate_report(findings)
```

### FastAPI Usage

```python
# api/main.py
from fastapi import FastAPI
from scanner.adapters.fastapi_app import create_app

app = create_app()

# Then: uvicorn api.main:app --reload
```

### CLI Usage

```bash
# Scan a target
python -m scanner.cli scan --url http://target.com --output results.json

# List plugins
python -m scanner.cli template list

# Export report
python -m scanner.cli report export --scan-id <id> --format html
```

