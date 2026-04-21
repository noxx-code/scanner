# Architecture Documentation

## Overview

The scanner project has been restructured using **Clean Architecture** principles with clear separation of concerns:

- **External Tools Isolation** - Scanners in `/tools/` remain untouched
- **Adapter Pattern** - Scanner runners normalize different tool outputs
- **Orchestrator Pattern** - Central coordinator manages multiple scanners
- **Layered Architecture** - API → Service → Orchestrator → Runners → Tools

## Directory Structure

```
scanner/
│
├── backend/                           # Main application backend
│   ├── app/                          # FastAPI application
│   │   ├── main.py                  # Application factory & ASGI entry
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── config.py            # Configuration & paths
│   │   │   ├── security.py          # JWT, bcrypt, authentication
│   │   │   └── logging_config.py    # Logging setup
│   │   ├── db/
│   │   │   ├── __init__.py
│   │   │   └── database.py          # SQLAlchemy async engine
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── user.py              # User ORM model
│   │   │   └── scan.py              # Scan & Vulnerability models
│   │   ├── routes/
│   │   │   ├── __init__.py
│   │   │   ├── auth.py              # Authentication endpoints
│   │   │   ├── scan.py              # Original scanning endpoints
│   │   │   ├── report.py            # Report endpoints
│   │   │   ├── dependencies.py      # FastAPI dependencies
│   │   │   └── scanning.py          # NEW: Scanner orchestration API
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── crawler.py           # Web crawler service
│   │   │   ├── scanner.py           # Original scanner service
│   │   │   └── scanning.py          # NEW: Orchestrated scanning service
│   │   ├── templates/               # Jinja2 templates
│   │   └── static/                  # CSS, JS, images
│   │
│   ├── scanners/                     # NEW: Scanner orchestration layer
│   │   ├── __init__.py
│   │   │
│   │   ├── base.py                  # Abstract runner interface
│   │   │   ├── ScanResult dataclass       # Unified result format
│   │   │   ├── BaseRunner abstract class  # Common interface
│   │   │   └── Common utilities           # Subprocess, file handling
│   │   │
│   │   ├── nuclei.py                # Nuclei scanner adapter
│   │   │   └── NucleiRunner         # Runs nuclei binary via subprocess
│   │   │
│   │   ├── secscan.py               # SecScan scanner adapter
│   │   │   └── SecscanRunner        # Runs secscan module via subprocess
│   │   │
│   │   ├── custom_scanner.py        # Custom scanner adapter
│   │   │   └── CustomScannerRunner  # Runs custom scanner via subprocess
│   │   │
│   │   └── orchestrator.py          # Central scanner coordinator
│   │       ├── ScannerType enum     # Scanner type constants
│   │       └── ScanOrchestrator     # Runs multiple scanners concurrently
│   │
│   └── assets/                       # NEW: Scan outputs & logs
│       ├── outputs/                 # Scan result files
│       │   ├── nuclei/              # Nuclei result files
│       │   ├── secscan/             # SecScan result files
│       │   └── custom_scanner/      # Custom scanner result files
│       ├── logs/                    # Execution logs
│       │   ├── nuclei/
│       │   ├── secscan/
│       │   └── custom_scanner/
│       └── temp/                    # Temporary files
│
├── tools/                            # NEW: Isolated external tools (unchanged)
│   ├── nuclei/                      # Nuclei binary + related files
│   ├── secscan/                     # SecScan Python package (original)
│   └── custom_scanner/              # Custom scanner (original)
│
├── examples/                         # Example outputs
├── requirements.txt                  # Dependencies
└── README.md                         # Project overview
```

## Execution Flow

### 1. HTTP Request → API Route

```
User Request
    ↓
GET /api/scan/scanners
POST /api/scan/run?target=...&scanner=...
GET /api/scan/status/{scan_id}
    ↓
backend/app/routes/scanning.py
    (Validates input, handles errors)
```

### 2. Route → Service Layer

```
FastAPI Route
    ↓
ScanningService (backend/app/services/scanning.py)
    ├── scan_target(target, scanner_name)
    ├── get_available_scanners()
    └── _aggregate_results()
    ↓
Uses Config to initialize Orchestrator
```

### 3. Service → Orchestrator

```
ScanningService
    ↓
ScanOrchestrator (backend/scanners/orchestrator.py)
    ├── run_single(scanner_type, target)
    ├── run_all(target)
    ├── run_selected(target, scanners)
    └── get_available_scanners()
    ↓
Selects appropriate runners
```

### 4. Orchestrator → Runners

```
ScanOrchestrator
    ↓
Selects Runners based on scanner_type
    ├── NucleiRunner (backend/scanners/nuclei.py)
    ├── SecscanRunner (backend/scanners/secscan.py)
    └── CustomScannerRunner (backend/scanners/custom_scanner.py)
    ↓
Each runner inherited from BaseRunner
```

### 5. Runners → External Tools

```
Runners (inherited from BaseRunner)
    ↓
Subprocess Execution
    ├── tools/nuclei/nuclei binary
    ├── tools/secscan/ Python module
    └── tools/custom_scanner/ Python package
    ↓
Capture stdout/stderr
Parse output to ScanResult dataclass
    ↓
Back to Orchestrator
```

### 6. Results → Response

```
Orchestrator collects results
    ↓
Service aggregates/deduplicates findings
    ↓
Route formats JSON response
    ↓
HTTP Response to User
```

## Key Classes & Interfaces

### BaseRunner (`backend/scanners/base.py`)

Abstract base class defining the runner interface:

```python
class BaseRunner:
    """Abstract base for all scanner runners."""
    
    def __init__(self, scanner_name: str, assets_dir: Path):
        self.scanner_name = scanner_name
        self.output_dir = assets_dir / "outputs" / scanner_name
        self.logs_dir = assets_dir / "logs" / scanner_name
        self.temp_dir = assets_dir / "temp"
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is compatible with this scanner."""
        raise NotImplementedError
    
    async def run(self, target: str, **kwargs) -> ScanResult:
        """Execute scan and return standardized result."""
        raise NotImplementedError
```

### ScanResult (`backend/scanners/base.py`)

Unified result format for all scanners:

```python
@dataclass
class ScanResult:
    """Standardized scan result format."""
    scan_id: str              # Unique scan identifier
    scanner: str              # Scanner name (nuclei, secscan, etc)
    target: str               # Target URL
    status: str              # success, failed, timeout
    findings: List[Dict]     # Unified findings
    findings_count: int      # Number of findings
    duration_seconds: float  # Execution time
    timestamp: str           # ISO timestamp
    error: Optional[str]     # Error message if failed
    raw_output: Optional[str] # Raw tool output
```

### NucleiRunner (`backend/scanners/nuclei.py`)

Runs nuclei binary via subprocess:

```python
class NucleiRunner(BaseRunner):
    """Runner for Nuclei binary."""
    
    def __init__(self, assets_dir: Path, nuclei_bin: Path):
        super().__init__("nuclei", assets_dir)
        self.nuclei_bin = nuclei_bin
    
    async def run(self, target: str, **kwargs) -> ScanResult:
        # Execute nuclei binary
        # Parse NDJSON output
        # Convert to ScanResult
```

### SecscanRunner (`backend/scanners/secscan.py`)

Runs secscan module via subprocess:

```python
class SecscanRunner(BaseRunner):
    """Runner for SecScan Python module."""
    
    async def run(self, target: str, **kwargs) -> ScanResult:
        # Execute secscan CLI
        # Parse JSON output
        # Convert to ScanResult
```

### CustomScannerRunner (`backend/scanners/custom_scanner.py`)

Runs custom scanner via subprocess:

```python
class CustomScannerRunner(BaseRunner):
    """Runner for custom security scanner."""
    
    async def run(self, target: str, **kwargs) -> ScanResult:
        # Execute custom scanner
        # Parse results
        # Convert to ScanResult
```

### ScanOrchestrator (`backend/scanners/orchestrator.py`)

Central coordinator for all scanners:

```python
class ScanOrchestrator:
    """Orchestrates multiple security scanners."""
    
    async def run_single(
        self, 
        scanner_type: ScannerType, 
        target: str
    ) -> ScanResult:
        """Run single scanner."""
    
    async def run_all(self, target: str) -> List[ScanResult]:
        """Run all available scanners concurrently."""
    
    async def run_selected(
        self, 
        target: str, 
        scanners: List[ScannerType]
    ) -> List[ScanResult]:
        """Run specific set of scanners."""
    
    def get_available_scanners(self) -> Dict[str, ScannerInfo]:
        """List available scanners with status."""
```

### ScanningService (`backend/app/services/scanning.py`)

High-level business logic:

```python
class ScanningService:
    """Scanning business logic layer."""
    
    async def scan_target(
        self,
        target: str,
        scanner_name: Optional[str] = None,
        timeout: int = 300
    ) -> Dict:
        """Scan target with specified scanner(s)."""
    
    async def get_available_scanners(self) -> Dict:
        """Get list of available scanners."""
    
    def _aggregate_results(
        self,
        results: List[ScanResult]
    ) -> Dict:
        """Aggregate and deduplicate findings."""
```

## Configuration Management

### Config Class Hierarchy

```
Config (base class)
    ├── ENVIRONMENT
    ├── DEBUG
    ├── LOG_LEVEL
    │
    ├── Paths (scanner tools)
    │   ├── NUCLEI_BIN
    │   ├── SECSCAN_PATH
    │   └── CUSTOM_SCANNER_PATH
    │
    ├── Assets (outputs & logs)
    │   ├── ASSETS_DIR
    │   ├── OUTPUT_DIR
    │   ├── LOGS_DIR
    │   └── TEMP_DIR
    │
    └── API Settings
        ├── API_PREFIX
        └── CORS_ORIGINS

    ├── DevelopmentConfig
    ├── ProductionConfig
    └── TestingConfig
```

### Path Resolution

```python
TOOLS_ROOT = Path(__file__).parent.parent.parent / "tools"

NUCLEI_BIN = TOOLS_ROOT / "nuclei" / "nuclei-dev" / "nuclei"
SECSCAN_PATH = TOOLS_ROOT / "secscan"
CUSTOM_SCANNER_PATH = TOOLS_ROOT / "custom_scanner"

ASSETS_DIR = Path(__file__).parent.parent / "assets"
OUTPUT_DIR = ASSETS_DIR / "outputs"
LOGS_DIR = ASSETS_DIR / "logs"
TEMP_DIR = ASSETS_DIR / "temp"
```

## API Integration

### Endpoints

```python
@router.get("/api/scan/scanners")
async def get_scanners(service: ScanningService = Depends()):
    """List available scanners."""
    return await service.get_available_scanners()

@router.post("/api/scan/run")
async def run_scan(
    target: str = Query(...),
    scanner: Optional[str] = Query(None),
    timeout: int = Query(300),
    service: ScanningService = Depends()
) -> Dict:
    """Execute scan."""
    return await service.scan_target(target, scanner, timeout)

@router.get("/api/scan/status/{scan_id}")
async def get_status(scan_id: str) -> Dict:
    """Get scan status."""
    # Implementation
```

## Design Patterns Used

### 1. Adapter Pattern

Each scanner has an adapter that:
- Normalizes tool-specific behavior
- Converts tool output to `ScanResult`
- Handles errors gracefully
- Manages subprocess execution

```
External Tool (Nuclei/SecScan/Custom)
    ↓ (adapter layer)
ScanResult (unified format)
    ↓
Higher-level code (doesn't care about specific tool)
```

### 2. Orchestrator Pattern

Central coordinator that:
- Manages multiple runners
- Handles concurrent execution
- Aggregates results
- Provides unified interface

### 3. Service Layer Pattern

Business logic layer that:
- Doesn't depend on HTTP framework
- Coordinates orchestrator
- Handles business rules
- Can be used programmatically or via API

### 4. Factory Pattern

`get_config()` factory creates appropriate config based on environment:

```python
def get_config() -> Config:
    env = os.getenv("ENVIRONMENT", "development")
    if env == "production":
        return ProductionConfig()
    elif env == "testing":
        return TestingConfig()
    else:
        return DevelopmentConfig()
```

## Dependency Injection

Services are injected via FastAPI dependencies:

```python
from fastapi import Depends

def get_service(config: Config = Depends(get_config)) -> ScanningService:
    return ScanningService(config)

@router.post("/api/scan/run")
async def run_scan(service: ScanningService = Depends(get_service)):
    pass
```

## Error Handling

### At Runner Level

- Subprocess execution errors
- Binary not found
- Timeout
- Invalid target format

### At Orchestrator Level

- Runner registration failures
- Aggregation errors
- Concurrent execution failures

### At Service Level

- Input validation
- Configuration issues
- Orchestrator failures

### At Route Level

- HTTP error codes
- User-friendly error messages
- Request validation

## Concurrency

### Async/Await

All runners support async execution:

```python
async def run_all(self, target: str) -> List[ScanResult]:
    """Run all scanners concurrently."""
    tasks = [
        runner.run(target)
        for runner in self.runners.values()
    ]
    return await asyncio.gather(*tasks, return_exceptions=True)
```

### Subprocess Isolation

Each tool runs in separate process:

```python
async def _execute_subprocess(
    self,
    command: List[str],
    timeout: Optional[int] = None
) -> Tuple[str, str, int]:
    """Execute command in subprocess."""
    # Safely run external tool
    # Capture output
    # Handle timeout
```

## Testing Strategy

### Unit Tests

Test individual runners:

```python
@pytest.mark.asyncio
async def test_nuclei_runner():
    runner = NucleiRunner(assets_dir, nuclei_bin)
    result = await runner.run("http://example.com")
    assert isinstance(result, ScanResult)
    assert result.scanner == "nuclei"
```

### Integration Tests

Test orchestrator coordination:

```python
@pytest.mark.asyncio
async def test_orchestrator_run_all():
    orchestrator = ScanOrchestrator(config)
    results = await orchestrator.run_all("http://example.com")
    assert len(results) == 3  # All scanners
```

### API Tests

Test HTTP endpoints:

```python
def test_api_scanners(client):
    response = client.get("/api/scan/scanners")
    assert response.status_code == 200
    assert "nuclei" in response.json()["scanners"]
```

## Performance Considerations

### Concurrent Execution

All scanners run in parallel:

```
Sequential (slow):    [Nuclei: 45s] → [SecScan: 32s] → [Custom: 48s] = 125s
Concurrent (fast):    [All in parallel max(45, 32, 48)] = 48s
```

### Resource Management

- Subprocess pooling (if needed)
- Output file cleanup
- Memory limits per runner
- Timeout enforcement

### Caching (Optional)

Could add:
- Result caching
- Scanner availability caching
- Configuration caching

## Security Considerations

### Isolation

- Each tool in separate process
- No shell injection (using `subprocess.run` with list args)
- Timeouts prevent hanging
- No direct import of tool code

### Validation

- Target URL validation
- Path validation
- Command injection prevention

### Logging

- Errors logged to `backend/assets/logs/`
- Sensitive data filtered
- Execution traces for debugging

## Extensibility

### Adding New Scanner

1. Create runner class inheriting from `BaseRunner`
2. Implement `validate_target()` and `run()` methods
3. Add to orchestrator
4. Immediately available via API

### Adding New Output Format

1. Extend `ScanResult` if needed
2. Update service aggregation logic
3. Update API response format

### Adding New Configuration

1. Add to `Config` class
2. Update environment variable handling
3. Use in components

## File Movement Summary

```
Original → New Location
──────────────────────────────
secscan/ → tools/secscan/       (unchanged)
vuln_scanner/ → tools/custom_scanner/ (unchanged)
nuclei-extracted/ → tools/nuclei/     (unchanged)
app/ → backend/app/             (existing code preserved)

NEW FILES CREATED:
backend/scanners/base.py        (abstract base + dataclasses)
backend/scanners/nuclei.py      (nuclei adapter)
backend/scanners/secscan.py     (secscan adapter)
backend/scanners/custom_scanner.py (custom adapter)
backend/scanners/orchestrator.py (central coordinator)
backend/app/services/scanning.py (scanning service)
backend/app/routes/scanning.py   (scanner API routes)
backend/app/core/config.py      (configuration)
backend/app/main.py             (app factory)
```

## Next Steps

1. **Verification** - Test imports and paths
2. **Integration** - Start API and test endpoints
3. **Validation** - Run test scans through architecture
4. **Documentation** - Add endpoint docs
5. **Monitoring** - Set up logging and alerting
6. **Optimization** - Profile and optimize hot paths
7. **Extension** - Add features as needed

---

**Clean Architecture. Modular Design. Easy Extension.** ✨
