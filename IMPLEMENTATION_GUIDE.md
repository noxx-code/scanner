# Implementation Guide

## Quick Reference

### 1. Running the Application

```bash
# Start the API server
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000

# In another terminal, test it
curl http://localhost:8000/api/scan/scanners
```

### 2. Test Endpoints

```bash
# List available scanners
curl http://localhost:8000/api/scan/scanners

# Run Nuclei scan
curl "http://localhost:8000/api/scan/run?target=http://example.com&scanner=nuclei"

# Run all scanners
curl "http://localhost:8000/api/scan/run?target=http://example.com"

# With timeout (600 seconds)
curl "http://localhost:8000/api/scan/run?target=http://example.com&timeout=600"

# Get scan status
curl "http://localhost:8000/api/scan/status/{scan_id}"
```

### 3. Using Programmatically

```python
from backend.app.core.config import get_config
from backend.app.services.scanning import ScanningService
import asyncio

async def main():
    config = get_config()
    service = ScanningService(config)
    
    # Single scanner
    result = await service.scan_target("http://example.com", scanner_name="nuclei")
    
    # All scanners
    result = await service.scan_target("http://example.com")
    
    print(f"Findings: {result['findings_count']}")
    print(f"Duration: {result['total_duration_seconds']}s")

asyncio.run(main())
```

## Troubleshooting Checklist

- [ ] All `backend/` subdirectories have `__init__.py` files
- [ ] `tools/` directory contains `nuclei/`, `secscan/`, `custom_scanner/`
- [ ] `backend/assets/` directory exists with subdirectories
- [ ] `backend/app/core/config.py` has correct tool paths
- [ ] FastAPI and uvicorn are installed: `pip install fastapi uvicorn[standard]`
- [ ] Python 3.8+ is being used

### Check Tool Paths

```python
from backend.app.core.config import Config
import os

config = Config()
print("NUCLEI_BIN:", config.NUCLEI_BIN, "→", os.path.exists(config.NUCLEI_BIN))
print("SECSCAN_PATH:", config.SECSCAN_PATH, "→", os.path.isdir(config.SECSCAN_PATH))
print("CUSTOM_SCANNER_PATH:", config.CUSTOM_SCANNER_PATH, "→", os.path.isdir(config.CUSTOM_SCANNER_PATH))
```

### Check API Server

```bash
# Should return health status
curl http://localhost:8000/health

# Should return scanner list
curl http://localhost:8000/api/scan/scanners
```

## Common Issues

### "ModuleNotFoundError: No module named 'backend'"

**Solution:** Run from project root:
```bash
cd scanner
python -m uvicorn backend.app.main:app --reload
```

### "Scanner not found" / Empty scanner list

**Solution:** Check tool paths in config:
```python
# backend/app/core/config.py
NUCLEI_BIN = TOOLS_ROOT / "nuclei" / "nuclei-dev" / "nuclei"
SECSCAN_PATH = TOOLS_ROOT / "secscan"
CUSTOM_SCANNER_PATH = TOOLS_ROOT / "custom_scanner"
```

Adjust paths if tools are in different locations.

### "FileNotFoundError: [Errno 2] No such file or directory"

**Solution:** Ensure assets directory exists:
```bash
mkdir -p backend/assets/{outputs,logs,temp}/{nuclei,secscan,custom_scanner}
```

### Scan timeout or takes forever

**Solution:** Check scanner tool availability:
```bash
ls -la tools/nuclei/
ls -la tools/secscan/
ls -la tools/custom_scanner/

# Test tools directly
tools/nuclei/nuclei-dev/nuclei -h
python -m secscan --help
```

## File Structure Verification

```bash
# Verify backend structure
find backend -type f -name "__init__.py"
# Should output:
# backend/__init__.py
# backend/app/__init__.py
# backend/app/core/__init__.py
# backend/app/routes/__init__.py
# backend/app/services/__init__.py
# backend/app/models/__init__.py
# backend/app/db/__init__.py
# backend/scanners/__init__.py
# backend/assets/ (dir structure exists)

# Verify tools structure
ls -la tools/
# Should output:
# nuclei/
# secscan/
# custom_scanner/

# Verify scanner files
ls -la backend/scanners/
# Should output:
# __init__.py
# base.py
# nuclei.py
# secscan.py
# custom_scanner.py
# orchestrator.py
```

## Integration Steps

### Step 1: Verify Structure

```bash
# From project root
ls -la backend/app/main.py
ls -la backend/scanners/orchestrator.py
ls -la tools/nuclei/
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Start API Server

```bash
uvicorn backend.app.main:app --reload
```

### Step 4: Test Endpoints

```bash
# In new terminal
curl http://localhost:8000/api/scan/scanners

# Should show:
# {
#   "status": "success",
#   "scanners": [...]
# }
```

### Step 5: Run Test Scan

```bash
curl "http://localhost:8000/api/scan/run?target=http://example.com&scanner=nuclei&timeout=60"

# Should show scan results
```

## Extending with New Scanner

### Create Runner

Create `backend/scanners/my_scanner.py`:

```python
from pathlib import Path
from backend.scanners.base import BaseRunner, ScanResult
import asyncio
import json
from datetime import datetime
import uuid

class MyRunnerRunner(BaseRunner):
    def __init__(self, assets_dir: Path, tool_path: Path):
        super().__init__("my_scanner", assets_dir)
        self.tool_path = Path(tool_path)
    
    def validate_target(self, target: str) -> bool:
        return target.startswith(('http://', 'https://'))
    
    async def run(self, target: str, **kwargs) -> ScanResult:
        scan_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        try:
            # Run your scanner tool
            cmd = [str(self.tool_path), target]
            stdout, stderr, returncode = await self._execute_subprocess(cmd)
            
            # Parse results
            findings = json.loads(stdout) if stdout else []
            
            return ScanResult(
                scan_id=scan_id,
                scanner="my_scanner",
                target=target,
                status="success",
                findings=findings,
                findings_count=len(findings),
                duration_seconds=(datetime.utcnow() - start_time).total_seconds(),
                timestamp=start_time.isoformat(),
                error=None,
                raw_output=stdout
            )
        except Exception as e:
            return ScanResult(
                scan_id=scan_id,
                scanner="my_scanner",
                target=target,
                status="failed",
                findings=[],
                findings_count=0,
                duration_seconds=(datetime.utcnow() - start_time).total_seconds(),
                timestamp=start_time.isoformat(),
                error=str(e),
                raw_output=None
            )
```

### Register in Orchestrator

Edit `backend/scanners/orchestrator.py`:

```python
from backend.scanners.my_scanner import MyRunnerRunner
from enum import Enum

class ScannerType(Enum):
    NUCLEI = "nuclei"
    SECSCAN = "secscan"
    CUSTOM_SCANNER = "custom_scanner"
    MY_SCANNER = "my_scanner"  # ADD

class ScanOrchestrator:
    def __init__(self, config):
        # ... existing code ...
        
        # Add MY_SCANNER registration
        tool_path = getattr(config, 'MY_SCANNER_PATH', None)
        if tool_path and tool_path.exists():
            self.runners[ScannerType.MY_SCANNER] = MyRunnerRunner(self.assets_dir, tool_path)
```

### Add Configuration

Edit `backend/app/core/config.py`:

```python
class Config:
    # ... existing paths ...
    
    # Add new scanner path
    MY_SCANNER_PATH = TOOLS_ROOT / "my_scanner"  # Add this line
```

### Place Tool in `/tools/`

```bash
# Copy or link your scanner tool
cp -r /path/to/my_scanner tools/my_scanner
# OR
ln -s /path/to/my_scanner tools/my_scanner
```

### Done!

Your scanner is now available:

```bash
# See all scanners
curl http://localhost:8000/api/scan/scanners

# Run with new scanner
curl "http://localhost:8000/api/scan/run?target=http://example.com&scanner=my_scanner"
```

## Configuration Files

### Environment Variables (`.env`)

```bash
# Application
ENVIRONMENT=development
DEBUG=True
LOG_LEVEL=INFO
SECRET_KEY=your-secret-key-change-in-production

# Scanning
SCAN_TIMEOUT=300
MAX_CONCURRENT_SCANS=5
SCAN_JSON_ENDPOINTS=true

# Database
DATABASE_URL=sqlite+aiosqlite:///./scanner.db

# API
API_PREFIX=/api
```

### Configuration Class (`backend/app/core/config.py`)

Paths are automatically resolved:

```python
from pathlib import Path
import os

class Config:
    # Base paths
    BASE_DIR = Path(__file__).parent.parent.parent
    TOOLS_ROOT = BASE_DIR / "tools"
    
    # Scanner paths (auto-detected, errors handled)
    NUCLEI_BIN = TOOLS_ROOT / "nuclei" / "nuclei-dev" / "nuclei"
    SECSCAN_PATH = TOOLS_ROOT / "secscan"
    CUSTOM_SCANNER_PATH = TOOLS_ROOT / "custom_scanner"
    
    # Assets
    ASSETS_DIR = Path(__file__).parent.parent / "assets"
    OUTPUT_DIR = ASSETS_DIR / "outputs"
    LOGS_DIR = ASSETS_DIR / "logs"
    TEMP_DIR = ASSETS_DIR / "temp"
```

## Logging

All scan operations are logged to `backend/assets/logs/{scanner}/`:

```bash
# Check logs
cat backend/assets/logs/nuclei/*.log
cat backend/assets/logs/secscan/*.log
cat backend/assets/logs/custom_scanner/*.log

# Tail logs in real-time
tail -f backend/assets/logs/nuclei/*.log
```

## Performance Tips

### Parallel Scanning

All scanners run in parallel by default:

```python
# This runs all scanners concurrently (much faster!)
result = await service.scan_target("http://example.com")
```

### Sequential Scanning (if needed)

```python
# Run one scanner at a time
for scanner_name in ["nuclei", "secscan", "custom_scanner"]:
    result = await service.scan_target("http://example.com", scanner_name=scanner_name)
    print(result)
```

### Timeout Control

```bash
# 10 minute timeout
curl "http://localhost:8000/api/scan/run?target=http://example.com&timeout=600"

# 5 minute timeout (default)
curl "http://localhost:8000/api/scan/run?target=http://example.com"
```

## Debugging

### Enable Debug Logging

In `.env`:
```bash
DEBUG=True
LOG_LEVEL=DEBUG
```

### Check Scanner Availability

```python
from backend.app.core.config import get_config
from backend.app.services.scanning import ScanningService
import asyncio

async def main():
    config = get_config()
    service = ScanningService(config)
    scanners = await service.get_available_scanners()
    for scanner in scanners:
        print(f"{scanner['name']}: {scanner['available']}")

asyncio.run(main())
```

### Verify Tool Execution

```bash
# Test nuclei directly
tools/nuclei/nuclei-dev/nuclei -h

# Test secscan directly
python -m secscan --help

# Test custom scanner directly
python tools/custom_scanner/__main__.py --help
```

## Production Deployment

### 1. Set Environment to Production

```bash
ENVIRONMENT=production
DEBUG=False
LOG_LEVEL=WARNING
SECRET_KEY=your-strong-secret-key-min-32-chars
```

### 2. Use Production ASGI Server

```bash
# Install gunicorn
pip install gunicorn

# Run with gunicorn (4 workers)
gunicorn backend.app.main:app -w 4 -b 0.0.0.0:8000
```

### 3. Configure SSL/TLS

```bash
# Generate self-signed cert (for testing)
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

# Use with gunicorn
gunicorn --certfile=cert.pem --keyfile=key.pem backend.app.main:app -b 0.0.0.0:8443
```

### 4. Set Up Monitoring

Monitor these directories:

```bash
backend/assets/logs/      # Scan logs
backend/assets/outputs/   # Scan results
```

### 5. Backup Assets

```bash
# Daily backup of results
tar -czf backup-$(date +%Y%m%d).tar.gz backend/assets/
```

## Support & Documentation

- **API Docs:** http://localhost:8000/docs (Swagger)
- **ReDoc:** http://localhost:8000/redoc
- **Architecture:** See `ARCHITECTURE.md`
- **README:** See `README.md`

---

**Happy scanning!** 🔍✨
