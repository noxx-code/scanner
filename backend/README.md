"""
Backend Integrated Modules - Scanner Components
================================================

This directory contains the complete backend system with all scanner modules
integrated from the previous separate directories.

Directory Structure:
├── app/                    - FastAPI application
│   ├── core/              - Configuration and logging
│   ├── routes/            - API endpoints
│   ├── services/          - Business logic layer
│   ├── models/            - Data models
│   ├── db/                - Database models
│   └── main.py            - FastAPI app entry
├── scanners/              - Core scanner implementations
│   ├── base.py            - BaseScanner interface
│   ├── orchestrator.py    - Orchestrator for managing scanners
│   ├── scanner1/          - Template-based scanner (formerly nuclei)
│   ├── scanner2/          - Security audit scanner (formerly secscan)
│   └── custom_scanner/    - Input validation scanner
├── secscan/               - Advanced web security scanner module
│   ├── crawler/           - Web crawling with BFS, robots.txt, rate limiting
│   ├── fingerprint/       - Technology/framework detection
│   ├── checks/            - Security checks (10+ different checks)
│   ├── reporter/          - Report generation (JSON, HTML, CSV)
│   ├── scanner/           - Core scanning engine
│   ├── utils/             - HTTP, config, models, logging
│   ├── cli.py             - Command-line interface
│   └── __main__.py        - Module entry point
├── vuln_scanner/          - Template-driven vulnerability scanner
│   ├── core/              - Engine, template loader, models
│   ├── dsl/               - Domain-specific language for templates
│   ├── operators/         - Matchers, extractors
│   ├── protocols/         - HTTP executor
│   ├── cache/             - Result caching
│   ├── reporting/         - Report exporters
│   ├── utils/             - Utilities
│   ├── cli.py             - Command-line interface
│   └── __main__.py        - Module entry point
└── assets/                - Shared assets

Integration Summary
===================

1. SCANNER MODULES (backend/scanners/)
   - scanner1: Template-based vulnerability detection
   - scanner2: Web application security auditing
   - custom_scanner: Input validation testing
   
   These are managed by the ScanOrchestrator which can run them:
   - Individually
   - In parallel
   - Selectively by name

2. SECSCAN ADVANCED MODULE (backend/secscan/)
   - More sophisticated crawler with scope management
   - Framework/technology fingerprinting
   - 10+ security checks
   - Multi-format reporting
   
   Can be used alongside the main scanners for advanced capabilities

3. VULN_SCANNER TEMPLATE ENGINE (backend/vuln_scanner/)
   - Template-driven vulnerability detection
   - DSL for flexible template creation
   - Pattern matching and extraction
   - Caching system
   
   Alternative or complementary scanning approach

Migration Status
================

✅ nuclei-extracted/    - DELETED (was binary only, using Python Scanner1 instead)
✅ secscan/            - INTEGRATED to backend/secscan/
✅ vuln_scanner/       - INTEGRATED to backend/vuln_scanner/
✅ Imports updated     - All 'from secscan' → 'from backend.secscan'
✅ Scanners renamed    - nuclei → scanner1, secscan → scanner2

API Endpoints
=============

POST /api/scan/run
  - Scan a target with specified scanner(s)
  - Parameters: target, scanner (scanner1/scanner2/custom_scanner)
  - Returns: Findings with severity breakdown

GET /api/scan/list
  - List available scanners and their info
  - Returns: Scanner metadata and availability

Usage Examples
==============

Python - Using ScanOrchestrator:
    from backend.scanners.orchestrator import ScanOrchestrator
    
    orchestrator = ScanOrchestrator()
    
    # Run Scanner1 (template-based)
    result = await orchestrator.run_single("scanner1", "https://example.com")
    
    # Run all scanners in parallel
    results = await orchestrator.run_all("https://example.com", concurrent=True)
    
    # Run specific scanners
    results = await orchestrator.run_selected(
        "https://example.com",
        ["scanner1", "scanner2"]
    )

REST API - Curl:
    # Run default scanners
    curl "http://localhost:8000/api/scan/run?target=https://example.com"
    
    # Run specific scanner
    curl "http://localhost:8000/api/scan/run?target=https://example.com&scanner=scanner1"
    
    # List available scanners
    curl "http://localhost:8000/api/scan/list"

Command Line - Using secscan:
    python -m backend.secscan \\
      --target https://example.com \\
      --depth 2 \\
      --rate-limit 10 \\
      --respect-robots-txt

Command Line - Using vuln_scanner:
    python -m backend.vuln_scanner \\
      --target https://example.com \\
      --templates /path/to/templates \\
      --output results.json

Configuration
==============

Core configuration in backend/app/core/config.py:
- SCANNER1_TIMEOUT
- SCANNER2_TIMEOUT
- REQUEST_TIMEOUT
- LOG_LEVEL
- DATABASE_URL

Next Steps
==========

1. Start the backend:
   uvicorn backend.app.main:app --reload

2. Access the API:
   http://localhost:8000/docs (Swagger UI)
   http://localhost:8000/redoc (ReDoc)

3. Test a scan:
   curl "http://localhost:8000/api/scan/run?target=https://httpbin.org"

4. Run examples:
   python examples_quick_start.py
"""
