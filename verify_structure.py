#!/usr/bin/env python3
"""
Verification script to check the restructured project structure.
Run from project root: python verify_structure.py
"""

import os
import sys
from pathlib import Path

def check_file(path: Path, description: str = "") -> bool:
    """Check if file exists and print status."""
    exists = path.exists()
    status = "✓" if exists else "✗"
    desc = f" ({description})" if description else ""
    print(f"  {status} {path}{desc}")
    return exists

def check_dir(path: Path, description: str = "") -> bool:
    """Check if directory exists and print status."""
    exists = path.is_dir()
    status = "✓" if exists else "✗"
    desc = f" ({description})" if description else ""
    print(f"  {status} {path}/{desc}")
    return exists

def main():
    root = Path(__file__).parent
    os.chdir(root)
    
    print("\n" + "="*60)
    print("PROJECT RESTRUCTURING VERIFICATION")
    print("="*60 + "\n")
    
    all_ok = True
    
    # Check main directories
    print("Directory Structure:")
    all_ok &= check_dir(root / "backend", "Main backend")
    all_ok &= check_dir(root / "backend/app", "FastAPI application")
    all_ok &= check_dir(root / "backend/scanners", "Scanner adapters")
    all_ok &= check_dir(root / "backend/assets", "Assets directory")
    all_ok &= check_dir(root / "tools", "Isolated external tools")
    
    print("\nTool Directories:")
    all_ok &= check_dir(root / "backend/secscan", "Advanced secscan module")
    all_ok &= check_dir(root / "backend/vuln_scanner", "Template vulnerability scanner")
    all_ok &= check_dir(root / "tools", "External tools directory")
    
    print("\nAssets Structure:")
    all_ok &= check_dir(root / "backend/assets/outputs", "Outputs")
    all_ok &= check_dir(root / "backend/assets/logs", "Logs")
    all_ok &= check_dir(root / "backend/assets/temp", "Temp")
    
    print("\nScanner Implementation Files:")
    all_ok &= check_file(root / "backend/scanners/__init__.py", "Package init")
    all_ok &= check_file(root / "backend/scanners/base.py", "Abstract base scanner")
    all_ok &= check_dir(root / "backend/scanners/scanner1", "Scanner1 (template-based)")
    all_ok &= check_dir(root / "backend/scanners/scanner2", "Scanner2 (security audit)")
    all_ok &= check_dir(root / "backend/scanners/custom_scanner", "CustomScanner implementation")
    all_ok &= check_file(root / "backend/scanners/orchestrator.py", "Central orchestrator")
    
    print("\nService & Route Files:")
    all_ok &= check_file(root / "backend/app/services/scanning.py", "Scanning service")
    all_ok &= check_file(root / "backend/app/routes/scanning.py", "Scanning API routes")
    all_ok &= check_file(root / "backend/app/routes/auth.py", "Auth routes (fixed imports)")
    all_ok &= check_file(root / "backend/app/routes/report.py", "Report routes (fixed imports)")
    all_ok &= check_file(root / "backend/app/routes/dependencies.py", "Route dependencies (fixed imports)")
    
    print("\nCore Configuration:")
    all_ok &= check_file(root / "backend/app/core/config.py", "Configuration")
    all_ok &= check_file(root / "backend/app/main.py", "App factory")
    
    print("\nPackage Initializers:")
    all_ok &= check_file(root / "backend/__init__.py")
    all_ok &= check_file(root / "backend/app/__init__.py")
    all_ok &= check_file(root / "backend/app/services/__init__.py")
    all_ok &= check_file(root / "backend/app/routes/__init__.py")
    all_ok &= check_file(root / "backend/app/core/__init__.py")
    all_ok &= check_file(root / "tools/__init__.py")
    
    print("\nDocumentation:")
    all_ok &= check_file(root / "README.md", "Project README")
    all_ok &= check_file(root / "ARCHITECTURE.md", "Architecture docs")
    all_ok &= check_file(root / "IMPLEMENTATION_GUIDE.md", "Implementation guide")
    
    print("\n" + "="*60)
    if all_ok:
        print("✓ All structure verification checks PASSED!")
        print("\nNext Steps:")
        print("  1. Start API: uvicorn backend.app.main:app --reload")
        print("  2. Test: curl http://localhost:8000/api/scan/scanners")
        print("  3. Check API docs: http://localhost:8000/docs")
        sys.exit(0)
    else:
        print("✗ Some structure verification checks FAILED!")
        print("\nPlease fix the missing files/directories and try again.")
        sys.exit(1)

if __name__ == "__main__":
    main()
