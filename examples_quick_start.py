#!/usr/bin/env python3
"""
Quick Start Examples - Python Security Scanner System
Usage: python examples.py
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from backend.scanners.scanner1.engine import Scanner1
from backend.scanners.scanner2.engine import Scanner2
from backend.scanners.custom_scanner.engine import CustomScanner
from backend.scanners.orchestrator import ScanOrchestrator


async def example_1_single_scanner():
    """Example 1: Run a single scanner"""
    print("\n" + "="*60)
    print("EXAMPLE 1: Single Scanner (Scanner1)")
    print("="*60)
    
    scanner = Scanner1()
    target = "https://httpbin.org"
    
    print(f"\nScanning: {target}")
    result = await scanner.run(target)
    
    print(f"Status: {result.status}")
    print(f"Findings: {len(result.findings)}")
    print(f"Duration: {result.duration_seconds:.2f}s")
    
    for finding in result.findings[:3]:  # Show first 3
        print(f"  - {finding.title} ({finding.severity})")


async def example_2_all_scanners():
    """Example 2: Run all scanners on target"""
    print("\n" + "="*60)
    print("EXAMPLE 2: All Scanners Concurrently")
    print("="*60)
    
    orchestrator = ScanOrchestrator()
    target = "https://httpbin.org"
    
    print(f"\nScanning with all scanners: {target}")
    results = await orchestrator.run_all(target, concurrent=True)
    
    for result in results:
        status_icon = "✓" if result.status == "success" else "✗"
        print(f"  {status_icon} {result.scanner_name}: {len(result.findings)} findings")
    
    # Show aggregated results
    aggregated = orchestrator.aggregate_results(results)
    print(f"\nTotal findings: {aggregated['total_findings']}")
    print(f"Severity breakdown: {aggregated['severity_breakdown']}")


async def example_3_selected_scanners():
    """Example 3: Run specific scanners"""
    print("\n" + "="*60)
    print("EXAMPLE 3: Selected Scanners")
    print("="*60)
    
    orchestrator = ScanOrchestrator()
    target = "https://httpbin.org"
    
    # Run only scanner1 and scanner2
    print(f"\nRunning scanner1 and scanner2 on: {target}")
    results = await orchestrator.run_selected(
        target,
        ["scanner1", "scanner2"],
        concurrent=True
    )
    
    for result in results:
        print(f"\n{result.scanner_name}:")
        print(f"  Status: {result.status}")
        print(f"  Findings: {len(result.findings)}")
        print(f"  Duration: {result.duration_seconds:.2f}s")


async def example_4_scanner_availability():
    """Example 4: Check available scanners"""
    print("\n" + "="*60)
    print("EXAMPLE 4: Available Scanners")
    print("="*60)
    
    orchestrator = ScanOrchestrator()
    scanners = orchestrator.get_available_scanners()
    
    print("\nAvailable Scanners:")
    for name, info in scanners.items():
        status = "✓" if info.get('available') else "✗"
        print(f"  {status} {info['name']}")
        print(f"     {info['description']}")


async def example_5_target_validation():
    """Example 5: Target validation"""
    print("\n" + "="*60)
    print("EXAMPLE 5: Target Validation")
    print("="*60)
    
    scanner = Scanner1()
    
    targets = [
        "https://example.com",          # Valid
        "http://localhost:8000",        # Valid
        "example.com",                  # Invalid - no scheme
        "ftp://example.com",            # Invalid - unsupported scheme
        "https://",                     # Invalid - no host
    ]
    
    print("\nValidating targets:")
    for target in targets:
        valid = scanner.validate_target(target)
        status = "✓" if valid else "✗"
        print(f"  {status} {target}")


async def example_6_result_formatting():
    """Example 6: Result formatting and serialization"""
    print("\n" + "="*60)
    print("EXAMPLE 6: Result Formatting")
    print("="*60)
    
    scanner = Scanner2()
    target = "https://httpbin.org"
    
    print(f"\nScanning: {target}")
    result = await scanner.run(target)
    
    # Show result as dictionary
    print("\nResult as dictionary:")
    result_dict = result.to_dict()
    print(f"  Scanner: {result_dict['scanner_name']}")
    print(f"  Status: {result_dict['status']}")
    print(f"  Findings: {len(result_dict['findings'])}")
    print(f"  Duration: {result_dict['duration_seconds']}")
    
    # Show result as JSON (first 200 chars)
    print("\nResult as JSON (truncated):")
    json_str = result.to_json()
    print(f"  {json_str[:200]}...")


async def example_7_error_handling():
    """Example 7: Error handling"""
    print("\n" + "="*60)
    print("EXAMPLE 7: Error Handling")
    print("="*60)
    
    scanner = Scanner1()
    
    # Invalid target
    print("\nAttempting to scan invalid target...")
    result = await scanner.run("not-a-url")
    print(f"  Status: {result.status}")
    print(f"  Error: {result.error_message}")
    
    # Unreachable target
    print("\nAttempting to scan unreachable target...")
    result = await scanner.run("https://localhost:99999")
    print(f"  Status: {result.status}")
    print(f"  Findings: {len(result.findings)}")
    if result.error_message:
        print(f"  Error (first 100 chars): {result.error_message[:100]}...")


async def main():
    """Run all examples"""
    print("\n")
    print("╔" + "="*58 + "╗")
    print("║" + " "*58 + "║")
    print("║" + "  Python Security Scanner - Quick Start Examples".center(58) + "║")
    print("║" + " "*58 + "║")
    print("╚" + "="*58 + "╝")
    
    try:
        # Run examples
        await example_1_single_scanner()
        await example_2_all_scanners()
        await example_3_selected_scanners()
        await example_4_scanner_availability()
        await example_5_target_validation()
        await example_6_result_formatting()
        await example_7_error_handling()
        
        print("\n" + "="*60)
        print("All examples completed!")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\n✗ Example error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
