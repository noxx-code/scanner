"""
Main entry point for running the scanner as a module.

Usage:
    python -m vuln_scanner scan -t templates/ -u http://target.com
"""

from .cli import main

if __name__ == "__main__":
    main()
