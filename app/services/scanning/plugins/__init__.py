"""Built-in vulnerability scanner plugins."""

from app.services.scanning.contracts import ScannerPlugin
from app.services.scanning.plugins.sqli import SqliPlugin
from app.services.scanning.plugins.xss import XssPlugin


def default_plugins() -> list[ScannerPlugin]:
    """Return default plugin instances used by the scanner engine."""
    return [XssPlugin(), SqliPlugin()]
