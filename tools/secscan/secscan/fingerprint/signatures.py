"""Fingerprint signatures and mock vulnerable-version data."""

from __future__ import annotations

import re

HEADER_TECH_SIGNATURES: dict[str, tuple[str, str]] = {
    "server": ("server", "server"),
    "x-powered-by": ("framework", "x-powered-by"),
    "x-aspnet-version": ("framework", "asp.net"),
}

HTML_LIBRARY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("React", re.compile(r"react(?:[-.]dom)?(?:@|[\\s:/-])?(\\d+\\.\\d+(?:\\.\\d+)?)?", re.IGNORECASE)),
    ("Angular", re.compile(r"angular(?:@|[\\s:/-])?(\\d+\\.\\d+(?:\\.\\d+)?)?", re.IGNORECASE)),
    ("Vue", re.compile(r"vue(?:@|[\\s:/-])?(\\d+\\.\\d+(?:\\.\\d+)?)?", re.IGNORECASE)),
    ("Django", re.compile(r"django(?:@|[\\s:/-])?(\\d+\\.\\d+(?:\\.\\d+)?)?", re.IGNORECASE)),
    ("jQuery", re.compile(r"jquery(?:[-.]min)?(?:@|[\\s:/-])?(\\d+\\.\\d+(?:\\.\\d+)?)?", re.IGNORECASE)),
    ("Bootstrap", re.compile(r"bootstrap(?:[-.]min)?(?:@|[\\s:/-])?(\\d+\\.\\d+(?:\\.\\d+)?)?", re.IGNORECASE)),
]

MOCK_VULN_MINIMUMS: dict[str, tuple[int, int, int]] = {
    "jQuery": (3, 5, 0),
    "Bootstrap": (4, 6, 0),
    "Angular": (1, 8, 3),
}
