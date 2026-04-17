"""Scan context helpers for structured logging across scanner internals."""

from __future__ import annotations

from contextvars import ContextVar

_SCAN_ID: ContextVar[int | None] = ContextVar("scan_id", default=None)
_TARGET_URL: ContextVar[str | None] = ContextVar("target_url", default=None)


def set_scan_context(scan_id: int | None, target_url: str | None) -> tuple[object, object]:
    """Set contextual values and return context tokens for reset."""
    scan_token = _SCAN_ID.set(scan_id)
    target_token = _TARGET_URL.set(target_url)
    return scan_token, target_token


def reset_scan_context(tokens: tuple[object, object]) -> None:
    """Reset contextual values after scan completion."""
    scan_token, target_token = tokens
    _SCAN_ID.reset(scan_token)  # type: ignore[arg-type]
    _TARGET_URL.reset(target_token)  # type: ignore[arg-type]


def get_scan_context() -> dict[str, int | str | None]:
    """Return context values suitable for logging extras."""
    return {"scan_id": _SCAN_ID.get(), "target_url": _TARGET_URL.get()}
