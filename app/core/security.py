"""
Security helpers: password hashing, JWT creation/verification,
and a simple in-memory brute-force counter.
"""

import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    """Return a bcrypt hash of *plain*."""
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Return True when *plain* matches *hashed*."""
    return _pwd_context.verify(plain, hashed)


# ---------------------------------------------------------------------------
# JWT tokens
# ---------------------------------------------------------------------------


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a signed JWT.

    :param subject: Usually the username or user-id to embed in the token.
    :param expires_delta: Custom TTL; falls back to settings value.
    :return: Encoded JWT string.
    """
    delta = expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    expire = datetime.now(timezone.utc) + delta
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_access_token(token: str) -> Optional[str]:
    """
    Decode and validate a JWT.

    :return: The *sub* claim (username) on success, or None if invalid/expired.
    """
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        return payload.get("sub")
    except JWTError:
        return None


# ---------------------------------------------------------------------------
# Brute-force protection
# ---------------------------------------------------------------------------

# Structure: { username: [(attempt_timestamp, ...), ...] }
_login_attempts: dict[str, list[float]] = defaultdict(list)


def record_failed_login(username: str) -> None:
    """Record a failed login attempt for *username*."""
    now = time.monotonic()
    _login_attempts[username].append(now)


def is_account_locked(username: str) -> bool:
    """
    Return True when *username* has exceeded the allowed number of failed
    login attempts within the configured time window.
    """
    now = time.monotonic()
    window = settings.login_attempt_window
    # Keep only attempts within the current window
    recent = [t for t in _login_attempts[username] if now - t < window]
    _login_attempts[username] = recent
    return len(recent) >= settings.max_login_attempts


def reset_login_attempts(username: str) -> None:
    """Clear the failed-attempt counter after a successful login."""
    _login_attempts.pop(username, None)
