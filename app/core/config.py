"""
Application configuration.

Settings are loaded from environment variables with sensible defaults
so the app can run out of the box for local development.
"""

from pathlib import Path

from pydantic_settings import BaseSettings


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Central settings object — override any value via environment variable."""

    # Application
    app_name: str = "Security Scanner"
    debug: bool = False

    # JWT / auth
    secret_key: str = "change-me-in-production-use-a-long-random-string"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # Brute-force protection: max failed login attempts per username
    max_login_attempts: int = 5
    # Window (in seconds) before the counter resets
    login_attempt_window: int = 300

    # Database
    database_url: str = "sqlite+aiosqlite:///./scanner.db"

    # Crawler defaults
    default_crawl_depth: int = 2
    crawl_timeout: int = 10  # seconds per HTTP request
    api_common_endpoints: str = (
        "/api,/rest,/search,/graphql,/api/search,/api/products,/api/users,/rest/products/search"
    )
    api_bruteforce_enabled: bool = True
    scan_json_endpoints: bool = True

    # Scanner defaults
    scanner_timeout: int = 12
    sqli_time_threshold_seconds: float = 2.5

    class Config:
        env_file = PROJECT_ROOT / ".env"
        env_file_encoding = "utf-8"


# Module-level singleton — import this everywhere
settings = Settings()
