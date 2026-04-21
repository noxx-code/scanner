"""Application configuration."""
from pathlib import Path
import os


class Config:
    """Base configuration."""
    
    # Project structure
    PROJECT_ROOT = Path(__file__).parent.parent.parent
    BACKEND_ROOT = PROJECT_ROOT / "backend"
    TOOLS_ROOT = PROJECT_ROOT / "tools"
    
    # Assets
    ASSETS_DIR = BACKEND_ROOT / "assets"
    OUTPUT_DIR = ASSETS_DIR / "outputs"
    LOGS_DIR = ASSETS_DIR / "logs"
    TEMP_DIR = ASSETS_DIR / "temp"
    
    # Scanner tool paths (legacy - now using Python implementations in backend)
    # These are kept for reference but are no longer used
    # Scanners are now implemented as Python modules in backend/scanners/
    NUCLEI_BIN = TOOLS_ROOT / "nuclei" / "nuclei-dev" / "nuclei"
    SECSCAN_PATH = BACKEND_ROOT / "secscan"  # Integrated from separate directory
    CUSTOM_SCANNER_PATH = BACKEND_ROOT / "scanners" / "custom_scanner"
    
    # API
    API_TITLE = "Security Scanner API"
    API_VERSION = "1.0.0"
    
    # Database (if using)
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./scanner.db")
    
    # Security
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    
    # Scanning defaults
    SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "300"))
    MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    TESTING = False


class TestingConfig(Config):
    """Testing configuration."""
    DEBUG = True
    TESTING = True
    DATABASE_URL = "sqlite:///:memory:"


def get_config() -> Config:
    """Get configuration based on environment.
    
    Returns:
        Configuration object
    """
    env = os.getenv("ENVIRONMENT", "development")
    
    if env == "production":
        return ProductionConfig()
    elif env == "testing":
        return TestingConfig()
    else:
        return DevelopmentConfig()
