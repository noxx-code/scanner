"""Built-in security check plugins."""

from backend.secscan.checks.base import SecurityCheck
from backend.secscan.checks.cookie_check import CookieSecurityCheck
from backend.secscan.checks.cors_check import CorsMisconfigurationCheck
from backend.secscan.checks.directory_exposure_check import DirectoryExposureCheck
from backend.secscan.checks.headers_check import HeadersCheck
from backend.secscan.checks.input_reflection_check import InputReflectionCheck
from backend.secscan.checks.js_analysis_check import JavaScriptAnalysisCheck
from backend.secscan.checks.open_redirect_check import OpenRedirectCheck
from backend.secscan.checks.sensitive_data_check import SensitiveDataExposureCheck
from backend.secscan.checks.sql_error_check import SqlErrorExposureCheck
from backend.secscan.checks.ssl_tls_check import SslTlsCheck


def default_checks() -> list[SecurityCheck]:
    """Return built-in checks."""
    return [
        HeadersCheck(),
        SslTlsCheck(),
        CookieSecurityCheck(),
        InputReflectionCheck(),
        SqlErrorExposureCheck(),
        OpenRedirectCheck(),
        DirectoryExposureCheck(),
        SensitiveDataExposureCheck(),
        JavaScriptAnalysisCheck(),
        CorsMisconfigurationCheck(),
    ]
