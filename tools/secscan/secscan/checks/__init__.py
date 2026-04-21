"""Built-in security check plugins."""

from secscan.checks.base import SecurityCheck
from secscan.checks.cookie_check import CookieSecurityCheck
from secscan.checks.cors_check import CorsMisconfigurationCheck
from secscan.checks.directory_exposure_check import DirectoryExposureCheck
from secscan.checks.headers_check import HeadersCheck
from secscan.checks.input_reflection_check import InputReflectionCheck
from secscan.checks.js_analysis_check import JavaScriptAnalysisCheck
from secscan.checks.open_redirect_check import OpenRedirectCheck
from secscan.checks.sensitive_data_check import SensitiveDataExposureCheck
from secscan.checks.sql_error_check import SqlErrorExposureCheck
from secscan.checks.ssl_tls_check import SslTlsCheck


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
