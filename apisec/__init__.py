"""APIsec Agent - AI-powered API security testing configuration tool."""

# Suppress urllib3 SSL warning on macOS (LibreSSL vs OpenSSL compatibility)
import warnings
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")

__version__ = "0.1.0"
