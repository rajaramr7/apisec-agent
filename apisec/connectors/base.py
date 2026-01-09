"""
Base connector class for external API tool integrations.

All connectors inherit from BaseConnector and implement:
- connect(): Establish connection to the external source
- fetch_config(): Retrieve API configuration data

Connectors return ConnectorResult with standardized fields.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from pathlib import Path


@dataclass
class ConnectorResult:
    """Standardized result from connector operations.

    Attributes:
        success: Whether the operation succeeded
        data: The retrieved configuration data
        source: Description of where data came from (e.g., "postman://workspace/collection")
        needs_auth: True if authentication is required but not provided
        error: Error message if operation failed
        endpoints: List of discovered endpoints
        auth_config: Authentication configuration extracted
        environment: Environment variables extracted
        warnings: Non-fatal warnings during processing
    """
    success: bool
    data: Optional[Dict[str, Any]] = None
    source: str = ""
    needs_auth: bool = False
    error: Optional[str] = None
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    auth_config: Optional[Dict[str, Any]] = None
    environment: Dict[str, str] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for JSON serialization."""
        result = {
            "success": self.success,
            "source": self.source,
        }

        if self.data:
            result["data"] = self.data
        if self.needs_auth:
            result["needs_auth"] = True
        if self.error:
            result["error"] = self.error
        if self.endpoints:
            result["endpoints"] = self.endpoints
            result["endpoint_count"] = len(self.endpoints)
        if self.auth_config:
            result["auth_config"] = self.auth_config
        if self.environment:
            result["environment"] = self.environment
        if self.warnings:
            result["warnings"] = self.warnings

        return result


class ConnectorError(Exception):
    """Exception raised by connectors."""
    pass


class BaseConnector(ABC):
    """Abstract base class for all connectors.

    Connectors fetch API configuration from external sources and return
    standardized ConnectorResult objects.

    Subclasses must implement:
        - connect(): Establish connection to the source
        - fetch_config(): Retrieve configuration data

    Optional overrides:
        - validate_connection(): Verify credentials/access
        - get_endpoints(): Extract endpoint definitions
        - get_auth_config(): Extract authentication settings
        - get_environment(): Extract environment variables
    """

    def __init__(self, **kwargs):
        """Initialize connector with optional configuration.

        Args:
            **kwargs: Connector-specific configuration options
        """
        self._config = kwargs
        self._connected = False
        self._last_result: Optional[ConnectorResult] = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the connector name (e.g., 'postman', 'env_file')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Return a brief description of what this connector does."""
        pass

    @abstractmethod
    def connect(self, **kwargs) -> ConnectorResult:
        """Establish connection to the external source.

        Args:
            **kwargs: Connection parameters (credentials, paths, etc.)

        Returns:
            ConnectorResult indicating success/failure of connection
        """
        pass

    @abstractmethod
    def fetch_config(self) -> ConnectorResult:
        """Fetch API configuration from the connected source.

        Must call connect() first.

        Returns:
            ConnectorResult with configuration data
        """
        pass

    def validate_connection(self) -> bool:
        """Validate that the connection is working.

        Returns:
            True if connection is valid, False otherwise
        """
        return self._connected

    def get_endpoints(self) -> List[Dict[str, Any]]:
        """Extract endpoint definitions from fetched config.

        Returns:
            List of endpoint dicts with method, path, and optional metadata
        """
        if self._last_result and self._last_result.endpoints:
            return self._last_result.endpoints
        return []

    def get_auth_config(self) -> Optional[Dict[str, Any]]:
        """Extract authentication configuration.

        Returns:
            Dict with auth type and parameters, or None
        """
        if self._last_result and self._last_result.auth_config:
            return self._last_result.auth_config
        return None

    def get_environment(self) -> Dict[str, str]:
        """Extract environment variables.

        Returns:
            Dict of environment variable name -> value
        """
        if self._last_result and self._last_result.environment:
            return self._last_result.environment
        return {}

    def _set_result(self, result: ConnectorResult) -> ConnectorResult:
        """Store and return a result."""
        self._last_result = result
        return result

    def _success(
        self,
        data: Optional[Dict[str, Any]] = None,
        source: str = "",
        endpoints: Optional[List[Dict[str, Any]]] = None,
        auth_config: Optional[Dict[str, Any]] = None,
        environment: Optional[Dict[str, str]] = None,
        warnings: Optional[List[str]] = None,
    ) -> ConnectorResult:
        """Create a success result."""
        return self._set_result(ConnectorResult(
            success=True,
            data=data,
            source=source or f"{self.name}://",
            endpoints=endpoints or [],
            auth_config=auth_config,
            environment=environment or {},
            warnings=warnings or [],
        ))

    def _error(
        self,
        error: str,
        needs_auth: bool = False,
        source: str = "",
    ) -> ConnectorResult:
        """Create an error result."""
        return self._set_result(ConnectorResult(
            success=False,
            error=error,
            needs_auth=needs_auth,
            source=source or f"{self.name}://",
        ))


class FileConnector(BaseConnector):
    """Base class for file-based connectors.

    Provides common file handling for connectors that read from local files.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._file_path: Optional[Path] = None

    def connect(self, path: str, **kwargs) -> ConnectorResult:
        """Connect to a local file.

        Args:
            path: Path to the file to read

        Returns:
            ConnectorResult indicating if file exists and is readable
        """
        self._file_path = Path(path).resolve()

        if not self._file_path.exists():
            return self._error(f"File not found: {path}")

        if not self._file_path.is_file():
            return self._error(f"Not a file: {path}")

        try:
            # Test that we can read it
            self._file_path.read_text(encoding='utf-8')
            self._connected = True
            return self._success(source=f"{self.name}://{self._file_path}")
        except PermissionError:
            return self._error(f"Permission denied: {path}")
        except Exception as e:
            return self._error(f"Cannot read file: {e}")

    def _read_file(self) -> str:
        """Read the connected file's content."""
        if not self._file_path:
            raise ConnectorError("Not connected to a file")
        return self._file_path.read_text(encoding='utf-8')


class APIConnector(BaseConnector):
    """Base class for API-based connectors.

    Provides common HTTP handling for connectors that fetch from remote APIs.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._base_url: Optional[str] = None
        self._api_key: Optional[str] = None
        self._headers: Dict[str, str] = {}

    def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Make an HTTP request to the API.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            **kwargs: Additional requests parameters

        Returns:
            Response data as dict

        Raises:
            ConnectorError: If request fails
        """
        import requests

        if not self._base_url:
            raise ConnectorError("Not connected - no base URL set")

        url = f"{self._base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        headers = {**self._headers, **kwargs.pop('headers', {})}

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                timeout=kwargs.pop('timeout', 30),
                **kwargs
            )
            response.raise_for_status()
            return response.json()
        except requests.Timeout:
            raise ConnectorError(f"Request timed out: {url}")
        except requests.RequestException as e:
            raise ConnectorError(f"Request failed: {e}")
