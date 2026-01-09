"""
HAR (HTTP Archive) connector.

Parses HAR files to extract API information:
- Endpoints and methods
- Request/response headers
- Request bodies and payloads
- Authentication headers
- Timing information

HAR files are exported from browser DevTools, Charles Proxy,
Fiddler, mitmproxy, and other HTTP debugging tools.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from .base import FileConnector, ConnectorResult


class HARConnector(FileConnector):
    """Connector for HAR (HTTP Archive) files."""

    @property
    def name(self) -> str:
        return "har"

    @property
    def description(self) -> str:
        return "Parse HAR files to extract API endpoints and payloads"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._har_data: Optional[Dict] = None
        self._base_url_filter: Optional[str] = kwargs.get("base_url_filter")

    def connect(self, path: str, **kwargs) -> ConnectorResult:
        """Connect to a HAR file.

        Args:
            path: Path to HAR file

        Returns:
            ConnectorResult indicating success/failure
        """
        result = super().connect(path, **kwargs)
        if not result.success:
            return result

        try:
            content = self._read_file()
            data = json.loads(content)

            # Validate HAR structure
            if "log" not in data:
                return self._error("Invalid HAR file: missing 'log' object")

            if "entries" not in data["log"]:
                return self._error("Invalid HAR file: missing 'entries' array")

            self._har_data = data
            entry_count = len(data["log"]["entries"])

            return self._success(
                source=f"har://{self._file_path}",
                data={
                    "entries": entry_count,
                    "version": data["log"].get("version", "unknown"),
                    "creator": data["log"].get("creator", {}).get("name", "unknown"),
                }
            )

        except json.JSONDecodeError as e:
            return self._error(f"Invalid JSON in HAR file: {e}")

    def fetch_config(self) -> ConnectorResult:
        """Parse the HAR file and extract API configuration.

        Returns:
            ConnectorResult with parsed data
        """
        if not self._connected or not self._har_data:
            return self._error("Not connected to a HAR file")

        try:
            entries = self._har_data["log"]["entries"]

            # Extract endpoints
            endpoints = []
            seen_endpoints: Set[str] = set()
            base_urls: Set[str] = set()

            for entry in entries:
                request = entry.get("request", {})
                response = entry.get("response", {})

                method = request.get("method", "GET")
                url = request.get("url", "")

                if not url:
                    continue

                # Parse URL
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                path = parsed.path or "/"

                # Apply filter if set
                if self._base_url_filter and self._base_url_filter not in base_url:
                    continue

                base_urls.add(base_url)

                # Skip static resources
                if self._is_static_resource(path):
                    continue

                # Create endpoint key for deduplication
                endpoint_key = f"{method} {path}"
                if endpoint_key in seen_endpoints:
                    continue
                seen_endpoints.add(endpoint_key)

                # Extract request body
                body = None
                post_data = request.get("postData", {})
                if post_data:
                    mime_type = post_data.get("mimeType", "")
                    if "json" in mime_type:
                        try:
                            body = json.loads(post_data.get("text", "{}"))
                        except json.JSONDecodeError:
                            body = post_data.get("text")
                    elif post_data.get("params"):
                        body = {
                            p.get("name"): p.get("value")
                            for p in post_data.get("params", [])
                        }

                # Extract headers
                headers = {
                    h.get("name"): h.get("value")
                    for h in request.get("headers", [])
                    if h.get("name") and not h.get("name").startswith(":")
                }

                # Get response status
                status = response.get("status", 0)

                endpoints.append({
                    "method": method,
                    "path": path,
                    "url": url,
                    "base_url": base_url,
                    "has_body": body is not None,
                    "body": body,
                    "headers": headers if headers else None,
                    "response_status": status,
                    "content_type": post_data.get("mimeType") if post_data else None,
                })

            # Extract auth configuration from headers
            auth_config = self._extract_auth_from_entries(entries)

            # Determine primary base URL
            primary_base_url = None
            if len(base_urls) == 1:
                primary_base_url = list(base_urls)[0]
            elif base_urls:
                # Pick the most common one
                url_counts = {}
                for entry in entries:
                    url = entry.get("request", {}).get("url", "")
                    parsed = urlparse(url)
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    url_counts[base] = url_counts.get(base, 0) + 1
                primary_base_url = max(url_counts, key=url_counts.get)

            data = {
                "total_entries": len(entries),
                "unique_endpoints": len(endpoints),
                "base_urls": list(base_urls),
                "primary_base_url": primary_base_url,
                "methods_found": list(set(e["method"] for e in endpoints)),
            }

            return self._success(
                data=data,
                source=f"har://{self._file_path}",
                endpoints=endpoints,
                auth_config=auth_config,
            )

        except Exception as e:
            return self._error(f"Failed to parse HAR file: {e}")

    def _is_static_resource(self, path: str) -> bool:
        """Check if path is a static resource."""
        static_extensions = {
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
            ".html", ".htm",
        }
        path_lower = path.lower()
        return any(path_lower.endswith(ext) for ext in static_extensions)

    def _extract_auth_from_entries(self, entries: List[Dict]) -> Optional[Dict[str, Any]]:
        """Extract authentication configuration from request headers."""
        for entry in entries:
            headers = entry.get("request", {}).get("headers", [])
            headers_dict = {h.get("name", "").lower(): h.get("value", "") for h in headers}

            # Check Authorization header
            auth_header = headers_dict.get("authorization", "")

            if auth_header.lower().startswith("bearer "):
                return {
                    "type": "bearer",
                    "header": "Authorization",
                    "sample_token": auth_header[7:][:20] + "..." if len(auth_header) > 27 else auth_header[7:],
                }
            elif auth_header.lower().startswith("basic "):
                return {
                    "type": "basic",
                    "header": "Authorization",
                }
            elif "apikey" in auth_header.lower():
                return {
                    "type": "api_key",
                    "header": "Authorization",
                }

            # Check common API key headers
            for header_name in ["x-api-key", "api-key", "apikey", "x-auth-token"]:
                if header_name in headers_dict and headers_dict[header_name]:
                    return {
                        "type": "api_key",
                        "header": header_name,
                    }

            # Check cookies for session-based auth
            if headers_dict.get("cookie"):
                cookie = headers_dict["cookie"]
                if any(
                    name in cookie.lower()
                    for name in ["session", "token", "auth", "jwt"]
                ):
                    return {
                        "type": "cookie",
                        "cookie_present": True,
                    }

        return None

    def get_endpoints_by_method(self, method: str) -> List[Dict[str, Any]]:
        """Get endpoints filtered by HTTP method.

        Args:
            method: HTTP method to filter (GET, POST, etc.)

        Returns:
            List of endpoints matching the method
        """
        if not self._last_result or not self._last_result.endpoints:
            return []

        return [
            e for e in self._last_result.endpoints
            if e.get("method", "").upper() == method.upper()
        ]

    def get_endpoints_with_payloads(self) -> List[Dict[str, Any]]:
        """Get endpoints that have request bodies.

        Returns:
            List of endpoints with payloads
        """
        if not self._last_result or not self._last_result.endpoints:
            return []

        return [
            e for e in self._last_result.endpoints
            if e.get("has_body")
        ]


def parse_har_file(
    path: str,
    base_url_filter: Optional[str] = None
) -> Dict[str, Any]:
    """Parse a HAR file.

    Args:
        path: Path to the HAR file
        base_url_filter: Optional base URL to filter requests

    Returns:
        Dict with parsed configuration
    """
    connector = HARConnector(base_url_filter=base_url_filter)
    connect_result = connector.connect(path=path)

    if not connect_result.success:
        return connect_result.to_dict()

    result = connector.fetch_config()
    return result.to_dict()
