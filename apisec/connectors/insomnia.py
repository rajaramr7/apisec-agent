"""
Insomnia connector for parsing Insomnia export files.

Insomnia is a popular API client similar to Postman.
Exports are in JSON format (Insomnia v4 format).

Extracts:
- Requests with methods, URLs, headers, bodies
- Authentication configuration
- Environment variables
- Request groups (folders)
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import FileConnector, ConnectorResult


class InsomniaConnector(FileConnector):
    """Connector for Insomnia export files."""

    @property
    def name(self) -> str:
        return "insomnia"

    @property
    def description(self) -> str:
        return "Parse Insomnia API client export files"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._export_data: Optional[Dict] = None

    def connect(self, path: str, **kwargs) -> ConnectorResult:
        """Connect to an Insomnia export file.

        Args:
            path: Path to Insomnia export JSON file

        Returns:
            ConnectorResult indicating success/failure
        """
        result = super().connect(path, **kwargs)
        if not result.success:
            return result

        try:
            content = self._read_file()
            data = json.loads(content)

            # Validate it's an Insomnia export
            if "_type" not in data and "resources" not in data:
                # Check for Insomnia v4 format
                if not isinstance(data, dict) or "resources" not in data:
                    return self._error("Not a valid Insomnia export file")

            self._export_data = data
            return self._success(
                source=f"insomnia://{self._file_path}",
                data={"format": "insomnia_v4" if "resources" in data else "insomnia_legacy"}
            )

        except json.JSONDecodeError as e:
            return self._error(f"Invalid JSON: {e}")

    def fetch_config(self) -> ConnectorResult:
        """Parse the Insomnia export and extract configuration.

        Returns:
            ConnectorResult with parsed data
        """
        if not self._connected or not self._export_data:
            return self._error("Not connected to an Insomnia file")

        try:
            resources = self._export_data.get("resources", [])

            # Separate resource types
            requests = []
            environments = {}
            request_groups = []
            workspaces = []

            for resource in resources:
                rtype = resource.get("_type", "")

                if rtype == "request":
                    requests.append(resource)
                elif rtype == "environment":
                    env_data = resource.get("data", {})
                    environments.update(env_data)
                elif rtype == "request_group":
                    request_groups.append(resource.get("name", ""))
                elif rtype == "workspace":
                    workspaces.append(resource.get("name", ""))

            # Extract endpoints
            endpoints = []
            for req in requests:
                endpoint = self._parse_request(req)
                if endpoint:
                    endpoints.append(endpoint)

            # Extract auth config from requests or environments
            auth_config = self._extract_auth_config(requests, environments)

            # Build data summary
            data = {
                "workspace": workspaces[0] if workspaces else "Unknown",
                "request_count": len(requests),
                "request_groups": request_groups,
                "environment_vars": len(environments),
            }

            return self._success(
                data=data,
                source=f"insomnia://{self._file_path}",
                endpoints=endpoints,
                auth_config=auth_config,
                environment=environments,
            )

        except Exception as e:
            return self._error(f"Failed to parse Insomnia export: {e}")

    def _parse_request(self, req: Dict) -> Optional[Dict[str, Any]]:
        """Parse a single Insomnia request."""
        method = req.get("method", "GET")
        url = req.get("url", "")

        if not url:
            return None

        # Extract path from URL (remove base URL variables)
        path = url
        if "{{" in url:
            # Has variables, try to extract path portion
            parts = url.split("/")
            path_parts = [p for p in parts if not p.startswith("{{")]
            if path_parts:
                path = "/" + "/".join(path_parts)

        # Extract headers
        headers = {}
        for header in req.get("headers", []):
            if not header.get("disabled", False):
                headers[header.get("name", "")] = header.get("value", "")

        # Extract body
        body = None
        body_data = req.get("body", {})
        if body_data:
            if body_data.get("mimeType") == "application/json":
                try:
                    body = json.loads(body_data.get("text", "{}"))
                except json.JSONDecodeError:
                    body = body_data.get("text")
            elif body_data.get("params"):
                body = {
                    p.get("name"): p.get("value")
                    for p in body_data.get("params", [])
                    if not p.get("disabled", False)
                }

        return {
            "method": method,
            "path": path,
            "url": url,
            "name": req.get("name", ""),
            "headers": headers if headers else None,
            "body": body,
            "has_body": body is not None,
        }

    def _extract_auth_config(
        self,
        requests: List[Dict],
        environments: Dict
    ) -> Optional[Dict[str, Any]]:
        """Extract authentication configuration."""
        # Check requests for auth
        for req in requests:
            auth = req.get("authentication", {})
            auth_type = auth.get("type", "").lower()

            if auth_type == "bearer":
                return {
                    "type": "bearer",
                    "token": auth.get("token", ""),
                }
            elif auth_type == "basic":
                return {
                    "type": "basic",
                    "username": auth.get("username", ""),
                    "password": auth.get("password", ""),
                }
            elif auth_type == "oauth2":
                return {
                    "type": "oauth2",
                    "grant_type": auth.get("grantType", ""),
                    "access_token_url": auth.get("accessTokenUrl", ""),
                    "client_id": auth.get("clientId", ""),
                }

        # Check environments for auth-related variables
        auth_vars = {
            k: v for k, v in environments.items()
            if any(p in k.lower() for p in ["token", "key", "auth", "secret"])
        }

        if auth_vars:
            if any("token" in k.lower() for k in auth_vars):
                return {"type": "bearer", "from_environment": True}
            elif any("api_key" in k.lower() or "apikey" in k.lower() for k in auth_vars):
                return {"type": "api_key", "from_environment": True}

        return None


def parse_insomnia_export(path: str) -> Dict[str, Any]:
    """Parse an Insomnia export file.

    Args:
        path: Path to the Insomnia export JSON file

    Returns:
        Dict with parsed configuration
    """
    connector = InsomniaConnector()
    connect_result = connector.connect(path=path)

    if not connect_result.success:
        return connect_result.to_dict()

    result = connector.fetch_config()
    return result.to_dict()
