"""
Postman connector for fetching API configurations.

Supports two modes:
1. Local file parsing: Read Postman collection/environment JSON files
2. API integration: Fetch from Postman workspace using API key

Extracts:
- Endpoints with methods and paths
- Request payloads
- Authentication configuration
- Environment variables
- User identities for BOLA testing
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from .base import BaseConnector, FileConnector, ConnectorResult, ConnectorError

# Import existing parser functionality
from ..inference.postman import (
    parse_postman,
    parse_postman_environment,
    PostmanParser,
    format_collection_summary,
    format_environment_summary,
)


class PostmanFileConnector(FileConnector):
    """Connector for local Postman collection/environment files."""

    @property
    def name(self) -> str:
        return "postman_file"

    @property
    def description(self) -> str:
        return "Parse local Postman collection and environment files"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._collection_data: Optional[Dict] = None
        self._environment_data: Optional[Dict] = None
        self._file_type: Optional[str] = None  # 'collection' or 'environment'

    def connect(self, path: str, **kwargs) -> ConnectorResult:
        """Connect to a local Postman file.

        Args:
            path: Path to Postman collection or environment file

        Returns:
            ConnectorResult indicating success/failure
        """
        result = super().connect(path, **kwargs)
        if not result.success:
            return result

        # Detect file type
        try:
            content = self._read_file()
            data = json.loads(content)

            if "info" in data and "item" in data:
                self._file_type = "collection"
            elif "values" in data:
                self._file_type = "environment"
            else:
                return self._error(f"Unknown Postman file format: {path}")

            return self._success(
                source=f"postman_file://{self._file_path}",
                data={"file_type": self._file_type}
            )

        except json.JSONDecodeError as e:
            return self._error(f"Invalid JSON in Postman file: {e}")

    def fetch_config(self) -> ConnectorResult:
        """Parse the connected Postman file.

        Returns:
            ConnectorResult with parsed configuration
        """
        if not self._connected or not self._file_path:
            return self._error("Not connected to a file")

        try:
            if self._file_type == "collection":
                return self._parse_collection()
            elif self._file_type == "environment":
                return self._parse_environment()
            else:
                return self._error("Unknown file type")

        except Exception as e:
            return self._error(f"Failed to parse Postman file: {e}")

    def _parse_collection(self) -> ConnectorResult:
        """Parse a Postman collection file."""
        parsed = parse_postman(str(self._file_path))
        self._collection_data = parsed

        # Extract endpoints
        endpoints = []
        for req in parsed.get("requests", []):
            method = req.get("method", "GET")
            path = req.get("path", req.get("url", ""))
            endpoints.append({
                "method": method,
                "path": path,
                "name": req.get("name"),
                "has_body": bool(req.get("body")),
                "body": req.get("body"),
            })

        # Extract auth config
        auth_config = parsed.get("auth")

        # Get summary
        summary = format_collection_summary(parsed)

        # Build data
        data = {
            "type": "collection",
            "name": parsed.get("info", {}).get("name", "Unknown"),
            "request_count": len(parsed.get("requests", [])),
            "folders": parsed.get("folders", []),
            "variables": parsed.get("variables", {}),
            "env_vars_used": list(parsed.get("environment_vars_used", set())),
            "has_pre_request_script": bool(parsed.get("pre_request_script")),
            "summary": summary,
        }

        return self._success(
            data=data,
            source=f"postman_file://{self._file_path}",
            endpoints=endpoints,
            auth_config=auth_config,
        )

    def _parse_environment(self) -> ConnectorResult:
        """Parse a Postman environment file."""
        parsed = parse_postman_environment(str(self._file_path))
        self._environment_data = parsed

        # Extract environment variables
        environment = parsed.get("variables", {})

        # Build auth config from environment
        auth_config = self._extract_auth_from_env(parsed)

        # Get summary
        summary = format_environment_summary(parsed)

        # Build data
        data = {
            "type": "environment",
            "name": parsed.get("name", "Unknown"),
            "variable_count": len(environment),
            "has_credentials": parsed.get("has_credentials", False),
            "has_user_tokens": parsed.get("has_user_tokens", False),
            "empty_secrets": parsed.get("empty_secrets", []),
            "user_identities": parsed.get("user_identities", {}),
            "summary": summary,
        }

        # Warnings for empty secrets
        warnings = []
        empty = parsed.get("empty_secrets", [])
        if empty:
            warnings.append(f"Found {len(empty)} empty secret(s): {', '.join(empty[:5])}")

        return self._success(
            data=data,
            source=f"postman_file://{self._file_path}",
            auth_config=auth_config,
            environment=environment,
            warnings=warnings,
        )

    def _extract_auth_from_env(self, parsed: Dict) -> Optional[Dict[str, Any]]:
        """Extract auth configuration from environment variables."""
        auth_related = parsed.get("auth_related", {})
        if not auth_related:
            return None

        auth_config: Dict[str, Any] = {"type": "unknown"}

        # Check for OAuth2 client credentials
        has_client = any("client_id" in k.lower() for k in auth_related)
        has_secret = any("client_secret" in k.lower() for k in auth_related)

        if has_client and has_secret:
            client_id_key = next((k for k in auth_related if "client_id" in k.lower()), None)
            client_secret_key = next((k for k in auth_related if "client_secret" in k.lower()), None)

            auth_config = {
                "type": "oauth2_client_credentials",
                "client_id_var": client_id_key,
                "client_secret_var": client_secret_key,
            }

            # Look for token URL
            urls = parsed.get("url_related", {})
            token_url_key = next(
                (k for k in urls if any(p in k.lower() for p in ["token", "oauth", "auth"])),
                None
            )
            if token_url_key:
                auth_config["token_url_var"] = token_url_key

        # Check for API key
        elif any("api_key" in k.lower() or "apikey" in k.lower() for k in auth_related):
            api_key_key = next(
                (k for k in auth_related if "api_key" in k.lower() or "apikey" in k.lower()),
                None
            )
            if api_key_key:
                auth_config = {
                    "type": "api_key",
                    "key_var": api_key_key,
                }

        # Check for bearer token
        elif any("token" in k.lower() and "access" in k.lower() for k in auth_related):
            token_key = next(
                (k for k in auth_related if "token" in k.lower()),
                None
            )
            if token_key:
                auth_config = {
                    "type": "bearer",
                    "token_var": token_key,
                }

        return auth_config if auth_config["type"] != "unknown" else None

    def get_user_identities(self) -> Dict[str, Dict[str, str]]:
        """Get user identities for BOLA testing."""
        if self._environment_data:
            return self._environment_data.get("user_identities", {})
        return {}


class PostmanAPIConnector(BaseConnector):
    """Connector for Postman API to fetch from workspaces."""

    POSTMAN_API_BASE = "https://api.getpostman.com"

    @property
    def name(self) -> str:
        return "postman_api"

    @property
    def description(self) -> str:
        return "Fetch collections and environments from Postman workspace"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._api_key: Optional[str] = None
        self._workspace_id: Optional[str] = None
        self._collections: List[Dict] = []
        self._environments: List[Dict] = []

    def connect(self, api_key: str, workspace_id: Optional[str] = None, **kwargs) -> ConnectorResult:
        """Connect to Postman API.

        Args:
            api_key: Postman API key
            workspace_id: Optional workspace ID (lists collections if provided)

        Returns:
            ConnectorResult indicating success/failure
        """
        self._api_key = api_key
        self._workspace_id = workspace_id

        # Validate API key by fetching user info
        try:
            response = requests.get(
                f"{self.POSTMAN_API_BASE}/me",
                headers={"X-Api-Key": api_key},
                timeout=10
            )

            if response.status_code == 401:
                return self._error("Invalid Postman API key", needs_auth=True)

            if response.status_code != 200:
                return self._error(f"Postman API error: {response.status_code}")

            user_data = response.json()
            user = user_data.get("user", {})

            self._connected = True

            return self._success(
                data={
                    "user": user.get("username"),
                    "email": user.get("email"),
                },
                source=f"postman_api://{user.get('username', 'unknown')}"
            )

        except requests.Timeout:
            return self._error("Postman API timeout")
        except requests.RequestException as e:
            return self._error(f"Connection error: {e}")

    def fetch_config(self) -> ConnectorResult:
        """Fetch collections and environments from Postman.

        Returns:
            ConnectorResult with available collections/environments
        """
        if not self._connected:
            return self._error("Not connected to Postman API")

        try:
            # List workspaces if no specific workspace
            if not self._workspace_id:
                workspaces = self._list_workspaces()
                return self._success(
                    data={
                        "workspaces": workspaces,
                        "message": "Provide a workspace_id to fetch collections"
                    },
                    source="postman_api://workspaces"
                )

            # Fetch workspace details
            collections = self._list_collections()
            environments = self._list_environments()

            self._collections = collections
            self._environments = environments

            return self._success(
                data={
                    "workspace_id": self._workspace_id,
                    "collections": [
                        {"id": c["uid"], "name": c["name"]}
                        for c in collections
                    ],
                    "environments": [
                        {"id": e["uid"], "name": e["name"]}
                        for e in environments
                    ],
                },
                source=f"postman_api://workspace/{self._workspace_id}"
            )

        except ConnectorError as e:
            return self._error(str(e))
        except Exception as e:
            return self._error(f"Failed to fetch from Postman: {e}")

    def fetch_collection(self, collection_id: str) -> ConnectorResult:
        """Fetch a specific collection.

        Args:
            collection_id: Postman collection UID

        Returns:
            ConnectorResult with collection data
        """
        if not self._connected:
            return self._error("Not connected to Postman API")

        try:
            response = requests.get(
                f"{self.POSTMAN_API_BASE}/collections/{collection_id}",
                headers={"X-Api-Key": self._api_key},
                timeout=30
            )

            if response.status_code == 404:
                return self._error(f"Collection not found: {collection_id}")

            if response.status_code != 200:
                return self._error(f"Postman API error: {response.status_code}")

            data = response.json()
            collection = data.get("collection", {})

            # Parse the collection using existing parser
            # The API returns the same format as exported files
            endpoints = self._extract_endpoints_from_collection(collection)
            auth_config = self._extract_auth_from_collection(collection)

            return self._success(
                data={
                    "name": collection.get("info", {}).get("name"),
                    "request_count": len(endpoints),
                },
                source=f"postman_api://collection/{collection_id}",
                endpoints=endpoints,
                auth_config=auth_config,
            )

        except requests.Timeout:
            return self._error("Request timed out")
        except requests.RequestException as e:
            return self._error(f"Request failed: {e}")

    def fetch_environment(self, environment_id: str) -> ConnectorResult:
        """Fetch a specific environment.

        Args:
            environment_id: Postman environment UID

        Returns:
            ConnectorResult with environment data
        """
        if not self._connected:
            return self._error("Not connected to Postman API")

        try:
            response = requests.get(
                f"{self.POSTMAN_API_BASE}/environments/{environment_id}",
                headers={"X-Api-Key": self._api_key},
                timeout=30
            )

            if response.status_code == 404:
                return self._error(f"Environment not found: {environment_id}")

            if response.status_code != 200:
                return self._error(f"Postman API error: {response.status_code}")

            data = response.json()
            env = data.get("environment", {})

            # Extract variables
            environment = {}
            for var in env.get("values", []):
                if var.get("enabled", True):
                    environment[var.get("key", "")] = var.get("value", "")

            return self._success(
                data={
                    "name": env.get("name"),
                    "variable_count": len(environment),
                },
                source=f"postman_api://environment/{environment_id}",
                environment=environment,
            )

        except requests.Timeout:
            return self._error("Request timed out")
        except requests.RequestException as e:
            return self._error(f"Request failed: {e}")

    def _list_workspaces(self) -> List[Dict]:
        """List available workspaces."""
        response = requests.get(
            f"{self.POSTMAN_API_BASE}/workspaces",
            headers={"X-Api-Key": self._api_key},
            timeout=10
        )

        if response.status_code != 200:
            raise ConnectorError(f"Failed to list workspaces: {response.status_code}")

        data = response.json()
        return [
            {"id": w["id"], "name": w["name"], "type": w.get("type")}
            for w in data.get("workspaces", [])
        ]

    def _list_collections(self) -> List[Dict]:
        """List collections in workspace."""
        params = {}
        if self._workspace_id:
            params["workspace"] = self._workspace_id

        response = requests.get(
            f"{self.POSTMAN_API_BASE}/collections",
            headers={"X-Api-Key": self._api_key},
            params=params,
            timeout=10
        )

        if response.status_code != 200:
            raise ConnectorError(f"Failed to list collections: {response.status_code}")

        data = response.json()
        return data.get("collections", [])

    def _list_environments(self) -> List[Dict]:
        """List environments in workspace."""
        params = {}
        if self._workspace_id:
            params["workspace"] = self._workspace_id

        response = requests.get(
            f"{self.POSTMAN_API_BASE}/environments",
            headers={"X-Api-Key": self._api_key},
            params=params,
            timeout=10
        )

        if response.status_code != 200:
            raise ConnectorError(f"Failed to list environments: {response.status_code}")

        data = response.json()
        return data.get("environments", [])

    def _extract_endpoints_from_collection(self, collection: Dict) -> List[Dict]:
        """Extract endpoints from collection data."""
        endpoints = []

        def process_items(items: List, parent_auth: Dict = None):
            for item in items:
                if "item" in item:
                    # Folder - recurse
                    folder_auth = item.get("auth") or parent_auth
                    process_items(item["item"], folder_auth)
                elif "request" in item:
                    # Request
                    req = item["request"]
                    url = req.get("url", "")

                    if isinstance(url, dict):
                        path = "/" + "/".join(url.get("path", []))
                    else:
                        path = url

                    endpoints.append({
                        "method": req.get("method", "GET"),
                        "path": path,
                        "name": item.get("name"),
                        "has_body": bool(req.get("body")),
                    })

        process_items(collection.get("item", []))
        return endpoints

    def _extract_auth_from_collection(self, collection: Dict) -> Optional[Dict]:
        """Extract auth configuration from collection."""
        auth = collection.get("auth")
        if not auth:
            return None

        auth_type = auth.get("type", "").lower()
        result = {"type": auth_type}

        if auth_type == "bearer":
            for item in auth.get("bearer", []):
                if item.get("key") == "token":
                    result["token"] = item.get("value", "")

        elif auth_type == "oauth2":
            for item in auth.get("oauth2", []):
                key = item.get("key")
                value = item.get("value", "")
                if key in ["accessTokenUrl", "tokenUrl"]:
                    result["token_url"] = value
                elif key == "clientId":
                    result["client_id"] = value

        return result


# Convenience functions for agent tools

def parse_postman_collection(path: str) -> Dict[str, Any]:
    """Parse a local Postman collection file.

    Args:
        path: Path to the collection file

    Returns:
        Dict with parsed configuration
    """
    connector = PostmanFileConnector()
    connect_result = connector.connect(path=path)

    if not connect_result.success:
        return connect_result.to_dict()

    result = connector.fetch_config()
    return result.to_dict()


def parse_postman_env(path: str) -> Dict[str, Any]:
    """Parse a local Postman environment file.

    Args:
        path: Path to the environment file

    Returns:
        Dict with parsed configuration
    """
    connector = PostmanFileConnector()
    connect_result = connector.connect(path=path)

    if not connect_result.success:
        return connect_result.to_dict()

    result = connector.fetch_config()
    return result.to_dict()


def fetch_from_postman_api(
    api_key: str,
    workspace_id: Optional[str] = None,
    collection_id: Optional[str] = None,
    environment_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch configuration from Postman API.

    Args:
        api_key: Postman API key
        workspace_id: Optional workspace ID
        collection_id: Optional collection ID to fetch
        environment_id: Optional environment ID to fetch

    Returns:
        Dict with fetched configuration
    """
    connector = PostmanAPIConnector()
    connect_result = connector.connect(api_key=api_key, workspace_id=workspace_id)

    if not connect_result.success:
        return connect_result.to_dict()

    # Fetch specific items if requested
    if collection_id:
        result = connector.fetch_collection(collection_id)
        return result.to_dict()

    if environment_id:
        result = connector.fetch_environment(environment_id)
        return result.to_dict()

    # Otherwise return workspace listing
    result = connector.fetch_config()
    return result.to_dict()
