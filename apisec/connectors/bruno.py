"""
Bruno connector for parsing Bruno API client collections.

Bruno is an open-source API client that stores collections as files.
Collections use .bru files (Bruno markup) and folder structure.

Extracts:
- Requests with methods, URLs, headers, bodies
- Environment variables from environments/
- Collection-level settings
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseConnector, ConnectorResult


class BrunoConnector(BaseConnector):
    """Connector for Bruno API client collections."""

    @property
    def name(self) -> str:
        return "bruno"

    @property
    def description(self) -> str:
        return "Parse Bruno API client collections"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._collection_path: Optional[Path] = None
        self._requests: List[Dict] = []
        self._environments: Dict[str, Dict] = {}

    def connect(self, path: str, **kwargs) -> ConnectorResult:
        """Connect to a Bruno collection directory.

        Args:
            path: Path to Bruno collection directory (contains bruno.json)

        Returns:
            ConnectorResult indicating success/failure
        """
        self._collection_path = Path(path).resolve()

        if not self._collection_path.exists():
            return self._error(f"Path not found: {path}")

        # Check if it's a Bruno collection
        bruno_json = self._collection_path / "bruno.json"
        if not bruno_json.exists():
            # Maybe it's a .bru file directly
            if self._collection_path.suffix == ".bru":
                self._connected = True
                return self._success(
                    source=f"bruno://{self._collection_path}",
                    data={"type": "single_request"}
                )
            return self._error("Not a Bruno collection (no bruno.json found)")

        self._connected = True
        return self._success(
            source=f"bruno://{self._collection_path}",
            data={"type": "collection"}
        )

    def fetch_config(self) -> ConnectorResult:
        """Parse the Bruno collection and extract configuration.

        Returns:
            ConnectorResult with parsed data
        """
        if not self._connected or not self._collection_path:
            return self._error("Not connected to a Bruno collection")

        try:
            # Parse collection info
            collection_info = self._parse_collection_info()

            # Find and parse all .bru files
            self._requests = []
            if self._collection_path.suffix == ".bru":
                # Single file
                req = self._parse_bru_file(self._collection_path)
                if req:
                    self._requests.append(req)
            else:
                # Directory - find all .bru files
                for bru_file in self._collection_path.rglob("*.bru"):
                    req = self._parse_bru_file(bru_file)
                    if req:
                        self._requests.append(req)

            # Parse environments
            self._environments = self._parse_environments()

            # Extract endpoints
            endpoints = [
                {
                    "method": req.get("method", "GET"),
                    "path": req.get("url", ""),
                    "name": req.get("name", ""),
                    "has_body": bool(req.get("body")),
                    "body": req.get("body"),
                }
                for req in self._requests
            ]

            # Build environment variables dict
            env_vars = {}
            for env_name, env_data in self._environments.items():
                for key, value in env_data.items():
                    env_vars[f"{env_name}_{key}"] = value

            # Extract auth config
            auth_config = self._extract_auth_config()

            data = {
                "collection_name": collection_info.get("name", "Unknown"),
                "request_count": len(self._requests),
                "environments": list(self._environments.keys()),
            }

            return self._success(
                data=data,
                source=f"bruno://{self._collection_path}",
                endpoints=endpoints,
                auth_config=auth_config,
                environment=env_vars,
            )

        except Exception as e:
            return self._error(f"Failed to parse Bruno collection: {e}")

    def _parse_collection_info(self) -> Dict[str, Any]:
        """Parse bruno.json for collection info."""
        bruno_json = self._collection_path / "bruno.json"
        if bruno_json.exists():
            try:
                return json.loads(bruno_json.read_text(encoding='utf-8'))
            except Exception:
                pass
        return {"name": self._collection_path.name}

    def _parse_bru_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Parse a .bru file.

        Bruno uses a custom markup format:
        meta {
          name: Request Name
        }
        get {
          url: {{baseUrl}}/endpoint
        }
        headers {
          Content-Type: application/json
        }
        body:json {
          "key": "value"
        }
        """
        try:
            content = file_path.read_text(encoding='utf-8')
            result = {
                "name": file_path.stem,
                "file": str(file_path),
            }

            # Parse meta block
            meta_match = re.search(r'meta\s*\{([^}]+)\}', content, re.DOTALL)
            if meta_match:
                meta_content = meta_match.group(1)
                name_match = re.search(r'name:\s*(.+)', meta_content)
                if name_match:
                    result["name"] = name_match.group(1).strip()

            # Parse HTTP method and URL
            for method in ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']:
                method_match = re.search(
                    rf'{method}\s*\{{([^}}]+)\}}',
                    content,
                    re.DOTALL | re.IGNORECASE
                )
                if method_match:
                    result["method"] = method.upper()
                    method_content = method_match.group(1)
                    url_match = re.search(r'url:\s*(.+)', method_content)
                    if url_match:
                        result["url"] = url_match.group(1).strip()
                    break

            # Parse headers
            headers_match = re.search(r'headers\s*\{([^}]+)\}', content, re.DOTALL)
            if headers_match:
                headers = {}
                for line in headers_match.group(1).strip().split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                result["headers"] = headers

            # Parse body
            body_match = re.search(r'body:json\s*\{(.+)\}', content, re.DOTALL)
            if body_match:
                try:
                    # The body content might span multiple lines
                    body_content = body_match.group(1).strip()
                    # Try to find JSON object/array
                    json_match = re.search(r'(\{[\s\S]*\}|\[[\s\S]*\])', body_content)
                    if json_match:
                        result["body"] = json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass

            # Parse auth
            auth_match = re.search(r'auth:(\w+)\s*\{([^}]+)\}', content, re.DOTALL)
            if auth_match:
                auth_type = auth_match.group(1).lower()
                auth_content = auth_match.group(2)
                result["auth"] = {"type": auth_type}

                if auth_type == "bearer":
                    token_match = re.search(r'token:\s*(.+)', auth_content)
                    if token_match:
                        result["auth"]["token"] = token_match.group(1).strip()

            return result if result.get("method") else None

        except Exception:
            return None

    def _parse_environments(self) -> Dict[str, Dict[str, str]]:
        """Parse environment files from environments/ directory."""
        environments = {}
        env_dir = self._collection_path / "environments"

        if not env_dir.exists():
            return environments

        for env_file in env_dir.glob("*.bru"):
            try:
                content = env_file.read_text(encoding='utf-8')
                env_name = env_file.stem

                # Parse vars block
                vars_match = re.search(r'vars\s*\{([^}]+)\}', content, re.DOTALL)
                if vars_match:
                    env_vars = {}
                    for line in vars_match.group(1).strip().split('\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            env_vars[key.strip()] = value.strip()
                    environments[env_name] = env_vars

            except Exception:
                continue

        return environments

    def _extract_auth_config(self) -> Optional[Dict[str, Any]]:
        """Extract auth configuration from requests."""
        for req in self._requests:
            if req.get("auth"):
                return req["auth"]
        return None


def parse_bruno_collection(path: str) -> Dict[str, Any]:
    """Parse a Bruno collection.

    Args:
        path: Path to Bruno collection directory or .bru file

    Returns:
        Dict with parsed configuration
    """
    connector = BrunoConnector()
    connect_result = connector.connect(path=path)

    if not connect_result.success:
        return connect_result.to_dict()

    result = connector.fetch_config()
    return result.to_dict()
