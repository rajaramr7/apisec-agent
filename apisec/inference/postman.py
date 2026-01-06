"""Postman collection parser."""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


def parse_postman(path: str) -> Dict[str, Any]:
    """Parse a Postman collection file.

    Extracts requests, authentication configuration, environment variables,
    and pre-request scripts.

    Args:
        path: Path to the Postman collection file (JSON)

    Returns:
        Dictionary with parsed collection information:
        {
            "info": {...},
            "requests": [...],
            "auth": {...},
            "variables": {...},
            "pre_request_script": str,
            "folders": [...]
        }
    """
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(f"Postman collection not found: {path}")

    content = file_path.read_text(encoding="utf-8")
    collection = json.loads(content)

    if not collection:
        raise ValueError(f"Empty or invalid Postman collection: {path}")

    return {
        "info": _extract_info(collection),
        "requests": _extract_requests(collection),
        "auth": _extract_auth(collection),
        "variables": _extract_variables(collection),
        "pre_request_script": _extract_pre_request_script(collection),
        "folders": _extract_folders(collection),
        "environment_vars_used": _find_env_vars_used(collection),
    }


def _extract_info(collection: Dict) -> Dict[str, Any]:
    """Extract collection info."""
    info = collection.get("info", {})
    return {
        "name": info.get("name", "Unknown Collection"),
        "description": info.get("description"),
        "schema": info.get("schema"),
    }


def _extract_requests(collection: Dict, parent_auth: Dict = None) -> List[Dict[str, Any]]:
    """Extract all requests from the collection, including nested items."""
    requests = []
    items = collection.get("item", [])

    for item in items:
        # If item has nested items, it's a folder
        if "item" in item:
            # Get folder-level auth
            folder_auth = item.get("auth") or parent_auth
            nested = _extract_requests(item, folder_auth)
            requests.extend(nested)
        elif "request" in item:
            request = _parse_request(item, parent_auth)
            requests.append(request)

    return requests


def _parse_request(item: Dict, parent_auth: Dict = None) -> Dict[str, Any]:
    """Parse a single request item."""
    request = item.get("request", {})

    # Handle URL (can be string or object)
    url = request.get("url", "")
    if isinstance(url, dict):
        url_raw = url.get("raw", "")
        url_path = "/" + "/".join(url.get("path", []))
        url_host = ".".join(url.get("host", []))
    else:
        url_raw = url
        url_path = url
        url_host = ""

    # Extract headers
    headers = {}
    for header in request.get("header", []):
        if not header.get("disabled", False):
            headers[header.get("key", "")] = header.get("value", "")

    # Extract body
    body = None
    body_data = request.get("body", {})
    if body_data:
        mode = body_data.get("mode")
        if mode == "raw":
            raw = body_data.get("raw", "")
            # Try to parse as JSON
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                body = raw
        elif mode == "urlencoded":
            body = {
                item.get("key"): item.get("value")
                for item in body_data.get("urlencoded", [])
                if not item.get("disabled", False)
            }
        elif mode == "formdata":
            body = {
                item.get("key"): item.get("value")
                for item in body_data.get("formdata", [])
                if not item.get("disabled", False)
            }

    # Extract auth (item-level overrides parent)
    auth = item.get("auth") or request.get("auth") or parent_auth

    return {
        "name": item.get("name", ""),
        "method": request.get("method", "GET"),
        "url": url_raw,
        "path": url_path,
        "host": url_host,
        "headers": headers,
        "body": body,
        "auth": _parse_auth(auth) if auth else None,
        "description": request.get("description"),
    }


def _extract_auth(collection: Dict) -> Optional[Dict[str, Any]]:
    """Extract collection-level auth configuration."""
    auth = collection.get("auth")
    if not auth:
        return None
    return _parse_auth(auth)


def _parse_auth(auth: Dict) -> Dict[str, Any]:
    """Parse auth configuration."""
    auth_type = auth.get("type", "").lower()

    result = {"type": auth_type}

    if auth_type == "bearer":
        bearer = auth.get("bearer", [])
        for item in bearer:
            if item.get("key") == "token":
                result["token"] = item.get("value", "")
                break

    elif auth_type == "basic":
        basic = auth.get("basic", [])
        for item in basic:
            key = item.get("key")
            if key == "username":
                result["username"] = item.get("value", "")
            elif key == "password":
                result["password"] = item.get("value", "")

    elif auth_type == "apikey":
        apikey = auth.get("apikey", [])
        for item in apikey:
            key = item.get("key")
            if key == "key":
                result["header_name"] = item.get("value", "")
            elif key == "value":
                result["api_key"] = item.get("value", "")
            elif key == "in":
                result["in"] = item.get("value", "header")

    elif auth_type == "oauth2":
        oauth2 = auth.get("oauth2", [])
        for item in oauth2:
            key = item.get("key")
            value = item.get("value", "")
            if key in ["accessTokenUrl", "tokenUrl"]:
                result["token_url"] = value
            elif key == "grant_type":
                result["grant_type"] = value
            elif key == "clientId":
                result["client_id"] = value
            elif key == "clientSecret":
                result["client_secret"] = value

    return result


def _extract_variables(collection: Dict) -> Dict[str, str]:
    """Extract collection variables."""
    variables = {}
    for var in collection.get("variable", []):
        key = var.get("key", "")
        value = var.get("value", "")
        if key:
            variables[key] = value
    return variables


def _extract_pre_request_script(collection: Dict) -> Optional[str]:
    """Extract collection-level pre-request script."""
    events = collection.get("event", [])
    for event in events:
        if event.get("listen") == "prerequest":
            script = event.get("script", {})
            exec_lines = script.get("exec", [])
            if exec_lines:
                return "\n".join(exec_lines)
    return None


def _extract_folders(collection: Dict) -> List[str]:
    """Extract folder names from the collection."""
    folders = []
    items = collection.get("item", [])

    for item in items:
        if "item" in item:  # It's a folder
            folders.append(item.get("name", ""))

    return folders


def _find_env_vars_used(collection: Dict) -> Set[str]:
    """Find all environment variables referenced in the collection.

    Looks for {{variable_name}} patterns.
    """
    # Convert entire collection to string for simple pattern matching
    collection_str = json.dumps(collection)

    # Find all {{variable}} patterns
    pattern = r"\{\{([^}]+)\}\}"
    matches = re.findall(pattern, collection_str)

    return set(matches)


def parse_postman_environment(path: str) -> Dict[str, str]:
    """Parse a Postman environment file.

    Args:
        path: Path to the environment file

    Returns:
        Dictionary of variable name to value
    """
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(f"Postman environment not found: {path}")

    content = file_path.read_text(encoding="utf-8")
    env = json.loads(content)

    variables = {}
    for var in env.get("values", []):
        if var.get("enabled", True):
            key = var.get("key", "")
            value = var.get("value", "")
            if key:
                variables[key] = value

    return variables


class PostmanParser:
    """Parser for Postman collections.

    Extracts API information including requests, authentication
    configuration, environment variables, and test scripts.
    """

    def __init__(self, collection_path: Optional[str] = None):
        """Initialize the Postman parser.

        Args:
            collection_path: Path to the Postman collection file
        """
        self.collection_path = Path(collection_path) if collection_path else None
        self.parsed = None

    def load(self, collection_path: str) -> None:
        """Load a Postman collection.

        Args:
            collection_path: Path to the collection file
        """
        self.collection_path = Path(collection_path)
        self.parsed = parse_postman(collection_path)

    def parse(self) -> Dict[str, Any]:
        """Parse the loaded collection.

        Returns:
            Parsed API information
        """
        if self.parsed is None and self.collection_path:
            self.parsed = parse_postman(str(self.collection_path))
        return self.parsed

    def get_requests(self) -> List[Dict[str, Any]]:
        """Extract all requests from the collection."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("requests", [])

    def get_auth_config(self) -> Optional[Dict[str, Any]]:
        """Extract authentication configuration."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("auth")

    def get_variables(self) -> Dict[str, str]:
        """Extract collection variables."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("variables", {})

    def get_environment_vars_used(self) -> Set[str]:
        """Get all environment variables referenced in the collection."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("environment_vars_used", set())

    def get_pre_request_script(self) -> Optional[str]:
        """Get the collection-level pre-request script."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("pre_request_script")

    def has_token_flow(self) -> bool:
        """Check if the pre-request script handles token fetching."""
        script = self.get_pre_request_script()
        if not script:
            return False

        # Look for common token flow patterns
        token_patterns = [
            "pm.sendRequest",
            "access_token",
            "token_endpoint",
            "auth/token",
            "oauth",
        ]

        script_lower = script.lower()
        return any(pattern in script_lower for pattern in token_patterns)
