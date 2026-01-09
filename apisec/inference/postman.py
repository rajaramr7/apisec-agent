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


def parse_postman_environment(path: str) -> Dict[str, Any]:
    """Parse a Postman environment file and extract configuration.

    Analyzes the environment file to identify auth-related variables,
    URL-related variables, user identity variables, and credential status.

    Args:
        path: Path to the Postman environment file

    Returns:
        Dictionary with structured environment information:
        {
            "name": "staging",
            "variables": {"base_url": "https://...", ...},
            "auth_related": {"client_id": "...", "client_secret": "...", ...},
            "url_related": {"base_url": "https://...", "auth_url": "...", ...},
            "user_identities": {"user_a": {"username": "...", "token": "..."}, ...},
            "has_credentials": True,
            "has_user_tokens": True,
            "empty_secrets": ["user_a_token", ...]
        }
    """
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(f"Postman environment not found: {path}")

    content = file_path.read_text(encoding="utf-8")
    env = json.loads(content)

    # Extract environment name
    env_name = env.get("name", Path(path).stem.replace(".postman_environment", ""))

    # Extract all variables
    variables = {}
    secrets = {}
    empty_secrets = []

    for var in env.get("values", []):
        if var.get("enabled", True):
            key = var.get("key", "")
            value = var.get("value", "")
            var_type = var.get("type", "default")

            if key:
                variables[key] = value

                # Track secrets
                if var_type == "secret":
                    secrets[key] = value
                    if not value or value.strip() == "":
                        empty_secrets.append(key)

    # Identify auth-related variables
    auth_patterns = ["token", "key", "secret", "auth", "password", "credential", "api_key", "apikey"]
    auth_related = {}
    for key, value in variables.items():
        key_lower = key.lower()
        if any(pattern in key_lower for pattern in auth_patterns):
            auth_related[key] = value

    # Identify URL-related variables
    url_patterns = ["url", "host", "endpoint", "base", "uri", "server"]
    url_related = {}
    for key, value in variables.items():
        key_lower = key.lower()
        if any(pattern in key_lower for pattern in url_patterns):
            url_related[key] = value

    # Identify user identity variables
    user_identities = _extract_user_identities(variables)

    # Check for credentials and tokens
    has_credentials = bool(auth_related.get("client_id") or auth_related.get("client_secret"))
    has_user_tokens = any(
        key.endswith("_token") and value
        for key, value in auth_related.items()
        if "user" in key.lower() or "admin" in key.lower()
    )

    return {
        "name": env_name,
        "variables": variables,
        "auth_related": auth_related,
        "url_related": url_related,
        "user_identities": user_identities,
        "has_credentials": has_credentials,
        "has_user_tokens": has_user_tokens,
        "empty_secrets": empty_secrets,
    }


def _extract_user_identities(variables: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    """Extract user identity information from variables.

    Looks for patterns like user_a_username, user_a_password, user_a_token.

    Args:
        variables: Dictionary of all environment variables

    Returns:
        Dictionary mapping user identifiers to their credentials:
        {
            "user_a": {"username": "user_a", "password": "...", "token": "..."},
            "admin": {"username": "admin", "password": "...", "token": "..."}
        }
    """
    identities = {}

    # Common user identifier patterns
    user_patterns = [
        r"^(user_[a-z0-9]+)_(\w+)$",  # user_a_username, user_b_token
        r"^(admin)_(\w+)$",            # admin_password, admin_token
        r"^(service)_(\w+)$",          # service_account, service_token
    ]

    for key, value in variables.items():
        for pattern in user_patterns:
            match = re.match(pattern, key.lower())
            if match:
                user_id = match.group(1)
                field = match.group(2)

                if user_id not in identities:
                    identities[user_id] = {}

                identities[user_id][field] = value
                break

    return identities


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


def format_collection_summary(parsed: Dict[str, Any]) -> str:
    """
    Format collection parsing results for display.

    Args:
        parsed: Result from parse_postman()

    Returns:
        Formatted string for display
    """
    lines = []

    # Collection info
    info = parsed.get("info", {})
    name = info.get("name", "Unknown Collection")
    lines.append(f"Collection: {name}")

    # Count requests by method
    requests = parsed.get("requests", [])
    lines.append(f"\nFound {len(requests)} requests:")

    by_method: Dict[str, List[Dict]] = {}
    for req in requests:
        method = req.get("method", "GET")
        if method not in by_method:
            by_method[method] = []
        by_method[method].append(req)

    # Display by method
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
        if method not in by_method:
            continue
        lines.append(f"\n  {method}:")
        for req in by_method[method][:5]:
            path = req.get("path", req.get("url", ""))
            has_payload = " (has payload)" if req.get("body") else ""
            lines.append(f"    {path}{has_payload}")
        if len(by_method[method]) > 5:
            lines.append(f"    ... and {len(by_method[method]) - 5} more")

    # Auth info
    auth = parsed.get("auth")
    if auth:
        auth_type = auth.get("type", "none")
        lines.append(f"\nAuth: {auth_type}")
        if auth.get("token_url"):
            lines.append(f"  Token URL: {auth['token_url']}")

    # Environment variables used
    env_vars = parsed.get("environment_vars_used", set())
    if env_vars:
        lines.append(f"\nEnvironment variables used: {len(env_vars)}")
        for var in sorted(env_vars)[:10]:
            lines.append(f"  {{{{{var}}}}}")
        if len(env_vars) > 10:
            lines.append(f"  ... and {len(env_vars) - 10} more")

    return "\n".join(lines)


def format_environment_summary(env: Dict[str, Any]) -> str:
    """
    Format environment parsing results for display.

    Args:
        env: Result from parse_postman_environment()

    Returns:
        Formatted string for display
    """
    lines = []

    name = env.get("name", "Unknown")
    lines.append(f"Environment: {name}")

    # URLs
    urls = env.get("url_related", {})
    if urls:
        lines.append("\n  URLs:")
        for key, value in urls.items():
            lines.append(f"    {key}: {value}")

    # Credentials (masked)
    auth = env.get("auth_related", {})
    creds = {k: v for k, v in auth.items()
             if any(p in k.lower() for p in ["client_id", "client_secret", "api_key", "password"])}
    if creds:
        lines.append("\n  Credentials:")
        for key, value in creds.items():
            if value and len(str(value)) > 4:
                display = str(value)[:4] + "..." + str(value)[-2:] if len(str(value)) > 8 else "[set]"
            else:
                display = "[empty]" if not value else "[set]"
            lines.append(f"    {key}: {display}")

    # Tokens
    identities = env.get("user_identities", {})
    if identities:
        lines.append("\n  User Identities:")
        for user_id, fields in identities.items():
            token = fields.get("token", "")
            token_status = f"[present, {len(token)} chars]" if token else "[empty]"
            lines.append(f"    {user_id}: {token_status}")

    # Empty secrets warning
    empty = env.get("empty_secrets", [])
    if empty:
        lines.append(f"\n  Warning: {len(empty)} empty secrets:")
        for secret in empty[:5]:
            lines.append(f"    - {secret}")

    # Credential status
    has_creds = env.get("has_credentials", False)
    has_tokens = env.get("has_user_tokens", False)
    lines.append(f"\n  Has credentials: {'Yes' if has_creds else 'No'}")
    lines.append(f"  Has user tokens: {'Yes' if has_tokens else 'No'}")

    return "\n".join(lines)


def parse_postman_files(
    collection_path: Optional[str] = None,
    environment_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Parse Postman collection and/or environment files.

    This is a convenience function that combines collection and environment parsing.

    Args:
        collection_path: Path to Postman collection file
        environment_path: Path to Postman environment file

    Returns:
        {
            "endpoints": ["GET /orders", ...],
            "payloads": {"POST /orders": {...}, ...},
            "auth": {"type": "oauth2", "token_url": "..."},
            "urls": {"base_url": "https://...", ...},
            "credentials": {"client_id": "...", ...},
            "tokens": {"user_a_token": "...", ...},
            "identities": {"user_a": {"username": "...", "token": "..."}, ...},
            "collection_summary": "...",
            "environment_summary": "..."
        }
    """
    result = {
        "endpoints": [],
        "payloads": {},
        "auth": None,
        "urls": {},
        "credentials": {},
        "tokens": {},
        "identities": {},
        "collection_summary": None,
        "environment_summary": None
    }

    # Parse collection
    if collection_path:
        try:
            collection = parse_postman(collection_path)

            # Extract endpoints
            for req in collection.get("requests", []):
                method = req.get("method", "GET")
                path = req.get("path", req.get("url", ""))
                endpoint = f"{method} {path}"
                if endpoint not in result["endpoints"]:
                    result["endpoints"].append(endpoint)

                # Extract payloads
                if req.get("body") and endpoint not in result["payloads"]:
                    result["payloads"][endpoint] = req["body"]

            # Extract auth
            if collection.get("auth"):
                result["auth"] = collection["auth"]

            result["collection_summary"] = format_collection_summary(collection)

        except Exception as e:
            result["collection_error"] = str(e)

    # Parse environment
    if environment_path:
        try:
            env = parse_postman_environment(environment_path)

            result["urls"] = env.get("url_related", {})
            result["identities"] = env.get("user_identities", {})

            # Separate credentials and tokens
            auth_related = env.get("auth_related", {})
            for key, value in auth_related.items():
                key_lower = key.lower()
                if any(p in key_lower for p in ["token", "bearer", "jwt"]):
                    result["tokens"][key] = value
                elif any(p in key_lower for p in ["client_id", "client_secret", "api_key", "password"]):
                    result["credentials"][key] = value

            result["environment_summary"] = format_environment_summary(env)

        except Exception as e:
            result["environment_error"] = str(e)

    return result
