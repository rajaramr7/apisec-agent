"""Environment file parser."""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def parse_env(path: str) -> Dict[str, any]:
    """Parse an environment file and extract key-value pairs.

    Also identifies common patterns like BASE_URL, AUTH_ENDPOINT, etc.

    Args:
        path: Path to the environment file

    Returns:
        Dictionary with parsed environment information:
        {
            "variables": {...},
            "base_url": str or None,
            "auth_endpoint": str or None,
            "credentials": [...],
            "identified_patterns": {...}
        }
    """
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(f"Environment file not found: {path}")

    content = file_path.read_text(encoding="utf-8")
    variables = _parse_env_content(content)

    return {
        "variables": variables,
        "base_url": _find_base_url(variables),
        "auth_endpoint": _find_auth_endpoint(variables),
        "credentials": _find_credentials(variables),
        "identified_patterns": _identify_patterns(variables),
    }


def _parse_env_content(content: str) -> Dict[str, str]:
    """Parse environment file content into key-value pairs."""
    variables = {}

    for line in content.splitlines():
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Handle export prefix
        if line.startswith("export "):
            line = line[7:]

        # Split on first = sign
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()

            # Remove quotes
            if value and value[0] in ('"', "'") and value[-1] == value[0]:
                value = value[1:-1]

            if key:
                variables[key] = value

    return variables


def _find_base_url(variables: Dict[str, str]) -> Optional[str]:
    """Find base URL from environment variables."""
    # Common patterns for base URL
    url_patterns = [
        "BASE_URL",
        "API_URL",
        "API_BASE_URL",
        "SERVER_URL",
        "SERVICE_URL",
        "BACKEND_URL",
        "HOST",
        "API_HOST",
    ]

    for pattern in url_patterns:
        # Try exact match
        if pattern in variables:
            return variables[pattern]
        # Try case-insensitive match
        for key, value in variables.items():
            if key.upper() == pattern:
                return value

    # Look for any key containing URL with http
    for key, value in variables.items():
        if "URL" in key.upper() and value.startswith(("http://", "https://")):
            return value

    return None


def _find_auth_endpoint(variables: Dict[str, str]) -> Optional[str]:
    """Find authentication endpoint from environment variables."""
    auth_patterns = [
        "AUTH_ENDPOINT",
        "TOKEN_ENDPOINT",
        "AUTH_URL",
        "TOKEN_URL",
        "LOGIN_URL",
        "OAUTH_URL",
        "AUTH_API",
    ]

    for pattern in auth_patterns:
        if pattern in variables:
            return variables[pattern]
        for key, value in variables.items():
            if key.upper() == pattern:
                return value

    # Look for any key containing AUTH and URL/ENDPOINT
    for key, value in variables.items():
        key_upper = key.upper()
        if "AUTH" in key_upper and ("URL" in key_upper or "ENDPOINT" in key_upper):
            return value

    return None


def _find_credentials(variables: Dict[str, str]) -> List[Dict[str, str]]:
    """Find credential-related variables.

    Returns list of identified credential patterns (keys only, not values).
    """
    credentials = []

    # Username patterns
    username_patterns = ["USERNAME", "USER", "CLIENT_ID", "API_USER", "LOGIN"]
    # Password/secret patterns
    password_patterns = ["PASSWORD", "SECRET", "API_KEY", "TOKEN", "CREDENTIAL"]

    found_usernames = []
    found_passwords = []

    for key in variables.keys():
        key_upper = key.upper()

        for pattern in username_patterns:
            if pattern in key_upper:
                found_usernames.append(key)
                break

        for pattern in password_patterns:
            if pattern in key_upper:
                found_passwords.append(key)
                break

    # Try to pair usernames with passwords
    for username_key in found_usernames:
        # Extract prefix (e.g., "TEST_USER" -> "TEST")
        prefix = _extract_prefix(username_key)

        # Find matching password
        matching_password = None
        for password_key in found_passwords:
            if prefix and prefix in password_key.upper():
                matching_password = password_key
                break

        credentials.append({
            "username_var": username_key,
            "password_var": matching_password,
            "prefix": prefix,
        })

    # Add standalone passwords/secrets
    for password_key in found_passwords:
        # Check if already paired
        already_paired = any(
            cred.get("password_var") == password_key
            for cred in credentials
        )
        if not already_paired:
            credentials.append({
                "username_var": None,
                "password_var": password_key,
                "prefix": _extract_prefix(password_key),
            })

    return credentials


def _extract_prefix(key: str) -> Optional[str]:
    """Extract prefix from a variable name.

    e.g., "TEST_USER_PASSWORD" -> "TEST_USER"
         "ADMIN_SECRET" -> "ADMIN"
    """
    # Common suffixes to remove
    suffixes = [
        "_PASSWORD", "_SECRET", "_TOKEN", "_KEY", "_CREDENTIAL",
        "_USERNAME", "_USER", "_LOGIN", "_ID",
    ]

    key_upper = key.upper()
    for suffix in suffixes:
        if key_upper.endswith(suffix):
            return key_upper[:-len(suffix)]

    return None


def _identify_patterns(variables: Dict[str, str]) -> Dict[str, List[str]]:
    """Identify common patterns in environment variables."""
    patterns = {
        "urls": [],
        "credentials": [],
        "api_keys": [],
        "database": [],
        "logging": [],
        "other": [],
    }

    for key, value in variables.items():
        key_upper = key.upper()

        # URL patterns
        if "URL" in key_upper or "ENDPOINT" in key_upper or "HOST" in key_upper:
            patterns["urls"].append(key)

        # Credential patterns
        elif any(p in key_upper for p in ["USER", "PASSWORD", "SECRET", "CREDENTIAL"]):
            patterns["credentials"].append(key)

        # API key patterns
        elif any(p in key_upper for p in ["API_KEY", "TOKEN", "AUTH"]):
            patterns["api_keys"].append(key)

        # Database patterns
        elif any(p in key_upper for p in ["DATABASE", "DB_", "POSTGRES", "MYSQL", "MONGO", "REDIS"]):
            patterns["database"].append(key)

        # Logging patterns
        elif any(p in key_upper for p in ["LOG", "DEBUG", "VERBOSE"]):
            patterns["logging"].append(key)

        else:
            patterns["other"].append(key)

    return patterns


def find_env_files(repo_path: str) -> List[str]:
    """Find environment files in a repository.

    Args:
        repo_path: Path to the repository

    Returns:
        List of paths to environment files
    """
    from .scanner import scan_repo

    artifacts = scan_repo(repo_path)
    return artifacts.get("env", [])


class EnvParser:
    """Parser for environment configuration files.

    Extracts configuration from .env files and similar
    environment configuration formats.
    """

    def __init__(self, env_path: Optional[str] = None):
        """Initialize the environment parser.

        Args:
            env_path: Path to the environment file
        """
        self.env_path = Path(env_path) if env_path else None
        self.parsed = None

    def load(self, env_path: str) -> None:
        """Load an environment file.

        Args:
            env_path: Path to the environment file
        """
        self.env_path = Path(env_path)
        self.parsed = parse_env(env_path)

    def parse(self) -> Dict[str, any]:
        """Parse the loaded environment file.

        Returns:
            Parsed environment information
        """
        if self.parsed is None and self.env_path:
            self.parsed = parse_env(str(self.env_path))
        return self.parsed

    def get_variables(self) -> Dict[str, str]:
        """Get all variables."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("variables", {})

    def get_base_url(self) -> Optional[str]:
        """Extract base URL from environment."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("base_url")

    def get_auth_endpoint(self) -> Optional[str]:
        """Extract authentication endpoint."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("auth_endpoint")

    def get_credentials(self) -> List[Dict[str, str]]:
        """Extract credential-related variables."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("credentials", [])

    def get(self, key: str, default: str = None) -> Optional[str]:
        """Get a specific variable value.

        Args:
            key: Variable name
            default: Default value if not found

        Returns:
            Variable value or default
        """
        if self.parsed is None:
            self.parse()
        return self.parsed.get("variables", {}).get(key, default)
