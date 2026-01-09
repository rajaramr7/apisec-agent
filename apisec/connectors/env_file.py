"""
Environment file connector for parsing .env files.

Extracts API configuration from environment files:
- Base URLs and API endpoints
- Authentication tokens and credentials
- API keys and secrets
- Environment-specific configurations

Supports multiple formats:
- .env
- .env.local
- .env.development / .env.production / .env.test
- .env.example (for discovering required variables)
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from .base import FileConnector, ConnectorResult


@dataclass
class EnvVariable:
    """Parsed environment variable."""
    name: str
    value: str
    category: str  # 'auth', 'url', 'secret', 'config', 'unknown'
    is_sensitive: bool = False
    is_placeholder: bool = False
    source_file: str = ""
    line_number: int = 0


# Patterns to categorize variables
URL_PATTERNS = [
    r'.*_URL$', r'.*_URI$', r'.*_ENDPOINT$', r'.*_HOST$',
    r'^API_URL$', r'^BASE_URL$', r'^SERVER_URL$',
    r'^BACKEND_URL$', r'^FRONTEND_URL$',
]

AUTH_PATTERNS = [
    r'.*_TOKEN$', r'.*_KEY$', r'.*_SECRET$', r'.*_PASSWORD$',
    r'.*_AUTH$', r'^JWT_.*', r'^OAUTH_.*', r'^API_KEY$',
    r'^AUTH_TOKEN$', r'^ACCESS_TOKEN$', r'^REFRESH_TOKEN$',
    r'^BEARER_TOKEN$', r'^CLIENT_ID$', r'^CLIENT_SECRET$',
]

SECRET_PATTERNS = [
    r'.*_PASSWORD$', r'.*_SECRET$', r'.*_PRIVATE_KEY$',
    r'^DB_PASSWORD$', r'^DATABASE_PASSWORD$',
    r'^ENCRYPTION_KEY$', r'^SIGNING_KEY$',
]

# Patterns that indicate placeholder values
PLACEHOLDER_PATTERNS = [
    r'^your[-_]',
    r'^<.*>$',
    r'^\$\{.*\}$',
    r'^xxx+$',
    r'^TODO',
    r'^CHANGE[-_]?ME',
    r'^REPLACE[-_]?ME',
    r'^INSERT[-_]?HERE',
    r'example\.com',
    r'^sk[-_]test[-_]',  # Stripe test key pattern
    r'^pk[-_]test[-_]',
]


def categorize_variable(name: str, value: str) -> Tuple[str, bool, bool]:
    """Categorize an environment variable.

    Args:
        name: Variable name
        value: Variable value

    Returns:
        Tuple of (category, is_sensitive, is_placeholder)
    """
    name_upper = name.upper()
    value_lower = value.lower() if value else ""

    # Check if placeholder
    is_placeholder = False
    for pattern in PLACEHOLDER_PATTERNS:
        if re.match(pattern, value_lower, re.IGNORECASE):
            is_placeholder = True
            break

    # Check for empty or obviously fake values
    if not value or value in ('""', "''", 'null', 'none', 'undefined'):
        is_placeholder = True

    # Categorize by name patterns
    is_sensitive = False
    category = 'unknown'

    # Check secret patterns first (most restrictive)
    for pattern in SECRET_PATTERNS:
        if re.match(pattern, name_upper):
            category = 'secret'
            is_sensitive = True
            break

    # Check auth patterns
    if category == 'unknown':
        for pattern in AUTH_PATTERNS:
            if re.match(pattern, name_upper):
                category = 'auth'
                is_sensitive = True
                break

    # Check URL patterns
    if category == 'unknown':
        for pattern in URL_PATTERNS:
            if re.match(pattern, name_upper):
                category = 'url'
                break

    # Check if value looks like a URL
    if category == 'unknown' and value:
        if value.startswith(('http://', 'https://', 'ws://', 'wss://')):
            category = 'url'

    # Default to config for other variables
    if category == 'unknown':
        category = 'config'

    return category, is_sensitive, is_placeholder


def parse_env_line(line: str, line_number: int, source_file: str) -> Optional[EnvVariable]:
    """Parse a single line from an env file.

    Args:
        line: The line to parse
        line_number: Line number in file
        source_file: Source file path

    Returns:
        EnvVariable if valid, None otherwise
    """
    # Skip empty lines and comments
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # Handle export prefix
    if line.startswith('export '):
        line = line[7:]

    # Parse KEY=VALUE
    match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$', line)
    if not match:
        return None

    name = match.group(1)
    value = match.group(2)

    # Remove quotes from value
    if value:
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]

    # Handle escaped characters
    value = value.replace('\\n', '\n').replace('\\t', '\t')

    category, is_sensitive, is_placeholder = categorize_variable(name, value)

    return EnvVariable(
        name=name,
        value=value,
        category=category,
        is_sensitive=is_sensitive,
        is_placeholder=is_placeholder,
        source_file=source_file,
        line_number=line_number,
    )


class EnvFileConnector(FileConnector):
    """Connector for parsing .env files."""

    @property
    def name(self) -> str:
        return "env_file"

    @property
    def description(self) -> str:
        return "Parse environment files (.env) for API configuration"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._variables: List[EnvVariable] = []
        self._include_sensitive: bool = kwargs.get('include_sensitive', False)

    def fetch_config(self) -> ConnectorResult:
        """Parse the connected env file and extract configuration.

        Returns:
            ConnectorResult with parsed environment data
        """
        if not self._connected or not self._file_path:
            return self._error("Not connected to a file")

        try:
            content = self._read_file()
            self._variables = []

            lines = content.splitlines()
            for i, line in enumerate(lines, start=1):
                var = parse_env_line(line, i, str(self._file_path))
                if var:
                    self._variables.append(var)

            # Build result data
            return self._build_result()

        except Exception as e:
            return self._error(f"Failed to parse env file: {e}")

    def _build_result(self) -> ConnectorResult:
        """Build ConnectorResult from parsed variables."""
        # Group by category
        by_category: Dict[str, List[EnvVariable]] = {
            'url': [],
            'auth': [],
            'secret': [],
            'config': [],
        }

        for var in self._variables:
            if var.category in by_category:
                by_category[var.category].append(var)

        # Build environment dict (mask sensitive values unless requested)
        environment = {}
        for var in self._variables:
            if var.is_sensitive and not self._include_sensitive:
                environment[var.name] = "***MASKED***"
            else:
                environment[var.name] = var.value

        # Extract auth config
        auth_config = self._extract_auth_config(by_category['auth'])

        # Extract base URL
        base_url = self._extract_base_url(by_category['url'])

        # Build data summary
        data = {
            "variables_count": len(self._variables),
            "categories": {
                cat: len(vars) for cat, vars in by_category.items()
            },
            "base_url": base_url,
            "has_auth": len(by_category['auth']) > 0,
            "placeholders_count": sum(1 for v in self._variables if v.is_placeholder),
        }

        # Generate warnings
        warnings = []
        placeholders = [v for v in self._variables if v.is_placeholder]
        if placeholders:
            placeholder_names = [v.name for v in placeholders[:5]]
            warnings.append(
                f"Found {len(placeholders)} placeholder value(s): {', '.join(placeholder_names)}"
            )

        # If we found auth but it's all placeholders, warn
        auth_placeholders = [v for v in by_category['auth'] if v.is_placeholder]
        if auth_placeholders and len(auth_placeholders) == len(by_category['auth']):
            warnings.append("All authentication values appear to be placeholders")

        return self._success(
            data=data,
            source=f"env_file://{self._file_path}",
            auth_config=auth_config,
            environment=environment,
            warnings=warnings,
        )

    def _extract_auth_config(self, auth_vars: List[EnvVariable]) -> Optional[Dict[str, Any]]:
        """Extract authentication configuration from auth variables."""
        if not auth_vars:
            return None

        # Look for common auth patterns
        auth_config: Dict[str, Any] = {"type": "unknown"}

        var_dict = {v.name.upper(): v for v in auth_vars}

        # Check for Bearer/JWT token auth
        token_names = ['API_TOKEN', 'AUTH_TOKEN', 'ACCESS_TOKEN', 'BEARER_TOKEN', 'JWT_TOKEN', 'TOKEN']
        for name in token_names:
            if name in var_dict:
                var = var_dict[name]
                auth_config = {
                    "type": "bearer",
                    "token_env_var": var.name,
                    "is_placeholder": var.is_placeholder,
                }
                break

        # Check for API key auth
        if auth_config["type"] == "unknown":
            key_names = ['API_KEY', 'APIKEY', 'X_API_KEY']
            for name in key_names:
                if name in var_dict:
                    var = var_dict[name]
                    auth_config = {
                        "type": "api_key",
                        "key_env_var": var.name,
                        "header_name": "X-API-Key",  # Common default
                        "is_placeholder": var.is_placeholder,
                    }
                    break

        # Check for OAuth client credentials
        if auth_config["type"] == "unknown":
            if 'CLIENT_ID' in var_dict and 'CLIENT_SECRET' in var_dict:
                auth_config = {
                    "type": "oauth2_client_credentials",
                    "client_id_env_var": var_dict['CLIENT_ID'].name,
                    "client_secret_env_var": var_dict['CLIENT_SECRET'].name,
                    "is_placeholder": (
                        var_dict['CLIENT_ID'].is_placeholder or
                        var_dict['CLIENT_SECRET'].is_placeholder
                    ),
                }

        # Check for basic auth
        if auth_config["type"] == "unknown":
            username_names = ['USERNAME', 'API_USERNAME', 'AUTH_USERNAME', 'USER']
            password_names = ['PASSWORD', 'API_PASSWORD', 'AUTH_PASSWORD', 'PASS']

            username_var = None
            password_var = None

            for name in username_names:
                if name in var_dict:
                    username_var = var_dict[name]
                    break

            for name in password_names:
                if name in var_dict:
                    password_var = var_dict[name]
                    break

            if username_var and password_var:
                auth_config = {
                    "type": "basic",
                    "username_env_var": username_var.name,
                    "password_env_var": password_var.name,
                    "is_placeholder": (
                        username_var.is_placeholder or password_var.is_placeholder
                    ),
                }

        return auth_config if auth_config["type"] != "unknown" else None

    def _extract_base_url(self, url_vars: List[EnvVariable]) -> Optional[str]:
        """Extract the base URL from URL variables."""
        if not url_vars:
            return None

        # Priority order for base URL
        priority_names = [
            'API_URL', 'BASE_URL', 'API_BASE_URL', 'BACKEND_URL',
            'SERVER_URL', 'API_ENDPOINT', 'API_HOST',
        ]

        var_dict = {v.name.upper(): v for v in url_vars}

        for name in priority_names:
            if name in var_dict and not var_dict[name].is_placeholder:
                return var_dict[name].value

        # Return first non-placeholder URL
        for var in url_vars:
            if not var.is_placeholder:
                return var.value

        return None

    def get_urls(self) -> Dict[str, str]:
        """Get all URL variables."""
        return {
            v.name: v.value
            for v in self._variables
            if v.category == 'url' and not v.is_placeholder
        }

    def get_auth_variables(self) -> Dict[str, str]:
        """Get all authentication variables (masked if sensitive)."""
        result = {}
        for v in self._variables:
            if v.category in ('auth', 'secret'):
                if self._include_sensitive:
                    result[v.name] = v.value
                else:
                    result[v.name] = "***MASKED***"
        return result

    def get_placeholders(self) -> List[str]:
        """Get list of variable names that are placeholders."""
        return [v.name for v in self._variables if v.is_placeholder]


def scan_env_files(directory: str) -> Dict[str, Any]:
    """Scan a directory for all .env files.

    Args:
        directory: Path to directory to scan

    Returns:
        Dict with found files and combined configuration
    """
    dir_path = Path(directory).resolve()

    if not dir_path.is_dir():
        return {"success": False, "error": f"Not a directory: {directory}"}

    # Find .env files
    env_patterns = [
        '.env', '.env.local', '.env.development', '.env.production',
        '.env.test', '.env.example', '.env.sample',
    ]

    found_files = []
    for pattern in env_patterns:
        env_file = dir_path / pattern
        if env_file.exists():
            found_files.append(str(env_file))

    if not found_files:
        return {
            "success": False,
            "error": "No .env files found",
            "searched": str(dir_path),
        }

    # Parse all files
    all_variables: Dict[str, EnvVariable] = {}
    file_results = []

    for file_path in found_files:
        connector = EnvFileConnector()
        connect_result = connector.connect(path=file_path)

        if connect_result.success:
            result = connector.fetch_config()
            file_results.append({
                "file": file_path,
                "success": result.success,
                "variables": len(connector._variables),
                "data": result.data,
            })

            # Merge variables (later files override earlier)
            for var in connector._variables:
                all_variables[var.name] = var

    # Build combined result
    return {
        "success": True,
        "files_found": found_files,
        "file_results": file_results,
        "total_variables": len(all_variables),
        "environment": {
            v.name: v.value if not v.is_sensitive else "***MASKED***"
            for v in all_variables.values()
        },
    }


# Convenience function for agent tool
def parse_env_file(path: str, include_sensitive: bool = False) -> Dict[str, Any]:
    """Parse a single .env file.

    This is the main entry point for the agent tool.

    Args:
        path: Path to the .env file
        include_sensitive: Whether to include sensitive values unmasked

    Returns:
        Dict with parsed configuration
    """
    connector = EnvFileConnector(include_sensitive=include_sensitive)
    connect_result = connector.connect(path=path)

    if not connect_result.success:
        return connect_result.to_dict()

    result = connector.fetch_config()
    return result.to_dict()
