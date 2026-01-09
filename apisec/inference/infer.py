"""High-level inference functions for API configuration."""

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .openapi import parse_openapi
from .postman import parse_postman
from .logs import parse_logs
from .env import parse_env


def infer_api_config(repo_path: str, artifacts: Dict[str, List[str]]) -> Dict[str, Any]:
    """Infer API configuration from discovered artifacts.

    Analyzes OpenAPI specs, Postman collections, logs, and env files
    to build a comprehensive configuration.

    Args:
        repo_path: Path to the repository
        artifacts: Dictionary of artifact types to file paths

    Returns:
        Dictionary with inferred configuration:
            - api_name: Name of the API
            - base_url: Base URL for the API
            - auth: Authentication configuration
            - spec_path: Path to OpenAPI spec (if found)
            - endpoints: List of discovered endpoints
            - users: List of users found (for BOLA testing)
    """
    repo = Path(repo_path)
    inferred = {
        "api_name": None,
        "base_url": None,
        "auth": None,
        "spec_path": None,
        "endpoints": [],
        "users": [],
    }

    # Parse OpenAPI specs first (highest priority for structure)
    openapi_specs = artifacts.get("openapi", [])
    for spec_path in openapi_specs:
        try:
            full_path = repo / spec_path
            openapi_data = parse_openapi(str(full_path))

            if not inferred["api_name"] and openapi_data.get("title"):
                inferred["api_name"] = openapi_data["title"]

            if not inferred["base_url"]:
                servers = openapi_data.get("servers", [])
                if servers:
                    inferred["base_url"] = servers[0].get("url", "")

            # Store spec path
            if not inferred["spec_path"]:
                inferred["spec_path"] = spec_path

            # Get endpoints
            endpoints = openapi_data.get("endpoints", [])
            for ep in endpoints:
                inferred["endpoints"].append({
                    "path": ep.get("path"),
                    "method": ep.get("method"),
                    "operation_id": ep.get("operation_id"),
                    "auth_required": ep.get("security") is not None,
                })

            # Get auth from security schemes
            security_schemes = openapi_data.get("security_schemes", {})
            if security_schemes and not inferred["auth"]:
                inferred["auth"] = _infer_auth_from_openapi(security_schemes)

        except Exception:
            continue

    # Parse Postman collections for additional info
    postman_collections = artifacts.get("postman", [])
    for collection_path in postman_collections:
        try:
            full_path = repo / collection_path
            postman_data = parse_postman(str(full_path))

            if not inferred["api_name"] and postman_data.get("name"):
                inferred["api_name"] = postman_data["name"]

            # Get auth from Postman
            if not inferred["auth"] and postman_data.get("auth"):
                inferred["auth"] = _infer_auth_from_postman(postman_data["auth"])

            # Get base URL from variables
            variables = postman_data.get("variables", {})
            if not inferred["base_url"] and variables.get("base_url"):
                inferred["base_url"] = variables["base_url"]

        except Exception:
            continue

    # Parse logs for user patterns and endpoint usage
    log_files = artifacts.get("logs", [])
    for log_path in log_files:
        try:
            full_path = repo / log_path
            log_data = parse_logs(str(full_path))

            # Extract users from logs
            users = log_data.get("users", [])
            for user in users:
                user_id = user.get("user_id") or user.get("username")
                if user_id and user_id not in inferred["users"]:
                    inferred["users"].append(user_id)

            # Get auth type from logs if not found elsewhere
            if not inferred["auth"]:
                auth_patterns = log_data.get("auth_patterns", {})
                if auth_patterns:
                    inferred["auth"] = _infer_auth_from_logs(auth_patterns)

        except Exception:
            continue

    # Parse env files for URLs and credential variable names
    env_files = artifacts.get("env", [])
    for env_path in env_files:
        try:
            full_path = repo / env_path
            env_data = parse_env(str(full_path))

            # Get base URL from env
            urls = env_data.get("urls", [])
            if not inferred["base_url"] and urls:
                # Prefer API_URL or BASE_URL
                for url_info in urls:
                    var_name = url_info.get("name", "").upper()
                    if "API" in var_name or "BASE" in var_name:
                        inferred["base_url"] = url_info.get("value")
                        break
                if not inferred["base_url"] and urls:
                    inferred["base_url"] = urls[0].get("value")

            # Get credential variable names
            if inferred["auth"]:
                cred_vars = env_data.get("credentials", [])
                inferred["auth"]["credential_vars"] = cred_vars

        except Exception:
            continue

    # Set defaults if not found
    if not inferred["api_name"]:
        # Use repo directory name
        inferred["api_name"] = repo.name.replace("-", " ").replace("_", " ").title()

    if not inferred["base_url"]:
        inferred["base_url"] = "http://localhost:8000"

    if not inferred["auth"]:
        inferred["auth"] = {"type": "none"}

    return inferred


def _infer_auth_from_openapi(security_schemes: Dict) -> Dict[str, Any]:
    """Infer auth configuration from OpenAPI security schemes."""
    for name, scheme in security_schemes.items():
        scheme_type = scheme.get("type", "")

        if scheme_type == "oauth2":
            flows = scheme.get("flows", {})
            if "password" in flows:
                flow = flows["password"]
                return {
                    "type": "oauth2_password",
                    "token_endpoint": flow.get("tokenUrl"),
                }
            elif "clientCredentials" in flows:
                flow = flows["clientCredentials"]
                return {
                    "type": "oauth2_client_credentials",
                    "token_endpoint": flow.get("tokenUrl"),
                }

        elif scheme_type == "http":
            scheme_scheme = scheme.get("scheme", "")
            if scheme_scheme == "bearer":
                return {"type": "bearer"}
            elif scheme_scheme == "basic":
                return {"type": "basic"}

        elif scheme_type == "apiKey":
            return {
                "type": "api_key",
                "header": scheme.get("name", "X-API-Key"),
                "in": scheme.get("in", "header"),
            }

    return {"type": "none"}


def _infer_auth_from_postman(auth_config: Dict) -> Dict[str, Any]:
    """Infer auth configuration from Postman auth settings."""
    auth_type = auth_config.get("type", "")

    if auth_type == "oauth2":
        return {
            "type": "oauth2_password",
            "token_endpoint": auth_config.get("token_url"),
        }
    elif auth_type == "bearer":
        return {"type": "bearer"}
    elif auth_type == "basic":
        return {"type": "basic"}
    elif auth_type == "apikey":
        return {
            "type": "api_key",
            "header": auth_config.get("key", "X-API-Key"),
        }

    return {"type": "none"}


def _infer_auth_from_logs(auth_patterns: Dict) -> Dict[str, Any]:
    """Infer auth configuration from log analysis."""
    if auth_patterns.get("oauth2"):
        return {"type": "oauth2_password"}
    elif auth_patterns.get("bearer"):
        return {"type": "bearer"}
    elif auth_patterns.get("api_key"):
        return {"type": "api_key"}
    elif auth_patterns.get("basic"):
        return {"type": "basic"}

    return {"type": "none"}


def generate_apisec_config(inferred: Dict[str, Any]) -> str:
    """Generate APIsec configuration YAML from inferred data.

    Args:
        inferred: Dictionary with inferred configuration from infer_api_config()

    Returns:
        YAML formatted configuration string
    """
    config = {
        "version": "1.0",
        "api_name": inferred.get("api_name", "API"),
        "base_url": inferred.get("base_url", "http://localhost:8000"),
    }

    # Add spec path if available
    if inferred.get("spec_path"):
        config["spec_path"] = inferred["spec_path"]

    # Add authentication
    auth = inferred.get("auth", {})
    auth_type = auth.get("type", "none")

    if auth_type != "none":
        config["auth"] = {"type": auth_type}

        if auth.get("token_endpoint"):
            config["auth"]["token_endpoint"] = auth["token_endpoint"]

        # Add credential configuration
        config["auth"]["credentials"] = {"source": "env"}

        if auth_type in ("oauth2_password", "oauth2_client_credentials"):
            config["auth"]["credentials"]["client_id_var"] = "APISEC_CLIENT_ID"
            config["auth"]["credentials"]["client_secret_var"] = "APISEC_CLIENT_SECRET"
            if auth_type == "oauth2_password":
                config["auth"]["credentials"]["username_var"] = "APISEC_USERNAME"
                config["auth"]["credentials"]["password_var"] = "APISEC_PASSWORD"

        elif auth_type == "bearer":
            config["auth"]["credentials"]["token_var"] = "APISEC_BEARER_TOKEN"

        elif auth_type == "basic":
            config["auth"]["credentials"]["username_var"] = "APISEC_USERNAME"
            config["auth"]["credentials"]["password_var"] = "APISEC_PASSWORD"

        elif auth_type == "api_key":
            config["auth"]["credentials"]["api_key_var"] = "APISEC_API_KEY"
            if auth.get("header"):
                config["auth"]["api_key_header"] = auth["header"]
    else:
        config["auth"] = {"type": "none"}

    # Add test identities for BOLA testing
    users = inferred.get("users", [])
    if users:
        config["identities"] = []
        for i, user in enumerate(users[:5]):  # Limit to 5 users
            config["identities"].append({
                "name": f"user_{i+1}",
                "description": f"Test identity based on user: {user}",
                "credentials": {
                    "source": "env",
                    "username_var": f"APISEC_USER{i+1}_USERNAME",
                    "password_var": f"APISEC_USER{i+1}_PASSWORD",
                },
            })

    # Add security tests configuration
    config["security_tests"] = {
        "enabled": True,
        "test_types": [
            "bola",
            "auth_bypass",
            "injection",
            "schema_validation",
        ],
    }

    # Add endpoints summary if available
    endpoints = inferred.get("endpoints", [])
    if endpoints:
        # Just include count, not all endpoints
        config["endpoints_discovered"] = len(endpoints)

    # Generate YAML
    return yaml.dump(
        config,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
