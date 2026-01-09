"""Agent tools for OpenAI function calling."""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..inference import (
    scan_repo,
    parse_openapi,
    parse_postman,
    parse_postman_environment,
    parse_logs,
    parse_env,
    # New parsers
    parse_gateway_logs,
    parse_test_logs,
    parse_fixtures,
    parse_devops_config,
)
from ..config.generator import ConfigGenerator
from ..pr.github import GitHubPRManager

# New integrations
from ..integrations.github import (
    GitHubIntegration,
    validate_github_token as gh_validate_token,
    clone_github_repo as gh_clone_repo,
)
from ..validators.token import (
    validate_jwt_token,
    validate_multiple_tokens as validate_tokens_batch,
    check_tokens,
    format_token_validation,
)
from ..parsers.tests import extract_working_payloads

# Connectors - P0
from ..connectors import (
    parse_env_file as connector_parse_env_file,
    scan_env_files as connector_scan_env_files,
    parse_postman_collection as connector_parse_postman_collection,
    parse_postman_env as connector_parse_postman_env,
    fetch_from_postman_api as connector_fetch_postman_api,
)

# Connectors - P1
from ..connectors import (
    parse_insomnia_export as connector_parse_insomnia,
    parse_bruno_collection as connector_parse_bruno,
    clone_gitlab_repo as connector_clone_gitlab,
    validate_gitlab_token as connector_validate_gitlab_token,
    clone_bitbucket_repo as connector_clone_bitbucket,
    validate_bitbucket_auth as connector_validate_bitbucket,
    fetch_kong_config as connector_fetch_kong,
    fetch_aws_api_gateway_config as connector_fetch_aws_apigw,
    fetch_vault_secret as connector_fetch_vault_secret,
    fetch_vault_api_credentials as connector_fetch_vault_creds,
    fetch_aws_secret as connector_fetch_aws_secret,
    fetch_aws_api_credentials as connector_fetch_aws_creds,
    parse_har_file as connector_parse_har,
    parse_jest_tests as connector_parse_jest,
)

# APIsec Platform connector
from ..connectors.apisec_platform import (
    validate_apisec_token as platform_validate_token,
    upload_to_apisec as platform_upload,
    get_apisec_token_instructions as platform_get_instructions,
)

# Global working directory - set by the agent
_working_dir: str = "."


def set_working_dir(path: str) -> None:
    """Set the working directory for tool operations."""
    global _working_dir
    _working_dir = path


def get_working_dir() -> str:
    """Get the current working directory."""
    return _working_dir


# =============================================================================
# Tool Schemas (OpenAI Function Calling Format)
# =============================================================================

TOOLS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "scan_repo",
            "description": "Scan a directory for API artifacts like OpenAPI specs, Postman collections, environment files, and logs. Call this first to understand what's available. ALWAYS provide the path parameter.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the directory to scan (e.g., '/tmp/sample-orders-api' or '.')",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "parse_openapi",
            "description": "Parse an OpenAPI/Swagger specification file to extract endpoints, security schemes, request/response schemas, and examples.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the OpenAPI spec file (relative to repo root)",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "parse_postman",
            "description": "Parse a Postman collection to extract requests, authentication configuration, environment variables, and pre-request scripts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the Postman collection JSON file (relative to repo root)",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "parse_logs",
            "description": "Parse API access logs (JSON lines format) to extract endpoints, user patterns, authentication information, and request examples.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the log file (relative to repo root)",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "parse_env",
            "description": "Parse an environment configuration file to extract URLs, credential variable names, and other settings.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the environment file (relative to repo root)",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "parse_postman_environment",
            "description": "Parse a Postman environment file (.postman_environment.json) to extract URLs, credentials, and tokens. This is extremely valuable - developers often have their entire auth setup in Postman environments, including test user tokens. If you find environment files, parse them early. You may not need to ask for credentials at all.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the Postman environment file (relative to repo root)",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_config",
            "description": "Generate the APIsec configuration YAML file based on collected information. Call this when you have gathered enough information to create a complete configuration.",
            "parameters": {
                "type": "object",
                "properties": {
                    "api_name": {
                        "type": "string",
                        "description": "Human-readable name of the API",
                    },
                    "base_url": {
                        "type": "string",
                        "description": "Base URL for the API (e.g., https://api.example.com)",
                    },
                    "spec_path": {
                        "type": "string",
                        "description": "Path to the OpenAPI spec file (relative to repo root)",
                    },
                    "auth_type": {
                        "type": "string",
                        "enum": ["oauth2_client_credentials", "oauth2_password", "api_key", "basic", "bearer", "none"],
                        "description": "Authentication type used by the API",
                    },
                    "token_endpoint": {
                        "type": "string",
                        "description": "Token endpoint URL for OAuth2 authentication",
                    },
                    "credentials": {
                        "type": "object",
                        "description": "Credential configuration with environment variable names",
                        "properties": {
                            "source": {
                                "type": "string",
                                "enum": ["env"],
                                "description": "Source of credentials (always 'env')",
                            },
                            "client_id_var": {
                                "type": "string",
                                "description": "Environment variable name for client ID",
                            },
                            "client_secret_var": {
                                "type": "string",
                                "description": "Environment variable name for client secret",
                            },
                            "username_var": {
                                "type": "string",
                                "description": "Environment variable name for username",
                            },
                            "password_var": {
                                "type": "string",
                                "description": "Environment variable name for password",
                            },
                            "api_key_var": {
                                "type": "string",
                                "description": "Environment variable name for API key",
                            },
                            "api_key_header": {
                                "type": "string",
                                "description": "Header name for API key (e.g., X-API-Key)",
                            },
                        },
                    },
                    "identities": {
                        "type": "array",
                        "description": "Test identities for BOLA/RBAC testing",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "description": {"type": "string"},
                                "role": {"type": "string"},
                                "credentials": {"type": "object"},
                                "owns_resources": {"type": "object"},
                            },
                        },
                    },
                    "exclude_endpoints": {
                        "type": "array",
                        "description": "Endpoints to exclude from security testing",
                        "items": {"type": "string"},
                    },
                },
                "required": ["api_name", "base_url", "auth_type"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_pr",
            "description": "Create a GitHub pull request with the APIsec configuration file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "branch_name": {
                        "type": "string",
                        "description": "Name for the new branch (e.g., 'apisec-config')",
                    },
                    "commit_message": {
                        "type": "string",
                        "description": "Commit message for the config file",
                    },
                    "pr_title": {
                        "type": "string",
                        "description": "Title for the pull request",
                    },
                    "pr_body": {
                        "type": "string",
                        "description": "Description/body for the pull request (markdown)",
                    },
                },
                "required": ["branch_name", "commit_message", "pr_title", "pr_body"],
            },
        },
    },
    # New tools for intelligent requirement gathering
    {
        "type": "function",
        "function": {
            "name": "parse_gateway_logs",
            "description": "Parse API gateway logs (Kong, AWS API Gateway, Apigee, nginx, Envoy). These are goldmines — they show real traffic patterns, auth headers, endpoints actually in use, user identities, and which users access which resources.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the gateway log file (relative to repo root)",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "parse_test_logs",
            "description": "Parse test framework output logs (pytest, Jest, Newman, Karate, REST Assured). These reveal tested endpoints, sample payloads, expected responses, and auth flows used in tests.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the test output file (relative to repo root)",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "parse_fixtures",
            "description": "Parse test fixtures and seed data files (JSON, YAML, SQL, CSV). These are goldmines for BOLA testing — they show exactly which users exist and which resources they own.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the fixtures file (relative to repo root)",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "parse_devops_config",
            "description": "Parse DevOps configuration files (docker-compose.yml, GitHub Actions, GitLab CI, Jenkins, CircleCI). These reveal environment URLs, service dependencies, environment variables, and secrets configuration.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the DevOps config file (relative to repo root)",
                    }
                },
                "required": ["path"],
            },
        },
    },
    # GitHub integration tools
    {
        "type": "function",
        "function": {
            "name": "validate_github_token",
            "description": "Validate a GitHub Personal Access Token and check its scopes. Use this before attempting to clone a private repository.",
            "parameters": {
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "GitHub Personal Access Token to validate",
                    }
                },
                "required": ["token"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "clone_github_repo",
            "description": "Clone a GitHub repository for scanning. For PUBLIC repos, no token needed. For PRIVATE repos, requires a GitHub PAT with 'repo' scope. Try without token first - if it fails with 'needs_auth', then ask for token.",
            "parameters": {
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository in 'owner/repo' format (e.g., 'swagger-api/swagger-petstore')",
                    },
                    "token": {
                        "type": "string",
                        "description": "GitHub Personal Access Token (only needed for private repos)",
                    },
                    "branch": {
                        "type": "string",
                        "description": "Optional: specific branch to clone (defaults to default branch)",
                    }
                },
                "required": ["repo"],
            },
        },
    },
    # Token validation tools
    {
        "type": "function",
        "function": {
            "name": "validate_token",
            "description": "Validate a JWT token - check if it's well-formed and not expired. ALWAYS validate tokens before using them. Expired tokens = failed tests.",
            "parameters": {
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "JWT token to validate",
                    }
                },
                "required": ["token"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "validate_multiple_tokens",
            "description": "Validate multiple JWT tokens at once. Returns validation status for each token. Use this to check all tokens from a Postman environment.",
            "parameters": {
                "type": "object",
                "properties": {
                    "tokens": {
                        "type": "object",
                        "description": "Dictionary of token_name -> token_value (e.g., {'user_a_token': 'eyJ...', 'admin_token': 'eyJ...'})",
                    }
                },
                "required": ["tokens"],
            },
        },
    },
    # Integration test parser
    {
        "type": "function",
        "function": {
            "name": "parse_integration_tests",
            "description": "Parse integration test CODE to extract working payloads. These payloads come from passing tests, so they're confirmed to work. This parses the actual test files (not output logs) using AST analysis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to tests directory (e.g., 'tests/integration' or 'tests')",
                    }
                },
                "required": ["path"],
            },
        },
    },
    # ==== CONNECTORS ====
    # Enhanced env file parsing with categorization
    {
        "type": "function",
        "function": {
            "name": "parse_env_file_v2",
            "description": "Parse an environment file (.env) with smart categorization. Identifies URLs, auth tokens, API keys, and secrets. Detects placeholder values and warns about them. Better than parse_env for extracting auth configuration.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the .env file",
                    },
                    "include_sensitive": {
                        "type": "boolean",
                        "description": "Include unmasked sensitive values (default: false)",
                    }
                },
                "required": ["path"],
            },
        },
    },
    # Scan directory for all env files
    {
        "type": "function",
        "function": {
            "name": "scan_env_files",
            "description": "Scan a directory for all .env files (.env, .env.local, .env.development, .env.production, .env.example). Parses all found files and merges variables. Great for understanding the full environment setup.",
            "parameters": {
                "type": "object",
                "properties": {
                    "directory": {
                        "type": "string",
                        "description": "Path to directory to scan for .env files",
                    }
                },
                "required": ["directory"],
            },
        },
    },
    # Postman collection with connector
    {
        "type": "function",
        "function": {
            "name": "parse_postman_collection_v2",
            "description": "Parse a Postman collection with enhanced endpoint extraction. Returns structured endpoint data with methods, paths, payloads, and auth config in standardized format.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the Postman collection JSON file",
                    }
                },
                "required": ["path"],
            },
        },
    },
    # Postman environment with connector
    {
        "type": "function",
        "function": {
            "name": "parse_postman_env_v2",
            "description": "Parse a Postman environment file with smart auth detection. Identifies OAuth2 credentials, API keys, bearer tokens, and user identities for BOLA testing. Better than parse_postman_environment for extracting auth setup.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the Postman environment JSON file",
                    }
                },
                "required": ["path"],
            },
        },
    },
    # Postman API integration
    {
        "type": "function",
        "function": {
            "name": "fetch_postman_workspace",
            "description": "Fetch collections and environments directly from a Postman workspace using the Postman API. Requires a Postman API key. Use this when the user wants to pull config from their Postman account.",
            "parameters": {
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "Postman API key (from https://web.postman.co/settings/me/api-keys)",
                    },
                    "workspace_id": {
                        "type": "string",
                        "description": "Optional: specific workspace ID to fetch from",
                    },
                    "collection_id": {
                        "type": "string",
                        "description": "Optional: specific collection ID to fetch",
                    },
                    "environment_id": {
                        "type": "string",
                        "description": "Optional: specific environment ID to fetch",
                    }
                },
                "required": ["api_key"],
            },
        },
    },
    # ==== P1 CONNECTORS ====
    # Insomnia
    {
        "type": "function",
        "function": {
            "name": "parse_insomnia",
            "description": "Parse an Insomnia API client export file. Extracts requests, auth config, and environment variables.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to Insomnia export JSON file",
                    }
                },
                "required": ["path"],
            },
        },
    },
    # Bruno
    {
        "type": "function",
        "function": {
            "name": "parse_bruno",
            "description": "Parse a Bruno API client collection. Bruno stores collections as .bru files in folders.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to Bruno collection directory (contains bruno.json)",
                    }
                },
                "required": ["path"],
            },
        },
    },
    # GitLab
    {
        "type": "function",
        "function": {
            "name": "clone_gitlab_repo",
            "description": "Clone a GitLab repository. Works with gitlab.com and self-hosted GitLab instances.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project": {
                        "type": "string",
                        "description": "GitLab project path (e.g., 'group/project')",
                    },
                    "token": {
                        "type": "string",
                        "description": "GitLab Personal Access Token (optional for public repos)",
                    },
                    "host": {
                        "type": "string",
                        "description": "GitLab host URL (default: https://gitlab.com)",
                    },
                    "branch": {
                        "type": "string",
                        "description": "Branch to clone (optional)",
                    }
                },
                "required": ["project"],
            },
        },
    },
    # Bitbucket
    {
        "type": "function",
        "function": {
            "name": "clone_bitbucket_repo",
            "description": "Clone a Bitbucket repository. Requires username and app password for private repos.",
            "parameters": {
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Bitbucket repo in 'workspace/repo' format",
                    },
                    "username": {
                        "type": "string",
                        "description": "Bitbucket username (optional for public repos)",
                    },
                    "app_password": {
                        "type": "string",
                        "description": "Bitbucket App Password",
                    },
                    "branch": {
                        "type": "string",
                        "description": "Branch to clone (optional)",
                    }
                },
                "required": ["repo"],
            },
        },
    },
    # Kong
    {
        "type": "function",
        "function": {
            "name": "fetch_kong_config",
            "description": "Fetch API configuration from Kong API Gateway. Returns services, routes, plugins, and auth config.",
            "parameters": {
                "type": "object",
                "properties": {
                    "admin_url": {
                        "type": "string",
                        "description": "Kong Admin API URL (e.g., http://localhost:8001)",
                    },
                    "api_key": {
                        "type": "string",
                        "description": "API key for Kong Admin API (optional)",
                    }
                },
                "required": ["admin_url"],
            },
        },
    },
    # AWS API Gateway
    {
        "type": "function",
        "function": {
            "name": "fetch_aws_api_gateway",
            "description": "Fetch API configuration from AWS API Gateway. Returns REST APIs, HTTP APIs, routes, and authorizers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "region": {
                        "type": "string",
                        "description": "AWS region (default: us-east-1)",
                    },
                    "profile_name": {
                        "type": "string",
                        "description": "AWS profile name (optional)",
                    }
                },
                "required": [],
            },
        },
    },
    # HashiCorp Vault
    {
        "type": "function",
        "function": {
            "name": "fetch_vault_credentials",
            "description": "Fetch API credentials from HashiCorp Vault. Extracts auth config, tokens, and secrets.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Vault server URL (e.g., https://vault.example.com:8200)",
                    },
                    "token": {
                        "type": "string",
                        "description": "Vault token",
                    },
                    "path": {
                        "type": "string",
                        "description": "Secret path (default: api-credentials)",
                    },
                    "mount": {
                        "type": "string",
                        "description": "Secret engine mount (default: secret)",
                    }
                },
                "required": ["url", "token"],
            },
        },
    },
    # AWS Secrets Manager
    {
        "type": "function",
        "function": {
            "name": "fetch_aws_secret",
            "description": "Fetch API credentials from AWS Secrets Manager.",
            "parameters": {
                "type": "object",
                "properties": {
                    "secret_name": {
                        "type": "string",
                        "description": "Name or ARN of the secret",
                    },
                    "region": {
                        "type": "string",
                        "description": "AWS region (default: us-east-1)",
                    },
                    "profile_name": {
                        "type": "string",
                        "description": "AWS profile name (optional)",
                    }
                },
                "required": ["secret_name"],
            },
        },
    },
    # HAR files
    {
        "type": "function",
        "function": {
            "name": "parse_har_file",
            "description": "Parse a HAR (HTTP Archive) file to extract API endpoints and payloads. HAR files are exported from browser DevTools, Charles Proxy, Fiddler, etc.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to HAR file",
                    },
                    "base_url_filter": {
                        "type": "string",
                        "description": "Filter to specific base URL (optional)",
                    }
                },
                "required": ["path"],
            },
        },
    },
    # Jest/Supertest
    {
        "type": "function",
        "function": {
            "name": "parse_jest_tests",
            "description": "Parse Jest/Supertest test files to extract API endpoints and payloads. Works with .test.js, .test.ts, .spec.js, .spec.ts files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to test directory or file",
                    }
                },
                "required": ["path"],
            },
        },
    },
]


# =============================================================================
# Tool Handler Functions
# =============================================================================

def handle_scan_repo(path: Optional[str] = None) -> Dict[str, Any]:
    """Scan the repository for API artifacts."""
    global _working_dir
    try:
        # Use provided path or fall back to working dir
        scan_path = path if path else _working_dir
        # Update working dir if path provided
        if path:
            _working_dir = path
        artifacts = scan_repo(scan_path)

        # Build a friendly summary
        summary_parts = []
        if artifacts.get("openapi"):
            summary_parts.append(f"OpenAPI specs: {', '.join(artifacts['openapi'])}")
        if artifacts.get("postman"):
            summary_parts.append(f"Postman collections: {', '.join(artifacts['postman'])}")
        if artifacts.get("postman_environments"):
            summary_parts.append(f"Postman environments: {', '.join(artifacts['postman_environments'])}")
        if artifacts.get("env"):
            summary_parts.append(f"Environment files: {', '.join(artifacts['env'])}")
        if artifacts.get("logs"):
            summary_parts.append(f"Log files: {', '.join(artifacts['logs'])}")
        if artifacts.get("code"):
            summary_parts.append(f"Code files: {len(artifacts['code'])} files")

        return {
            "success": True,
            "artifacts": artifacts,
            "summary": "\n".join(summary_parts) if summary_parts else "No artifacts found",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_parse_openapi(path: str) -> Dict[str, Any]:
    """Parse an OpenAPI specification file."""
    try:
        full_path = Path(_working_dir) / path
        result = parse_openapi(str(full_path))
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_parse_postman(path: str) -> Dict[str, Any]:
    """Parse a Postman collection file."""
    try:
        full_path = Path(_working_dir) / path
        result = parse_postman(str(full_path))
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_parse_logs(path: str) -> Dict[str, Any]:
    """Parse API access logs."""
    try:
        full_path = Path(_working_dir) / path
        result = parse_logs(str(full_path))
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_parse_env(path: str) -> Dict[str, Any]:
    """Parse an environment file."""
    try:
        full_path = Path(_working_dir) / path
        result = parse_env(str(full_path))
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_parse_postman_environment(path: str) -> Dict[str, Any]:
    """Parse a Postman environment file."""
    try:
        full_path = Path(_working_dir) / path
        result = parse_postman_environment(str(full_path))
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_parse_gateway_logs(path: str) -> Dict[str, Any]:
    """Parse API gateway logs."""
    try:
        full_path = Path(_working_dir) / path
        result = parse_gateway_logs(str(full_path))
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_parse_test_logs(path: str) -> Dict[str, Any]:
    """Parse test framework output logs."""
    try:
        full_path = Path(_working_dir) / path
        result = parse_test_logs(str(full_path))
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_parse_fixtures(path: str) -> Dict[str, Any]:
    """Parse test fixtures/seed data files."""
    try:
        full_path = Path(_working_dir) / path
        result = parse_fixtures(str(full_path))
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_parse_devops_config(path: str) -> Dict[str, Any]:
    """Parse DevOps configuration files."""
    try:
        full_path = Path(_working_dir) / path
        result = parse_devops_config(str(full_path))
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_validate_github_token(token: str) -> Dict[str, Any]:
    """Validate a GitHub Personal Access Token."""
    try:
        result = gh_validate_token(token)
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


# Global reference for GitHub cloned repo
_github_clone_path: Optional[str] = None


def handle_clone_github_repo(
    repo: str,
    token: Optional[str] = None,
    branch: Optional[str] = None
) -> Dict[str, Any]:
    """Clone a GitHub repository (public or private)."""
    global _github_clone_path, _working_dir

    try:
        result = gh_clone_repo(repo, token, branch)

        if result.get("success"):
            # Update working directory to cloned repo
            _github_clone_path = result["path"]
            _working_dir = result["path"]

        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_validate_token(token: str) -> Dict[str, Any]:
    """Validate a JWT token."""
    try:
        validation = validate_jwt_token(token)
        return {
            "success": True,
            "data": {
                "valid": validation.valid,
                "expired": validation.expired,
                "user": validation.user,
                "roles": validation.roles,
                "expires_in_seconds": validation.expires_in_seconds,
                "expired_ago_seconds": validation.expired_ago_seconds,
                "error": validation.error,
                "formatted": format_token_validation(validation),
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_validate_multiple_tokens(tokens: Dict[str, str]) -> Dict[str, Any]:
    """Validate multiple JWT tokens."""
    try:
        result = check_tokens(tokens)
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_parse_integration_tests(path: str) -> Dict[str, Any]:
    """Parse integration test code to extract working payloads."""
    try:
        full_path = Path(_working_dir) / path
        result = extract_working_payloads(str(full_path))
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


# =============================================================================
# Connector Tool Handlers
# =============================================================================

def handle_parse_env_file_v2(path: str, include_sensitive: bool = False) -> Dict[str, Any]:
    """Parse an environment file using the connector with smart categorization."""
    try:
        full_path = Path(_working_dir) / path
        result = connector_parse_env_file(str(full_path), include_sensitive=include_sensitive)
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_scan_env_files(directory: str) -> Dict[str, Any]:
    """Scan a directory for all .env files."""
    try:
        full_path = Path(_working_dir) / directory
        result = connector_scan_env_files(str(full_path))
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_parse_postman_collection_v2(path: str) -> Dict[str, Any]:
    """Parse a Postman collection using the connector."""
    try:
        full_path = Path(_working_dir) / path
        result = connector_parse_postman_collection(str(full_path))
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_parse_postman_env_v2(path: str) -> Dict[str, Any]:
    """Parse a Postman environment using the connector."""
    try:
        full_path = Path(_working_dir) / path
        result = connector_parse_postman_env(str(full_path))
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_fetch_postman_workspace(
    api_key: str,
    workspace_id: Optional[str] = None,
    collection_id: Optional[str] = None,
    environment_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch from Postman workspace using API."""
    try:
        result = connector_fetch_postman_api(
            api_key=api_key,
            workspace_id=workspace_id,
            collection_id=collection_id,
            environment_id=environment_id,
        )
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


# =============================================================================
# P1 Connector Tool Handlers
# =============================================================================

def handle_parse_insomnia(path: str) -> Dict[str, Any]:
    """Parse an Insomnia export file."""
    try:
        full_path = Path(_working_dir) / path
        result = connector_parse_insomnia(str(full_path))
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_parse_bruno(path: str) -> Dict[str, Any]:
    """Parse a Bruno collection."""
    try:
        full_path = Path(_working_dir) / path
        result = connector_parse_bruno(str(full_path))
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_clone_gitlab_repo(
    project: str,
    token: Optional[str] = None,
    host: Optional[str] = None,
    branch: Optional[str] = None,
) -> Dict[str, Any]:
    """Clone a GitLab repository."""
    global _working_dir
    try:
        result = connector_clone_gitlab(
            project=project,
            token=token,
            host=host,
            branch=branch,
        )
        if result.get("success") and result.get("data", {}).get("path"):
            _working_dir = result["data"]["path"]
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_clone_bitbucket_repo(
    repo: str,
    username: Optional[str] = None,
    app_password: Optional[str] = None,
    branch: Optional[str] = None,
) -> Dict[str, Any]:
    """Clone a Bitbucket repository."""
    global _working_dir
    try:
        result = connector_clone_bitbucket(
            repo=repo,
            username=username,
            app_password=app_password,
            branch=branch,
        )
        if result.get("success") and result.get("data", {}).get("path"):
            _working_dir = result["data"]["path"]
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_fetch_kong_config(
    admin_url: str,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch configuration from Kong API Gateway."""
    try:
        result = connector_fetch_kong(
            admin_url=admin_url,
            api_key=api_key,
        )
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_fetch_aws_api_gateway(
    region: str = "us-east-1",
    profile_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch configuration from AWS API Gateway."""
    try:
        result = connector_fetch_aws_apigw(
            region=region,
            profile_name=profile_name,
        )
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_fetch_vault_credentials(
    url: str,
    token: str,
    path: str = "api-credentials",
    mount: str = "secret",
) -> Dict[str, Any]:
    """Fetch API credentials from HashiCorp Vault."""
    try:
        result = connector_fetch_vault_creds(
            url=url,
            token=token,
            path=path,
            mount=mount,
        )
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_fetch_aws_secret(
    secret_name: str,
    region: str = "us-east-1",
    profile_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch API credentials from AWS Secrets Manager."""
    try:
        result = connector_fetch_aws_creds(
            secret_name=secret_name,
            region=region,
            profile_name=profile_name,
        )
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_parse_har_file(
    path: str,
    base_url_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """Parse a HAR file."""
    try:
        full_path = Path(_working_dir) / path
        result = connector_parse_har(
            path=str(full_path),
            base_url_filter=base_url_filter,
        )
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_parse_jest_tests(path: str) -> Dict[str, Any]:
    """Parse Jest/Supertest test files."""
    try:
        full_path = Path(_working_dir) / path
        result = connector_parse_jest(str(full_path))
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


# Store the last generated config for PR creation
_last_generated_config: Optional[str] = None


def handle_generate_config(
    api_name: str,
    base_url: str,
    auth_type: str,
    spec_path: Optional[str] = None,
    token_endpoint: Optional[str] = None,
    credentials: Optional[Dict] = None,
    identities: Optional[List] = None,
    exclude_endpoints: Optional[List] = None,
) -> Dict[str, Any]:
    """Generate APIsec configuration."""
    global _last_generated_config

    try:
        generator = ConfigGenerator()
        generator.set_api_info(api_name, base_url)

        # Build auth config
        auth_config = {"type": auth_type}
        if token_endpoint:
            auth_config["token_endpoint"] = token_endpoint
        if credentials:
            auth_config["credentials"] = credentials
        generator.set_auth_config(auth_config)

        # Add spec path to API info
        if spec_path:
            generator.config_data["spec_path"] = spec_path

        # Add identities
        if identities:
            generator.config_data["identities"] = identities

        # Add exclusions
        if exclude_endpoints:
            generator.config_data["security_tests"]["exclude_endpoints"] = exclude_endpoints

        # Generate YAML
        yaml_content = generator.to_yaml()
        _last_generated_config = yaml_content

        # Save to file
        output_path = Path(_working_dir) / "apisec-config.yaml"
        generator.save(str(output_path))

        return {
            "success": True,
            "config": yaml_content,
            "saved_to": str(output_path),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_create_pr(
    branch_name: str,
    commit_message: str,
    pr_title: str,
    pr_body: str,
) -> Dict[str, Any]:
    """Create a GitHub PR with the configuration."""
    global _last_generated_config

    try:
        if not _last_generated_config:
            return {
                "success": False,
                "error": "No configuration generated yet. Call generate_config first.",
            }

        # Get GitHub token from environment
        github_token = os.environ.get("GITHUB_TOKEN")
        if not github_token:
            return {
                "success": False,
                "error": "GITHUB_TOKEN environment variable not set.",
            }

        # Try to detect repo from git remote
        repo_name = _detect_github_repo()
        if not repo_name:
            return {
                "success": False,
                "error": "Could not detect GitHub repository. Please set up git remote.",
            }

        pr_manager = GitHubPRManager(token=github_token, repo=repo_name)
        pr_url = pr_manager.create_config_pr(
            config_content=_last_generated_config,
            branch_name=branch_name,
        )

        return {
            "success": True,
            "pr_url": pr_url,
            "repository": repo_name,
            "branch": branch_name,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _detect_github_repo() -> Optional[str]:
    """Try to detect GitHub repository from git remote."""
    try:
        import subprocess
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=_working_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            url = result.stdout.strip()
            # Parse GitHub URL
            if "github.com" in url:
                # Handle SSH: git@github.com:owner/repo.git
                if url.startswith("git@"):
                    parts = url.split(":")[-1]
                    return parts.replace(".git", "")
                # Handle HTTPS: https://github.com/owner/repo.git
                elif "github.com/" in url:
                    parts = url.split("github.com/")[-1]
                    return parts.replace(".git", "")
    except Exception:
        pass
    return None


# =============================================================================
# APIsec Platform Handlers
# =============================================================================

def handle_validate_apisec_token(token: str) -> Dict[str, Any]:
    """Validate an APIsec platform API token."""
    try:
        result = platform_validate_token(token)
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_upload_to_apisec(
    config: Dict[str, Any],
    api_name: str,
    token: str,
    update_existing: bool = False
) -> Dict[str, Any]:
    """Upload API config to APIsec platform."""
    try:
        result = platform_upload(config, api_name, token, update_existing)
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


def handle_get_apisec_token_instructions() -> Dict[str, Any]:
    """Get instructions for creating APIsec API token."""
    try:
        instructions = platform_get_instructions()
        return {"success": True, "data": {"instructions": instructions}}
    except Exception as e:
        return {"success": False, "error": str(e)}


# =============================================================================
# Tool Handlers Mapping
# =============================================================================

TOOL_HANDLERS: Dict[str, callable] = {
    "scan_repo": handle_scan_repo,
    "parse_openapi": handle_parse_openapi,
    "parse_postman": handle_parse_postman,
    "parse_postman_environment": handle_parse_postman_environment,
    "parse_logs": handle_parse_logs,
    "parse_env": handle_parse_env,
    "generate_config": handle_generate_config,
    "create_pr": handle_create_pr,
    # New handlers for intelligent requirement gathering
    "parse_gateway_logs": handle_parse_gateway_logs,
    "parse_test_logs": handle_parse_test_logs,
    "parse_fixtures": handle_parse_fixtures,
    "parse_devops_config": handle_parse_devops_config,
    # GitHub integration
    "validate_github_token": handle_validate_github_token,
    "clone_github_repo": handle_clone_github_repo,
    # Token validation
    "validate_token": handle_validate_token,
    "validate_multiple_tokens": handle_validate_multiple_tokens,
    # Integration test parsing
    "parse_integration_tests": handle_parse_integration_tests,
    # Connector tools (v2 - enhanced versions)
    "parse_env_file_v2": handle_parse_env_file_v2,
    "scan_env_files": handle_scan_env_files,
    "parse_postman_collection_v2": handle_parse_postman_collection_v2,
    "parse_postman_env_v2": handle_parse_postman_env_v2,
    "fetch_postman_workspace": handle_fetch_postman_workspace,
    # P1 Connector tools
    "parse_insomnia": handle_parse_insomnia,
    "parse_bruno": handle_parse_bruno,
    "clone_gitlab_repo": handle_clone_gitlab_repo,
    "clone_bitbucket_repo": handle_clone_bitbucket_repo,
    "fetch_kong_config": handle_fetch_kong_config,
    "fetch_aws_api_gateway": handle_fetch_aws_api_gateway,
    "fetch_vault_credentials": handle_fetch_vault_credentials,
    "fetch_aws_secret": handle_fetch_aws_secret,
    "parse_har_file": handle_parse_har_file,
    "parse_jest_tests": handle_parse_jest_tests,
    # APIsec Platform tools
    "validate_apisec_token": handle_validate_apisec_token,
    "upload_to_apisec": handle_upload_to_apisec,
    "get_apisec_token_instructions": handle_get_apisec_token_instructions,
}


def execute_tool(tool_name: str, arguments: Dict[str, Any]) -> str:
    """Execute a tool by name with given arguments.

    Args:
        tool_name: Name of the tool to execute
        arguments: Dictionary of arguments for the tool

    Returns:
        JSON string with the tool result
    """
    if tool_name not in TOOL_HANDLERS:
        return json.dumps({"success": False, "error": f"Unknown tool: {tool_name}"})

    handler = TOOL_HANDLERS[tool_name]

    try:
        result = handler(**arguments)
        return json.dumps(result, indent=2, default=str)
    except TypeError as e:
        return json.dumps({"success": False, "error": f"Invalid arguments: {str(e)}"})
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


def get_last_config() -> Optional[str]:
    """Get the last generated configuration."""
    return _last_generated_config
