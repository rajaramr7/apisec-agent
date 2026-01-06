"""Agent tools for OpenAI function calling."""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..inference import (
    scan_repo,
    parse_openapi,
    parse_postman,
    parse_logs,
    parse_env,
)
from ..config.generator import ConfigGenerator
from ..pr.github import GitHubPRManager

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
            "description": "Scan the repository for API artifacts like OpenAPI specs, Postman collections, environment files, and logs. Call this first to understand what's available in the repository.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
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
]


# =============================================================================
# Tool Handler Functions
# =============================================================================

def handle_scan_repo() -> Dict[str, Any]:
    """Scan the repository for API artifacts."""
    try:
        artifacts = scan_repo(_working_dir)

        # Build a friendly summary
        summary_parts = []
        if artifacts.get("openapi"):
            summary_parts.append(f"OpenAPI specs: {', '.join(artifacts['openapi'])}")
        if artifacts.get("postman"):
            summary_parts.append(f"Postman collections: {', '.join(artifacts['postman'])}")
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
# Tool Handlers Mapping
# =============================================================================

TOOL_HANDLERS: Dict[str, callable] = {
    "scan_repo": handle_scan_repo,
    "parse_openapi": handle_parse_openapi,
    "parse_postman": handle_parse_postman,
    "parse_logs": handle_parse_logs,
    "parse_env": handle_parse_env,
    "generate_config": handle_generate_config,
    "create_pr": handle_create_pr,
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
