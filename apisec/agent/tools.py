"""Agent tools for file operations and inference."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..inference import (
    scan_repo,
    parse_openapi,
    parse_postman,
    parse_logs,
    parse_env,
    get_artifact_summary,
)


class AgentTools:
    """Tools available to the agent for gathering information.

    Provides file system access, inference capabilities, and
    configuration management.
    """

    def __init__(self, repo_path: str):
        """Initialize agent tools.

        Args:
            repo_path: Path to the repository being analyzed
        """
        self.repo_path = Path(repo_path).resolve()
        self.discovered_artifacts: Dict[str, List[str]] = {}
        self.parsed_data: Dict[str, Any] = {}

    def get_tool_definitions(self) -> List[dict]:
        """Get OpenAI-compatible tool definitions.

        Returns:
            List of tool definitions for function calling
        """
        return [
            {
                "type": "function",
                "function": {
                    "name": "scan_repo",
                    "description": "Scan the repository for API artifacts like OpenAPI specs, Postman collections, environment files, and logs. Call this first to understand what's available.",
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
                    "description": "Parse an OpenAPI/Swagger specification file to extract endpoints, security schemes, and request/response schemas.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the OpenAPI spec file (relative to repo root)",
                            }
                        },
                        "required": ["file_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "parse_postman",
                    "description": "Parse a Postman collection to extract requests, authentication configuration, and pre-request scripts.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the Postman collection JSON file (relative to repo root)",
                            }
                        },
                        "required": ["file_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "parse_logs",
                    "description": "Parse API access logs to extract endpoints, user patterns, and authentication information.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the log file (relative to repo root)",
                            }
                        },
                        "required": ["file_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "parse_env",
                    "description": "Parse an environment configuration file to extract URLs, credentials variables, and other settings.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the environment file (relative to repo root)",
                            }
                        },
                        "required": ["file_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read the raw contents of any file in the repository.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the file (relative to repo root)",
                            }
                        },
                        "required": ["file_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "generate_config",
                    "description": "Generate the APIsec configuration YAML file based on collected information. Call this when you have gathered enough information.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "api_name": {
                                "type": "string",
                                "description": "Name of the API",
                            },
                            "base_url": {
                                "type": "string",
                                "description": "Base URL for the API",
                            },
                            "spec_path": {
                                "type": "string",
                                "description": "Path to the OpenAPI spec (relative)",
                            },
                            "auth_type": {
                                "type": "string",
                                "description": "Authentication type (oauth2_client_credentials, oauth2_password, api_key, basic, bearer)",
                            },
                            "token_endpoint": {
                                "type": "string",
                                "description": "Token endpoint URL (for OAuth2)",
                            },
                            "credentials": {
                                "type": "object",
                                "description": "Credential configuration with env var names",
                            },
                            "identities": {
                                "type": "array",
                                "description": "Test identities for BOLA/RBAC testing",
                            },
                            "exclude_endpoints": {
                                "type": "array",
                                "description": "Endpoints to exclude from testing",
                            },
                        },
                        "required": ["api_name", "base_url", "auth_type"],
                    },
                },
            },
        ]

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Execute a tool and return the result.

        Args:
            tool_name: Name of the tool to execute
            arguments: Tool arguments

        Returns:
            Tool execution result as JSON string
        """
        tool_map = {
            "scan_repo": self._scan_repo,
            "parse_openapi": self._parse_openapi,
            "parse_postman": self._parse_postman,
            "parse_logs": self._parse_logs,
            "parse_env": self._parse_env,
            "read_file": self._read_file,
            "generate_config": self._generate_config,
        }

        if tool_name not in tool_map:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})

        try:
            result = tool_map[tool_name](**arguments)
            return json.dumps(result, indent=2, default=str)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def _scan_repo(self) -> Dict[str, Any]:
        """Scan repository for API artifacts."""
        self.discovered_artifacts = scan_repo(str(self.repo_path))
        summary = get_artifact_summary(self.discovered_artifacts)

        return {
            "artifacts": self.discovered_artifacts,
            "summary": summary,
        }

    def _parse_openapi(self, file_path: str) -> Dict[str, Any]:
        """Parse an OpenAPI specification."""
        full_path = self.repo_path / file_path
        result = parse_openapi(str(full_path))
        self.parsed_data["openapi"] = result
        return result

    def _parse_postman(self, file_path: str) -> Dict[str, Any]:
        """Parse a Postman collection."""
        full_path = self.repo_path / file_path
        result = parse_postman(str(full_path))
        self.parsed_data["postman"] = result
        return result

    def _parse_logs(self, file_path: str) -> Dict[str, Any]:
        """Parse API access logs."""
        full_path = self.repo_path / file_path
        result = parse_logs(str(full_path))
        self.parsed_data["logs"] = result
        return result

    def _parse_env(self, file_path: str) -> Dict[str, Any]:
        """Parse an environment file."""
        full_path = self.repo_path / file_path
        result = parse_env(str(full_path))
        self.parsed_data["env"] = result
        return result

    def _read_file(self, file_path: str) -> Dict[str, Any]:
        """Read a file from the repository."""
        full_path = self.repo_path / file_path

        if not full_path.exists():
            return {"error": f"File not found: {file_path}"}

        try:
            content = full_path.read_text(encoding="utf-8")
            # Truncate very large files
            if len(content) > 50000:
                content = content[:50000] + "\n... [truncated]"
            return {
                "path": file_path,
                "content": content,
                "size": full_path.stat().st_size,
            }
        except Exception as e:
            return {"error": f"Failed to read file: {str(e)}"}

    def _generate_config(
        self,
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
        config = {
            "version": "1.0",
            "api": {
                "name": api_name,
                "base_url": base_url,
            },
            "auth": {
                "type": auth_type,
            },
            "scan": {},
        }

        if spec_path:
            config["api"]["spec_path"] = spec_path

        if token_endpoint:
            config["auth"]["token_endpoint"] = token_endpoint

        if credentials:
            config["auth"]["credentials"] = credentials

        if identities:
            config["identities"] = identities

        if exclude_endpoints:
            config["scan"]["exclude_endpoints"] = exclude_endpoints

        self.parsed_data["generated_config"] = config
        return config

    def get_parsed_data(self) -> Dict[str, Any]:
        """Get all parsed data collected during the session.

        Returns:
            Dictionary of all parsed artifacts
        """
        return self.parsed_data

    def get_generated_config(self) -> Optional[Dict[str, Any]]:
        """Get the generated configuration if available.

        Returns:
            Generated config dict or None
        """
        return self.parsed_data.get("generated_config")
