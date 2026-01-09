"""
Tool Registry with status tracking.

This module provides:
- ToolStatus enum for explicit tool availability
- ToolRegistry class for registering and managing tools
- Capability checking before LLM calls
- Dynamic system prompt generation
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set


class ToolStatus(Enum):
    """Status of a registered tool."""
    WORKING = "working"          # Fully implemented and tested
    BETA = "beta"                # Implemented but not fully tested
    PLANNED = "planned"          # Not yet implemented
    DEPRECATED = "deprecated"    # Being phased out
    DISABLED = "disabled"        # Temporarily disabled


@dataclass
class ToolDefinition:
    """Definition of a registered tool."""
    name: str
    function: Optional[Callable]
    description: str
    status: ToolStatus
    parameters: Dict[str, Any]
    category: str = "general"
    requires_auth: bool = False
    auth_types: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)

    def is_available(self) -> bool:
        """Check if tool is available for use."""
        return self.status in (ToolStatus.WORKING, ToolStatus.BETA)

    def to_openai_schema(self) -> Dict[str, Any]:
        """Convert to OpenAI function calling schema."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            }
        }


class ToolRegistry:
    """Registry for all agent tools with status tracking."""

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._categories: Dict[str, List[str]] = {}

    def register(
        self,
        name: str,
        function: Optional[Callable],
        description: str,
        status: ToolStatus,
        parameters: Dict[str, Any],
        category: str = "general",
        requires_auth: bool = False,
        auth_types: Optional[List[str]] = None,
        examples: Optional[List[str]] = None,
    ) -> None:
        """Register a tool with the registry.

        Args:
            name: Unique tool name
            function: Handler function (None for PLANNED tools)
            description: Tool description for LLM
            status: Current implementation status
            parameters: OpenAI-style parameter schema
            category: Tool category for grouping
            requires_auth: Whether tool requires authentication
            auth_types: Types of auth this tool can provide/use
            examples: Example usage strings
        """
        if status != ToolStatus.PLANNED and function is None:
            raise ValueError(f"Tool '{name}' with status {status} requires a function")

        tool = ToolDefinition(
            name=name,
            function=function,
            description=description,
            status=status,
            parameters=parameters,
            category=category,
            requires_auth=requires_auth,
            auth_types=auth_types or [],
            examples=examples or [],
        )

        self._tools[name] = tool

        # Track by category
        if category not in self._categories:
            self._categories[category] = []
        if name not in self._categories[category]:
            self._categories[category].append(name)

    def get(self, name: str) -> Optional[ToolDefinition]:
        """Get a tool by name."""
        return self._tools.get(name)

    def get_handler(self, name: str) -> Optional[Callable]:
        """Get the handler function for a tool."""
        tool = self._tools.get(name)
        if tool and tool.is_available():
            return tool.function
        return None

    def is_available(self, name: str) -> bool:
        """Check if a tool is available."""
        tool = self._tools.get(name)
        return tool.is_available() if tool else False

    def get_status(self, name: str) -> Optional[ToolStatus]:
        """Get the status of a tool."""
        tool = self._tools.get(name)
        return tool.status if tool else None

    def list_available(self) -> List[str]:
        """List all available tool names."""
        return [name for name, tool in self._tools.items() if tool.is_available()]

    def list_by_status(self, status: ToolStatus) -> List[str]:
        """List tools with a specific status."""
        return [name for name, tool in self._tools.items() if tool.status == status]

    def list_by_category(self, category: str) -> List[str]:
        """List tools in a category."""
        return self._categories.get(category, [])

    def get_categories(self) -> List[str]:
        """Get all category names."""
        return list(self._categories.keys())

    def get_openai_tools(self, include_planned: bool = False) -> List[Dict[str, Any]]:
        """Get OpenAI-format tool schemas for available tools.

        Args:
            include_planned: Include PLANNED tools (for testing)

        Returns:
            List of OpenAI function calling schemas
        """
        tools = []
        for tool in self._tools.values():
            if tool.is_available() or (include_planned and tool.status == ToolStatus.PLANNED):
                tools.append(tool.to_openai_schema())
        return tools

    def get_handlers(self) -> Dict[str, Callable]:
        """Get all available tool handlers."""
        return {
            name: tool.function
            for name, tool in self._tools.items()
            if tool.is_available() and tool.function
        }

    def check_capability(self, request: str) -> Dict[str, Any]:
        """Check if request can be fulfilled with available tools.

        Args:
            request: User request text

        Returns:
            Dict with 'can_fulfill', 'available_tools', 'missing_tools'
        """
        # Keywords mapped to required tools
        capability_map = {
            "postman": ["parse_postman", "parse_postman_environment", "fetch_postman_workspace"],
            "insomnia": ["parse_insomnia"],
            "bruno": ["parse_bruno"],
            "gitlab": ["clone_gitlab_repo"],
            "bitbucket": ["clone_bitbucket_repo"],
            "kong": ["fetch_kong_config"],
            "aws api gateway": ["fetch_aws_api_gateway"],
            "vault": ["fetch_vault_credentials"],
            "aws secrets": ["fetch_aws_secret"],
            "har": ["parse_har_file"],
            "jest": ["parse_jest_tests"],
            "supertest": ["parse_jest_tests"],
            "github": ["clone_github_repo"],
            "openapi": ["parse_openapi"],
            "swagger": ["parse_openapi"],
            "env": ["parse_env", "parse_env_file_v2", "scan_env_files"],
        }

        request_lower = request.lower()
        required_tools: Set[str] = set()

        for keyword, tools in capability_map.items():
            if keyword in request_lower:
                required_tools.update(tools)

        available = []
        missing = []

        for tool_name in required_tools:
            if self.is_available(tool_name):
                available.append(tool_name)
            else:
                status = self.get_status(tool_name)
                missing.append({
                    "name": tool_name,
                    "status": status.value if status else "unknown"
                })

        return {
            "can_fulfill": len(missing) == 0,
            "available_tools": available,
            "missing_tools": missing,
        }

    def build_capability_summary(self) -> str:
        """Build a summary of available capabilities for system prompt.

        Returns:
            Markdown-formatted capability summary
        """
        lines = ["## Available Tools\n"]

        for category in sorted(self._categories.keys()):
            tool_names = self._categories[category]
            available_in_cat = [
                name for name in tool_names
                if self._tools[name].is_available()
            ]

            if available_in_cat:
                lines.append(f"\n### {category.replace('_', ' ').title()}\n")
                for name in available_in_cat:
                    tool = self._tools[name]
                    status_badge = "" if tool.status == ToolStatus.WORKING else " (beta)"
                    lines.append(f"- **{name}**{status_badge}: {tool.description}")

        # Add planned tools section
        planned = self.list_by_status(ToolStatus.PLANNED)
        if planned:
            lines.append("\n### Coming Soon (Not Yet Available)\n")
            for name in planned:
                tool = self._tools[name]
                lines.append(f"- ~~{name}~~: {tool.description}")

        return "\n".join(lines)

    def build_opening_message_tools(self) -> Dict[str, List[str]]:
        """Build tool lists for opening message.

        Returns:
            Dict with 'working' and 'planned' tool lists
        """
        working = []
        planned = []

        # Group by category for cleaner display
        category_labels = {
            "scanning": "Code scanning",
            "parsing": "File parsing",
            "api_clients": "API clients (Postman, Insomnia, Bruno)",
            "version_control": "Version control (GitHub, GitLab, Bitbucket)",
            "api_gateways": "API gateways (Kong, AWS)",
            "secrets": "Secret managers (Vault, AWS Secrets)",
            "testing": "Test frameworks",
        }

        for category, label in category_labels.items():
            tools_in_cat = self._categories.get(category, [])
            available = [t for t in tools_in_cat if self._tools[t].is_available()]
            not_available = [t for t in tools_in_cat if not self._tools[t].is_available()]

            if available:
                working.append(label)
            if not_available:
                planned.append(label)

        return {"working": working, "planned": planned}


# Global registry instance
registry = ToolRegistry()


def get_registry() -> ToolRegistry:
    """Get the global tool registry."""
    return registry
