"""
Tool Registry initialization.

This module initializes the global tool registry with all available tools
and their current implementation status.

Usage:
    from apisec.tools import get_registry

    registry = get_registry()
    if registry.is_available("scan_repo"):
        handler = registry.get_handler("scan_repo")
"""

from .registry import ToolRegistry, ToolStatus, ToolDefinition, get_registry, registry

# Import handlers from the agent tools module
from ..agent.tools import (
    # Core handlers
    handle_scan_repo,
    handle_parse_openapi,
    handle_parse_postman,
    handle_parse_postman_environment,
    handle_parse_logs,
    handle_parse_env,
    handle_generate_config,
    handle_create_pr,
    # Intelligent parsers
    handle_parse_gateway_logs,
    handle_parse_test_logs,
    handle_parse_fixtures,
    handle_parse_devops_config,
    # GitHub integration
    handle_validate_github_token,
    handle_clone_github_repo,
    # Token validation
    handle_validate_token,
    handle_validate_multiple_tokens,
    # Integration tests
    handle_parse_integration_tests,
    # P0 Connectors
    handle_parse_env_file_v2,
    handle_scan_env_files,
    handle_parse_postman_collection_v2,
    handle_parse_postman_env_v2,
    handle_fetch_postman_workspace,
    # P1 Connectors
    handle_parse_insomnia,
    handle_parse_bruno,
    handle_clone_gitlab_repo,
    handle_clone_bitbucket_repo,
    handle_fetch_kong_config,
    handle_fetch_aws_api_gateway,
    handle_fetch_vault_credentials,
    handle_fetch_aws_secret,
    handle_parse_har_file,
    handle_parse_jest_tests,
    # APIsec Platform
    handle_validate_apisec_token,
    handle_upload_to_apisec,
    handle_get_apisec_token_instructions,
)


def _register_all_tools() -> None:
    """Register all tools with their status in the global registry."""

    # ==========================================================================
    # CORE TOOLS - WORKING
    # ==========================================================================

    registry.register(
        name="scan_repo",
        function=handle_scan_repo,
        description="Scan a directory for API artifacts like OpenAPI specs, Postman collections, environment files, and logs.",
        status=ToolStatus.WORKING,
        category="scanning",
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the directory to scan",
                }
            },
            "required": ["path"],
        },
    )

    registry.register(
        name="parse_openapi",
        function=handle_parse_openapi,
        description="Parse an OpenAPI/Swagger specification file to extract endpoints, security schemes, and schemas.",
        status=ToolStatus.WORKING,
        category="parsing",
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the OpenAPI spec file",
                }
            },
            "required": ["path"],
        },
    )

    registry.register(
        name="parse_postman",
        function=handle_parse_postman,
        description="Parse a Postman collection to extract requests, authentication configuration, and variables.",
        status=ToolStatus.WORKING,
        category="api_clients",
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the Postman collection JSON file",
                }
            },
            "required": ["path"],
        },
    )

    registry.register(
        name="parse_postman_environment",
        function=handle_parse_postman_environment,
        description="Parse a Postman environment file to extract URLs, credentials, and tokens.",
        status=ToolStatus.WORKING,
        category="api_clients",
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the Postman environment file",
                }
            },
            "required": ["path"],
        },
    )

    registry.register(
        name="parse_logs",
        function=handle_parse_logs,
        description="Parse API access logs (JSON lines format) to extract endpoints and patterns.",
        status=ToolStatus.WORKING,
        category="parsing",
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the log file",
                }
            },
            "required": ["path"],
        },
    )

    registry.register(
        name="parse_env",
        function=handle_parse_env,
        description="Parse an environment configuration file to extract URLs and variables.",
        status=ToolStatus.WORKING,
        category="parsing",
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the environment file",
                }
            },
            "required": ["path"],
        },
    )

    registry.register(
        name="generate_config",
        function=handle_generate_config,
        description="Generate the APIsec configuration YAML file based on collected information.",
        status=ToolStatus.WORKING,
        category="config",
        parameters={
            "type": "object",
            "properties": {
                "api_name": {"type": "string", "description": "Human-readable name of the API"},
                "base_url": {"type": "string", "description": "Base URL for the API"},
                "auth_type": {
                    "type": "string",
                    "enum": ["oauth2_client_credentials", "oauth2_password", "api_key", "basic", "bearer", "none"],
                },
                "spec_path": {"type": "string", "description": "Path to OpenAPI spec"},
                "token_endpoint": {"type": "string", "description": "Token endpoint for OAuth2"},
                "credentials": {"type": "object", "description": "Credential configuration"},
                "identities": {"type": "array", "description": "Test identities for BOLA testing"},
                "exclude_endpoints": {"type": "array", "description": "Endpoints to exclude"},
            },
            "required": ["api_name", "base_url", "auth_type"],
        },
    )

    registry.register(
        name="create_pr",
        function=handle_create_pr,
        description="Create a GitHub pull request with the APIsec configuration file.",
        status=ToolStatus.WORKING,
        category="version_control",
        requires_auth=True,
        auth_types=["github_token"],
        parameters={
            "type": "object",
            "properties": {
                "branch_name": {"type": "string", "description": "Branch name"},
                "commit_message": {"type": "string", "description": "Commit message"},
                "pr_title": {"type": "string", "description": "PR title"},
                "pr_body": {"type": "string", "description": "PR description"},
            },
            "required": ["branch_name", "commit_message", "pr_title", "pr_body"],
        },
    )

    # ==========================================================================
    # INTELLIGENT PARSERS - WORKING
    # ==========================================================================

    registry.register(
        name="parse_gateway_logs",
        function=handle_parse_gateway_logs,
        description="Parse API gateway logs (Kong, AWS, nginx, Envoy) to extract traffic patterns.",
        status=ToolStatus.WORKING,
        category="parsing",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to gateway log file"}
            },
            "required": ["path"],
        },
    )

    registry.register(
        name="parse_test_logs",
        function=handle_parse_test_logs,
        description="Parse test framework output logs to reveal tested endpoints and auth flows.",
        status=ToolStatus.WORKING,
        category="testing",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to test output file"}
            },
            "required": ["path"],
        },
    )

    registry.register(
        name="parse_fixtures",
        function=handle_parse_fixtures,
        description="Parse test fixtures and seed data for BOLA testing identities.",
        status=ToolStatus.WORKING,
        category="testing",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to fixtures file"}
            },
            "required": ["path"],
        },
    )

    registry.register(
        name="parse_devops_config",
        function=handle_parse_devops_config,
        description="Parse DevOps configs (docker-compose, CI/CD) for environment URLs and secrets.",
        status=ToolStatus.WORKING,
        category="parsing",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to DevOps config file"}
            },
            "required": ["path"],
        },
    )

    # ==========================================================================
    # GITHUB INTEGRATION - WORKING
    # ==========================================================================

    registry.register(
        name="validate_github_token",
        function=handle_validate_github_token,
        description="Validate a GitHub Personal Access Token and check its scopes.",
        status=ToolStatus.WORKING,
        category="version_control",
        requires_auth=True,
        auth_types=["github_token"],
        parameters={
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "GitHub PAT to validate"}
            },
            "required": ["token"],
        },
    )

    registry.register(
        name="clone_github_repo",
        function=handle_clone_github_repo,
        description="Clone a GitHub repository (public or private) for scanning.",
        status=ToolStatus.WORKING,
        category="version_control",
        parameters={
            "type": "object",
            "properties": {
                "repo": {"type": "string", "description": "Repository in 'owner/repo' format"},
                "token": {"type": "string", "description": "GitHub PAT for private repos"},
                "branch": {"type": "string", "description": "Specific branch to clone"},
            },
            "required": ["repo"],
        },
    )

    # ==========================================================================
    # TOKEN VALIDATION - WORKING
    # ==========================================================================

    registry.register(
        name="validate_token",
        function=handle_validate_token,
        description="Validate a JWT token - check if well-formed and not expired.",
        status=ToolStatus.WORKING,
        category="auth",
        parameters={
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "JWT token to validate"}
            },
            "required": ["token"],
        },
    )

    registry.register(
        name="validate_multiple_tokens",
        function=handle_validate_multiple_tokens,
        description="Validate multiple JWT tokens at once.",
        status=ToolStatus.WORKING,
        category="auth",
        parameters={
            "type": "object",
            "properties": {
                "tokens": {"type": "object", "description": "Dict of token_name -> token_value"}
            },
            "required": ["tokens"],
        },
    )

    registry.register(
        name="parse_integration_tests",
        function=handle_parse_integration_tests,
        description="Parse integration test code to extract working payloads from passing tests.",
        status=ToolStatus.WORKING,
        category="testing",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to tests directory"}
            },
            "required": ["path"],
        },
    )

    # ==========================================================================
    # P0 CONNECTORS - WORKING
    # ==========================================================================

    registry.register(
        name="parse_env_file_v2",
        function=handle_parse_env_file_v2,
        description="Parse .env file with smart categorization. Identifies URLs, auth tokens, API keys.",
        status=ToolStatus.WORKING,
        category="parsing",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to .env file"},
                "include_sensitive": {"type": "boolean", "description": "Include unmasked values"},
            },
            "required": ["path"],
        },
    )

    registry.register(
        name="scan_env_files",
        function=handle_scan_env_files,
        description="Scan directory for all .env files and merge variables.",
        status=ToolStatus.WORKING,
        category="scanning",
        parameters={
            "type": "object",
            "properties": {
                "directory": {"type": "string", "description": "Directory to scan"}
            },
            "required": ["directory"],
        },
    )

    registry.register(
        name="parse_postman_collection_v2",
        function=handle_parse_postman_collection_v2,
        description="Parse Postman collection with enhanced endpoint extraction.",
        status=ToolStatus.WORKING,
        category="api_clients",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to collection JSON"}
            },
            "required": ["path"],
        },
    )

    registry.register(
        name="parse_postman_env_v2",
        function=handle_parse_postman_env_v2,
        description="Parse Postman environment with smart auth detection.",
        status=ToolStatus.WORKING,
        category="api_clients",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to environment JSON"}
            },
            "required": ["path"],
        },
    )

    registry.register(
        name="fetch_postman_workspace",
        function=handle_fetch_postman_workspace,
        description="Fetch collections and environments from Postman API.",
        status=ToolStatus.WORKING,
        category="api_clients",
        requires_auth=True,
        auth_types=["postman_api_key"],
        parameters={
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": "Postman API key"},
                "workspace_id": {"type": "string", "description": "Workspace ID"},
                "collection_id": {"type": "string", "description": "Collection ID"},
                "environment_id": {"type": "string", "description": "Environment ID"},
            },
            "required": ["api_key"],
        },
    )

    # ==========================================================================
    # P1 CONNECTORS - WORKING
    # ==========================================================================

    registry.register(
        name="parse_insomnia",
        function=handle_parse_insomnia,
        description="Parse Insomnia API client export file.",
        status=ToolStatus.WORKING,
        category="api_clients",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to Insomnia export JSON"}
            },
            "required": ["path"],
        },
    )

    registry.register(
        name="parse_bruno",
        function=handle_parse_bruno,
        description="Parse Bruno API client collection (.bru files).",
        status=ToolStatus.WORKING,
        category="api_clients",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to Bruno collection directory"}
            },
            "required": ["path"],
        },
    )

    registry.register(
        name="clone_gitlab_repo",
        function=handle_clone_gitlab_repo,
        description="Clone a GitLab repository (gitlab.com or self-hosted).",
        status=ToolStatus.WORKING,
        category="version_control",
        parameters={
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "GitLab project path"},
                "token": {"type": "string", "description": "GitLab PAT"},
                "host": {"type": "string", "description": "GitLab host URL"},
                "branch": {"type": "string", "description": "Branch to clone"},
            },
            "required": ["project"],
        },
    )

    registry.register(
        name="clone_bitbucket_repo",
        function=handle_clone_bitbucket_repo,
        description="Clone a Bitbucket repository.",
        status=ToolStatus.WORKING,
        category="version_control",
        parameters={
            "type": "object",
            "properties": {
                "repo": {"type": "string", "description": "Repo in 'workspace/repo' format"},
                "username": {"type": "string", "description": "Bitbucket username"},
                "app_password": {"type": "string", "description": "App password"},
                "branch": {"type": "string", "description": "Branch to clone"},
            },
            "required": ["repo"],
        },
    )

    registry.register(
        name="fetch_kong_config",
        function=handle_fetch_kong_config,
        description="Fetch API configuration from Kong API Gateway.",
        status=ToolStatus.WORKING,
        category="api_gateways",
        parameters={
            "type": "object",
            "properties": {
                "admin_url": {"type": "string", "description": "Kong Admin API URL"},
                "api_key": {"type": "string", "description": "API key for Kong Admin"},
            },
            "required": ["admin_url"],
        },
    )

    registry.register(
        name="fetch_aws_api_gateway",
        function=handle_fetch_aws_api_gateway,
        description="Fetch configuration from AWS API Gateway.",
        status=ToolStatus.WORKING,
        category="api_gateways",
        requires_auth=True,
        auth_types=["aws_credentials"],
        parameters={
            "type": "object",
            "properties": {
                "region": {"type": "string", "description": "AWS region"},
                "profile_name": {"type": "string", "description": "AWS profile name"},
            },
            "required": [],
        },
    )

    registry.register(
        name="fetch_vault_credentials",
        function=handle_fetch_vault_credentials,
        description="Fetch API credentials from HashiCorp Vault.",
        status=ToolStatus.WORKING,
        category="secrets",
        requires_auth=True,
        auth_types=["vault_token"],
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Vault server URL"},
                "token": {"type": "string", "description": "Vault token"},
                "path": {"type": "string", "description": "Secret path"},
                "mount": {"type": "string", "description": "Secret engine mount"},
            },
            "required": ["url", "token"],
        },
    )

    registry.register(
        name="fetch_aws_secret",
        function=handle_fetch_aws_secret,
        description="Fetch API credentials from AWS Secrets Manager.",
        status=ToolStatus.WORKING,
        category="secrets",
        requires_auth=True,
        auth_types=["aws_credentials"],
        parameters={
            "type": "object",
            "properties": {
                "secret_name": {"type": "string", "description": "Secret name or ARN"},
                "region": {"type": "string", "description": "AWS region"},
                "profile_name": {"type": "string", "description": "AWS profile"},
            },
            "required": ["secret_name"],
        },
    )

    registry.register(
        name="parse_har_file",
        function=handle_parse_har_file,
        description="Parse HAR files to extract API endpoints and payloads.",
        status=ToolStatus.WORKING,
        category="parsing",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to HAR file"},
                "base_url_filter": {"type": "string", "description": "Filter to base URL"},
            },
            "required": ["path"],
        },
    )

    registry.register(
        name="parse_jest_tests",
        function=handle_parse_jest_tests,
        description="Parse Jest/Supertest test files to extract API endpoints.",
        status=ToolStatus.WORKING,
        category="testing",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to test directory or file"}
            },
            "required": ["path"],
        },
    )

    # ==========================================================================
    # APISEC PLATFORM - WORKING
    # ==========================================================================

    registry.register(
        name="validate_apisec_token",
        function=handle_validate_apisec_token,
        description="Validate APIsec platform API token and get tenant info.",
        status=ToolStatus.WORKING,
        category="platform",
        requires_auth=True,
        auth_types=["apisec_token"],
        parameters={
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "APIsec API token"}
            },
            "required": ["token"],
        },
    )

    registry.register(
        name="upload_to_apisec",
        function=handle_upload_to_apisec,
        description="Upload API config to APIsec platform for security scanning.",
        status=ToolStatus.WORKING,
        category="platform",
        requires_auth=True,
        auth_types=["apisec_token"],
        parameters={
            "type": "object",
            "properties": {
                "config": {"type": "object", "description": "API configuration dict"},
                "api_name": {"type": "string", "description": "Name for the API in APIsec"},
                "token": {"type": "string", "description": "APIsec API token"},
                "update_existing": {"type": "boolean", "description": "Update if API exists"},
            },
            "required": ["config", "api_name", "token"],
        },
    )

    registry.register(
        name="get_apisec_token_instructions",
        function=handle_get_apisec_token_instructions,
        description="Get instructions for creating an APIsec API token.",
        status=ToolStatus.WORKING,
        category="platform",
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
    )


# Initialize registry on module import
_register_all_tools()


__all__ = [
    "ToolRegistry",
    "ToolStatus",
    "ToolDefinition",
    "get_registry",
    "registry",
]
