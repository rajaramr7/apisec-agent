"""APIsec configuration generator.

Generates configuration files with REAL values - no placeholders.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .schema import (
    APIsecConfig,
    AuthConfig,
    EndpointConfig,
    IdentityConfig,
    BOLATestConfig,
    RBACTestConfig,
)


class ConfigGenerator:
    """Generator for APIsec configuration files.

    Combines inferred information from various sources
    to generate a complete APIsec configuration.

    Key principle: NEVER use placeholders - only real values.
    """

    def __init__(self):
        """Initialize the config generator."""
        self.api_name: str = ""
        self.base_url: str = ""
        self.spec_path: Optional[str] = None
        self.auth_config: Optional[Dict] = None
        self.endpoints: List[Dict] = []
        self.identities: List[Dict] = []
        self.bola_tests: List[Dict] = []
        self.rbac_tests: List[Dict] = []
        self.sources_used: List[str] = []
        self.environment: Optional[str] = None

    def set_api_info(
        self,
        name: str,
        base_url: str,
        spec_path: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> "ConfigGenerator":
        """Set basic API information.

        Args:
            name: API name
            base_url: Base URL
            spec_path: Path to OpenAPI spec
            environment: Target environment

        Returns:
            self for chaining
        """
        self.api_name = name
        self.base_url = base_url
        self.spec_path = spec_path
        self.environment = environment
        return self

    def set_auth_config(
        self,
        auth_type: str,
        token_endpoint: Optional[str] = None,
        grant_type: Optional[str] = None,
        client_id_var: Optional[str] = None,
        client_secret_var: Optional[str] = None,
    ) -> "ConfigGenerator":
        """Set authentication configuration.

        Args:
            auth_type: Auth type (oauth2, bearer, api_key, basic)
            token_endpoint: OAuth token endpoint
            grant_type: OAuth grant type
            client_id_var: Env var for client ID
            client_secret_var: Env var for client secret

        Returns:
            self for chaining
        """
        self.auth_config = {
            "type": auth_type,
        }
        if token_endpoint:
            self.auth_config["token_endpoint"] = token_endpoint
        if grant_type:
            self.auth_config["grant_type"] = grant_type
        if client_id_var or client_secret_var:
            self.auth_config["credentials"] = {}
            if client_id_var:
                self.auth_config["credentials"]["client_id_var"] = client_id_var
            if client_secret_var:
                self.auth_config["credentials"]["client_secret_var"] = client_secret_var
        return self

    def add_endpoint(
        self,
        method: str,
        path: str,
        auth_required: bool = True,
        valid_ids: Optional[Dict[str, List[str]]] = None,
        test_payload: Optional[Dict] = None,
        roles: Optional[List[str]] = None,
    ) -> "ConfigGenerator":
        """Add an endpoint configuration.

        Args:
            method: HTTP method
            path: Endpoint path
            auth_required: Whether auth is required
            valid_ids: Valid IDs for path parameters
            test_payload: Test payload (from working tests)
            roles: Roles that can access

        Returns:
            self for chaining
        """
        endpoint = {
            "method": method,
            "path": path,
            "auth_required": auth_required,
        }
        if valid_ids:
            endpoint["path_params"] = {
                param: {"valid_values": ids}
                for param, ids in valid_ids.items()
            }
        if test_payload:
            endpoint["test_payload"] = test_payload
        if roles:
            endpoint["roles"] = roles

        self.endpoints.append(endpoint)
        return self

    def add_identity(
        self,
        name: str,
        token_var: str,
        roles: Optional[List[str]] = None,
        owns: Optional[Dict[str, List[str]]] = None,
        is_admin: bool = False,
        description: Optional[str] = None,
    ) -> "ConfigGenerator":
        """Add a user identity for testing.

        Args:
            name: Identity name (e.g., 'user_a')
            token_var: Env var containing the token
            roles: Roles assigned
            owns: Resources owned (for BOLA testing)
            is_admin: Whether this is an admin identity
            description: Human-readable description

        Returns:
            self for chaining
        """
        identity = {
            "name": name,
            "token_var": token_var,
            "roles": roles or (["admin"] if is_admin else ["user"]),
        }
        if description:
            identity["description"] = description
        else:
            identity["description"] = f"{'Admin' if is_admin else 'Regular'} user for testing"

        if owns:
            identity["owns"] = owns
        if is_admin:
            identity["can_access"] = "all"

        self.identities.append(identity)
        return self

    def add_bola_test(
        self,
        attacker: str,
        victim: str,
        endpoint: str,
        resource_id: str,
        resource_param: str = "id",
        expected_status: int = 403,
    ) -> "ConfigGenerator":
        """Add a BOLA test case.

        Tests that `attacker` cannot access `victim`'s resource.

        Args:
            attacker: Identity attempting access
            victim: Identity who owns the resource
            endpoint: Endpoint (e.g., 'GET /orders/{id}')
            resource_id: ID of victim's resource
            resource_param: Parameter name for the ID
            expected_status: Expected status (should be 403)

        Returns:
            self for chaining
        """
        test = {
            "description": f"{attacker} should NOT access {victim}'s resource",
            "identity": attacker,
            "endpoint": endpoint,
            "params": {resource_param: resource_id},
            "expected_status": expected_status,
        }
        self.bola_tests.append(test)
        return self

    def add_rbac_test(
        self,
        identity: str,
        endpoint: str,
        should_succeed: bool,
        description: Optional[str] = None,
    ) -> "ConfigGenerator":
        """Add an RBAC test case.

        Args:
            identity: Identity attempting access
            endpoint: Endpoint to test
            should_succeed: Whether access should be allowed
            description: Test description

        Returns:
            self for chaining
        """
        expected_status = 200 if should_succeed else 403
        test = {
            "description": description or f"{identity} {'can' if should_succeed else 'cannot'} access {endpoint}",
            "identity": identity,
            "endpoint": endpoint,
            "expected_status": expected_status,
        }
        self.rbac_tests.append(test)
        return self

    def add_source(self, source: str) -> "ConfigGenerator":
        """Track which sources were used.

        Args:
            source: Source description

        Returns:
            self for chaining
        """
        if source not in self.sources_used:
            self.sources_used.append(source)
        return self

    def generate_bola_tests_from_ownership(self) -> "ConfigGenerator":
        """Auto-generate BOLA tests from identity ownership.

        For each identity with owned resources, creates tests
        where other identities try to access those resources.

        Returns:
            self for chaining
        """
        # Find identities with ownership
        owners = [i for i in self.identities if i.get("owns")]

        for owner in owners:
            owner_name = owner["name"]
            owned = owner["owns"]

            # Find other non-admin identities
            attackers = [
                i["name"] for i in self.identities
                if i["name"] != owner_name and i.get("can_access") != "all"
            ]

            for resource_type, resource_ids in owned.items():
                # Infer endpoint pattern
                endpoint = f"GET /{resource_type}/{{id}}"

                for attacker in attackers:
                    for resource_id in resource_ids[:2]:  # Limit to first 2
                        self.add_bola_test(
                            attacker=attacker,
                            victim=owner_name,
                            endpoint=endpoint,
                            resource_id=str(resource_id),
                        )

        return self

    def validate(self) -> List[str]:
        """Validate config has all required real values.

        Returns:
            List of validation issues (empty if valid)
        """
        issues = []

        # Required fields
        if not self.api_name:
            issues.append("Missing API name")
        if not self.base_url:
            issues.append("Missing base URL")

        # Should have endpoints
        if not self.endpoints:
            issues.append("No endpoints configured")

        # Should have identities for BOLA testing
        if not self.identities:
            issues.append("No identities configured (needed for BOLA testing)")

        # Check for placeholder patterns
        placeholder_patterns = ["placeholder", "TODO", "FIXME", "xxx", "your_", "example"]
        config_str = str(self.to_dict()).lower()
        for pattern in placeholder_patterns:
            if pattern in config_str:
                issues.append(f"Found placeholder pattern: {pattern}")

        return issues

    def to_dict(self) -> Dict[str, Any]:
        """Generate the configuration dictionary.

        Returns:
            Configuration dictionary
        """
        config = {
            "version": "1.0",
            "api": {
                "name": self.api_name,
                "base_url": self.base_url,
            }
        }

        if self.spec_path:
            config["api"]["spec_path"] = self.spec_path

        if self.auth_config:
            config["auth"] = self.auth_config

        if self.identities:
            config["identities"] = self.identities

        if self.endpoints:
            config["endpoints"] = self.endpoints

        if self.bola_tests:
            config["bola_tests"] = self.bola_tests

        if self.rbac_tests:
            config["rbac_tests"] = self.rbac_tests

        if self.environment:
            config["environment"] = self.environment

        if self.sources_used:
            config["sources_used"] = self.sources_used

        return config

    def to_yaml(self) -> str:
        """Generate YAML string representation.

        Returns:
            YAML formatted configuration with header
        """
        header = f"""# APIsec Configuration for {self.api_name}
# Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
#
# Sources used: {', '.join(self.sources_used) if self.sources_used else 'manual'}
#
# This config contains REAL values - no placeholders.

"""
        yaml_content = yaml.dump(
            self.to_dict(),
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )

        return header + yaml_content

    def save(self, output_path: str = ".apisec") -> Path:
        """Save configuration to a file.

        Args:
            output_path: Directory or file path to save

        Returns:
            Path to the saved file
        """
        output = Path(output_path)

        # If it's a directory, create filename from API name
        if output.is_dir() or not output.suffix:
            output.mkdir(parents=True, exist_ok=True)
            filename = f"{self.api_name.lower().replace(' ', '-')}.yaml"
            filepath = output / filename
        else:
            output.parent.mkdir(parents=True, exist_ok=True)
            filepath = output

        filepath.write_text(self.to_yaml())
        return filepath

    @classmethod
    def from_inferred(
        cls,
        api_name: str,
        base_url: str,
        openapi_data: Optional[Dict] = None,
        postman_data: Optional[Dict] = None,
        fixture_data: Optional[Dict] = None,
        env_data: Optional[Dict] = None,
    ) -> "ConfigGenerator":
        """Create a generator from inferred data.

        Args:
            api_name: API name
            base_url: Base URL
            openapi_data: Data from OpenAPI spec
            postman_data: Data from Postman files
            fixture_data: Data from test fixtures
            env_data: Data from environment files

        Returns:
            ConfigGenerator with merged data
        """
        gen = cls()
        gen.set_api_info(api_name, base_url)

        # Add endpoints from OpenAPI
        if openapi_data:
            gen.add_source("OpenAPI spec")
            for endpoint in openapi_data.get("endpoints", []):
                gen.add_endpoint(
                    method=endpoint.get("method", "GET"),
                    path=endpoint.get("path", "/"),
                    auth_required=endpoint.get("auth_required", True),
                )

            # Auth config
            if openapi_data.get("auth"):
                auth = openapi_data["auth"]
                gen.set_auth_config(
                    auth_type=auth.get("type", "bearer"),
                    token_endpoint=auth.get("token_endpoint"),
                )

        # Add payloads from Postman
        if postman_data:
            gen.add_source("Postman collection")
            # Merge payloads into endpoints
            for endpoint_key, payload in postman_data.get("payloads", {}).items():
                method, path = endpoint_key.split(" ", 1) if " " in endpoint_key else ("GET", endpoint_key)
                # Find matching endpoint and add payload
                for ep in gen.endpoints:
                    if ep["method"] == method and ep["path"] == path:
                        ep["test_payload"] = payload
                        break

        # Add identities from fixtures
        if fixture_data:
            gen.add_source("Test fixtures")
            ownership = fixture_data.get("ownership_map", {})
            users = fixture_data.get("test_users", [])

            for user in users:
                user_owns = ownership.get(user, {})
                # Remove role from owns if present
                role = user_owns.pop("_role", None)
                is_admin = role == "admin" if role else "admin" in user.lower()

                gen.add_identity(
                    name=user,
                    token_var=f"{user.upper()}_TOKEN",
                    roles=[role] if role else None,
                    owns=user_owns if user_owns else None,
                    is_admin=is_admin,
                )

        # Add credentials from env
        if env_data:
            gen.add_source("Environment file")

        return gen


def generate_config(
    api_name: str,
    base_url: str,
    endpoints: Optional[List[Dict]] = None,
    identities: Optional[List[Dict]] = None,
    auth: Optional[Dict] = None,
    output_path: str = ".apisec",
) -> Dict[str, Any]:
    """
    Generate APIsec configuration.

    This is the main entry point for the agent tool.

    Args:
        api_name: API name
        base_url: Base URL
        endpoints: List of endpoint configs
        identities: List of identity configs
        auth: Auth configuration
        output_path: Where to save

    Returns:
        {
            "success": True/False,
            "path": "/path/to/config.yaml",
            "validation_issues": [...],
            "config": {...}
        }
    """
    gen = ConfigGenerator()
    gen.set_api_info(api_name, base_url)

    # Add auth
    if auth:
        gen.set_auth_config(
            auth_type=auth.get("type", "bearer"),
            token_endpoint=auth.get("token_endpoint"),
            grant_type=auth.get("grant_type"),
            client_id_var=auth.get("client_id_var"),
            client_secret_var=auth.get("client_secret_var"),
        )

    # Add endpoints
    for ep in (endpoints or []):
        gen.add_endpoint(
            method=ep.get("method", "GET"),
            path=ep.get("path", "/"),
            auth_required=ep.get("auth_required", True),
            valid_ids=ep.get("valid_ids"),
            test_payload=ep.get("test_payload"),
        )

    # Add identities
    for identity in (identities or []):
        gen.add_identity(
            name=identity.get("name"),
            token_var=identity.get("token_var"),
            roles=identity.get("roles"),
            owns=identity.get("owns"),
            is_admin=identity.get("is_admin", False),
        )

    # Auto-generate BOLA tests
    gen.generate_bola_tests_from_ownership()

    # Validate
    issues = gen.validate()

    # Save
    try:
        filepath = gen.save(output_path)
        return {
            "success": len(issues) == 0,
            "path": str(filepath),
            "validation_issues": issues,
            "config": gen.to_dict(),
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "validation_issues": issues,
        }
