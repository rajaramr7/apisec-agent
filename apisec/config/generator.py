"""APIsec configuration generator."""

from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from .schema import APIsecConfig, AuthConfig, EndpointConfig


class ConfigGenerator:
    """Generator for APIsec configuration files.

    Combines inferred information from various sources
    to generate a complete APIsec configuration.
    """

    def __init__(self):
        """Initialize the config generator."""
        self.config_data = {
            "version": "1.0",
            "api_name": "",
            "base_url": "",
            "auth": {},
            "endpoints": [],
            "security_tests": {
                "enabled": True,
                "test_types": ["bola", "auth_bypass", "injection"],
            },
        }

    def set_api_info(
        self,
        name: str,
        base_url: str,
        description: Optional[str] = None,
    ) -> None:
        """Set basic API information.

        Args:
            name: API name
            base_url: Base URL
            description: Optional description
        """
        self.config_data["api_name"] = name
        self.config_data["base_url"] = base_url
        if description:
            self.config_data["description"] = description

    def set_auth_config(self, auth_config: Dict[str, Any]) -> None:
        """Set authentication configuration.

        Args:
            auth_config: Authentication configuration dict
        """
        self.config_data["auth"] = auth_config

    def add_endpoint(self, endpoint: Dict[str, Any]) -> None:
        """Add an endpoint to the configuration.

        Args:
            endpoint: Endpoint configuration dict
        """
        self.config_data["endpoints"].append(endpoint)

    def add_endpoints(self, endpoints: list) -> None:
        """Add multiple endpoints to the configuration.

        Args:
            endpoints: List of endpoint configuration dicts
        """
        self.config_data["endpoints"].extend(endpoints)

    def set_security_tests(self, config: Dict[str, Any]) -> None:
        """Set security test configuration.

        Args:
            config: Security test configuration dict
        """
        self.config_data["security_tests"] = config

    def validate(self) -> APIsecConfig:
        """Validate the configuration against the schema.

        Returns:
            Validated APIsecConfig object

        Raises:
            ValidationError: If configuration is invalid
        """
        return APIsecConfig(**self.config_data)

    def generate(self) -> Dict[str, Any]:
        """Generate the configuration dictionary.

        Returns:
            Configuration dictionary
        """
        # Validate before returning
        self.validate()
        return self.config_data

    def to_yaml(self) -> str:
        """Generate YAML string representation.

        Returns:
            YAML formatted configuration
        """
        return yaml.dump(
            self.generate(),
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )

    def save(self, output_path: str) -> None:
        """Save configuration to a file.

        Args:
            output_path: Path to save the configuration
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            f.write(self.to_yaml())

    @classmethod
    def from_inferred(
        cls,
        openapi_data: Optional[Dict] = None,
        postman_data: Optional[Dict] = None,
        log_data: Optional[Dict] = None,
        env_data: Optional[Dict] = None,
    ) -> "ConfigGenerator":
        """Create a generator from inferred data.

        Args:
            openapi_data: Data inferred from OpenAPI spec
            postman_data: Data inferred from Postman collection
            log_data: Data inferred from logs
            env_data: Data inferred from environment files

        Returns:
            ConfigGenerator with merged data
        """
        generator = cls()
        # TODO: Implement data merging logic
        return generator
