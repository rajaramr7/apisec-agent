"""APIsec configuration schema definitions."""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class CredentialConfig(BaseModel):
    """Credential configuration for authentication."""

    type: str = Field(description="Credential type (e.g., 'password', 'client_credentials')")
    username: Optional[str] = Field(None, description="Username or client ID")
    password_env: Optional[str] = Field(None, description="Environment variable for password/secret")


class AuthConfig(BaseModel):
    """Authentication configuration."""

    type: str = Field(description="Auth type (e.g., 'bearer', 'basic', 'api_key')")
    token_endpoint: Optional[str] = Field(None, description="Token endpoint URL")
    grant_type: Optional[str] = Field(None, description="OAuth grant type")
    credentials: Optional[List[CredentialConfig]] = Field(None, description="Test credentials")
    header_name: Optional[str] = Field(None, description="Header name for API key auth")
    token_prefix: Optional[str] = Field("Bearer", description="Token prefix in Authorization header")


class EndpointConfig(BaseModel):
    """API endpoint configuration."""

    path: str = Field(description="Endpoint path (e.g., '/orders/{id}')")
    method: str = Field(description="HTTP method")
    auth_required: bool = Field(True, description="Whether authentication is required")
    parameters: Optional[Dict[str, str]] = Field(None, description="Path/query parameters")
    request_body_schema: Optional[Dict] = Field(None, description="Request body JSON schema")
    roles: Optional[List[str]] = Field(None, description="Roles that can access this endpoint")


class SecurityTestConfig(BaseModel):
    """Security test configuration."""

    enabled: bool = Field(True, description="Whether to run security tests")
    test_types: List[str] = Field(
        default_factory=lambda: ["bola", "auth_bypass", "injection"],
        description="Types of security tests to run",
    )
    exclude_endpoints: Optional[List[str]] = Field(None, description="Endpoints to exclude from testing")


class APIsecConfig(BaseModel):
    """Root APIsec configuration schema."""

    version: str = Field("1.0", description="Config schema version")
    api_name: str = Field(description="Name of the API")
    base_url: str = Field(description="Base URL of the API")
    description: Optional[str] = Field(None, description="API description")

    auth: AuthConfig = Field(description="Authentication configuration")
    endpoints: List[EndpointConfig] = Field(description="API endpoints to test")
    security_tests: SecurityTestConfig = Field(
        default_factory=SecurityTestConfig,
        description="Security test configuration",
    )

    environment: Optional[str] = Field(None, description="Target environment (dev, staging, prod)")
    tags: Optional[List[str]] = Field(None, description="Tags for categorization")

    class Config:
        """Pydantic config."""

        json_schema_extra = {
            "example": {
                "version": "1.0",
                "api_name": "Orders API",
                "base_url": "https://api.example.com",
                "auth": {
                    "type": "bearer",
                    "token_endpoint": "/auth/token",
                    "grant_type": "password",
                },
                "endpoints": [
                    {
                        "path": "/orders",
                        "method": "GET",
                        "auth_required": True,
                    }
                ],
            }
        }
