"""APIsec configuration schema definitions."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class CredentialConfig(BaseModel):
    """Credential configuration for authentication."""

    type: str = Field(description="Credential type (e.g., 'password', 'client_credentials')")
    username: Optional[str] = Field(None, description="Username or client ID")
    password_env: Optional[str] = Field(None, description="Environment variable for password/secret")
    client_id_var: Optional[str] = Field(None, description="Environment variable for client ID")
    client_secret_var: Optional[str] = Field(None, description="Environment variable for client secret")


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


class IdentityConfig(BaseModel):
    """User identity configuration for BOLA/RBAC testing."""

    name: str = Field(description="Identity name (e.g., 'user_a', 'admin')")
    description: Optional[str] = Field(None, description="Description of this identity")
    token_var: str = Field(description="Environment variable containing the token")
    roles: List[str] = Field(default_factory=list, description="Roles assigned to this identity")
    owns: Optional[Dict[str, List[str]]] = Field(
        None,
        description="Resources owned by this identity (e.g., {'orders': ['1001', '1002']})"
    )
    can_access: Optional[str] = Field(
        None,
        description="Special access level (e.g., 'all' for admin)"
    )


class BOLATestConfig(BaseModel):
    """BOLA (Broken Object Level Authorization) test configuration."""

    description: str = Field(description="Test description")
    identity: str = Field(description="Identity performing the test (attacker)")
    endpoint: str = Field(description="Endpoint to test (e.g., 'GET /orders/{id}')")
    params: Dict[str, str] = Field(default_factory=dict, description="Path/query parameters")
    expected_status: int = Field(403, description="Expected HTTP status code (should be 403)")


class RBACTestConfig(BaseModel):
    """RBAC (Role-Based Access Control) test configuration."""

    description: str = Field(description="Test description")
    identity: str = Field(description="Identity performing the test")
    endpoint: str = Field(description="Endpoint to test")
    expected_status: int = Field(description="Expected HTTP status code")


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
    spec_path: Optional[str] = Field(None, description="Path to OpenAPI spec file")

    auth: Optional[AuthConfig] = Field(None, description="Authentication configuration")
    endpoints: List[EndpointConfig] = Field(default_factory=list, description="API endpoints to test")

    # Identity management for BOLA/RBAC testing
    identities: Optional[List[IdentityConfig]] = Field(
        None,
        description="User identities for security testing"
    )

    # BOLA tests
    bola_tests: Optional[List[BOLATestConfig]] = Field(
        None,
        description="BOLA (Broken Object Level Authorization) test cases"
    )

    # RBAC tests
    rbac_tests: Optional[List[RBACTestConfig]] = Field(
        None,
        description="RBAC (Role-Based Access Control) test cases"
    )

    security_tests: SecurityTestConfig = Field(
        default_factory=SecurityTestConfig,
        description="Security test configuration",
    )

    environment: Optional[str] = Field(None, description="Target environment (dev, staging, prod)")
    tags: Optional[List[str]] = Field(None, description="Tags for categorization")
    sources_used: Optional[List[str]] = Field(None, description="Data sources used to generate this config")

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
