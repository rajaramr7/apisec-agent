"""
Connectors for external API tools and services.

Connectors fetch API configuration from external sources:
- API Clients: Postman, Insomnia, Bruno
- Environment files (.env)
- Version Control: GitHub, GitLab, Bitbucket
- API Gateways: Kong, AWS API Gateway
- Secret Managers: HashiCorp Vault, AWS Secrets Manager
- Traffic Capture: HAR files
- Test Frameworks: Jest/Supertest
"""

from .base import (
    BaseConnector,
    FileConnector,
    APIConnector,
    ConnectorResult,
    ConnectorError,
)

# P0 Connectors
from .env_file import (
    EnvFileConnector,
    parse_env_file,
    scan_env_files,
)

from .postman import (
    PostmanFileConnector,
    PostmanAPIConnector,
    parse_postman_collection,
    parse_postman_env,
    fetch_from_postman_api,
)

# P1 Connectors - API Clients
from .insomnia import (
    InsomniaConnector,
    parse_insomnia_export,
)

from .bruno import (
    BrunoConnector,
    parse_bruno_collection,
)

# P1 Connectors - Version Control
from .gitlab import (
    GitLabConnector,
    clone_gitlab_repo,
    validate_gitlab_token,
)

from .bitbucket import (
    BitbucketConnector,
    clone_bitbucket_repo,
    validate_bitbucket_auth,
)

# P1 Connectors - API Gateways
from .kong import (
    KongConnector,
    fetch_kong_config,
)

from .aws_api_gateway import (
    AWSAPIGatewayConnector,
    fetch_aws_api_gateway_config,
)

# P1 Connectors - Secret Managers
from .vault import (
    VaultConnector,
    fetch_vault_secret,
    fetch_vault_api_credentials,
)

from .aws_secrets import (
    AWSSecretsConnector,
    fetch_aws_secret,
    fetch_aws_api_credentials,
)

# P1 Connectors - Traffic/Test
from .har import (
    HARConnector,
    parse_har_file,
)

from .jest_supertest import (
    JestSupertestConnector,
    parse_jest_tests,
)

__all__ = [
    # Base classes
    "BaseConnector",
    "FileConnector",
    "APIConnector",
    "ConnectorResult",
    "ConnectorError",
    # P0 - Env file connector
    "EnvFileConnector",
    "parse_env_file",
    "scan_env_files",
    # P0 - Postman connector
    "PostmanFileConnector",
    "PostmanAPIConnector",
    "parse_postman_collection",
    "parse_postman_env",
    "fetch_from_postman_api",
    # P1 - Insomnia
    "InsomniaConnector",
    "parse_insomnia_export",
    # P1 - Bruno
    "BrunoConnector",
    "parse_bruno_collection",
    # P1 - GitLab
    "GitLabConnector",
    "clone_gitlab_repo",
    "validate_gitlab_token",
    # P1 - Bitbucket
    "BitbucketConnector",
    "clone_bitbucket_repo",
    "validate_bitbucket_auth",
    # P1 - Kong
    "KongConnector",
    "fetch_kong_config",
    # P1 - AWS API Gateway
    "AWSAPIGatewayConnector",
    "fetch_aws_api_gateway_config",
    # P1 - Vault
    "VaultConnector",
    "fetch_vault_secret",
    "fetch_vault_api_credentials",
    # P1 - AWS Secrets Manager
    "AWSSecretsConnector",
    "fetch_aws_secret",
    "fetch_aws_api_credentials",
    # P1 - HAR
    "HARConnector",
    "parse_har_file",
    # P1 - Jest/Supertest
    "JestSupertestConnector",
    "parse_jest_tests",
]
