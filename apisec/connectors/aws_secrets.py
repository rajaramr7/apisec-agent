"""
AWS Secrets Manager connector.

Fetches secrets from AWS Secrets Manager:
- API credentials
- Database connection strings
- Tokens and keys

Requires boto3 and AWS credentials.
"""

import json
from typing import Any, Dict, List, Optional

from .base import BaseConnector, ConnectorResult


class AWSSecretsConnector(BaseConnector):
    """Connector for AWS Secrets Manager."""

    @property
    def name(self) -> str:
        return "aws_secrets"

    @property
    def description(self) -> str:
        return "Fetch secrets from AWS Secrets Manager"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._client = None
        self._region: Optional[str] = None

    def connect(
        self,
        region: str = "us-east-1",
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        profile_name: Optional[str] = None,
        **kwargs
    ) -> ConnectorResult:
        """Connect to AWS Secrets Manager.

        Args:
            region: AWS region
            access_key_id: AWS access key ID (optional if using profile/env)
            secret_access_key: AWS secret access key
            profile_name: AWS profile name to use

        Returns:
            ConnectorResult indicating success/failure
        """
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
        except ImportError:
            return self._error("boto3 is required: pip install boto3")

        self._region = region

        try:
            # Create session
            session_kwargs = {"region_name": region}
            if profile_name:
                session_kwargs["profile_name"] = profile_name

            session = boto3.Session(**session_kwargs)

            # Create client
            client_kwargs = {}
            if access_key_id and secret_access_key:
                client_kwargs["aws_access_key_id"] = access_key_id
                client_kwargs["aws_secret_access_key"] = secret_access_key

            self._client = session.client("secretsmanager", **client_kwargs)

            # Test connection by listing secrets (limit 1)
            self._client.list_secrets(MaxResults=1)

            self._connected = True
            return self._success(
                data={"region": region},
                source=f"aws_secrets://{region}"
            )

        except NoCredentialsError:
            return self._error("AWS credentials not found", needs_auth=True)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ["AccessDeniedException", "UnauthorizedAccess"]:
                return self._error(f"AWS access denied: {e}", needs_auth=True)
            return self._error(f"AWS Secrets Manager error: {e}")
        except Exception as e:
            return self._error(f"Failed to connect: {e}")

    def fetch_config(self) -> ConnectorResult:
        """List available secrets.

        Returns:
            ConnectorResult with list of secrets
        """
        if not self._connected:
            return self._error("Not connected to AWS Secrets Manager")

        try:
            secrets = []
            paginator = self._client.get_paginator("list_secrets")

            for page in paginator.paginate():
                for secret in page.get("SecretList", []):
                    secrets.append({
                        "name": secret.get("Name"),
                        "arn": secret.get("ARN"),
                        "description": secret.get("Description"),
                        "last_changed": str(secret.get("LastChangedDate", "")),
                        "tags": {
                            t["Key"]: t["Value"]
                            for t in secret.get("Tags", [])
                        },
                    })

            # Identify API-related secrets
            api_secrets = [
                s for s in secrets
                if any(
                    keyword in s["name"].lower()
                    for keyword in ["api", "auth", "token", "credential", "key"]
                )
            ]

            data = {
                "total_secrets": len(secrets),
                "api_related_secrets": len(api_secrets),
                "secrets": [
                    {"name": s["name"], "description": s.get("description")}
                    for s in secrets
                ],
            }

            return self._success(
                data=data,
                source=f"aws_secrets://{self._region}"
            )

        except Exception as e:
            return self._error(f"Failed to list secrets: {e}")

    def read_secret(self, secret_name: str) -> ConnectorResult:
        """Read a secret value.

        Args:
            secret_name: Name or ARN of the secret

        Returns:
            ConnectorResult with secret data
        """
        if not self._connected:
            return self._error("Not connected to AWS Secrets Manager")

        try:
            response = self._client.get_secret_value(SecretId=secret_name)

            # Parse secret value
            if "SecretString" in response:
                secret_string = response["SecretString"]
                try:
                    secret_data = json.loads(secret_string)
                except json.JSONDecodeError:
                    # Plain string secret
                    secret_data = {"value": secret_string}
            else:
                # Binary secret
                return self._error("Binary secrets not supported")

            return self._success(
                data={
                    "name": response.get("Name"),
                    "arn": response.get("ARN"),
                    "version_id": response.get("VersionId"),
                },
                environment=secret_data,
                source=f"aws_secrets://{secret_name}"
            )

        except self._client.exceptions.ResourceNotFoundException:
            return self._error(f"Secret not found: {secret_name}")
        except self._client.exceptions.AccessDeniedException:
            return self._error(f"Access denied to secret: {secret_name}", needs_auth=True)
        except Exception as e:
            return self._error(f"Failed to read secret: {e}")

    def read_api_credentials(self, secret_name: str) -> ConnectorResult:
        """Read API credentials from a secret.

        Expects JSON secret structured as:
        {
            "base_url": "https://api.example.com",
            "client_id": "...",
            "client_secret": "...",
            "api_key": "...",
            "tokens": {...}
        }

        Args:
            secret_name: Name or ARN of the credentials secret

        Returns:
            ConnectorResult with auth configuration
        """
        result = self.read_secret(secret_name)
        if not result.success:
            return result

        env = result.environment
        if not env:
            return self._error("No credentials found in secret")

        # Extract auth config
        auth_config = None

        if env.get("client_id") and env.get("client_secret"):
            auth_config = {
                "type": "oauth2_client_credentials",
                "client_id": env.get("client_id"),
                "client_secret": env.get("client_secret"),
                "token_url": env.get("token_url", env.get("auth_url")),
            }
        elif env.get("api_key"):
            auth_config = {
                "type": "api_key",
                "api_key": env.get("api_key"),
                "header_name": env.get("api_key_header", "X-API-Key"),
            }
        elif env.get("username") and env.get("password"):
            auth_config = {
                "type": "basic",
                "username": env.get("username"),
                "password": env.get("password"),
            }
        elif env.get("token") or env.get("access_token"):
            auth_config = {
                "type": "bearer",
                "token": env.get("token") or env.get("access_token"),
            }

        # Extract nested tokens
        tokens = env.get("tokens", {})
        if isinstance(tokens, dict):
            for k, v in tokens.items():
                env[k] = v

        return self._success(
            data={
                "base_url": env.get("base_url"),
                "has_auth": auth_config is not None,
            },
            auth_config=auth_config,
            environment=env,
            source=f"aws_secrets://{secret_name}"
        )

    def find_api_secrets(self, prefix: Optional[str] = None) -> ConnectorResult:
        """Find secrets that likely contain API credentials.

        Args:
            prefix: Optional prefix to filter secrets

        Returns:
            ConnectorResult with list of API-related secrets
        """
        if not self._connected:
            return self._error("Not connected to AWS Secrets Manager")

        try:
            secrets = []
            paginator = self._client.get_paginator("list_secrets")

            filters = []
            if prefix:
                filters.append({"Key": "name", "Values": [prefix]})

            for page in paginator.paginate(Filters=filters) if filters else paginator.paginate():
                for secret in page.get("SecretList", []):
                    name = secret.get("Name", "").lower()
                    desc = (secret.get("Description") or "").lower()
                    tags = {t["Key"].lower(): t["Value"] for t in secret.get("Tags", [])}

                    # Check if this looks like an API credential secret
                    is_api_related = any(
                        keyword in name or keyword in desc
                        for keyword in ["api", "auth", "token", "credential", "oauth"]
                    )

                    # Check tags
                    if tags.get("type") in ["api", "credentials", "auth"]:
                        is_api_related = True
                    if tags.get("application") or tags.get("service"):
                        is_api_related = True

                    if is_api_related:
                        secrets.append({
                            "name": secret.get("Name"),
                            "description": secret.get("Description"),
                            "tags": {t["Key"]: t["Value"] for t in secret.get("Tags", [])},
                        })

            return self._success(
                data={
                    "secrets": secrets,
                    "count": len(secrets),
                },
                source=f"aws_secrets://{self._region}/api-secrets"
            )

        except Exception as e:
            return self._error(f"Failed to find API secrets: {e}")


def fetch_aws_secret(
    secret_name: str,
    region: str = "us-east-1",
    access_key_id: Optional[str] = None,
    secret_access_key: Optional[str] = None,
    profile_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch a secret from AWS Secrets Manager.

    Args:
        secret_name: Name or ARN of the secret
        region: AWS region
        access_key_id: AWS access key ID (optional)
        secret_access_key: AWS secret access key (optional)
        profile_name: AWS profile name (optional)

    Returns:
        Dict with secret data
    """
    connector = AWSSecretsConnector()
    connect_result = connector.connect(
        region=region,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        profile_name=profile_name,
    )

    if not connect_result.success:
        return connect_result.to_dict()

    result = connector.read_secret(secret_name)
    return result.to_dict()


def fetch_aws_api_credentials(
    secret_name: str,
    region: str = "us-east-1",
    access_key_id: Optional[str] = None,
    secret_access_key: Optional[str] = None,
    profile_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch API credentials from AWS Secrets Manager.

    Args:
        secret_name: Name or ARN of the credentials secret
        region: AWS region
        access_key_id: AWS access key ID (optional)
        secret_access_key: AWS secret access key (optional)
        profile_name: AWS profile name (optional)

    Returns:
        Dict with auth configuration
    """
    connector = AWSSecretsConnector()
    connect_result = connector.connect(
        region=region,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        profile_name=profile_name,
    )

    if not connect_result.success:
        return connect_result.to_dict()

    result = connector.read_api_credentials(secret_name)
    return result.to_dict()
