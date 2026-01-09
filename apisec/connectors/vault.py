"""
HashiCorp Vault connector.

Fetches secrets from HashiCorp Vault:
- KV secrets (v1 and v2)
- Database credentials
- PKI certificates
- AWS/Azure/GCP credentials

Useful for retrieving API credentials, tokens, and certificates
needed for security testing.
"""

from typing import Any, Dict, List, Optional

import requests

from .base import BaseConnector, ConnectorResult


class VaultConnector(BaseConnector):
    """Connector for HashiCorp Vault."""

    @property
    def name(self) -> str:
        return "vault"

    @property
    def description(self) -> str:
        return "Fetch secrets from HashiCorp Vault"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._url: Optional[str] = None
        self._token: Optional[str] = None
        self._namespace: Optional[str] = None

    def connect(
        self,
        url: str,
        token: str,
        namespace: Optional[str] = None,
        **kwargs
    ) -> ConnectorResult:
        """Connect to Vault server.

        Args:
            url: Vault server URL (e.g., https://vault.example.com:8200)
            token: Vault token for authentication
            namespace: Optional Vault namespace (Enterprise)

        Returns:
            ConnectorResult indicating success/failure
        """
        self._url = url.rstrip("/")
        self._token = token
        self._namespace = namespace

        # Test connection
        try:
            headers = {
                "X-Vault-Token": token,
            }
            if namespace:
                headers["X-Vault-Namespace"] = namespace

            response = requests.get(
                f"{self._url}/v1/sys/health",
                headers=headers,
                timeout=10,
                verify=kwargs.get("verify_ssl", True)
            )

            if response.status_code == 200:
                data = response.json()
                self._connected = True
                return self._success(
                    data={
                        "initialized": data.get("initialized"),
                        "sealed": data.get("sealed"),
                        "version": data.get("version"),
                        "cluster_name": data.get("cluster_name"),
                    },
                    source=f"vault://{self._url}"
                )
            elif response.status_code in [401, 403]:
                return self._error("Invalid or insufficient token permissions", needs_auth=True)
            else:
                return self._error(f"Vault error: {response.status_code}")

        except requests.Timeout:
            return self._error("Vault connection timeout")
        except requests.RequestException as e:
            return self._error(f"Connection error: {e}")

    def fetch_config(self) -> ConnectorResult:
        """List available secret engines and mounts.

        Returns:
            ConnectorResult with Vault configuration
        """
        if not self._connected:
            return self._error("Not connected to Vault")

        try:
            headers = {"X-Vault-Token": self._token}
            if self._namespace:
                headers["X-Vault-Namespace"] = self._namespace

            # List secret engines
            response = requests.get(
                f"{self._url}/v1/sys/mounts",
                headers=headers,
                timeout=10
            )

            if response.status_code != 200:
                return self._error(f"Failed to list mounts: {response.status_code}")

            mounts = response.json().get("data", {})

            # Categorize mounts
            secret_engines = []
            for path, config in mounts.items():
                engine_type = config.get("type", "")
                if engine_type in ["kv", "generic", "database", "pki", "aws", "azure", "gcp"]:
                    secret_engines.append({
                        "path": path.rstrip("/"),
                        "type": engine_type,
                        "description": config.get("description", ""),
                        "options": config.get("options", {}),
                    })

            data = {
                "secret_engines": secret_engines,
                "engine_count": len(secret_engines),
            }

            return self._success(
                data=data,
                source=f"vault://{self._url}"
            )

        except Exception as e:
            return self._error(f"Failed to fetch Vault config: {e}")

    def read_secret(
        self,
        path: str,
        mount: str = "secret",
        version: Optional[int] = None
    ) -> ConnectorResult:
        """Read a secret from Vault.

        Args:
            path: Secret path within the mount
            mount: Secret engine mount path (default: 'secret')
            version: KV v2 secret version (optional)

        Returns:
            ConnectorResult with secret data
        """
        if not self._connected:
            return self._error("Not connected to Vault")

        try:
            headers = {"X-Vault-Token": self._token}
            if self._namespace:
                headers["X-Vault-Namespace"] = self._namespace

            # Try KV v2 first
            url = f"{self._url}/v1/{mount}/data/{path}"
            params = {}
            if version:
                params["version"] = version

            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                secret_data = data.get("data", {}).get("data", {})
                metadata = data.get("data", {}).get("metadata", {})

                return self._success(
                    data={
                        "kv_version": 2,
                        "version": metadata.get("version"),
                        "created_time": metadata.get("created_time"),
                    },
                    environment=secret_data,
                    source=f"vault://{mount}/{path}"
                )

            # Try KV v1
            url = f"{self._url}/v1/{mount}/{path}"
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                secret_data = data.get("data", {})

                return self._success(
                    data={"kv_version": 1},
                    environment=secret_data,
                    source=f"vault://{mount}/{path}"
                )

            elif response.status_code == 404:
                return self._error(f"Secret not found: {mount}/{path}")
            elif response.status_code in [401, 403]:
                return self._error(f"Access denied to {mount}/{path}", needs_auth=True)
            else:
                return self._error(f"Failed to read secret: {response.status_code}")

        except Exception as e:
            return self._error(f"Failed to read secret: {e}")

    def list_secrets(self, path: str, mount: str = "secret") -> ConnectorResult:
        """List secrets at a path.

        Args:
            path: Path to list
            mount: Secret engine mount path

        Returns:
            ConnectorResult with list of secret keys
        """
        if not self._connected:
            return self._error("Not connected to Vault")

        try:
            headers = {"X-Vault-Token": self._token}
            if self._namespace:
                headers["X-Vault-Namespace"] = self._namespace

            # Try KV v2 first
            url = f"{self._url}/v1/{mount}/metadata/{path}"
            response = requests.request(
                "LIST",
                url,
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                keys = data.get("data", {}).get("keys", [])
                return self._success(
                    data={"keys": keys, "count": len(keys)},
                    source=f"vault://{mount}/{path}"
                )

            # Try KV v1
            url = f"{self._url}/v1/{mount}/{path}"
            response = requests.request("LIST", url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                keys = data.get("data", {}).get("keys", [])
                return self._success(
                    data={"keys": keys, "count": len(keys)},
                    source=f"vault://{mount}/{path}"
                )

            elif response.status_code == 404:
                return self._error(f"Path not found: {mount}/{path}")
            else:
                return self._error(f"Failed to list secrets: {response.status_code}")

        except Exception as e:
            return self._error(f"Failed to list secrets: {e}")

    def read_api_credentials(
        self,
        path: str = "api-credentials",
        mount: str = "secret"
    ) -> ConnectorResult:
        """Read API credentials from a standard path.

        Expects secrets structured as:
        - base_url
        - auth_type
        - client_id / client_secret
        - api_key
        - username / password
        - tokens (user_a_token, user_b_token, etc.)

        Args:
            path: Path to API credentials secret
            mount: Secret engine mount path

        Returns:
            ConnectorResult with extracted auth configuration
        """
        result = self.read_secret(path, mount)
        if not result.success:
            return result

        env = result.environment
        if not env:
            return self._error("No credentials found")

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

        # Extract user tokens
        user_tokens = {
            k: v for k, v in env.items()
            if "token" in k.lower() and k not in ["token", "access_token"]
        }

        return self._success(
            data={
                "base_url": env.get("base_url"),
                "has_auth": auth_config is not None,
                "user_tokens_count": len(user_tokens),
            },
            auth_config=auth_config,
            environment=env,
            source=f"vault://{mount}/{path}"
        )


def fetch_vault_secret(
    url: str,
    token: str,
    path: str,
    mount: str = "secret",
    namespace: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch a secret from HashiCorp Vault.

    Args:
        url: Vault server URL
        token: Vault token
        path: Secret path
        mount: Secret engine mount path
        namespace: Optional Vault namespace

    Returns:
        Dict with secret data
    """
    connector = VaultConnector()
    connect_result = connector.connect(url=url, token=token, namespace=namespace)

    if not connect_result.success:
        return connect_result.to_dict()

    result = connector.read_secret(path=path, mount=mount)
    return result.to_dict()


def fetch_vault_api_credentials(
    url: str,
    token: str,
    path: str = "api-credentials",
    mount: str = "secret",
    namespace: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch API credentials from Vault.

    Args:
        url: Vault server URL
        token: Vault token
        path: Path to credentials secret
        mount: Secret engine mount path
        namespace: Optional Vault namespace

    Returns:
        Dict with auth configuration
    """
    connector = VaultConnector()
    connect_result = connector.connect(url=url, token=token, namespace=namespace)

    if not connect_result.success:
        return connect_result.to_dict()

    result = connector.read_api_credentials(path=path, mount=mount)
    return result.to_dict()
