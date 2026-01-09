"""
Kong API Gateway connector.

Fetches API configuration from Kong Admin API:
- Services and routes
- Plugins (especially auth plugins)
- Consumers and credentials
- Upstreams and targets

Supports both Kong OSS and Kong Enterprise.
"""

from typing import Any, Dict, List, Optional

import requests

from .base import APIConnector, ConnectorResult


class KongConnector(APIConnector):
    """Connector for Kong API Gateway."""

    @property
    def name(self) -> str:
        return "kong"

    @property
    def description(self) -> str:
        return "Fetch API configuration from Kong API Gateway"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._services: List[Dict] = []
        self._routes: List[Dict] = []
        self._plugins: List[Dict] = []
        self._consumers: List[Dict] = []

    def connect(
        self,
        admin_url: str,
        api_key: Optional[str] = None,
        **kwargs
    ) -> ConnectorResult:
        """Connect to Kong Admin API.

        Args:
            admin_url: Kong Admin API URL (e.g., http://localhost:8001)
            api_key: Optional API key for Kong Admin API authentication

        Returns:
            ConnectorResult indicating success/failure
        """
        self._base_url = admin_url.rstrip("/")

        if api_key:
            self._headers["apikey"] = api_key

        # Test connection
        try:
            response = requests.get(
                f"{self._base_url}/",
                headers=self._headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                self._connected = True
                return self._success(
                    data={
                        "version": data.get("version"),
                        "hostname": data.get("hostname"),
                        "tagline": data.get("tagline"),
                    },
                    source=f"kong://{self._base_url}"
                )
            elif response.status_code == 401:
                return self._error("Authentication required", needs_auth=True)
            else:
                return self._error(f"Kong Admin API error: {response.status_code}")

        except requests.Timeout:
            return self._error("Kong Admin API timeout")
        except requests.RequestException as e:
            return self._error(f"Connection error: {e}")

    def fetch_config(self) -> ConnectorResult:
        """Fetch all API configuration from Kong.

        Returns:
            ConnectorResult with Kong configuration
        """
        if not self._connected:
            return self._error("Not connected to Kong")

        try:
            # Fetch services
            self._services = self._fetch_all("/services")

            # Fetch routes
            self._routes = self._fetch_all("/routes")

            # Fetch plugins
            self._plugins = self._fetch_all("/plugins")

            # Fetch consumers
            self._consumers = self._fetch_all("/consumers")

            # Extract endpoints from routes
            endpoints = []
            for route in self._routes:
                service = self._get_service_for_route(route)
                for path in route.get("paths", []):
                    for method in route.get("methods", ["GET"]):
                        endpoints.append({
                            "method": method,
                            "path": path,
                            "service": service.get("name") if service else None,
                            "route_name": route.get("name"),
                            "protocols": route.get("protocols", []),
                        })

            # Extract auth config from plugins
            auth_config = self._extract_auth_config()

            # Build summary
            data = {
                "services_count": len(self._services),
                "routes_count": len(self._routes),
                "plugins_count": len(self._plugins),
                "consumers_count": len(self._consumers),
                "services": [
                    {
                        "name": s.get("name"),
                        "host": s.get("host"),
                        "port": s.get("port"),
                        "protocol": s.get("protocol"),
                    }
                    for s in self._services
                ],
                "auth_plugins": [
                    p.get("name") for p in self._plugins
                    if self._is_auth_plugin(p.get("name", ""))
                ],
            }

            return self._success(
                data=data,
                source=f"kong://{self._base_url}",
                endpoints=endpoints,
                auth_config=auth_config,
            )

        except Exception as e:
            return self._error(f"Failed to fetch Kong config: {e}")

    def _fetch_all(self, endpoint: str) -> List[Dict]:
        """Fetch all items from a paginated endpoint."""
        items = []
        url = f"{self._base_url}{endpoint}"

        while url:
            try:
                response = requests.get(
                    url,
                    headers=self._headers,
                    timeout=30
                )

                if response.status_code == 200:
                    data = response.json()
                    items.extend(data.get("data", []))
                    url = data.get("next")
                else:
                    break

            except Exception:
                break

        return items

    def _get_service_for_route(self, route: Dict) -> Optional[Dict]:
        """Get the service associated with a route."""
        service_info = route.get("service")
        if not service_info:
            return None

        service_id = service_info.get("id")
        for service in self._services:
            if service.get("id") == service_id:
                return service
        return None

    def _is_auth_plugin(self, plugin_name: str) -> bool:
        """Check if a plugin is an authentication plugin."""
        auth_plugins = [
            "key-auth", "basic-auth", "oauth2", "jwt",
            "hmac-auth", "ldap-auth", "session",
            "openid-connect", "mtls-auth",
        ]
        return plugin_name in auth_plugins

    def _extract_auth_config(self) -> Optional[Dict[str, Any]]:
        """Extract authentication configuration from plugins."""
        for plugin in self._plugins:
            plugin_name = plugin.get("name", "")

            if plugin_name == "key-auth":
                config = plugin.get("config", {})
                return {
                    "type": "api_key",
                    "key_names": config.get("key_names", ["apikey"]),
                    "key_in_header": config.get("key_in_header", True),
                    "key_in_query": config.get("key_in_query", False),
                    "key_in_body": config.get("key_in_body", False),
                }

            elif plugin_name == "basic-auth":
                return {
                    "type": "basic",
                    "hide_credentials": plugin.get("config", {}).get("hide_credentials", False),
                }

            elif plugin_name == "jwt":
                config = plugin.get("config", {})
                return {
                    "type": "jwt",
                    "claims_to_verify": config.get("claims_to_verify", []),
                    "key_claim_name": config.get("key_claim_name", "iss"),
                }

            elif plugin_name == "oauth2":
                config = plugin.get("config", {})
                return {
                    "type": "oauth2",
                    "scopes": config.get("scopes", []),
                    "enable_authorization_code": config.get("enable_authorization_code", False),
                    "enable_client_credentials": config.get("enable_client_credentials", False),
                    "enable_implicit_grant": config.get("enable_implicit_grant", False),
                    "enable_password_grant": config.get("enable_password_grant", False),
                    "token_expiration": config.get("token_expiration", 7200),
                }

            elif plugin_name == "openid-connect":
                config = plugin.get("config", {})
                return {
                    "type": "oidc",
                    "issuer": config.get("issuer"),
                    "client_id": config.get("client_id"),
                    "auth_methods": config.get("auth_methods", []),
                }

        return None

    def get_consumers(self) -> List[Dict[str, Any]]:
        """Get list of consumers with their credentials."""
        consumers_with_creds = []

        for consumer in self._consumers:
            consumer_id = consumer.get("id")
            consumer_info = {
                "id": consumer_id,
                "username": consumer.get("username"),
                "custom_id": consumer.get("custom_id"),
                "credentials": {},
            }

            # Fetch credentials for each auth type
            for cred_type in ["key-auth", "basic-auth", "jwt", "oauth2"]:
                try:
                    response = requests.get(
                        f"{self._base_url}/consumers/{consumer_id}/{cred_type}",
                        headers=self._headers,
                        timeout=10
                    )
                    if response.status_code == 200:
                        data = response.json()
                        creds = data.get("data", [])
                        if creds:
                            consumer_info["credentials"][cred_type] = creds
                except Exception:
                    continue

            consumers_with_creds.append(consumer_info)

        return consumers_with_creds


def fetch_kong_config(
    admin_url: str,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """Fetch configuration from Kong API Gateway.

    Args:
        admin_url: Kong Admin API URL
        api_key: Optional API key for authentication

    Returns:
        Dict with Kong configuration
    """
    connector = KongConnector()
    connect_result = connector.connect(admin_url=admin_url, api_key=api_key)

    if not connect_result.success:
        return connect_result.to_dict()

    result = connector.fetch_config()
    return result.to_dict()
