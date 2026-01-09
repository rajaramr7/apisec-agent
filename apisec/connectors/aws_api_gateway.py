"""
AWS API Gateway connector.

Fetches API configuration from AWS API Gateway:
- REST APIs and HTTP APIs
- Resources and methods
- Authorizers
- Stages and deployments

Requires boto3 and AWS credentials.
"""

from typing import Any, Dict, List, Optional

from .base import BaseConnector, ConnectorResult


class AWSAPIGatewayConnector(BaseConnector):
    """Connector for AWS API Gateway."""

    @property
    def name(self) -> str:
        return "aws_api_gateway"

    @property
    def description(self) -> str:
        return "Fetch API configuration from AWS API Gateway"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._client = None
        self._clientv2 = None
        self._region: Optional[str] = None
        self._apis: List[Dict] = []

    def connect(
        self,
        region: str = "us-east-1",
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        profile_name: Optional[str] = None,
        **kwargs
    ) -> ConnectorResult:
        """Connect to AWS API Gateway.

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

            # Create clients
            client_kwargs = {}
            if access_key_id and secret_access_key:
                client_kwargs["aws_access_key_id"] = access_key_id
                client_kwargs["aws_secret_access_key"] = secret_access_key

            self._client = session.client("apigateway", **client_kwargs)
            self._clientv2 = session.client("apigatewayv2", **client_kwargs)

            # Test connection by listing APIs
            self._client.get_rest_apis(limit=1)

            self._connected = True
            return self._success(
                data={"region": region},
                source=f"aws_api_gateway://{region}"
            )

        except NoCredentialsError:
            return self._error("AWS credentials not found", needs_auth=True)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ["AccessDeniedException", "UnauthorizedAccess"]:
                return self._error(f"AWS access denied: {e}", needs_auth=True)
            return self._error(f"AWS API Gateway error: {e}")
        except Exception as e:
            return self._error(f"Failed to connect: {e}")

    def fetch_config(self) -> ConnectorResult:
        """Fetch all API configuration from AWS API Gateway.

        Returns:
            ConnectorResult with API Gateway configuration
        """
        if not self._connected:
            return self._error("Not connected to AWS API Gateway")

        try:
            # Fetch REST APIs
            rest_apis = self._fetch_rest_apis()

            # Fetch HTTP APIs (API Gateway v2)
            http_apis = self._fetch_http_apis()

            self._apis = rest_apis + http_apis

            # Extract endpoints
            endpoints = []
            for api in self._apis:
                for endpoint in api.get("endpoints", []):
                    endpoints.append(endpoint)

            # Extract auth config
            auth_config = self._extract_auth_config()

            # Build summary
            data = {
                "rest_api_count": len(rest_apis),
                "http_api_count": len(http_apis),
                "total_endpoints": len(endpoints),
                "apis": [
                    {
                        "name": api.get("name"),
                        "id": api.get("id"),
                        "type": api.get("type"),
                        "endpoint": api.get("endpoint"),
                    }
                    for api in self._apis
                ],
            }

            return self._success(
                data=data,
                source=f"aws_api_gateway://{self._region}",
                endpoints=endpoints,
                auth_config=auth_config,
            )

        except Exception as e:
            return self._error(f"Failed to fetch API Gateway config: {e}")

    def _fetch_rest_apis(self) -> List[Dict]:
        """Fetch REST APIs and their resources."""
        apis = []

        try:
            paginator = self._client.get_paginator("get_rest_apis")
            for page in paginator.paginate():
                for api in page.get("items", []):
                    api_info = {
                        "id": api["id"],
                        "name": api.get("name"),
                        "type": "REST",
                        "description": api.get("description"),
                        "created_date": str(api.get("createdDate", "")),
                        "endpoints": [],
                        "authorizers": [],
                    }

                    # Fetch resources
                    try:
                        resources = self._client.get_resources(
                            restApiId=api["id"],
                            limit=500
                        )

                        for resource in resources.get("items", []):
                            path = resource.get("path", "/")
                            methods = resource.get("resourceMethods", {})

                            for method in methods.keys():
                                if method != "OPTIONS":
                                    api_info["endpoints"].append({
                                        "method": method,
                                        "path": path,
                                        "api_name": api.get("name"),
                                        "api_id": api["id"],
                                    })

                    except Exception:
                        pass

                    # Fetch authorizers
                    try:
                        authorizers = self._client.get_authorizers(
                            restApiId=api["id"]
                        )
                        api_info["authorizers"] = [
                            {
                                "name": auth.get("name"),
                                "type": auth.get("type"),
                                "provider_arns": auth.get("providerARNs", []),
                            }
                            for auth in authorizers.get("items", [])
                        ]
                    except Exception:
                        pass

                    # Get invoke URL
                    try:
                        stages = self._client.get_stages(restApiId=api["id"])
                        if stages.get("item"):
                            stage = stages["item"][0]
                            api_info["endpoint"] = (
                                f"https://{api['id']}.execute-api.{self._region}"
                                f".amazonaws.com/{stage['stageName']}"
                            )
                    except Exception:
                        pass

                    apis.append(api_info)

        except Exception:
            pass

        return apis

    def _fetch_http_apis(self) -> List[Dict]:
        """Fetch HTTP APIs (API Gateway v2)."""
        apis = []

        try:
            response = self._clientv2.get_apis()

            for api in response.get("Items", []):
                api_info = {
                    "id": api["ApiId"],
                    "name": api.get("Name"),
                    "type": "HTTP",
                    "protocol": api.get("ProtocolType"),
                    "endpoint": api.get("ApiEndpoint"),
                    "endpoints": [],
                    "authorizers": [],
                }

                # Fetch routes
                try:
                    routes = self._clientv2.get_routes(ApiId=api["ApiId"])

                    for route in routes.get("Items", []):
                        route_key = route.get("RouteKey", "")
                        # Route key format: "METHOD /path" or "$default"
                        if " " in route_key:
                            method, path = route_key.split(" ", 1)
                            api_info["endpoints"].append({
                                "method": method,
                                "path": path,
                                "api_name": api.get("Name"),
                                "api_id": api["ApiId"],
                            })

                except Exception:
                    pass

                # Fetch authorizers
                try:
                    authorizers = self._clientv2.get_authorizers(ApiId=api["ApiId"])
                    api_info["authorizers"] = [
                        {
                            "name": auth.get("Name"),
                            "type": auth.get("AuthorizerType"),
                            "identity_source": auth.get("IdentitySource", []),
                        }
                        for auth in authorizers.get("Items", [])
                    ]
                except Exception:
                    pass

                apis.append(api_info)

        except Exception:
            pass

        return apis

    def _extract_auth_config(self) -> Optional[Dict[str, Any]]:
        """Extract authentication configuration from APIs."""
        for api in self._apis:
            authorizers = api.get("authorizers", [])
            for auth in authorizers:
                auth_type = auth.get("type", "").upper()

                if auth_type == "COGNITO_USER_POOLS":
                    return {
                        "type": "cognito",
                        "user_pools": auth.get("provider_arns", []),
                    }
                elif auth_type == "JWT":
                    return {
                        "type": "jwt",
                        "identity_source": auth.get("identity_source", []),
                    }
                elif auth_type == "REQUEST":
                    return {
                        "type": "lambda_authorizer",
                        "name": auth.get("name"),
                    }
                elif auth_type == "TOKEN":
                    return {
                        "type": "token_authorizer",
                        "name": auth.get("name"),
                    }

        return None

    def export_openapi(self, api_id: str, stage: str = "prod") -> Optional[str]:
        """Export OpenAPI specification for an API.

        Args:
            api_id: API Gateway API ID
            stage: Stage name

        Returns:
            OpenAPI spec as JSON string, or None if failed
        """
        if not self._connected:
            return None

        try:
            response = self._client.get_export(
                restApiId=api_id,
                stageName=stage,
                exportType="oas30",
                accepts="application/json"
            )
            return response["body"].read().decode("utf-8")

        except Exception:
            return None


def fetch_aws_api_gateway_config(
    region: str = "us-east-1",
    access_key_id: Optional[str] = None,
    secret_access_key: Optional[str] = None,
    profile_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch configuration from AWS API Gateway.

    Args:
        region: AWS region
        access_key_id: AWS access key ID (optional)
        secret_access_key: AWS secret access key (optional)
        profile_name: AWS profile name (optional)

    Returns:
        Dict with API Gateway configuration
    """
    connector = AWSAPIGatewayConnector()
    connect_result = connector.connect(
        region=region,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        profile_name=profile_name,
    )

    if not connect_result.success:
        return connect_result.to_dict()

    result = connector.fetch_config()
    return result.to_dict()
