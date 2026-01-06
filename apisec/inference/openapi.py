"""OpenAPI specification parser."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


def parse_openapi(path: str) -> Dict[str, Any]:
    """Parse an OpenAPI specification file.

    Extracts endpoints, security schemes, schemas, examples, and server URLs.

    Args:
        path: Path to the OpenAPI specification file (YAML or JSON)

    Returns:
        Dictionary with parsed API information:
        {
            "info": {...},
            "servers": [...],
            "endpoints": [...],
            "security_schemes": {...},
            "schemas": {...}
        }
    """
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(f"OpenAPI spec not found: {path}")

    # Load the spec
    content = file_path.read_text(encoding="utf-8")

    if file_path.suffix in [".yaml", ".yml"]:
        spec = yaml.safe_load(content)
    else:
        spec = json.loads(content)

    if not spec:
        raise ValueError(f"Empty or invalid OpenAPI spec: {path}")

    return {
        "info": _extract_info(spec),
        "servers": _extract_servers(spec),
        "endpoints": _extract_endpoints(spec),
        "security_schemes": _extract_security_schemes(spec),
        "schemas": _extract_schemas(spec),
    }


def _extract_info(spec: Dict) -> Dict[str, Any]:
    """Extract API info from the spec."""
    info = spec.get("info", {})
    return {
        "title": info.get("title", "Unknown API"),
        "description": info.get("description"),
        "version": info.get("version", "1.0.0"),
    }


def _extract_servers(spec: Dict) -> List[Dict[str, Any]]:
    """Extract server URLs from the spec."""
    servers = spec.get("servers", [])
    return [
        {
            "url": server.get("url", ""),
            "description": server.get("description"),
        }
        for server in servers
    ]


def _extract_endpoints(spec: Dict) -> List[Dict[str, Any]]:
    """Extract all endpoints from the spec."""
    endpoints = []
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        # Handle path-level parameters
        path_params = path_item.get("parameters", [])

        for method in ["get", "post", "put", "patch", "delete", "head", "options"]:
            if method not in path_item:
                continue

            operation = path_item[method]
            endpoint = _parse_operation(path, method, operation, path_params)
            endpoints.append(endpoint)

    return endpoints


def _parse_operation(
    path: str,
    method: str,
    operation: Dict,
    path_params: List[Dict],
) -> Dict[str, Any]:
    """Parse a single operation into an endpoint definition."""
    # Combine path-level and operation-level parameters
    all_params = path_params + operation.get("parameters", [])

    # Extract parameters by location
    parameters = {
        "path": [],
        "query": [],
        "header": [],
    }

    for param in all_params:
        param_in = param.get("in", "query")
        if param_in in parameters:
            parameters[param_in].append({
                "name": param.get("name"),
                "required": param.get("required", False),
                "schema": param.get("schema", {}),
                "description": param.get("description"),
            })

    # Extract request body
    request_body = None
    if "requestBody" in operation:
        rb = operation["requestBody"]
        content = rb.get("content", {})

        # Prefer JSON content
        for content_type in ["application/json", "application/x-www-form-urlencoded"]:
            if content_type in content:
                media = content[content_type]
                request_body = {
                    "content_type": content_type,
                    "required": rb.get("required", False),
                    "schema": media.get("schema", {}),
                    "example": media.get("example"),
                }
                break

    # Extract responses
    responses = []
    for status_code, response in operation.get("responses", {}).items():
        resp = {
            "status": status_code,
            "description": response.get("description"),
        }

        # Extract response schema
        content = response.get("content", {})
        if "application/json" in content:
            media = content["application/json"]
            resp["schema"] = media.get("schema", {})
            resp["example"] = media.get("example")

        responses.append(resp)

    # Check if auth is required
    security = operation.get("security", [])
    auth_required = len(security) > 0 if security is not None else True

    return {
        "path": path,
        "method": method.upper(),
        "operation_id": operation.get("operationId"),
        "summary": operation.get("summary"),
        "description": operation.get("description"),
        "tags": operation.get("tags", []),
        "parameters": parameters,
        "request_body": request_body,
        "responses": responses,
        "auth_required": auth_required,
        "security": security,
    }


def _extract_security_schemes(spec: Dict) -> Dict[str, Any]:
    """Extract security schemes from the spec."""
    components = spec.get("components", {})
    schemes = components.get("securitySchemes", {})

    result = {}
    for name, scheme in schemes.items():
        scheme_type = scheme.get("type")

        parsed = {
            "type": scheme_type,
            "description": scheme.get("description"),
        }

        if scheme_type == "http":
            parsed["scheme"] = scheme.get("scheme")  # bearer, basic
            parsed["bearer_format"] = scheme.get("bearerFormat")

        elif scheme_type == "apiKey":
            parsed["in"] = scheme.get("in")  # header, query, cookie
            parsed["name"] = scheme.get("name")  # header/param name

        elif scheme_type == "oauth2":
            flows = scheme.get("flows", {})
            parsed["flows"] = {}

            for flow_type, flow in flows.items():
                parsed["flows"][flow_type] = {
                    "token_url": flow.get("tokenUrl"),
                    "authorization_url": flow.get("authorizationUrl"),
                    "refresh_url": flow.get("refreshUrl"),
                    "scopes": flow.get("scopes", {}),
                }

        elif scheme_type == "openIdConnect":
            parsed["openid_connect_url"] = scheme.get("openIdConnectUrl")

        result[name] = parsed

    return result


def _extract_schemas(spec: Dict) -> Dict[str, Any]:
    """Extract component schemas from the spec."""
    components = spec.get("components", {})
    schemas = components.get("schemas", {})

    result = {}
    for name, schema in schemas.items():
        result[name] = _simplify_schema(schema)

    return result


def _simplify_schema(schema: Dict) -> Dict[str, Any]:
    """Simplify a JSON schema for easier consumption."""
    if not schema:
        return {}

    simplified = {
        "type": schema.get("type"),
    }

    if "properties" in schema:
        simplified["properties"] = {}
        for prop_name, prop_schema in schema["properties"].items():
            simplified["properties"][prop_name] = {
                "type": prop_schema.get("type"),
                "description": prop_schema.get("description"),
                "format": prop_schema.get("format"),
                "enum": prop_schema.get("enum"),
            }

    if "required" in schema:
        simplified["required"] = schema["required"]

    if "items" in schema:
        simplified["items"] = _simplify_schema(schema["items"])

    if "$ref" in schema:
        simplified["$ref"] = schema["$ref"]

    return simplified


class OpenAPIParser:
    """Parser for OpenAPI/Swagger specifications.

    Extracts API information including endpoints, authentication
    schemes, request/response schemas, and examples.
    """

    def __init__(self, spec_path: Optional[str] = None):
        """Initialize the OpenAPI parser.

        Args:
            spec_path: Path to the OpenAPI specification file
        """
        self.spec_path = Path(spec_path) if spec_path else None
        self.parsed = None

    def load(self, spec_path: str) -> None:
        """Load an OpenAPI specification.

        Args:
            spec_path: Path to the specification file
        """
        self.spec_path = Path(spec_path)
        self.parsed = parse_openapi(spec_path)

    def parse(self) -> Dict[str, Any]:
        """Parse the loaded specification.

        Returns:
            Parsed API information
        """
        if self.parsed is None and self.spec_path:
            self.parsed = parse_openapi(str(self.spec_path))
        return self.parsed

    def get_endpoints(self) -> List[Dict[str, Any]]:
        """Extract all API endpoints."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("endpoints", [])

    def get_auth_schemes(self) -> Dict[str, Any]:
        """Extract authentication schemes."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("security_schemes", {})

    def get_schemas(self) -> Dict[str, Any]:
        """Extract request/response schemas."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("schemas", {})

    def get_base_url(self) -> Optional[str]:
        """Extract the base URL from servers."""
        if self.parsed is None:
            self.parse()
        servers = self.parsed.get("servers", [])
        if servers:
            return servers[0].get("url")
        return None

    def get_api_info(self) -> Dict[str, Any]:
        """Get basic API information."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("info", {})
