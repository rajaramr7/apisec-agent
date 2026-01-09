"""
Parse API gateway logs from various providers.
These logs are goldmines — they show real traffic patterns, auth headers,
endpoints actually in use, and response codes.
"""

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


def detect_gateway_log_format(path: str) -> str:
    """
    Detect which gateway format a log file uses.

    Returns: 'kong' | 'aws_api_gateway' | 'apigee' | 'nginx' | 'envoy' | 'unknown'
    """
    file_path = Path(path)
    if not file_path.exists():
        return "unknown"

    # Read first few lines to detect format
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            sample_lines = []
            for i, line in enumerate(f):
                if i >= 10:
                    break
                line = line.strip()
                if line:
                    sample_lines.append(line)

        if not sample_lines:
            return "unknown"

        # Try to parse as JSON
        for line in sample_lines:
            try:
                data = json.loads(line)

                # Kong format detection
                if "authenticated_entity" in data or "latencies" in data and "kong" in str(data.get("latencies", {})):
                    return "kong"

                # AWS API Gateway format detection
                if "requestId" in data and "resourcePath" in data:
                    return "aws_api_gateway"

                # Apigee format detection
                if "apiproxy" in data or "organization" in data:
                    return "apigee"

                # Envoy format detection
                if "upstream_cluster" in data or "x-envoy" in str(data):
                    return "envoy"

                # Generic JSON with request info (could be nginx JSON)
                if "request" in data or "remote_addr" in data:
                    return "nginx"

            except json.JSONDecodeError:
                pass

        # Check for nginx combined log format (non-JSON)
        nginx_pattern = r'^\d+\.\d+\.\d+\.\d+ - .+ \[.+\] ".+" \d+ \d+'
        for line in sample_lines:
            if re.match(nginx_pattern, line):
                return "nginx"

        return "unknown"

    except Exception:
        return "unknown"


def parse_kong_logs(path: str) -> Dict[str, Any]:
    """
    Parse Kong API Gateway access logs.

    Kong log format (JSON):
    {
        "request": {
            "uri": "/orders/1001",
            "method": "GET",
            "headers": {"authorization": "Bearer xxx", ...}
        },
        "response": {"status": 200},
        "authenticated_entity": {"consumer_id": "user_a"},
        "latencies": {"request": 45},
        "started_at": 1234567890
    }

    Returns:
        {
            "endpoints": [{"method": "GET", "path": "/orders/{id}", ...}],
            "users": ["user_a", "user_b"],
            "auth_patterns": {"type": "bearer", "header": "authorization"},
            "resource_access": {"user_a": ["/orders/1001", "/orders/1002"]}
        }
    """
    endpoints = defaultdict(lambda: {"methods": set(), "status_codes": set(), "count": 0})
    users = set()
    resource_access = defaultdict(list)
    auth_patterns = {}
    request_samples = defaultdict(list)

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Kong log file not found: {path}")

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)

                # Extract request info
                request = entry.get("request", {})
                uri = request.get("uri", "")
                method = request.get("method", "GET")
                headers = request.get("headers", {})
                body = request.get("body")

                # Extract response info
                response = entry.get("response", {})
                status = response.get("status", 0)

                # Extract user info
                auth_entity = entry.get("authenticated_entity", {})
                user_id = auth_entity.get("consumer_id")

                if user_id:
                    users.add(user_id)
                    resource_access[user_id].append(uri)

                # Normalize path (replace IDs with placeholders)
                normalized_path = _normalize_path(uri)

                # Track endpoint
                endpoints[normalized_path]["methods"].add(method)
                endpoints[normalized_path]["status_codes"].add(status)
                endpoints[normalized_path]["count"] += 1

                # Track auth patterns
                if "authorization" in headers:
                    auth_header = headers["authorization"]
                    if auth_header.lower().startswith("bearer"):
                        auth_patterns = {"type": "bearer", "header": "authorization"}
                    elif auth_header.lower().startswith("basic"):
                        auth_patterns = {"type": "basic", "header": "authorization"}

                # Store request samples (limit to 3 per endpoint)
                if body and len(request_samples[f"{method} {normalized_path}"]) < 3:
                    request_samples[f"{method} {normalized_path}"].append(body)

            except json.JSONDecodeError:
                continue

    # Convert to output format
    endpoint_list = []
    for path, data in endpoints.items():
        for method in data["methods"]:
            endpoint_list.append({
                "method": method,
                "path": path,
                "status_codes": list(data["status_codes"]),
                "request_count": data["count"]
            })

    # Deduplicate resource access
    for user in resource_access:
        resource_access[user] = list(set(resource_access[user]))

    return {
        "endpoints": endpoint_list,
        "users": list(users),
        "auth_patterns": auth_patterns,
        "resource_access": dict(resource_access),
        "request_samples": dict(request_samples)
    }


def parse_aws_api_gateway_logs(path: str) -> Dict[str, Any]:
    """
    Parse AWS API Gateway access logs.

    AWS API Gateway log format (JSON):
    {
        "requestId": "xxx",
        "ip": "1.2.3.4",
        "caller": "user_a",
        "user": "user_a",
        "requestTime": "2024-01-15T10:23:45Z",
        "httpMethod": "GET",
        "resourcePath": "/orders/{id}",
        "path": "/orders/1001",
        "status": 200,
        "responseLength": 256
    }

    Returns: same structure as kong parser
    """
    endpoints = defaultdict(lambda: {"methods": set(), "status_codes": set(), "count": 0})
    users = set()
    resource_access = defaultdict(list)
    auth_patterns = {}

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"AWS API Gateway log file not found: {path}")

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)

                method = entry.get("httpMethod", "GET")
                resource_path = entry.get("resourcePath", "")
                actual_path = entry.get("path", "")
                status = entry.get("status", 0)
                user_id = entry.get("user") or entry.get("caller")

                if user_id and user_id != "-":
                    users.add(user_id)
                    if actual_path:
                        resource_access[user_id].append(actual_path)

                # Use resourcePath if available (already has placeholders)
                path_key = resource_path if resource_path else _normalize_path(actual_path)

                endpoints[path_key]["methods"].add(method)
                endpoints[path_key]["status_codes"].add(status)
                endpoints[path_key]["count"] += 1

            except json.JSONDecodeError:
                continue

    # Convert to output format
    endpoint_list = []
    for path, data in endpoints.items():
        for method in data["methods"]:
            endpoint_list.append({
                "method": method,
                "path": path,
                "status_codes": list(data["status_codes"]),
                "request_count": data["count"]
            })

    for user in resource_access:
        resource_access[user] = list(set(resource_access[user]))

    return {
        "endpoints": endpoint_list,
        "users": list(users),
        "auth_patterns": auth_patterns,
        "resource_access": dict(resource_access),
        "request_samples": {}
    }


def parse_apigee_logs(path: str) -> Dict[str, Any]:
    """
    Parse Apigee API Gateway logs.

    Returns: same structure as kong parser
    """
    endpoints = defaultdict(lambda: {"methods": set(), "status_codes": set(), "count": 0})
    users = set()
    resource_access = defaultdict(list)

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Apigee log file not found: {path}")

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)

                method = entry.get("verb", entry.get("request_verb", "GET"))
                path = entry.get("request_uri", entry.get("proxy_pathsuffix", ""))
                status = entry.get("response_status_code", entry.get("status", 0))
                user_id = entry.get("developer_email") or entry.get("client_id")

                if user_id:
                    users.add(user_id)
                    resource_access[user_id].append(path)

                normalized_path = _normalize_path(path)
                endpoints[normalized_path]["methods"].add(method)
                endpoints[normalized_path]["status_codes"].add(status)
                endpoints[normalized_path]["count"] += 1

            except json.JSONDecodeError:
                continue

    endpoint_list = []
    for path, data in endpoints.items():
        for method in data["methods"]:
            endpoint_list.append({
                "method": method,
                "path": path,
                "status_codes": list(data["status_codes"]),
                "request_count": data["count"]
            })

    for user in resource_access:
        resource_access[user] = list(set(resource_access[user]))

    return {
        "endpoints": endpoint_list,
        "users": list(users),
        "auth_patterns": {},
        "resource_access": dict(resource_access),
        "request_samples": {}
    }


def parse_nginx_access_logs(path: str) -> Dict[str, Any]:
    """
    Parse nginx access logs (common in front of APIs).

    Common nginx log format:
    1.2.3.4 - user_a [15/Jan/2024:10:23:45 +0000] "GET /orders/1001 HTTP/1.1" 200 256 "-" "curl/7.64.1"

    JSON format (if configured):
    {"remote_addr": "1.2.3.4", "remote_user": "user_a", "request": "GET /orders/1001", ...}

    Returns: same structure as kong parser
    """
    endpoints = defaultdict(lambda: {"methods": set(), "status_codes": set(), "count": 0})
    users = set()
    resource_access = defaultdict(list)

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"nginx log file not found: {path}")

    # Combined log format regex
    combined_pattern = re.compile(
        r'^(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] '
        r'"(?P<method>\w+) (?P<path>\S+) [^"]*" (?P<status>\d+) (?P<size>\d+)'
    )

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Try JSON format first
            try:
                entry = json.loads(line)

                request = entry.get("request", "")
                if isinstance(request, str) and " " in request:
                    parts = request.split()
                    method = parts[0] if parts else "GET"
                    path = parts[1] if len(parts) > 1 else ""
                else:
                    method = entry.get("method", "GET")
                    path = entry.get("uri", entry.get("path", ""))

                status = int(entry.get("status", 0))
                user_id = entry.get("remote_user", "-")

                if user_id and user_id != "-":
                    users.add(user_id)
                    resource_access[user_id].append(path)

                normalized_path = _normalize_path(path)
                endpoints[normalized_path]["methods"].add(method)
                endpoints[normalized_path]["status_codes"].add(status)
                endpoints[normalized_path]["count"] += 1
                continue

            except json.JSONDecodeError:
                pass

            # Try combined log format
            match = combined_pattern.match(line)
            if match:
                method = match.group("method")
                path = match.group("path")
                status = int(match.group("status"))
                user_id = match.group("user")

                if user_id and user_id != "-":
                    users.add(user_id)
                    resource_access[user_id].append(path)

                normalized_path = _normalize_path(path)
                endpoints[normalized_path]["methods"].add(method)
                endpoints[normalized_path]["status_codes"].add(status)
                endpoints[normalized_path]["count"] += 1

    endpoint_list = []
    for path, data in endpoints.items():
        for method in data["methods"]:
            endpoint_list.append({
                "method": method,
                "path": path,
                "status_codes": list(data["status_codes"]),
                "request_count": data["count"]
            })

    for user in resource_access:
        resource_access[user] = list(set(resource_access[user]))

    return {
        "endpoints": endpoint_list,
        "users": list(users),
        "auth_patterns": {},
        "resource_access": dict(resource_access),
        "request_samples": {}
    }


def parse_envoy_logs(path: str) -> Dict[str, Any]:
    """
    Parse Envoy proxy access logs (common in Kubernetes/service mesh).

    Returns: same structure as kong parser
    """
    endpoints = defaultdict(lambda: {"methods": set(), "status_codes": set(), "count": 0})
    users = set()
    resource_access = defaultdict(list)

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Envoy log file not found: {path}")

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)

                method = entry.get("method", entry.get("request_method", "GET"))
                path = entry.get("path", entry.get("request_path", ""))
                status = int(entry.get("response_code", entry.get("status", 0)))

                # Envoy might have user info in various places
                user_id = entry.get("user") or entry.get("x-user-id") or entry.get("downstream_remote_address")

                if user_id and not user_id.startswith("10.") and ":" not in user_id:
                    users.add(user_id)
                    resource_access[user_id].append(path)

                normalized_path = _normalize_path(path)
                endpoints[normalized_path]["methods"].add(method)
                endpoints[normalized_path]["status_codes"].add(status)
                endpoints[normalized_path]["count"] += 1

            except json.JSONDecodeError:
                continue

    endpoint_list = []
    for path, data in endpoints.items():
        for method in data["methods"]:
            endpoint_list.append({
                "method": method,
                "path": path,
                "status_codes": list(data["status_codes"]),
                "request_count": data["count"]
            })

    for user in resource_access:
        resource_access[user] = list(set(resource_access[user]))

    return {
        "endpoints": endpoint_list,
        "users": list(users),
        "auth_patterns": {},
        "resource_access": dict(resource_access),
        "request_samples": {}
    }


def _normalize_path(path: str) -> str:
    """
    Normalize a path by replacing IDs with placeholders.

    /orders/1001 -> /orders/{id}
    /users/abc-123/orders/456 -> /users/{id}/orders/{id}
    """
    if not path:
        return path

    # Remove query string
    path = path.split("?")[0]

    parts = path.split("/")
    normalized = []

    for part in parts:
        if not part:
            normalized.append(part)
            continue

        # Check if part looks like an ID
        is_id = (
            part.isdigit() or  # Numeric ID
            re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', part.lower()) or  # UUID
            re.match(r'^[0-9a-f]{24}$', part.lower()) or  # MongoDB ObjectId
            (len(part) > 10 and re.match(r'^[a-zA-Z0-9_-]+$', part) and any(c.isdigit() for c in part))  # Mixed ID
        )

        if is_id:
            normalized.append("{id}")
        else:
            normalized.append(part)

    return "/".join(normalized)


def parse_gateway_logs(path: str) -> Dict[str, Any]:
    """
    Main entry point. Detects format and parses accordingly.

    Returns:
        {
            "format": "kong",
            "endpoints": [...],
            "users": [...],
            "auth_patterns": {...},
            "resource_access": {...},
            "request_samples": {...}
        }
    """
    format_type = detect_gateway_log_format(path)

    parsers = {
        "kong": parse_kong_logs,
        "aws_api_gateway": parse_aws_api_gateway_logs,
        "apigee": parse_apigee_logs,
        "nginx": parse_nginx_access_logs,
        "envoy": parse_envoy_logs
    }

    if format_type in parsers:
        try:
            result = parsers[format_type](path)
            return {"format": format_type, **result}
        except Exception as e:
            return {"format": format_type, "error": str(e)}
    else:
        return {"format": "unknown", "error": "Unrecognized log format"}
