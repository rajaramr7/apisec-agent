"""Log file analyzer."""

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


def parse_logs(path: str) -> Dict[str, Any]:
    """Parse a JSON-lines log file and extract API information.

    Extracts unique endpoints, user IDs, request patterns, auth patterns,
    and success/error rates.

    Args:
        path: Path to the JSON-lines log file

    Returns:
        Dictionary with analyzed log information:
        {
            "endpoints": [...],
            "users": [...],
            "auth_patterns": {...},
            "request_patterns": {...},
            "statistics": {...},
            "entry_count": int
        }
    """
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    entries = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                entries.append(entry)
            except json.JSONDecodeError:
                # Skip malformed lines
                continue

    if not entries:
        return {
            "endpoints": [],
            "users": [],
            "auth_patterns": {},
            "request_patterns": {},
            "statistics": {},
            "entry_count": 0,
        }

    return {
        "endpoints": _extract_endpoints(entries),
        "users": _extract_users(entries),
        "auth_patterns": _analyze_auth_patterns(entries),
        "request_patterns": _analyze_request_patterns(entries),
        "statistics": _calculate_statistics(entries),
        "entry_count": len(entries),
    }


def _extract_endpoints(entries: List[Dict]) -> List[Dict[str, Any]]:
    """Extract unique endpoints from log entries."""
    endpoint_data = defaultdict(lambda: {
        "methods": set(),
        "status_codes": defaultdict(int),
        "count": 0,
    })

    for entry in entries:
        path = entry.get("path", "")
        method = entry.get("method", "")
        status = entry.get("status", 0)

        if path and method:
            # Normalize path (replace numeric IDs with placeholders)
            normalized_path = _normalize_path(path)
            key = normalized_path

            endpoint_data[key]["methods"].add(method)
            endpoint_data[key]["status_codes"][status] += 1
            endpoint_data[key]["count"] += 1

    # Convert to list format
    endpoints = []
    for path, data in endpoint_data.items():
        endpoints.append({
            "path": path,
            "methods": sorted(list(data["methods"])),
            "status_codes": dict(data["status_codes"]),
            "request_count": data["count"],
        })

    # Sort by request count (most called first)
    endpoints.sort(key=lambda x: x["request_count"], reverse=True)

    return endpoints


def _normalize_path(path: str) -> str:
    """Normalize a path by replacing numeric IDs with placeholders."""
    parts = path.split("/")
    normalized = []

    for part in parts:
        # Replace numeric segments with {id}
        if part.isdigit():
            normalized.append("{id}")
        # Replace UUID-like segments
        elif len(part) == 36 and part.count("-") == 4:
            normalized.append("{id}")
        else:
            normalized.append(part)

    return "/".join(normalized)


def _extract_users(entries: List[Dict]) -> List[str]:
    """Extract unique user IDs from log entries."""
    users = set()

    for entry in entries:
        user_id = entry.get("user_id")
        if user_id:
            users.add(user_id)

    return sorted(list(users))


def _analyze_auth_patterns(entries: List[Dict]) -> Dict[str, Any]:
    """Analyze authentication patterns from log entries."""
    auth_types = defaultdict(int)
    has_auth = 0
    no_auth = 0

    for entry in entries:
        headers = entry.get("request_headers", {})
        auth_header = headers.get("Authorization", "")

        if auth_header:
            has_auth += 1

            # Detect auth type
            if auth_header.startswith("Bearer "):
                auth_types["bearer"] += 1
            elif auth_header.startswith("Basic "):
                auth_types["basic"] += 1
            elif "token" in auth_header.lower():
                auth_types["token"] += 1
            else:
                auth_types["other"] += 1
        else:
            # Check for API key in headers
            api_key_headers = ["X-API-Key", "x-api-key", "api-key", "apikey"]
            if any(h in headers for h in api_key_headers):
                has_auth += 1
                auth_types["api_key"] += 1
            else:
                no_auth += 1

    return {
        "types": dict(auth_types),
        "authenticated_requests": has_auth,
        "unauthenticated_requests": no_auth,
        "primary_type": max(auth_types.keys(), key=lambda k: auth_types[k]) if auth_types else None,
    }


def _analyze_request_patterns(entries: List[Dict]) -> Dict[str, Any]:
    """Analyze request body patterns for each endpoint."""
    patterns = defaultdict(lambda: {
        "bodies": [],
        "fields": defaultdict(int),
    })

    for entry in entries:
        path = entry.get("path", "")
        method = entry.get("method", "")
        body = entry.get("request_body")

        if not path or not method:
            continue

        normalized_path = _normalize_path(path)
        key = f"{method} {normalized_path}"

        if body and isinstance(body, dict):
            # Store sample bodies (limit to 3)
            if len(patterns[key]["bodies"]) < 3:
                patterns[key]["bodies"].append(body)

            # Count field occurrences
            for field in body.keys():
                patterns[key]["fields"][field] += 1

    # Convert to serializable format
    result = {}
    for key, data in patterns.items():
        result[key] = {
            "sample_bodies": data["bodies"],
            "common_fields": dict(data["fields"]),
        }

    return result


def _calculate_statistics(entries: List[Dict]) -> Dict[str, Any]:
    """Calculate statistics from log entries."""
    method_counts = defaultdict(int)
    status_counts = defaultdict(int)
    response_times = []

    for entry in entries:
        method = entry.get("method", "")
        status = entry.get("status", 0)
        response_time = entry.get("response_time_ms")

        if method:
            method_counts[method] += 1
        if status:
            status_counts[status] += 1
        if response_time is not None:
            response_times.append(response_time)

    # Calculate success/error rates
    total = len(entries)
    success = sum(count for status, count in status_counts.items() if 200 <= status < 300)
    client_errors = sum(count for status, count in status_counts.items() if 400 <= status < 500)
    server_errors = sum(count for status, count in status_counts.items() if 500 <= status < 600)

    # Calculate response time stats
    avg_response_time = None
    if response_times:
        avg_response_time = sum(response_times) / len(response_times)

    return {
        "total_requests": total,
        "methods": dict(method_counts),
        "status_codes": dict(status_counts),
        "success_rate": round(success / total * 100, 2) if total > 0 else 0,
        "client_error_rate": round(client_errors / total * 100, 2) if total > 0 else 0,
        "server_error_rate": round(server_errors / total * 100, 2) if total > 0 else 0,
        "avg_response_time_ms": round(avg_response_time, 2) if avg_response_time else None,
    }


class LogAnalyzer:
    """Analyzer for API access logs.

    Extracts API information from access logs including endpoints,
    authentication patterns, request/response examples, and usage statistics.
    """

    def __init__(self, log_path: Optional[str] = None):
        """Initialize the log analyzer.

        Args:
            log_path: Path to the log file
        """
        self.log_path = Path(log_path) if log_path else None
        self.parsed = None

    def load(self, log_path: str) -> None:
        """Load a log file.

        Args:
            log_path: Path to the log file
        """
        self.log_path = Path(log_path)
        self.parsed = parse_logs(log_path)

    def parse(self) -> Dict[str, Any]:
        """Parse the loaded logs.

        Returns:
            Parsed log analysis
        """
        if self.parsed is None and self.log_path:
            self.parsed = parse_logs(str(self.log_path))
        return self.parsed

    def get_endpoints(self) -> List[Dict[str, Any]]:
        """Extract unique endpoints from logs."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("endpoints", [])

    def get_users(self) -> List[str]:
        """Extract unique users from logs."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("users", [])

    def get_auth_patterns(self) -> Dict[str, Any]:
        """Analyze authentication patterns."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("auth_patterns", {})

    def get_request_examples(self, endpoint: str, method: str) -> List[Dict]:
        """Get example requests for an endpoint.

        Args:
            endpoint: API endpoint path
            method: HTTP method

        Returns:
            List of request examples
        """
        if self.parsed is None:
            self.parse()

        key = f"{method} {endpoint}"
        patterns = self.parsed.get("request_patterns", {})

        if key in patterns:
            return patterns[key].get("sample_bodies", [])

        return []

    def get_statistics(self) -> Dict[str, Any]:
        """Get usage statistics."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("statistics", {})

    def get_entry_count(self) -> int:
        """Get the number of log entries parsed."""
        if self.parsed is None:
            self.parse()
        return self.parsed.get("entry_count", 0)
