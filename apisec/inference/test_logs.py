"""
Parse QA/test framework output logs.
These reveal: tested endpoints, sample payloads, expected responses, and auth flows.
"""

import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional


def detect_test_log_format(path: str) -> str:
    """
    Detect which test framework produced the log.

    Returns: 'pytest' | 'jest' | 'newman' | 'karate' | 'rest_assured' | 'unknown'
    """
    file_path = Path(path)
    if not file_path.exists():
        return "unknown"

    filename = file_path.name.lower()

    # Filename-based detection
    if "newman" in filename or filename.endswith(".newman.json"):
        return "newman"
    if "karate" in filename:
        return "karate"
    if filename.startswith("pytest") or filename.endswith("pytest.json"):
        return "pytest"
    if filename.startswith("jest") or filename.endswith("jest.json"):
        return "jest"

    # Content-based detection
    try:
        content = file_path.read_text(encoding='utf-8')

        # Try JSON first
        try:
            data = json.loads(content)

            # Newman output detection
            if "run" in data and "executions" in data.get("run", {}):
                return "newman"

            # Jest output detection
            if "testResults" in data or "numPassedTests" in data:
                return "jest"

            # pytest-json output detection
            if "tests" in data and any("nodeid" in t for t in data.get("tests", [])):
                return "pytest"

        except json.JSONDecodeError:
            pass

        # Try XML (JUnit format - used by pytest, REST Assured, etc.)
        try:
            root = ET.fromstring(content)
            if root.tag in ["testsuites", "testsuite"]:
                # Check for REST Assured markers
                if "rest-assured" in content.lower():
                    return "rest_assured"
                # Check for pytest markers
                if "pytest" in content.lower():
                    return "pytest"
                # Check for Karate markers
                if "karate" in content.lower():
                    return "karate"
                # Default to generic JUnit
                return "junit"
        except ET.ParseError:
            pass

        # Plain text detection
        if "PASSED" in content and "FAILED" in content:
            if "pytest" in content.lower() or "::test_" in content:
                return "pytest"
            if "karate" in content.lower():
                return "karate"

    except Exception:
        pass

    return "unknown"


def parse_pytest_output(path: str) -> Dict[str, Any]:
    """
    Parse pytest output (JSON format from pytest-json-report).

    pytest-json-report output:
    {
        "tests": [
            {
                "nodeid": "tests/test_orders.py::test_get_order",
                "outcome": "passed",
                "call": {"duration": 0.5}
            }
        ]
    }

    Returns:
        {
            "tests": [{"name": "test_get_order", "file": "...", "status": "passed"}],
            "endpoints_tested": [{"method": "GET", "path": "/orders/{id}"}],
            "sample_payloads": {...},
            "assertions": [...]
        }
    """
    tests = []
    endpoints_tested = []
    sample_payloads = {}
    assertions = []

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"pytest output not found: {path}")

    content = file_path.read_text(encoding='utf-8')

    # Try JSON format first
    try:
        data = json.loads(content)

        for test in data.get("tests", []):
            nodeid = test.get("nodeid", "")
            outcome = test.get("outcome", "unknown")

            # Parse nodeid: tests/test_orders.py::test_get_order_by_id
            parts = nodeid.split("::")
            file_part = parts[0] if parts else ""
            test_name = parts[-1] if len(parts) > 1 else nodeid

            tests.append({
                "name": test_name,
                "file": file_part,
                "status": outcome,
                "duration": test.get("call", {}).get("duration")
            })

            # Extract endpoint info from test name
            endpoint = _extract_endpoint_from_test_name(test_name)
            if endpoint:
                endpoints_tested.append(endpoint)

            # Extract from captured output if available
            stdout = test.get("call", {}).get("stdout", "")
            if stdout:
                extracted = _extract_requests_from_text(stdout)
                endpoints_tested.extend(extracted.get("endpoints", []))
                sample_payloads.update(extracted.get("payloads", {}))

        # Look for summary data
        if "summary" in data:
            summary = data["summary"]

        return {
            "format": "pytest",
            "tests": tests,
            "endpoints_tested": _dedupe_endpoints(endpoints_tested),
            "sample_payloads": sample_payloads,
            "assertions": assertions,
            "summary": {
                "total": len(tests),
                "passed": len([t for t in tests if t["status"] == "passed"]),
                "failed": len([t for t in tests if t["status"] == "failed"]),
            }
        }

    except json.JSONDecodeError:
        pass

    # Try XML format (JUnit)
    try:
        root = ET.fromstring(content)
        return _parse_junit_xml(root, "pytest")
    except ET.ParseError:
        pass

    # Plain text parsing
    return _parse_pytest_text(content)


def parse_jest_output(path: str) -> Dict[str, Any]:
    """
    Parse Jest test output (JSON format).

    Jest JSON output:
    {
        "numPassedTests": 10,
        "numFailedTests": 2,
        "testResults": [
            {
                "name": "tests/api.test.js",
                "assertionResults": [
                    {"title": "should get order by id", "status": "passed"}
                ]
            }
        ]
    }

    Returns: same structure as pytest parser
    """
    tests = []
    endpoints_tested = []
    sample_payloads = {}

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Jest output not found: {path}")

    content = file_path.read_text(encoding='utf-8')
    data = json.loads(content)

    for result in data.get("testResults", []):
        file_name = result.get("name", "")

        for assertion in result.get("assertionResults", []):
            title = assertion.get("title", "")
            status = assertion.get("status", "unknown")

            tests.append({
                "name": title,
                "file": file_name,
                "status": status,
                "duration": assertion.get("duration")
            })

            # Extract endpoint from test name
            endpoint = _extract_endpoint_from_test_name(title)
            if endpoint:
                endpoints_tested.append(endpoint)

    return {
        "format": "jest",
        "tests": tests,
        "endpoints_tested": _dedupe_endpoints(endpoints_tested),
        "sample_payloads": sample_payloads,
        "assertions": [],
        "summary": {
            "total": data.get("numTotalTests", len(tests)),
            "passed": data.get("numPassedTests", 0),
            "failed": data.get("numFailedTests", 0),
        }
    }


def parse_newman_output(path: str) -> Dict[str, Any]:
    """
    Parse Newman (Postman CLI) test output.

    Newman JSON output includes actual requests made and responses received,
    which is incredibly valuable for understanding API behavior.

    {
        "run": {
            "executions": [
                {
                    "request": {
                        "method": "GET",
                        "url": {"path": ["orders", "1001"]},
                        "header": [...],
                        "body": {...}
                    },
                    "response": {"code": 200, "body": "..."},
                    "assertions": [...]
                }
            ]
        }
    }

    Returns:
        {
            "endpoints_tested": [...],
            "sample_payloads": {...},
            "sample_responses": {...},
            "auth_observed": {...},
            "assertions": [...]
        }
    """
    endpoints_tested = []
    sample_payloads = {}
    sample_responses = {}
    auth_observed = {}
    assertions = []
    tests = []

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Newman output not found: {path}")

    content = file_path.read_text(encoding='utf-8')
    data = json.loads(content)

    run = data.get("run", {})
    executions = run.get("executions", [])

    for execution in executions:
        item = execution.get("item", {})
        request = execution.get("request", {})
        response = execution.get("response", {})

        # Extract request details
        method = request.get("method", "GET")
        url = request.get("url", {})

        # Build path from URL parts
        if isinstance(url, dict):
            path_parts = url.get("path", [])
            path = "/" + "/".join(path_parts) if path_parts else "/"
        else:
            path = str(url)

        # Normalize path
        normalized_path = _normalize_path(path)

        endpoint_key = f"{method} {normalized_path}"
        endpoints_tested.append({
            "method": method,
            "path": normalized_path,
            "actual_path": path
        })

        # Extract request body
        body = request.get("body", {})
        if body:
            raw = body.get("raw")
            if raw:
                try:
                    sample_payloads[endpoint_key] = json.loads(raw)
                except json.JSONDecodeError:
                    sample_payloads[endpoint_key] = raw

        # Extract response
        response_body = response.get("body")
        response_code = response.get("code")
        if response_body:
            try:
                sample_responses[endpoint_key] = {
                    "status": response_code,
                    "body": json.loads(response_body)
                }
            except json.JSONDecodeError:
                sample_responses[endpoint_key] = {
                    "status": response_code,
                    "body": response_body
                }

        # Extract auth from headers
        headers = request.get("header", [])
        for header in headers:
            if isinstance(header, dict):
                key = header.get("key", "").lower()
                value = header.get("value", "")

                if key == "authorization":
                    if value.lower().startswith("bearer"):
                        auth_observed = {"type": "bearer", "header": "Authorization"}
                    elif value.lower().startswith("basic"):
                        auth_observed = {"type": "basic", "header": "Authorization"}
                elif key in ["x-api-key", "api-key", "apikey"]:
                    auth_observed = {"type": "api_key", "header": key}

        # Extract assertions
        for assertion in execution.get("assertions", []):
            assertion_name = assertion.get("assertion", "")
            passed = assertion.get("error") is None

            assertions.append({
                "name": assertion_name,
                "passed": passed,
                "endpoint": endpoint_key
            })

            tests.append({
                "name": f"{item.get('name', '')} - {assertion_name}",
                "status": "passed" if passed else "failed"
            })

    return {
        "format": "newman",
        "tests": tests,
        "endpoints_tested": _dedupe_endpoints(endpoints_tested),
        "sample_payloads": sample_payloads,
        "sample_responses": sample_responses,
        "auth_observed": auth_observed,
        "assertions": assertions,
        "summary": {
            "total": len(tests),
            "passed": len([t for t in tests if t["status"] == "passed"]),
            "failed": len([t for t in tests if t["status"] == "failed"]),
        }
    }


def parse_karate_output(path: str) -> Dict[str, Any]:
    """
    Parse Karate test framework output.

    Karate is powerful for API testing and its output often contains
    full request/response details.

    Returns: same structure as newman parser
    """
    tests = []
    endpoints_tested = []
    sample_payloads = {}
    sample_responses = {}

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Karate output not found: {path}")

    content = file_path.read_text(encoding='utf-8')

    # Try JSON format
    try:
        data = json.loads(content)

        # Karate JSON report format
        features = data.get("features", [data]) if "features" not in data else data.get("features", [])

        for feature in features:
            scenarios = feature.get("scenarios", feature.get("elements", []))

            for scenario in scenarios:
                name = scenario.get("name", "")
                status = "passed" if scenario.get("passed", True) else "failed"

                tests.append({
                    "name": name,
                    "status": status
                })

                # Extract steps for request/response info
                steps = scenario.get("steps", [])
                for step in steps:
                    step_name = step.get("name", "")

                    # Look for request patterns
                    if "url" in step_name.lower() or "path" in step_name.lower():
                        endpoint = _extract_endpoint_from_karate_step(step_name)
                        if endpoint:
                            endpoints_tested.append(endpoint)

                    # Look for request body
                    if "request" in step_name.lower() and "body" in step:
                        body = step.get("body")
                        if body:
                            sample_payloads[name] = body

        return {
            "format": "karate",
            "tests": tests,
            "endpoints_tested": _dedupe_endpoints(endpoints_tested),
            "sample_payloads": sample_payloads,
            "sample_responses": sample_responses,
            "assertions": [],
            "summary": {
                "total": len(tests),
                "passed": len([t for t in tests if t["status"] == "passed"]),
                "failed": len([t for t in tests if t["status"] == "failed"]),
            }
        }

    except json.JSONDecodeError:
        pass

    # Try XML format
    try:
        root = ET.fromstring(content)
        return _parse_junit_xml(root, "karate")
    except ET.ParseError:
        pass

    return {
        "format": "karate",
        "tests": [],
        "endpoints_tested": [],
        "sample_payloads": {},
        "sample_responses": {},
        "assertions": [],
        "summary": {"total": 0, "passed": 0, "failed": 0}
    }


def parse_rest_assured_output(path: str) -> Dict[str, Any]:
    """
    Parse REST Assured (Java) test output.

    Usually comes as JUnit XML format.

    Returns: same structure as other parsers
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"REST Assured output not found: {path}")

    content = file_path.read_text(encoding='utf-8')

    # REST Assured typically uses JUnit XML
    try:
        root = ET.fromstring(content)
        return _parse_junit_xml(root, "rest_assured")
    except ET.ParseError:
        pass

    # Try JSON if available
    try:
        data = json.loads(content)
        return _parse_generic_json_tests(data, "rest_assured")
    except json.JSONDecodeError:
        pass

    return {
        "format": "rest_assured",
        "tests": [],
        "endpoints_tested": [],
        "sample_payloads": {},
        "assertions": [],
        "summary": {"total": 0, "passed": 0, "failed": 0}
    }


def _parse_junit_xml(root: ET.Element, framework: str) -> Dict[str, Any]:
    """Parse JUnit XML format test results."""
    tests = []
    endpoints_tested = []

    # Handle both <testsuites> and <testsuite> root elements
    if root.tag == "testsuites":
        testsuites = root.findall("testsuite")
    else:
        testsuites = [root]

    for testsuite in testsuites:
        suite_name = testsuite.get("name", "")

        for testcase in testsuite.findall("testcase"):
            name = testcase.get("name", "")
            classname = testcase.get("classname", "")

            # Determine status
            failure = testcase.find("failure")
            error = testcase.find("error")
            skipped = testcase.find("skipped")

            if failure is not None or error is not None:
                status = "failed"
            elif skipped is not None:
                status = "skipped"
            else:
                status = "passed"

            tests.append({
                "name": name,
                "class": classname,
                "status": status,
                "duration": testcase.get("time")
            })

            # Extract endpoint from test name
            endpoint = _extract_endpoint_from_test_name(name)
            if endpoint:
                endpoints_tested.append(endpoint)

    return {
        "format": framework,
        "tests": tests,
        "endpoints_tested": _dedupe_endpoints(endpoints_tested),
        "sample_payloads": {},
        "assertions": [],
        "summary": {
            "total": len(tests),
            "passed": len([t for t in tests if t["status"] == "passed"]),
            "failed": len([t for t in tests if t["status"] == "failed"]),
        }
    }


def _parse_pytest_text(content: str) -> Dict[str, Any]:
    """Parse plain text pytest output."""
    tests = []
    endpoints_tested = []

    # Look for test results: tests/test_api.py::test_get_order PASSED
    test_pattern = re.compile(r'([^\s]+)::(\S+)\s+(PASSED|FAILED|SKIPPED|ERROR)')

    for match in test_pattern.finditer(content):
        file_path = match.group(1)
        test_name = match.group(2)
        status = match.group(3).lower()

        tests.append({
            "name": test_name,
            "file": file_path,
            "status": status
        })

        endpoint = _extract_endpoint_from_test_name(test_name)
        if endpoint:
            endpoints_tested.append(endpoint)

    return {
        "format": "pytest",
        "tests": tests,
        "endpoints_tested": _dedupe_endpoints(endpoints_tested),
        "sample_payloads": {},
        "assertions": [],
        "summary": {
            "total": len(tests),
            "passed": len([t for t in tests if t["status"] == "passed"]),
            "failed": len([t for t in tests if t["status"] == "failed"]),
        }
    }


def _parse_generic_json_tests(data: Dict, framework: str) -> Dict[str, Any]:
    """Parse generic JSON test output."""
    tests = []

    # Try common patterns
    if "tests" in data:
        for test in data["tests"]:
            tests.append({
                "name": test.get("name", test.get("title", "")),
                "status": test.get("status", test.get("result", "unknown"))
            })
    elif "results" in data:
        for result in data["results"]:
            tests.append({
                "name": result.get("name", ""),
                "status": result.get("status", "unknown")
            })

    return {
        "format": framework,
        "tests": tests,
        "endpoints_tested": [],
        "sample_payloads": {},
        "assertions": [],
        "summary": {
            "total": len(tests),
            "passed": len([t for t in tests if t.get("status") == "passed"]),
            "failed": len([t for t in tests if t.get("status") == "failed"]),
        }
    }


def _extract_endpoint_from_test_name(test_name: str) -> Optional[Dict[str, str]]:
    """
    Extract endpoint info from test name.

    Examples:
        test_get_order_by_id -> {"method": "GET", "path": "/orders/{id}"}
        test_create_order -> {"method": "POST", "path": "/orders"}
        test_delete_user_profile -> {"method": "DELETE", "path": "/users/{id}/profile"}
    """
    test_name = test_name.lower()

    # Method detection
    method = "GET"
    if any(word in test_name for word in ["create", "post", "add", "new"]):
        method = "POST"
    elif any(word in test_name for word in ["update", "put", "modify", "edit"]):
        method = "PUT"
    elif any(word in test_name for word in ["delete", "remove", "destroy"]):
        method = "DELETE"
    elif any(word in test_name for word in ["patch", "partial"]):
        method = "PATCH"

    # Resource detection
    resources = {
        "order": "/orders",
        "user": "/users",
        "product": "/products",
        "item": "/items",
        "profile": "/profile",
        "account": "/accounts",
        "payment": "/payments",
        "cart": "/cart",
        "auth": "/auth",
        "login": "/auth/login",
        "logout": "/auth/logout",
        "token": "/auth/token",
    }

    path = None
    for resource, resource_path in resources.items():
        if resource in test_name:
            path = resource_path

            # Check for sub-resource
            if "profile" in test_name and resource != "profile":
                path += "/{id}/profile"
            elif any(word in test_name for word in ["by_id", "byid", "single", "one", "detail"]):
                path += "/{id}"

            break

    if path:
        return {"method": method, "path": path}

    return None


def _extract_endpoint_from_karate_step(step_name: str) -> Optional[Dict[str, str]]:
    """Extract endpoint from Karate step name."""
    # Karate steps often look like: "url 'http://localhost:8080/orders/1001'"
    url_match = re.search(r"url\s+['\"]([^'\"]+)['\"]", step_name, re.IGNORECASE)
    if url_match:
        url = url_match.group(1)
        # Extract path from URL
        path_match = re.search(r'https?://[^/]+(/[^\s?#]*)', url)
        if path_match:
            path = _normalize_path(path_match.group(1))
            return {"method": "GET", "path": path}

    # Method + path pattern: "method get" followed by "path '/orders'"
    method_match = re.search(r"method\s+(\w+)", step_name, re.IGNORECASE)
    path_match = re.search(r"path\s+['\"]([^'\"]+)['\"]", step_name, re.IGNORECASE)

    if path_match:
        path = _normalize_path(path_match.group(1))
        method = method_match.group(1).upper() if method_match else "GET"
        return {"method": method, "path": path}

    return None


def _extract_requests_from_text(text: str) -> Dict[str, Any]:
    """Extract request information from text output."""
    endpoints = []
    payloads = {}

    # Look for HTTP request patterns
    request_pattern = re.compile(
        r'(GET|POST|PUT|DELETE|PATCH)\s+(https?://[^\s]+|/[^\s]+)',
        re.IGNORECASE
    )

    for match in request_pattern.finditer(text):
        method = match.group(1).upper()
        url = match.group(2)

        # Extract path
        if url.startswith("http"):
            path_match = re.search(r'https?://[^/]+(/[^\s?#]*)', url)
            path = path_match.group(1) if path_match else "/"
        else:
            path = url.split("?")[0]

        endpoints.append({
            "method": method,
            "path": _normalize_path(path)
        })

    return {"endpoints": endpoints, "payloads": payloads}


def _normalize_path(path: str) -> str:
    """Normalize path by replacing IDs with placeholders."""
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
            part.isdigit() or
            re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', part.lower()) or
            re.match(r'^[0-9a-f]{24}$', part.lower()) or
            (len(part) > 10 and re.match(r'^[a-zA-Z0-9_-]+$', part) and any(c.isdigit() for c in part))
        )

        if is_id:
            normalized.append("{id}")
        else:
            normalized.append(part)

    return "/".join(normalized)


def _dedupe_endpoints(endpoints: List[Dict]) -> List[Dict]:
    """Remove duplicate endpoints."""
    seen = set()
    unique = []

    for ep in endpoints:
        key = f"{ep.get('method', '')} {ep.get('path', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(ep)

    return unique


def parse_test_logs(path: str) -> Dict[str, Any]:
    """
    Main entry point. Detects format and parses accordingly.

    Returns:
        {
            "format": "pytest",
            "tests": [...],
            "endpoints_tested": [...],
            "sample_payloads": {...},
            "assertions": [...],
            "summary": {...}
        }
    """
    format_type = detect_test_log_format(path)

    parsers = {
        "pytest": parse_pytest_output,
        "jest": parse_jest_output,
        "newman": parse_newman_output,
        "karate": parse_karate_output,
        "rest_assured": parse_rest_assured_output,
        "junit": lambda p: _parse_junit_xml(ET.parse(p).getroot(), "junit")
    }

    if format_type in parsers:
        try:
            return parsers[format_type](path)
        except Exception as e:
            return {"format": format_type, "error": str(e)}
    else:
        return {"format": "unknown", "error": "Unrecognized test output format"}
