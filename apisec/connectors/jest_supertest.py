"""
Jest/Supertest connector.

Parses JavaScript/TypeScript test files that use:
- Jest test framework
- Supertest for HTTP assertions
- Axios, fetch, or node-fetch for requests

Extracts:
- API endpoints from test cases
- Request payloads and bodies
- Expected responses
- Authentication setup

This extends the Python test parser pattern to handle JS/TS tests.
"""

import re
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseConnector, ConnectorResult


class JestSupertestConnector(BaseConnector):
    """Connector for Jest/Supertest test files."""

    @property
    def name(self) -> str:
        return "jest_supertest"

    @property
    def description(self) -> str:
        return "Parse Jest/Supertest tests to extract API endpoints and payloads"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._test_dir: Optional[Path] = None
        self._test_files: List[Path] = []

    def connect(self, path: str, **kwargs) -> ConnectorResult:
        """Connect to a test directory or file.

        Args:
            path: Path to test directory or file

        Returns:
            ConnectorResult indicating success/failure
        """
        self._test_dir = Path(path).resolve()

        if not self._test_dir.exists():
            return self._error(f"Path not found: {path}")

        # Find test files
        self._test_files = []

        if self._test_dir.is_file():
            if self._is_test_file(self._test_dir):
                self._test_files.append(self._test_dir)
            else:
                return self._error("Not a test file")
        else:
            # Find all test files
            patterns = [
                "**/*.test.js", "**/*.test.ts",
                "**/*.spec.js", "**/*.spec.ts",
                "**/__tests__/*.js", "**/__tests__/*.ts",
            ]
            for pattern in patterns:
                self._test_files.extend(self._test_dir.glob(pattern))

        if not self._test_files:
            return self._error("No test files found")

        self._connected = True
        return self._success(
            source=f"jest_supertest://{self._test_dir}",
            data={"test_files": len(self._test_files)}
        )

    def fetch_config(self) -> ConnectorResult:
        """Parse test files and extract API configuration.

        Returns:
            ConnectorResult with parsed data
        """
        if not self._connected:
            return self._error("Not connected to test files")

        try:
            all_endpoints = []
            all_payloads = {}
            files_parsed = 0
            errors = []

            for test_file in self._test_files:
                try:
                    endpoints, payloads = self._parse_test_file(test_file)
                    all_endpoints.extend(endpoints)
                    all_payloads.update(payloads)
                    files_parsed += 1
                except Exception as e:
                    errors.append(f"{test_file.name}: {e}")

            # Deduplicate endpoints
            seen = set()
            unique_endpoints = []
            for endpoint in all_endpoints:
                key = f"{endpoint['method']} {endpoint['path']}"
                if key not in seen:
                    seen.add(key)
                    unique_endpoints.append(endpoint)

            # Extract auth config from test setup
            auth_config = self._extract_auth_config()

            data = {
                "files_parsed": files_parsed,
                "total_requests": len(all_endpoints),
                "unique_endpoints": len(unique_endpoints),
                "payloads_extracted": len(all_payloads),
            }

            warnings = errors[:5] if errors else []

            return self._success(
                data=data,
                source=f"jest_supertest://{self._test_dir}",
                endpoints=unique_endpoints,
                auth_config=auth_config,
                warnings=warnings,
            )

        except Exception as e:
            return self._error(f"Failed to parse test files: {e}")

    def _is_test_file(self, path: Path) -> bool:
        """Check if a file is a test file."""
        name = path.name.lower()
        return (
            name.endswith(".test.js") or name.endswith(".test.ts") or
            name.endswith(".spec.js") or name.endswith(".spec.ts")
        )

    def _parse_test_file(self, file_path: Path) -> tuple:
        """Parse a single test file.

        Returns:
            Tuple of (endpoints, payloads)
        """
        content = file_path.read_text(encoding='utf-8')
        endpoints = []
        payloads = {}

        # Pattern for supertest requests
        # request(app).get('/path'), request(app).post('/path').send({...})
        supertest_pattern = r'''
            (?:request|agent)\s*\([^)]*\)\s*\.
            (?P<method>get|post|put|patch|delete|head|options)\s*\(
            \s*[`'"](?P<path>[^`'"]+)[`'"]\s*\)
            (?:\.send\s*\(\s*(?P<body>\{[^}]+\}|\[[^\]]+\])\s*\))?
        '''

        for match in re.finditer(supertest_pattern, content, re.VERBOSE | re.IGNORECASE):
            method = match.group('method').upper()
            path = match.group('path')
            body_str = match.group('body')

            body = None
            if body_str:
                try:
                    # Try to parse as JSON
                    body = json.loads(body_str)
                except json.JSONDecodeError:
                    # Try to evaluate as JS object literal
                    body = self._parse_js_object(body_str)

            endpoint = {
                "method": method,
                "path": path,
                "source_file": str(file_path),
                "has_body": body is not None,
                "body": body,
            }
            endpoints.append(endpoint)

            if body:
                key = f"{method} {path}"
                if key not in payloads:
                    payloads[key] = body

        # Pattern for axios requests
        # axios.get('/path'), axios.post('/path', {...})
        axios_pattern = r'''
            axios\s*\.
            (?P<method>get|post|put|patch|delete)\s*\(
            \s*[`'"](?P<path>[^`'"]+)[`'"]\s*
            (?:,\s*(?P<body>\{[^}]+\}))?
        '''

        for match in re.finditer(axios_pattern, content, re.VERBOSE | re.IGNORECASE):
            method = match.group('method').upper()
            path = match.group('path')
            body_str = match.group('body')

            body = None
            if body_str:
                body = self._parse_js_object(body_str)

            endpoint = {
                "method": method,
                "path": path,
                "source_file": str(file_path),
                "has_body": body is not None,
                "body": body,
            }
            endpoints.append(endpoint)

            if body:
                key = f"{method} {path}"
                if key not in payloads:
                    payloads[key] = body

        # Pattern for fetch requests
        # fetch('/path', { method: 'POST', body: JSON.stringify({...}) })
        fetch_pattern = r'''
            fetch\s*\(\s*
            [`'"](?P<path>[^`'"]+)[`'"]\s*
            (?:,\s*\{\s*
                method\s*:\s*[`'"](?P<method>[^`'"]+)[`'"]\s*
                (?:,\s*body\s*:\s*(?:JSON\.stringify\s*\()?\s*(?P<body>\{[^}]+\})\s*\)?)?
            )?
        '''

        for match in re.finditer(fetch_pattern, content, re.VERBOSE | re.IGNORECASE):
            method = (match.group('method') or 'GET').upper()
            path = match.group('path')
            body_str = match.group('body')

            body = None
            if body_str:
                body = self._parse_js_object(body_str)

            endpoint = {
                "method": method,
                "path": path,
                "source_file": str(file_path),
                "has_body": body is not None,
                "body": body,
            }
            endpoints.append(endpoint)

            if body:
                key = f"{method} {path}"
                if key not in payloads:
                    payloads[key] = body

        return endpoints, payloads

    def _parse_js_object(self, obj_str: str) -> Optional[Dict]:
        """Attempt to parse a JavaScript object literal."""
        try:
            # Simple conversion of JS object to JSON
            # Handle unquoted keys
            json_str = re.sub(r'(\w+)\s*:', r'"\1":', obj_str)
            # Handle single quotes
            json_str = json_str.replace("'", '"')
            # Handle trailing commas
            json_str = re.sub(r',\s*([}\]])', r'\1', json_str)

            return json.loads(json_str)
        except Exception:
            return None

    def _extract_auth_config(self) -> Optional[Dict[str, Any]]:
        """Extract auth configuration from test setup files."""
        # Look for common setup patterns
        setup_files = [
            "setup.js", "setup.ts",
            "jest.setup.js", "jest.setup.ts",
            "setupTests.js", "setupTests.ts",
            "test-utils.js", "test-utils.ts",
        ]

        for setup_file in setup_files:
            setup_path = self._test_dir / setup_file
            if setup_path.exists():
                try:
                    content = setup_path.read_text(encoding='utf-8')
                    return self._parse_auth_from_setup(content)
                except Exception:
                    continue

        # Also check for beforeAll/beforeEach in test files
        for test_file in self._test_files[:5]:  # Check first 5 files
            try:
                content = test_file.read_text(encoding='utf-8')
                auth = self._parse_auth_from_setup(content)
                if auth:
                    return auth
            except Exception:
                continue

        return None

    def _parse_auth_from_setup(self, content: str) -> Optional[Dict[str, Any]]:
        """Parse auth configuration from setup code."""
        # Look for Authorization header setup
        auth_header_match = re.search(
            r'''['"](Authorization|X-API-Key)['"]\s*[:=]\s*['"`]([^'"`]+)['"`]''',
            content,
            re.IGNORECASE
        )

        if auth_header_match:
            header_name = auth_header_match.group(1)
            header_value = auth_header_match.group(2)

            if header_value.lower().startswith("bearer"):
                return {
                    "type": "bearer",
                    "header": header_name,
                    "from_setup": True,
                }
            elif header_name.lower() in ["x-api-key", "apikey"]:
                return {
                    "type": "api_key",
                    "header": header_name,
                    "from_setup": True,
                }

        # Look for token/apiKey variables
        token_match = re.search(
            r'''(?:const|let|var)\s+(token|apiKey|authToken|accessToken)\s*=''',
            content,
            re.IGNORECASE
        )

        if token_match:
            var_name = token_match.group(1)
            if "api" in var_name.lower() and "key" in var_name.lower():
                return {"type": "api_key", "from_setup": True}
            return {"type": "bearer", "from_setup": True}

        return None


def parse_jest_tests(path: str) -> Dict[str, Any]:
    """Parse Jest/Supertest test files.

    Args:
        path: Path to test directory or file

    Returns:
        Dict with parsed configuration
    """
    connector = JestSupertestConnector()
    connect_result = connector.connect(path=path)

    if not connect_result.success:
        return connect_result.to_dict()

    result = connector.fetch_config()
    return result.to_dict()
