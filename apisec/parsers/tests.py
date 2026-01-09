"""
Parse integration tests to extract working payloads.

This parser analyzes test CODE (not test output) using Python's AST
to find HTTP requests and extract their payloads.

Why this matters:
Integration tests contain payloads that PASS. If the test passes,
the payload WORKS. This is the best source of valid request bodies.
"""

import ast
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ExtractedPayload:
    """A payload extracted from a test file."""
    method: str
    endpoint: str
    payload: Optional[Dict] = None
    headers: Optional[Dict] = None
    expected_status: Optional[int] = None
    source_file: str = ""
    source_line: int = 0
    test_name: str = ""
    confidence: str = "high"  # high, medium, low


@dataclass
class TestParseResult:
    """Results from parsing test files."""
    payloads: List[ExtractedPayload] = field(default_factory=list)
    endpoints_tested: List[str] = field(default_factory=list)
    files_parsed: int = 0
    errors: List[str] = field(default_factory=list)


# Regex patterns for HTTP request detection
PYTHON_REQUEST_PATTERNS = [
    # Flask/Django test client: client.get('/path'), self.client.post('/path')
    r'(?:client|self\.client|app\.test_client\(\)|test_client)\.(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*["\'](?P<endpoint>[^"\']+)["\']',
    # requests library: requests.get('url')
    r'requests\.(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*["\'](?P<endpoint>[^"\']+)["\']',
    # httpx: httpx.get('url'), client.get('url')
    r'(?:httpx|async_client|client)\.(?P<method>get|post|put|patch|delete)\s*\(\s*["\'](?P<endpoint>[^"\']+)["\']',
    # aiohttp: session.get('url')
    r'session\.(?P<method>get|post|put|patch|delete)\s*\(\s*["\'](?P<endpoint>[^"\']+)["\']',
]

# HTTP methods to look for
HTTP_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options'}


class PythonTestParser(ast.NodeVisitor):
    """Parse Python test files using AST to extract HTTP requests."""

    def __init__(self):
        self.payloads: List[ExtractedPayload] = []
        self.current_file = ""
        self.current_test_name = ""

    def parse_file(self, path: Path) -> List[ExtractedPayload]:
        """Parse a Python test file.

        Args:
            path: Path to the test file

        Returns:
            List of extracted payloads
        """
        self.current_file = str(path)
        self.payloads = []

        try:
            content = path.read_text(encoding='utf-8')
            tree = ast.parse(content)
            self.visit(tree)
        except SyntaxError as e:
            # Fall back to regex parsing
            self._parse_with_regex(path.read_text(encoding='utf-8'))
        except Exception as e:
            pass  # Skip files that can't be parsed

        return self.payloads

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Track current test function name."""
        if node.name.startswith('test_'):
            self.current_test_name = node.name
        self.generic_visit(node)
        self.current_test_name = ""

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Track current async test function name."""
        if node.name.startswith('test_'):
            self.current_test_name = node.name
        self.generic_visit(node)
        self.current_test_name = ""

    def visit_Call(self, node: ast.Call):
        """Visit function calls looking for HTTP requests."""
        # Check for method calls like client.get(), requests.post(), etc.
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr.lower()

            if method_name in HTTP_METHODS:
                payload = self._extract_payload_from_call(node, method_name.upper())
                if payload:
                    self.payloads.append(payload)

        self.generic_visit(node)

    def _extract_payload_from_call(
        self,
        node: ast.Call,
        method: str
    ) -> Optional[ExtractedPayload]:
        """Extract payload from an HTTP call node."""
        endpoint = None
        payload_dict = None
        headers_dict = None
        expected_status = None

        # Get endpoint from first positional argument
        if node.args:
            first_arg = node.args[0]
            endpoint = self._extract_string_value(first_arg)

        if not endpoint:
            return None

        # Extract keyword arguments
        for keyword in node.keywords:
            arg_name = keyword.arg

            if arg_name in ('json', 'data'):
                payload_dict = self._ast_to_dict(keyword.value)
            elif arg_name == 'headers':
                headers_dict = self._ast_to_dict(keyword.value)

        return ExtractedPayload(
            method=method,
            endpoint=endpoint,
            payload=payload_dict,
            headers=headers_dict,
            expected_status=expected_status,
            source_file=self.current_file,
            source_line=node.lineno,
            test_name=self.current_test_name,
            confidence="high"
        )

    def _extract_string_value(self, node) -> Optional[str]:
        """Extract string value from AST node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.Str):  # Python 3.7 compatibility
            return node.s
        elif isinstance(node, ast.JoinedStr):  # f-string
            # Try to extract static parts
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(str(value.value))
                elif isinstance(value, ast.FormattedValue):
                    # Use placeholder for dynamic parts
                    parts.append("{...}")
            return "".join(parts) if parts else None
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # String concatenation
            left = self._extract_string_value(node.left)
            right = self._extract_string_value(node.right)
            if left and right:
                return left + right
        return None

    def _ast_to_dict(self, node) -> Optional[Dict]:
        """Convert AST node to Python dict."""
        try:
            if isinstance(node, ast.Dict):
                result = {}
                for key, value in zip(node.keys, node.values):
                    if key is None:  # **kwargs spread
                        continue
                    key_str = self._ast_to_value(key)
                    if key_str:
                        result[key_str] = self._ast_to_value(value)
                return result if result else None
            elif isinstance(node, ast.Name):
                # Variable reference - can't extract value
                return {"__variable__": node.id}
            elif isinstance(node, ast.Call):
                # Function call - can't extract value
                return {"__call__": self._get_call_name(node)}
        except Exception:
            pass
        return None

    def _ast_to_value(self, node) -> Any:
        """Convert AST node to Python value."""
        if node is None:
            return None
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Str):  # Python 3.7
            return node.s
        elif isinstance(node, ast.Num):  # Python 3.7
            return node.n
        elif isinstance(node, ast.List):
            return [self._ast_to_value(el) for el in node.elts]
        elif isinstance(node, ast.Tuple):
            return tuple(self._ast_to_value(el) for el in node.elts)
        elif isinstance(node, ast.Dict):
            return self._ast_to_dict(node)
        elif isinstance(node, ast.Name):
            return f"${{{node.id}}}"  # Variable reference
        elif isinstance(node, ast.NameConstant):  # Python 3.7
            return node.value
        elif isinstance(node, ast.Attribute):
            return f"${{{self._get_attribute_name(node)}}}"
        return None

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return self._get_attribute_name(node.func)
        return "unknown"

    def _get_attribute_name(self, node: ast.Attribute) -> str:
        """Get full attribute name like 'obj.attr.method'."""
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    def _parse_with_regex(self, content: str):
        """Fallback regex parsing when AST fails."""
        for pattern in PYTHON_REQUEST_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                method = match.group('method').upper()
                endpoint = match.group('endpoint')

                if endpoint:
                    # Try to find payload in nearby lines
                    payload = self._find_payload_near_match(content, match)

                    self.payloads.append(ExtractedPayload(
                        method=method,
                        endpoint=endpoint,
                        payload=payload,
                        source_file=self.current_file,
                        source_line=content[:match.start()].count('\n') + 1,
                        confidence="medium"
                    ))

    def _find_payload_near_match(
        self,
        content: str,
        match: re.Match
    ) -> Optional[Dict]:
        """Try to find a payload dict near a regex match."""
        # Look for json= or data= in the same line or next few lines
        start = match.end()
        end = min(start + 500, len(content))
        snippet = content[start:end]

        # Simple pattern for dict literal
        dict_match = re.search(r'(?:json|data)\s*=\s*\{([^}]+)\}', snippet)
        if dict_match:
            try:
                # Try to parse as Python literal
                dict_str = '{' + dict_match.group(1) + '}'
                # Very basic parsing - won't work for complex cases
                return {"__raw__": dict_str}
            except Exception:
                pass

        return None


def parse_test_file(path: str) -> List[ExtractedPayload]:
    """Parse a single test file.

    Args:
        path: Path to the test file

    Returns:
        List of extracted payloads
    """
    file_path = Path(path)

    if file_path.suffix == '.py':
        parser = PythonTestParser()
        return parser.parse_file(file_path)

    # TODO: Add support for JS/TS test files

    return []


def parse_test_directory(test_dir: str) -> TestParseResult:
    """Parse all test files in a directory.

    Args:
        test_dir: Path to tests directory

    Returns:
        TestParseResult with all extracted payloads
    """
    result = TestParseResult()
    dir_path = Path(test_dir)

    if not dir_path.exists():
        result.errors.append(f"Directory not found: {test_dir}")
        return result

    # Find test files
    patterns = [
        "test_*.py", "*_test.py",
        "tests.py",
        "*.test.js", "*.test.ts",
        "*.spec.js", "*.spec.ts"
    ]

    test_files = []
    for pattern in patterns:
        test_files.extend(dir_path.glob(f"**/{pattern}"))

    # Parse each file
    for test_file in test_files:
        try:
            payloads = parse_test_file(str(test_file))
            result.payloads.extend(payloads)
            result.files_parsed += 1
        except Exception as e:
            result.errors.append(f"Error parsing {test_file}: {e}")

    # Build unique endpoints list
    seen = set()
    for p in result.payloads:
        key = f"{p.method} {p.endpoint}"
        if key not in seen:
            seen.add(key)
            result.endpoints_tested.append(key)

    return result


def format_payload_summary(result: TestParseResult) -> str:
    """Format extracted payloads for display.

    Args:
        result: TestParseResult from parsing

    Returns:
        Formatted string for display
    """
    lines = []

    if result.errors:
        for error in result.errors[:3]:
            lines.append(f"Warning: {error}")
        lines.append("")

    lines.append(f"Parsed {result.files_parsed} test files")
    lines.append(f"Found {len(result.payloads)} HTTP requests:\n")

    # Group by endpoint
    by_endpoint: Dict[str, List[ExtractedPayload]] = {}
    for p in result.payloads:
        key = f"{p.method} {p.endpoint}"
        if key not in by_endpoint:
            by_endpoint[key] = []
        by_endpoint[key].append(p)

    # Display grouped
    for endpoint in sorted(by_endpoint.keys()):
        payloads = by_endpoint[endpoint]
        lines.append(f"  {endpoint}")

        # Show first payload with actual data
        for p in payloads:
            if p.payload:
                # Truncate large payloads
                payload_str = str(p.payload)
                if len(payload_str) > 100:
                    payload_str = payload_str[:100] + "..."
                lines.append(f"    Payload: {payload_str}")
                if p.test_name:
                    lines.append(f"    From: {p.test_name}")
                break
        else:
            # No payload found
            if payloads[0].test_name:
                lines.append(f"    From: {payloads[0].test_name}")

        lines.append("")

    if not by_endpoint:
        lines.append("  No HTTP requests found in test files")

    return "\n".join(lines)


def extract_working_payloads(test_dir: str) -> Dict[str, Any]:
    """
    Extract working payloads from integration tests.

    This is the main entry point for the agent tool.

    Args:
        test_dir: Path to tests directory

    Returns:
        {
            "success": True/False,
            "endpoints": ["GET /orders", "POST /orders", ...],
            "payloads": {
                "POST /orders": {"product": "...", "quantity": 1},
                ...
            },
            "summary": "Formatted summary string",
            "files_parsed": 5,
            "requests_found": 12
        }
    """
    result = parse_test_directory(test_dir)

    # Build payloads dict
    payloads_dict = {}
    for p in result.payloads:
        key = f"{p.method} {p.endpoint}"
        if key not in payloads_dict and p.payload:
            payloads_dict[key] = p.payload

    return {
        "success": len(result.payloads) > 0,
        "endpoints": result.endpoints_tested,
        "payloads": payloads_dict,
        "summary": format_payload_summary(result),
        "files_parsed": result.files_parsed,
        "requests_found": len(result.payloads),
        "errors": result.errors if result.errors else None
    }
