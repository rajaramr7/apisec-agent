"""Repository artifact scanner.

Discovers API artifacts including specs, collections, logs, fixtures,
and DevOps configurations to enable intelligent requirement gathering.
"""

import os
from pathlib import Path
from typing import Dict, List


def scan_repo(path: str) -> Dict[str, List[str]]:
    """Scan a directory for API artifacts.

    Discovers OpenAPI specs, Postman collections, environment files,
    gateway logs, test outputs, fixtures, DevOps configs, and code files.

    Args:
        path: Path to the directory to scan

    Returns:
        Dictionary with artifact types as keys and lists of file paths as values:
        {
            "openapi": [...],
            "postman": [...],
            "postman_environments": [...],
            "env": [...],
            "logs": [...],
            "gateway_logs": [...],
            "test_outputs": [...],
            "fixtures": [...],
            "docker_compose": [...],
            "ci_configs": [...],
            "code": [...]
        }
    """
    repo_path = Path(path).resolve()

    if not repo_path.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")

    if not repo_path.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {path}")

    artifacts = {
        "openapi": [],
        "postman": [],
        "postman_environments": [],
        "env": [],
        "logs": [],
        "gateway_logs": [],
        "test_outputs": [],
        "fixtures": [],
        "docker_compose": [],
        "ci_configs": [],
        "code": [],
    }

    # Directories to skip
    skip_dirs = {
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "env", ".env", "dist", "build", ".tox", ".pytest_cache",
        ".mypy_cache", "htmlcov", ".coverage", "eggs", "*.egg-info",
    }

    # Directories to explicitly include (override hidden dir filter)
    include_dirs = {".github", ".circleci"}

    for root, dirs, files in os.walk(repo_path):
        # Skip hidden and virtual environment directories, but keep CI directories
        dirs[:] = [d for d in dirs if d not in skip_dirs and (not d.startswith(".") or d in include_dirs)]

        rel_root = Path(root).relative_to(repo_path)

        for filename in files:
            file_path = Path(root) / filename
            rel_path = str(rel_root / filename) if str(rel_root) != "." else filename

            # OpenAPI specs
            if _is_openapi_file(filename):
                artifacts["openapi"].append(rel_path)

            # Postman collections
            elif _is_postman_collection(filename):
                artifacts["postman"].append(rel_path)

            # Postman environments
            elif _is_postman_environment(filename):
                artifacts["postman_environments"].append(rel_path)

            # Environment files
            elif _is_env_file(filename, rel_root):
                artifacts["env"].append(rel_path)

            # Gateway logs (check before generic logs)
            elif _is_gateway_log(filename, rel_root):
                artifacts["gateway_logs"].append(rel_path)

            # Log files
            elif _is_log_file(filename, rel_root):
                artifacts["logs"].append(rel_path)

            # Code files
            elif _is_code_file(filename):
                artifacts["code"].append(rel_path)

            # Test outputs
            elif _is_test_output(filename, rel_root):
                artifacts["test_outputs"].append(rel_path)

            # Fixtures
            elif _is_fixtures_file(filename, rel_root):
                artifacts["fixtures"].append(rel_path)

            # Docker Compose
            elif _is_docker_compose(filename):
                artifacts["docker_compose"].append(rel_path)

            # CI configs
            elif _is_ci_config(filename, rel_root, str(rel_path)):
                artifacts["ci_configs"].append(rel_path)

    return artifacts


def _is_openapi_file(filename: str) -> bool:
    """Check if file is an OpenAPI/Swagger specification."""
    openapi_names = {
        "openapi.yaml", "openapi.yml", "openapi.json",
        "swagger.yaml", "swagger.yml", "swagger.json",
        "api-spec.yaml", "api-spec.yml", "api-spec.json",
        "api.yaml", "api.yml", "api.json",
    }
    return filename.lower() in openapi_names


def _is_postman_collection(filename: str) -> bool:
    """Check if file is a Postman collection."""
    return filename.endswith(".postman_collection.json")


def _is_postman_environment(filename: str) -> bool:
    """Check if file is a Postman environment."""
    return filename.endswith(".postman_environment.json")


def _is_env_file(filename: str, rel_root: Path) -> bool:
    """Check if file is an environment file."""
    # Direct .env files
    if filename == ".env" or filename.startswith(".env."):
        return True

    # Files ending with .env
    if filename.endswith(".env"):
        return True

    # Environment files in config directories
    if "config" in str(rel_root).lower() and filename.endswith(".env"):
        return True

    return False


def _is_log_file(filename: str, rel_root: Path) -> bool:
    """Check if file is a log file."""
    # Files ending with .log
    if filename.endswith(".log"):
        return True

    # Files in logs directory
    if "logs" in str(rel_root).lower() and filename.endswith(".log"):
        return True

    return False


def _is_code_file(filename: str) -> bool:
    """Check if file is a common code file."""
    code_extensions = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php"}
    return any(filename.endswith(ext) for ext in code_extensions)


def _is_gateway_log(filename: str, rel_root: Path) -> bool:
    """Check if file is a gateway log file.

    Looks for logs from Kong, AWS API Gateway, Apigee, nginx, Envoy.
    """
    filename_lower = filename.lower()
    path_str = str(rel_root).lower()

    # Gateway-specific patterns in filename
    gateway_patterns = [
        "kong", "apigateway", "api-gateway", "apigee",
        "nginx-access", "nginx_access", "envoy", "istio"
    ]

    # Check filename for gateway patterns
    if any(pattern in filename_lower for pattern in gateway_patterns):
        if filename.endswith((".log", ".json")):
            return True

    # Check if in gateway-related directory
    gateway_dirs = ["gateway", "proxy", "ingress", "loadbalancer", "logs/gateway"]
    if any(gw_dir in path_str for gw_dir in gateway_dirs):
        if filename.endswith(".log") or filename.endswith(".json"):
            return True

    # Specific file patterns
    if filename_lower in ["access.log", "gateway.log", "proxy.log"]:
        return True

    return False


def _is_test_output(filename: str, rel_root: Path) -> bool:
    """Check if file is a test output/report file.

    Looks for pytest, Jest, Newman, Karate, REST Assured outputs.
    """
    filename_lower = filename.lower()
    path_str = str(rel_root).lower()

    # Test output patterns
    test_patterns = [
        "pytest", "jest", "newman", "karate", "test-results",
        "test_results", "testresults", "junit", "report"
    ]

    # Check filename
    if any(pattern in filename_lower for pattern in test_patterns):
        if filename.endswith((".json", ".xml", ".html")):
            return True

    # Check path for test output directories
    output_dirs = ["test-results", "test_results", "reports", "test-reports", "coverage"]
    if any(out_dir in path_str for out_dir in output_dirs):
        if filename.endswith((".json", ".xml")):
            return True

    # Newman-specific pattern
    if filename.endswith(".newman.json"):
        return True

    # JUnit XML pattern
    if filename.startswith("TEST-") and filename.endswith(".xml"):
        return True

    return False


def _is_fixtures_file(filename: str, rel_root: Path) -> bool:
    """Check if file is a test fixtures/seed data file."""
    filename_lower = filename.lower()
    path_str = str(rel_root).lower()

    # Fixtures directory patterns
    fixture_dirs = [
        "fixtures", "testdata", "test_data", "seed", "seeds",
        "sample_data", "mock_data", "mocks"
    ]

    # Check if in fixtures directory
    if any(fix_dir in path_str for fix_dir in fixture_dirs):
        if filename.endswith((".json", ".yaml", ".yml", ".sql", ".csv")):
            return True

    # Filename patterns
    fixture_patterns = [
        "fixtures", "seed", "testdata", "test_data",
        "sample", "mock", "fake"
    ]

    if any(pattern in filename_lower for pattern in fixture_patterns):
        if filename.endswith((".json", ".yaml", ".yml", ".sql", ".csv")):
            return True

    # Factory files (Python)
    if "factory" in filename_lower and filename.endswith(".py"):
        return True

    return False


def _is_docker_compose(filename: str) -> bool:
    """Check if file is a Docker Compose configuration."""
    filename_lower = filename.lower()

    compose_names = [
        "docker-compose.yml", "docker-compose.yaml",
        "docker-compose.dev.yml", "docker-compose.dev.yaml",
        "docker-compose.test.yml", "docker-compose.test.yaml",
        "docker-compose.staging.yml", "docker-compose.staging.yaml",
        "docker-compose.prod.yml", "docker-compose.prod.yaml",
        "docker-compose.override.yml", "docker-compose.override.yaml",
        "compose.yml", "compose.yaml"
    ]

    return filename_lower in compose_names


def _is_ci_config(filename: str, rel_root: Path, rel_path: str) -> bool:
    """Check if file is a CI/CD configuration file."""
    filename_lower = filename.lower()
    path_str = rel_path.lower()

    # GitHub Actions
    if ".github/workflows" in path_str and filename.endswith((".yml", ".yaml")):
        return True

    # GitLab CI
    if filename_lower == ".gitlab-ci.yml":
        return True

    # Jenkins
    if filename_lower == "jenkinsfile" or filename_lower.startswith("jenkinsfile."):
        return True

    # CircleCI
    if ".circleci" in path_str and filename_lower == "config.yml":
        return True

    # Travis CI
    if filename_lower == ".travis.yml":
        return True

    # Azure Pipelines
    if filename_lower == "azure-pipelines.yml":
        return True

    return False


def get_artifact_summary(artifacts: Dict[str, List[str]]) -> str:
    """Generate a human-readable summary of discovered artifacts.

    Args:
        artifacts: Dictionary from scan_repo()

    Returns:
        Formatted summary string
    """
    lines = ["Discovered artifacts:"]

    artifact_labels = {
        "openapi": "OpenAPI specs",
        "postman": "Postman collections",
        "postman_environments": "Postman environments",
        "env": "Environment files",
        "logs": "Log files",
        "gateway_logs": "Gateway logs",
        "test_outputs": "Test outputs",
        "fixtures": "Test fixtures",
        "docker_compose": "Docker Compose files",
        "ci_configs": "CI/CD configs",
        "code": "Code files",
    }

    for artifact_type, label in artifact_labels.items():
        files = artifacts.get(artifact_type, [])
        if files:
            lines.append(f"\n  {label} ({len(files)}):")
            for f in files[:10]:  # Limit to first 10
                lines.append(f"    - {f}")
            if len(files) > 10:
                lines.append(f"    ... and {len(files) - 10} more")

    if all(len(v) == 0 for v in artifacts.values()):
        lines.append("  No artifacts found")

    return "\n".join(lines)


class ArtifactScanner:
    """Scanner for discovering API artifacts in a repository.

    Finds and catalogs OpenAPI specs, Postman collections,
    log files, and environment configurations.
    """

    def __init__(self, repo_path: str):
        """Initialize the artifact scanner.

        Args:
            repo_path: Path to the repository to scan
        """
        self.repo_path = Path(repo_path).resolve()
        self.artifacts = None

    def scan(self) -> Dict[str, List[str]]:
        """Scan the repository for all artifact types.

        Returns:
            Dictionary mapping artifact types to file paths
        """
        self.artifacts = scan_repo(str(self.repo_path))
        return self.artifacts

    def get_summary(self) -> str:
        """Get a summary of discovered artifacts.

        Returns:
            Formatted summary string
        """
        if self.artifacts is None:
            self.scan()
        return get_artifact_summary(self.artifacts)

    def get_openapi_files(self) -> List[str]:
        """Get paths to OpenAPI specification files."""
        if self.artifacts is None:
            self.scan()
        return self.artifacts.get("openapi", [])

    def get_postman_files(self) -> List[str]:
        """Get paths to Postman collection files."""
        if self.artifacts is None:
            self.scan()
        return self.artifacts.get("postman", [])

    def get_postman_environment_files(self) -> List[str]:
        """Get paths to Postman environment files."""
        if self.artifacts is None:
            self.scan()
        return self.artifacts.get("postman_environments", [])

    def get_env_files(self) -> List[str]:
        """Get paths to environment files."""
        if self.artifacts is None:
            self.scan()
        return self.artifacts.get("env", [])

    def get_log_files(self) -> List[str]:
        """Get paths to log files."""
        if self.artifacts is None:
            self.scan()
        return self.artifacts.get("logs", [])

    def get_gateway_log_files(self) -> List[str]:
        """Get paths to gateway log files."""
        if self.artifacts is None:
            self.scan()
        return self.artifacts.get("gateway_logs", [])

    def get_test_output_files(self) -> List[str]:
        """Get paths to test output files."""
        if self.artifacts is None:
            self.scan()
        return self.artifacts.get("test_outputs", [])

    def get_fixtures_files(self) -> List[str]:
        """Get paths to fixture files."""
        if self.artifacts is None:
            self.scan()
        return self.artifacts.get("fixtures", [])

    def get_docker_compose_files(self) -> List[str]:
        """Get paths to Docker Compose files."""
        if self.artifacts is None:
            self.scan()
        return self.artifacts.get("docker_compose", [])

    def get_ci_config_files(self) -> List[str]:
        """Get paths to CI configuration files."""
        if self.artifacts is None:
            self.scan()
        return self.artifacts.get("ci_configs", [])

    def get_full_path(self, relative_path: str) -> Path:
        """Get the full path for a relative artifact path.

        Args:
            relative_path: Relative path from scan results

        Returns:
            Full absolute path
        """
        return self.repo_path / relative_path
