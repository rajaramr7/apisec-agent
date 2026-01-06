"""Repository artifact scanner."""

import os
from pathlib import Path
from typing import Dict, List


def scan_repo(path: str) -> Dict[str, List[str]]:
    """Scan a directory for API artifacts.

    Discovers OpenAPI specs, Postman collections, environment files,
    log files, and common code files.

    Args:
        path: Path to the directory to scan

    Returns:
        Dictionary with artifact types as keys and lists of file paths as values:
        {
            "openapi": [...],
            "postman": [...],
            "env": [...],
            "logs": [...],
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
        "env": [],
        "logs": [],
        "code": [],
    }

    # Directories to skip
    skip_dirs = {
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "env", ".env", "dist", "build", ".tox", ".pytest_cache",
        ".mypy_cache", "htmlcov", ".coverage", "eggs", "*.egg-info",
    }

    for root, dirs, files in os.walk(repo_path):
        # Skip hidden and virtual environment directories
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]

        rel_root = Path(root).relative_to(repo_path)

        for filename in files:
            file_path = Path(root) / filename
            rel_path = str(rel_root / filename) if str(rel_root) != "." else filename

            # OpenAPI specs
            if _is_openapi_file(filename):
                artifacts["openapi"].append(rel_path)

            # Postman collections
            elif _is_postman_file(filename):
                artifacts["postman"].append(rel_path)

            # Environment files
            elif _is_env_file(filename, rel_root):
                artifacts["env"].append(rel_path)

            # Log files
            elif _is_log_file(filename, rel_root):
                artifacts["logs"].append(rel_path)

            # Code files
            elif _is_code_file(filename):
                artifacts["code"].append(rel_path)

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


def _is_postman_file(filename: str) -> bool:
    """Check if file is a Postman collection."""
    return filename.endswith(".postman_collection.json")


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
        "env": "Environment files",
        "logs": "Log files",
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

    def get_full_path(self, relative_path: str) -> Path:
        """Get the full path for a relative artifact path.

        Args:
            relative_path: Relative path from scan results

        Returns:
            Full absolute path
        """
        return self.repo_path / relative_path
