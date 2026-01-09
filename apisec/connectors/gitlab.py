"""
GitLab connector for cloning and accessing GitLab repositories.

Similar to GitHub integration but for GitLab-hosted repos.
Supports both gitlab.com and self-hosted GitLab instances.

Features:
- Clone public/private repositories
- Validate access tokens
- List repository contents
"""

import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

import requests

from .base import BaseConnector, ConnectorResult, ConnectorError


@dataclass
class GitLabTokenInfo:
    """Information about a GitLab token."""
    valid: bool
    username: Optional[str] = None
    scopes: List[str] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.scopes is None:
            self.scopes = []


class GitLabConnector(BaseConnector):
    """Connector for GitLab repositories."""

    DEFAULT_HOST = "https://gitlab.com"

    @property
    def name(self) -> str:
        return "gitlab"

    @property
    def description(self) -> str:
        return "Clone and access GitLab repositories"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._token: Optional[str] = None
        self._host: str = self.DEFAULT_HOST
        self._temp_dir: Optional[Path] = None
        self._clone_path: Optional[Path] = None
        self._token_info: Optional[GitLabTokenInfo] = None

    def connect(
        self,
        token: Optional[str] = None,
        host: Optional[str] = None,
        **kwargs
    ) -> ConnectorResult:
        """Connect to GitLab API.

        Args:
            token: GitLab Personal Access Token (optional for public repos)
            host: GitLab host URL (default: https://gitlab.com)

        Returns:
            ConnectorResult indicating success/failure
        """
        self._token = token
        self._host = (host or self.DEFAULT_HOST).rstrip("/")

        if token:
            # Validate token
            self._token_info = self._validate_token()
            if not self._token_info.valid:
                return self._error(
                    f"Invalid token: {self._token_info.error}",
                    needs_auth=True
                )

            self._connected = True
            return self._success(
                data={
                    "username": self._token_info.username,
                    "scopes": self._token_info.scopes,
                    "host": self._host,
                },
                source=f"gitlab://{self._token_info.username}@{self._host}"
            )

        # No token - can still work with public repos
        self._connected = True
        return self._success(
            data={"host": self._host, "authenticated": False},
            source=f"gitlab://{self._host}"
        )

    def fetch_config(self) -> ConnectorResult:
        """Not applicable for GitLab - use clone() instead."""
        return self._error("Use clone() method to clone a repository")

    def clone(self, project: str, branch: Optional[str] = None) -> ConnectorResult:
        """Clone a GitLab repository.

        Args:
            project: Project path (e.g., 'group/project' or project ID)
            branch: Optional branch name

        Returns:
            ConnectorResult with clone path
        """
        if not self._connected:
            return self._error("Not connected to GitLab")

        # Check project access
        project_info = self._get_project_info(project)
        if not project_info:
            return self._error(
                f"Cannot access project: {project}",
                needs_auth=not self._token
            )

        # Use default branch if not specified
        if not branch:
            branch = project_info.get("default_branch", "main")

        # Build clone URL
        if self._token:
            # Authenticated clone
            clone_url = f"{self._host.replace('https://', f'https://oauth2:{self._token}@')}/{project}.git"
        else:
            # Public clone
            clone_url = f"{self._host}/{project}.git"

        # Create temp directory
        self._temp_dir = Path(tempfile.mkdtemp(prefix="apisec_gitlab_"))
        self._clone_path = self._temp_dir / "repo"

        # Clone command
        cmd = [
            "git", "clone",
            "--depth", "1",
            "--branch", branch,
            "--single-branch",
            clone_url,
            str(self._clone_path)
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                env={"GIT_TERMINAL_PROMPT": "0"}
            )

            if result.returncode != 0:
                error = result.stderr
                if self._token:
                    error = error.replace(self._token, "***")
                self.cleanup()
                return self._error(f"Clone failed: {error}")

            return self._success(
                data={
                    "path": str(self._clone_path),
                    "branch": branch,
                    "project": project,
                    "visibility": project_info.get("visibility", "unknown"),
                },
                source=f"gitlab://{project}@{branch}"
            )

        except subprocess.TimeoutExpired:
            self.cleanup()
            return self._error("Clone timed out")
        except FileNotFoundError:
            return self._error("Git is not installed")

    def _validate_token(self) -> GitLabTokenInfo:
        """Validate the GitLab token."""
        try:
            response = requests.get(
                f"{self._host}/api/v4/user",
                headers={"PRIVATE-TOKEN": self._token},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                # GitLab doesn't return scopes in user endpoint
                # We'd need to check /personal_access_tokens for that
                return GitLabTokenInfo(
                    valid=True,
                    username=data.get("username"),
                    scopes=["api"]  # Assume api scope if token works
                )
            elif response.status_code == 401:
                return GitLabTokenInfo(valid=False, error="Invalid or expired token")
            else:
                return GitLabTokenInfo(
                    valid=False,
                    error=f"GitLab API error: {response.status_code}"
                )

        except requests.Timeout:
            return GitLabTokenInfo(valid=False, error="GitLab API timeout")
        except requests.RequestException as e:
            return GitLabTokenInfo(valid=False, error=f"Connection error: {e}")

    def _get_project_info(self, project: str) -> Optional[Dict[str, Any]]:
        """Get project information."""
        # URL-encode the project path
        encoded_project = project.replace("/", "%2F")

        headers = {}
        if self._token:
            headers["PRIVATE-TOKEN"] = self._token

        try:
            response = requests.get(
                f"{self._host}/api/v4/projects/{encoded_project}",
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                return response.json()
            return None

        except Exception:
            return None

    def list_projects(self, search: Optional[str] = None) -> ConnectorResult:
        """List accessible projects.

        Args:
            search: Optional search term

        Returns:
            ConnectorResult with project list
        """
        if not self._connected or not self._token:
            return self._error("Authentication required to list projects")

        try:
            params = {"membership": "true", "per_page": 100}
            if search:
                params["search"] = search

            response = requests.get(
                f"{self._host}/api/v4/projects",
                headers={"PRIVATE-TOKEN": self._token},
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                projects = response.json()
                return self._success(
                    data={
                        "projects": [
                            {
                                "id": p["id"],
                                "path": p["path_with_namespace"],
                                "name": p["name"],
                                "visibility": p["visibility"],
                                "default_branch": p.get("default_branch"),
                            }
                            for p in projects
                        ]
                    },
                    source=f"gitlab://{self._host}/projects"
                )
            else:
                return self._error(f"Failed to list projects: {response.status_code}")

        except Exception as e:
            return self._error(f"Failed to list projects: {e}")

    def cleanup(self):
        """Remove temporary directory."""
        if self._temp_dir and self._temp_dir.exists():
            try:
                shutil.rmtree(self._temp_dir)
            except Exception:
                pass
            self._temp_dir = None
            self._clone_path = None

    def __del__(self):
        self.cleanup()


def clone_gitlab_repo(
    project: str,
    token: Optional[str] = None,
    host: Optional[str] = None,
    branch: Optional[str] = None
) -> Dict[str, Any]:
    """Clone a GitLab repository.

    Args:
        project: Project path (e.g., 'group/project')
        token: GitLab Personal Access Token (optional for public repos)
        host: GitLab host URL (default: gitlab.com)
        branch: Optional branch name

    Returns:
        Dict with clone result
    """
    connector = GitLabConnector()
    connect_result = connector.connect(token=token, host=host)

    if not connect_result.success:
        return connect_result.to_dict()

    result = connector.clone(project=project, branch=branch)
    return result.to_dict()


def validate_gitlab_token(token: str, host: Optional[str] = None) -> Dict[str, Any]:
    """Validate a GitLab Personal Access Token.

    Args:
        token: GitLab PAT to validate
        host: GitLab host URL (default: gitlab.com)

    Returns:
        Dict with validation result
    """
    connector = GitLabConnector()
    result = connector.connect(token=token, host=host)
    return result.to_dict()
