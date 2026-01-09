"""
Bitbucket connector for cloning and accessing Bitbucket repositories.

Supports both Bitbucket Cloud and Bitbucket Server/Data Center.

Features:
- Clone public/private repositories
- Validate app passwords/tokens
- List repository contents
"""

import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

import requests

from .base import BaseConnector, ConnectorResult


@dataclass
class BitbucketAuthInfo:
    """Information about Bitbucket authentication."""
    valid: bool
    username: Optional[str] = None
    display_name: Optional[str] = None
    error: Optional[str] = None


class BitbucketConnector(BaseConnector):
    """Connector for Bitbucket repositories."""

    CLOUD_API = "https://api.bitbucket.org/2.0"
    CLOUD_HOST = "https://bitbucket.org"

    @property
    def name(self) -> str:
        return "bitbucket"

    @property
    def description(self) -> str:
        return "Clone and access Bitbucket repositories"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._username: Optional[str] = None
        self._app_password: Optional[str] = None
        self._host: str = self.CLOUD_HOST
        self._api_url: str = self.CLOUD_API
        self._temp_dir: Optional[Path] = None
        self._clone_path: Optional[Path] = None
        self._auth_info: Optional[BitbucketAuthInfo] = None

    def connect(
        self,
        username: Optional[str] = None,
        app_password: Optional[str] = None,
        host: Optional[str] = None,
        **kwargs
    ) -> ConnectorResult:
        """Connect to Bitbucket API.

        Args:
            username: Bitbucket username
            app_password: Bitbucket App Password
            host: Bitbucket host URL (default: bitbucket.org)

        Returns:
            ConnectorResult indicating success/failure
        """
        self._username = username
        self._app_password = app_password

        if host:
            self._host = host.rstrip("/")
            # For Bitbucket Server, API is different
            if "bitbucket.org" not in host:
                self._api_url = f"{self._host}/rest/api/1.0"

        if username and app_password:
            # Validate credentials
            self._auth_info = self._validate_auth()
            if not self._auth_info.valid:
                return self._error(
                    f"Authentication failed: {self._auth_info.error}",
                    needs_auth=True
                )

            self._connected = True
            return self._success(
                data={
                    "username": self._auth_info.username,
                    "display_name": self._auth_info.display_name,
                    "host": self._host,
                },
                source=f"bitbucket://{self._auth_info.username}@{self._host}"
            )

        # No credentials - can still work with public repos
        self._connected = True
        return self._success(
            data={"host": self._host, "authenticated": False},
            source=f"bitbucket://{self._host}"
        )

    def fetch_config(self) -> ConnectorResult:
        """Not applicable for Bitbucket - use clone() instead."""
        return self._error("Use clone() method to clone a repository")

    def clone(self, repo: str, branch: Optional[str] = None) -> ConnectorResult:
        """Clone a Bitbucket repository.

        Args:
            repo: Repository in 'workspace/repo' format
            branch: Optional branch name

        Returns:
            ConnectorResult with clone path
        """
        if not self._connected:
            return self._error("Not connected to Bitbucket")

        # Check repo access
        repo_info = self._get_repo_info(repo)
        if not repo_info:
            return self._error(
                f"Cannot access repository: {repo}",
                needs_auth=not self._app_password
            )

        # Use default branch if not specified
        if not branch:
            branch = repo_info.get("mainbranch", {}).get("name", "main")

        # Build clone URL
        if self._username and self._app_password:
            # Authenticated clone
            clone_url = f"https://{self._username}:{self._app_password}@bitbucket.org/{repo}.git"
        else:
            # Public clone
            clone_url = f"https://bitbucket.org/{repo}.git"

        # Create temp directory
        self._temp_dir = Path(tempfile.mkdtemp(prefix="apisec_bitbucket_"))
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
                if self._app_password:
                    error = error.replace(self._app_password, "***")
                self.cleanup()
                return self._error(f"Clone failed: {error}")

            return self._success(
                data={
                    "path": str(self._clone_path),
                    "branch": branch,
                    "repo": repo,
                    "is_private": repo_info.get("is_private", False),
                },
                source=f"bitbucket://{repo}@{branch}"
            )

        except subprocess.TimeoutExpired:
            self.cleanup()
            return self._error("Clone timed out")
        except FileNotFoundError:
            return self._error("Git is not installed")

    def _validate_auth(self) -> BitbucketAuthInfo:
        """Validate Bitbucket credentials."""
        try:
            response = requests.get(
                f"{self._api_url}/user",
                auth=(self._username, self._app_password),
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return BitbucketAuthInfo(
                    valid=True,
                    username=data.get("username"),
                    display_name=data.get("display_name"),
                )
            elif response.status_code == 401:
                return BitbucketAuthInfo(
                    valid=False,
                    error="Invalid username or app password"
                )
            else:
                return BitbucketAuthInfo(
                    valid=False,
                    error=f"Bitbucket API error: {response.status_code}"
                )

        except requests.Timeout:
            return BitbucketAuthInfo(valid=False, error="Bitbucket API timeout")
        except requests.RequestException as e:
            return BitbucketAuthInfo(valid=False, error=f"Connection error: {e}")

    def _get_repo_info(self, repo: str) -> Optional[Dict[str, Any]]:
        """Get repository information."""
        auth = None
        if self._username and self._app_password:
            auth = (self._username, self._app_password)

        try:
            response = requests.get(
                f"{self._api_url}/repositories/{repo}",
                auth=auth,
                timeout=10
            )

            if response.status_code == 200:
                return response.json()
            return None

        except Exception:
            return None

    def list_repos(self, workspace: Optional[str] = None) -> ConnectorResult:
        """List accessible repositories.

        Args:
            workspace: Optional workspace to list repos from

        Returns:
            ConnectorResult with repository list
        """
        if not self._connected or not self._app_password:
            return self._error("Authentication required to list repositories")

        try:
            if workspace:
                url = f"{self._api_url}/repositories/{workspace}"
            else:
                url = f"{self._api_url}/user/permissions/repositories"

            response = requests.get(
                url,
                auth=(self._username, self._app_password),
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                repos = data.get("values", [])

                return self._success(
                    data={
                        "repositories": [
                            {
                                "full_name": r.get("full_name", r.get("repository", {}).get("full_name")),
                                "name": r.get("name", r.get("repository", {}).get("name")),
                                "is_private": r.get("is_private", r.get("repository", {}).get("is_private")),
                            }
                            for r in repos
                        ]
                    },
                    source=f"bitbucket://{self._host}/repositories"
                )
            else:
                return self._error(f"Failed to list repos: {response.status_code}")

        except Exception as e:
            return self._error(f"Failed to list repos: {e}")

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


def clone_bitbucket_repo(
    repo: str,
    username: Optional[str] = None,
    app_password: Optional[str] = None,
    branch: Optional[str] = None
) -> Dict[str, Any]:
    """Clone a Bitbucket repository.

    Args:
        repo: Repository in 'workspace/repo' format
        username: Bitbucket username (optional for public repos)
        app_password: Bitbucket App Password
        branch: Optional branch name

    Returns:
        Dict with clone result
    """
    connector = BitbucketConnector()
    connect_result = connector.connect(username=username, app_password=app_password)

    if not connect_result.success:
        return connect_result.to_dict()

    result = connector.clone(repo=repo, branch=branch)
    return result.to_dict()


def validate_bitbucket_auth(username: str, app_password: str) -> Dict[str, Any]:
    """Validate Bitbucket credentials.

    Args:
        username: Bitbucket username
        app_password: Bitbucket App Password

    Returns:
        Dict with validation result
    """
    connector = BitbucketConnector()
    result = connector.connect(username=username, app_password=app_password)
    return result.to_dict()
