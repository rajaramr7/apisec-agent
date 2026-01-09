"""
GitHub integration for APIsec agent.
Clones private repos and provides access for scanning.
"""

import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

import requests


@dataclass
class RepoInfo:
    """Information about a GitHub repository."""
    accessible: bool
    private: bool = False
    default_branch: str = "main"
    error: Optional[str] = None


@dataclass
class TokenInfo:
    """Information about a GitHub token."""
    valid: bool
    user: Optional[str] = None
    scopes: List[str] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.scopes is None:
            self.scopes = []

    def has_repo_scope(self) -> bool:
        """Check if token has repo scope."""
        return "repo" in self.scopes or "public_repo" in self.scopes


class GitHubError(Exception):
    """GitHub integration error."""
    pass


class GitHubIntegration:
    """Clone and access GitHub repositories.

    Usage:
        with GitHubIntegration(token) as gh:
            repo_path = gh.clone("org/repo")
            # Scan repo_path...
        # Cleanup happens automatically
    """

    def __init__(self, token: str):
        """Initialize GitHub integration.

        Args:
            token: GitHub Personal Access Token
        """
        self.token = token
        self._temp_dir: Optional[Path] = None
        self._clone_path: Optional[Path] = None

    def validate_token(self) -> TokenInfo:
        """
        Validate token and return user info.

        Returns:
            TokenInfo with validity, user, and scopes
        """
        if not self.token or not isinstance(self.token, str):
            return TokenInfo(valid=False, error="Token is empty or invalid")

        # Clean up token (remove 'ghp_' prefix spaces, etc.)
        token = self.token.strip()

        try:
            response = requests.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json"
                },
                timeout=10
            )

            if response.status_code == 200:
                user_data = response.json()
                scopes_header = response.headers.get("X-OAuth-Scopes", "")
                scopes = [s.strip() for s in scopes_header.split(",") if s.strip()]

                return TokenInfo(
                    valid=True,
                    user=user_data.get("login"),
                    scopes=scopes
                )
            elif response.status_code == 401:
                return TokenInfo(valid=False, error="Invalid or expired token")
            elif response.status_code == 403:
                return TokenInfo(valid=False, error="Token lacks required permissions")
            else:
                return TokenInfo(
                    valid=False,
                    error=f"GitHub API error: {response.status_code}"
                )

        except requests.Timeout:
            return TokenInfo(valid=False, error="GitHub API timeout")
        except requests.RequestException as e:
            return TokenInfo(valid=False, error=f"Connection error: {str(e)}")

    def check_repo_access(self, repo: str) -> RepoInfo:
        """
        Check if token can access the specified repo.

        Args:
            repo: Repository in "org/repo" format

        Returns:
            RepoInfo with accessibility and details
        """
        # Normalize repo format
        repo = self._normalize_repo(repo)

        try:
            response = requests.get(
                f"https://api.github.com/repos/{repo}",
                headers={
                    "Authorization": f"token {self.token}",
                    "Accept": "application/vnd.github.v3+json"
                },
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return RepoInfo(
                    accessible=True,
                    private=data.get("private", False),
                    default_branch=data.get("default_branch", "main")
                )
            elif response.status_code == 404:
                return RepoInfo(
                    accessible=False,
                    error="Repository not found or no access"
                )
            elif response.status_code == 403:
                return RepoInfo(
                    accessible=False,
                    error="Access forbidden - check token permissions"
                )
            else:
                return RepoInfo(
                    accessible=False,
                    error=f"GitHub API error: {response.status_code}"
                )

        except requests.Timeout:
            return RepoInfo(accessible=False, error="GitHub API timeout")
        except requests.RequestException as e:
            return RepoInfo(accessible=False, error=f"Connection error: {str(e)}")

    def clone(self, repo: str, branch: Optional[str] = None) -> Path:
        """
        Clone repository to temporary directory.

        Args:
            repo: Repository in "org/repo" format or full URL
            branch: Optional branch name (defaults to repo's default branch)

        Returns:
            Path to cloned repository

        Raises:
            GitHubError: If clone fails
        """
        # Normalize repo format
        repo = self._normalize_repo(repo)

        # Check access first
        repo_info = self.check_repo_access(repo)
        if not repo_info.accessible:
            raise GitHubError(f"Cannot access repository: {repo_info.error}")

        # Use default branch if not specified
        if not branch:
            branch = repo_info.default_branch

        # Build authenticated URL (token in URL for git clone)
        auth_url = f"https://{self.token}@github.com/{repo}.git"

        # Create temp directory
        self._temp_dir = Path(tempfile.mkdtemp(prefix="apisec_github_"))
        self._clone_path = self._temp_dir / "repo"

        # Build clone command (shallow for speed)
        cmd = [
            "git", "clone",
            "--depth", "1",
            "--branch", branch,
            "--single-branch",
            auth_url,
            str(self._clone_path)
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                env={"GIT_TERMINAL_PROMPT": "0"}  # Prevent git from prompting
            )

            if result.returncode != 0:
                # Sanitize error message (remove token)
                error = result.stderr.replace(self.token, "***")
                raise GitHubError(f"Clone failed: {error}")

            return self._clone_path

        except subprocess.TimeoutExpired:
            self.cleanup()
            raise GitHubError("Clone timed out - repository may be too large")
        except FileNotFoundError:
            raise GitHubError("Git is not installed or not in PATH")

    def get_clone_path(self) -> Optional[Path]:
        """Return path to cloned repo, if any."""
        return self._clone_path

    def cleanup(self):
        """Remove temporary directory and cloned files."""
        if self._temp_dir and self._temp_dir.exists():
            try:
                shutil.rmtree(self._temp_dir)
            except Exception:
                pass  # Best effort cleanup
            self._temp_dir = None
            self._clone_path = None

    def _normalize_repo(self, repo: str) -> str:
        """Normalize repository string to org/repo format."""
        # Remove protocol and domain
        if repo.startswith("https://github.com/"):
            repo = repo.replace("https://github.com/", "")
        elif repo.startswith("http://github.com/"):
            repo = repo.replace("http://github.com/", "")
        elif repo.startswith("git@github.com:"):
            repo = repo.replace("git@github.com:", "")

        # Remove .git suffix
        if repo.endswith(".git"):
            repo = repo[:-4]

        # Remove trailing slash
        repo = repo.rstrip("/")

        return repo

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup."""
        self.cleanup()


def validate_github_token(token: str) -> Dict[str, Any]:
    """
    Validate a GitHub Personal Access Token.

    Args:
        token: GitHub PAT to validate

    Returns:
        {
            "valid": True/False,
            "user": "username",
            "scopes": ["repo", "read:org"],
            "has_repo_scope": True/False,
            "error": "error message if invalid"
        }
    """
    gh = GitHubIntegration(token)
    info = gh.validate_token()

    return {
        "valid": info.valid,
        "user": info.user,
        "scopes": info.scopes,
        "has_repo_scope": info.has_repo_scope() if info.valid else False,
        "error": info.error
    }


def check_repo_public(repo: str) -> Dict[str, Any]:
    """
    Check if a GitHub repo is public (no auth needed).

    Args:
        repo: Repository in "org/repo" format

    Returns:
        {"public": True/False, "default_branch": "main", "error": "..."}
    """
    # Normalize repo
    if repo.startswith("https://"):
        repo = repo.replace("https://github.com/", "")
    if repo.endswith(".git"):
        repo = repo[:-4]
    repo = repo.rstrip("/")

    try:
        response = requests.get(
            f"https://api.github.com/repos/{repo}",
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            return {
                "public": not data.get("private", True),
                "default_branch": data.get("default_branch", "main"),
                "exists": True
            }
        elif response.status_code == 404:
            return {"public": False, "exists": False, "error": "Repo not found (may be private)"}
        else:
            return {"public": False, "error": f"GitHub API error: {response.status_code}"}

    except Exception as e:
        return {"public": False, "error": str(e)}


def clone_public_repo(repo: str, branch: Optional[str] = None) -> Dict[str, Any]:
    """
    Clone a public GitHub repo (no token needed).

    Args:
        repo: Repository in "org/repo" format
        branch: Optional branch to clone

    Returns:
        {"success": True/False, "path": "...", "error": "..."}
    """
    # Normalize repo
    if repo.startswith("https://"):
        repo = repo.replace("https://github.com/", "")
    if repo.endswith(".git"):
        repo = repo[:-4]
    repo = repo.rstrip("/")

    # Check if public first
    check = check_repo_public(repo)
    if not check.get("public"):
        return {
            "success": False,
            "needs_auth": True,
            "error": check.get("error", "Repository is private or not found")
        }

    # Use default branch if not specified
    if not branch:
        branch = check.get("default_branch", "main")

    # Create temp directory
    temp_dir = Path(tempfile.mkdtemp(prefix="apisec_github_"))
    clone_path = temp_dir / "repo"

    # Clone URL (no auth)
    clone_url = f"https://github.com/{repo}.git"

    cmd = [
        "git", "clone",
        "--depth", "1",
        "--branch", branch,
        "--single-branch",
        clone_url,
        str(clone_path)
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
            shutil.rmtree(temp_dir, ignore_errors=True)
            return {
                "success": False,
                "error": f"Clone failed: {result.stderr}"
            }

        return {
            "success": True,
            "path": str(clone_path),
            "branch": branch,
            "private": False
        }

    except subprocess.TimeoutExpired:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return {"success": False, "error": "Clone timed out"}
    except FileNotFoundError:
        return {"success": False, "error": "Git is not installed"}


def clone_github_repo(
    repo: str,
    token: Optional[str] = None,
    branch: Optional[str] = None
) -> Dict[str, Any]:
    """
    Clone a GitHub repository for scanning.

    For public repos, token is optional.
    For private repos, token with 'repo' scope is required.

    Args:
        repo: Repository in "org/repo" format
        token: GitHub Personal Access Token (optional for public repos)
        branch: Optional branch to clone

    Returns:
        {
            "success": True/False,
            "path": "/path/to/cloned/repo",
            "branch": "main",
            "error": "error message if failed",
            "needs_auth": True if private repo needs token
        }
    """
    # First, try as public repo if no token provided
    if not token:
        result = clone_public_repo(repo, branch)
        if result.get("success") or result.get("needs_auth"):
            return result
        return result

    # If token provided, use authenticated clone
    gh = GitHubIntegration(token)

    try:
        # Validate token first
        token_info = gh.validate_token()
        if not token_info.valid:
            return {
                "success": False,
                "error": f"Invalid token: {token_info.error}"
            }

        if not token_info.has_repo_scope():
            return {
                "success": False,
                "error": "Token lacks 'repo' scope - please create a token with repo access"
            }

        # Check repo access
        repo_info = gh.check_repo_access(repo)
        if not repo_info.accessible:
            return {
                "success": False,
                "error": f"Cannot access repo: {repo_info.error}"
            }

        # Clone
        clone_path = gh.clone(repo, branch)

        return {
            "success": True,
            "path": str(clone_path),
            "branch": branch or repo_info.default_branch,
            "private": repo_info.private,
            "user": token_info.user
        }

    except GitHubError as e:
        gh.cleanup()
        return {
            "success": False,
            "error": str(e)
        }


# Global reference for cleanup
_active_github_integration: Optional[GitHubIntegration] = None


def cleanup_github_clone():
    """Clean up any cloned repository."""
    global _active_github_integration
    if _active_github_integration:
        _active_github_integration.cleanup()
        _active_github_integration = None
