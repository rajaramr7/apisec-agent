"""GitHub pull request module for APIsec configuration."""

import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from github import Github, GithubException


def get_repo_info(repo_path: str) -> Tuple[str, str]:
    """Get GitHub repository owner and name from a local git repo.

    Reads .git/config or runs git remote -v to get the remote URL,
    then parses owner and repo name.

    Args:
        repo_path: Path to the local git repository

    Returns:
        Tuple of (owner, repo_name)

    Raises:
        ValueError: If repo info cannot be determined
    """
    repo_path = Path(repo_path).resolve()

    # Try running git remote -v first (more reliable)
    try:
        result = subprocess.run(
            ["git", "remote", "-v"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            remote_url = _parse_remote_output(result.stdout)
            if remote_url:
                return _parse_github_url(remote_url)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback: Try reading .git/config directly
    git_config = repo_path / ".git" / "config"
    if git_config.exists():
        try:
            content = git_config.read_text()
            remote_url = _parse_git_config(content)
            if remote_url:
                return _parse_github_url(remote_url)
        except Exception:
            pass

    raise ValueError(
        f"Could not determine GitHub repository info from {repo_path}. "
        "Make sure this is a git repository with a GitHub remote."
    )


def _parse_remote_output(output: str) -> Optional[str]:
    """Parse git remote -v output to extract origin URL.

    Args:
        output: Output from git remote -v

    Returns:
        Remote URL or None
    """
    for line in output.strip().split("\n"):
        if line.startswith("origin") and "(fetch)" in line:
            # origin\thttps://github.com/owner/repo.git (fetch)
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]

    # If no origin found, try the first remote
    for line in output.strip().split("\n"):
        if "(fetch)" in line:
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]

    return None


def _parse_git_config(content: str) -> Optional[str]:
    """Parse .git/config content to extract remote URL.

    Args:
        content: Content of .git/config file

    Returns:
        Remote URL or None
    """
    # Look for [remote "origin"] section
    in_origin_section = False
    for line in content.split("\n"):
        line = line.strip()

        if line == '[remote "origin"]':
            in_origin_section = True
            continue

        if in_origin_section:
            if line.startswith("["):
                # New section started
                in_origin_section = False
                continue

            if line.startswith("url = "):
                return line[6:].strip()

    return None


def _parse_github_url(url: str) -> Tuple[str, str]:
    """Parse a GitHub URL to extract owner and repo name.

    Handles both HTTPS and SSH formats:
    - https://github.com/owner/repo.git
    - https://github.com/owner/repo
    - git@github.com:owner/repo.git
    - ssh://git@github.com/owner/repo.git

    Args:
        url: GitHub remote URL

    Returns:
        Tuple of (owner, repo_name)

    Raises:
        ValueError: If URL cannot be parsed
    """
    # Remove .git suffix if present
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]

    # SSH format: git@github.com:owner/repo
    ssh_match = re.match(r"git@github\.com:([^/]+)/(.+)", url)
    if ssh_match:
        return ssh_match.group(1), ssh_match.group(2)

    # SSH format with ssh://
    ssh_url_match = re.match(r"ssh://git@github\.com/([^/]+)/(.+)", url)
    if ssh_url_match:
        return ssh_url_match.group(1), ssh_url_match.group(2)

    # HTTPS format: https://github.com/owner/repo
    https_match = re.match(r"https?://github\.com/([^/]+)/(.+)", url)
    if https_match:
        return https_match.group(1), https_match.group(2)

    # HTTPS with token: https://token@github.com/owner/repo
    https_token_match = re.match(r"https?://[^@]+@github\.com/([^/]+)/(.+)", url)
    if https_token_match:
        return https_token_match.group(1), https_token_match.group(2)

    raise ValueError(f"Could not parse GitHub URL: {url}")


def create_config_pr(
    repo_path: str,
    config_content: str,
    github_token: str,
    branch_name: str = "apisec-init",
    pr_title: str = "[APIsec] Initialize security testing configuration",
    pr_body: Optional[str] = None,
) -> str:
    """Create a GitHub PR with APIsec configuration.

    Args:
        repo_path: Path to the local git repository
        config_content: YAML content for the configuration file
        github_token: GitHub personal access token
        branch_name: Name for the new branch
        pr_title: Title for the pull request
        pr_body: Body/description for the PR (auto-generated if None)

    Returns:
        URL of the created pull request

    Raises:
        ValueError: If repo info cannot be determined
        RuntimeError: If PR creation fails
    """
    # Get repo info from local path
    owner, repo_name = get_repo_info(repo_path)
    full_repo_name = f"{owner}/{repo_name}"

    # Authenticate with GitHub
    gh = Github(github_token)
    repo = gh.get_repo(full_repo_name)

    # Get default branch
    default_branch = repo.default_branch
    base_ref = repo.get_branch(default_branch)
    base_sha = base_ref.commit.sha

    # Create new branch
    try:
        ref = f"refs/heads/{branch_name}"
        repo.create_git_ref(ref=ref, sha=base_sha)
    except GithubException as e:
        if e.status != 422:  # 422 = branch already exists, which is ok
            raise RuntimeError(f"Failed to create branch: {e}")

    # Create or update the config file in the new branch
    config_path = ".apisec/config.yaml"
    commit_message = "Initialize APIsec security testing configuration"

    try:
        # Try to get existing file
        existing_file = repo.get_contents(config_path, ref=branch_name)
        repo.update_file(
            path=config_path,
            message=commit_message,
            content=config_content,
            sha=existing_file.sha,
            branch=branch_name,
        )
    except GithubException as e:
        if e.status == 404:
            # File doesn't exist, create it
            repo.create_file(
                path=config_path,
                message=commit_message,
                content=config_content,
                branch=branch_name,
            )
        else:
            raise RuntimeError(f"Failed to create config file: {e}")

    # Generate PR body if not provided
    if pr_body is None:
        pr_body = _generate_default_pr_body(config_content)

    # Create pull request
    try:
        pr = repo.create_pull(
            title=pr_title,
            body=pr_body,
            head=branch_name,
            base=default_branch,
        )
        return pr.html_url
    except GithubException as e:
        if e.status == 422:
            # PR might already exist
            pulls = repo.get_pulls(
                state="open",
                head=f"{owner}:{branch_name}",
                base=default_branch,
            )
            for existing_pr in pulls:
                return existing_pr.html_url
        raise RuntimeError(f"Failed to create PR: {e}")


def _generate_default_pr_body(config_content: str) -> str:
    """Generate a default PR body from config content.

    Args:
        config_content: YAML configuration content

    Returns:
        Markdown formatted PR body
    """
    return f"""## 🔐 APIsec Security Testing Configuration

This PR initializes APIsec security testing for this repository.

### What's Included

- `.apisec/config.yaml` - Configuration file for automated API security scanning

### Configuration

```yaml
{config_content}
```

### Next Steps

1. **Review** the configuration above
2. **Set up secrets** - Add required credentials to your CI/CD secrets
3. **Merge** this PR to enable security scanning

### Security Tests Enabled

- ✅ **BOLA Testing** - Broken Object Level Authorization
- ✅ **Authentication Bypass** - Testing auth mechanisms
- ✅ **Injection Testing** - SQL, NoSQL, Command injection
- ✅ **Schema Validation** - Request/response schema checks

---
*🤖 Generated by [APIsec Agent](https://github.com/rajaramr7/apisec-agent)*
"""


def generate_pr_body(inferred: Dict[str, Any], todos: List[str]) -> str:
    """Generate a detailed PR description with inferred info and TODOs.

    Args:
        inferred: Dictionary of auto-configured values:
            - api_name: Name of the API
            - base_url: Base URL for the API
            - auth_type: Authentication type detected
            - endpoints: List or count of endpoints
            - spec_path: Path to OpenAPI spec (if found)
            - users: List of users found (for BOLA testing)

        todos: List of items that need manual configuration:
            - e.g., "Add production credentials to CI/CD secrets"
            - e.g., "Confirm BOLA test user mappings"

    Returns:
        Markdown formatted PR body
    """
    # Build "What was auto-configured" section
    configured_items = []

    if inferred.get("api_name"):
        configured_items.append(f"API Name: **{inferred['api_name']}**")

    if inferred.get("base_url"):
        configured_items.append(f"Base URL: `{inferred['base_url']}`")

    if inferred.get("auth_type"):
        auth_display = {
            "oauth2_password": "OAuth2 (Password Grant)",
            "oauth2_client_credentials": "OAuth2 (Client Credentials)",
            "bearer": "Bearer Token",
            "api_key": "API Key",
            "basic": "Basic Auth",
            "none": "No Authentication",
        }.get(inferred["auth_type"], inferred["auth_type"])
        configured_items.append(f"Authentication: **{auth_display}**")

    if inferred.get("spec_path"):
        configured_items.append(f"OpenAPI Spec: `{inferred['spec_path']}`")

    endpoints = inferred.get("endpoints")
    if endpoints:
        if isinstance(endpoints, list):
            configured_items.append(f"Endpoints: **{len(endpoints)}** discovered")
        else:
            configured_items.append(f"Endpoints: **{endpoints}** discovered")

    if inferred.get("users"):
        users = inferred["users"]
        if isinstance(users, list):
            user_list = ", ".join(users[:5])
            if len(users) > 5:
                user_list += f" (+{len(users) - 5} more)"
            configured_items.append(f"Test Users: {user_list}")

    configured_section = "\n".join(f"- ✅ {item}" for item in configured_items) if configured_items else "- No items were auto-configured"

    # Build "What needs your input" section
    if todos:
        todos_section = "\n".join(f"- ⬜ {todo}" for todo in todos)
    else:
        todos_section = "- ✅ Everything is configured! Ready to merge."

    # Build the full PR body
    return f"""## 🔐 APIsec Security Testing Configuration

This PR sets up automated API security testing using APIsec.

---

### ✅ What Was Auto-Configured

{configured_section}

---

### 📋 What Needs Your Input

{todos_section}

---

### 🚀 Next Steps

1. **Review** the items above marked with ⬜
2. **Update** the configuration if needed by editing `.apisec/config.yaml`
3. **Set up CI/CD secrets** for any credentials referenced in the config:
   - `APISEC_CLIENT_ID` - OAuth2 client ID
   - `APISEC_CLIENT_SECRET` - OAuth2 client secret
   - Or the appropriate variables for your auth type
4. **Merge** this PR to enable security scanning

---

### 🔒 Security Tests That Will Run

| Test | Description |
|------|-------------|
| **BOLA** | Broken Object Level Authorization - tests if users can access each other's data |
| **Auth Bypass** | Attempts to access protected endpoints without valid authentication |
| **Injection** | SQL, NoSQL, and command injection vulnerability testing |
| **Schema Validation** | Validates requests/responses against OpenAPI spec |

---

### ❓ Questions?

- 📚 [APIsec Documentation](https://apisec.ai/docs)
- 💬 [Get Support](https://apisec.ai/support)
- 🐛 [Report Issues](https://github.com/rajaramr7/apisec-agent/issues)

---
*🤖 Generated by [APIsec Agent](https://github.com/rajaramr7/apisec-agent)*
"""


# Keep the class-based interface for backward compatibility
class GitHubPRManager:
    """Manager for GitHub pull request operations.

    Handles creating branches, committing files, and
    opening pull requests for APIsec configurations.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        repo: Optional[str] = None,
    ):
        """Initialize the GitHub PR manager.

        Args:
            token: GitHub personal access token (uses env var if not provided)
            repo: Repository in format 'owner/repo'
        """
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.repo_name = repo
        self.github: Optional[Github] = None
        self.repo = None

        if self.token:
            self.authenticate()

    def authenticate(self, token: Optional[str] = None) -> None:
        """Authenticate with GitHub."""
        if token:
            self.token = token

        if not self.token:
            raise ValueError("GitHub token is required.")

        self.github = Github(self.token)

        if self.repo_name:
            self.set_repo(self.repo_name)

    def set_repo(self, repo: str) -> None:
        """Set the target repository."""
        if not self.github:
            raise RuntimeError("Not authenticated.")

        self.repo_name = repo
        self.repo = self.github.get_repo(repo)

    def create_branch(self, branch_name: str, base_branch: str = "main") -> bool:
        """Create a new branch."""
        if not self.repo:
            raise RuntimeError("Repository not set.")

        try:
            base_ref = self.repo.get_branch(base_branch)
            ref = f"refs/heads/{branch_name}"
            self.repo.create_git_ref(ref=ref, sha=base_ref.commit.sha)
            return True
        except GithubException as e:
            if e.status == 422:
                return True
            raise

    def commit_file(
        self,
        file_path: str,
        content: str,
        branch: str,
        commit_message: str,
    ) -> bool:
        """Commit a file to a branch."""
        if not self.repo:
            raise RuntimeError("Repository not set.")

        try:
            try:
                existing = self.repo.get_contents(file_path, ref=branch)
                self.repo.update_file(
                    path=file_path,
                    message=commit_message,
                    content=content,
                    sha=existing.sha,
                    branch=branch,
                )
            except GithubException as e:
                if e.status == 404:
                    self.repo.create_file(
                        path=file_path,
                        message=commit_message,
                        content=content,
                        branch=branch,
                    )
                else:
                    raise
            return True
        except GithubException as e:
            raise RuntimeError(f"Failed to commit: {e}")

    def create_pr(
        self,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str = "main",
        draft: bool = False,
    ) -> Optional[str]:
        """Create a pull request."""
        if not self.repo:
            raise RuntimeError("Repository not set.")

        try:
            pr = self.repo.create_pull(
                title=title,
                body=body,
                head=head_branch,
                base=base_branch,
                draft=draft,
            )
            return pr.html_url
        except GithubException as e:
            if e.status == 422:
                pulls = self.repo.get_pulls(
                    state="open",
                    head=f"{self.repo.owner.login}:{head_branch}",
                    base=base_branch,
                )
                for pr in pulls:
                    return pr.html_url
            raise RuntimeError(f"Failed to create PR: {e}")

    def create_config_pr(
        self,
        config_content: str,
        branch_name: str = "apisec-config",
        config_path: str = ".apisec/config.yaml",
        draft: bool = False,
    ) -> Optional[str]:
        """Create a PR with APIsec configuration."""
        if not self.repo:
            raise RuntimeError("Repository not set.")

        base_branch = self.repo.default_branch
        self.create_branch(branch_name, base_branch)

        self.commit_file(
            file_path=config_path,
            content=config_content,
            branch=branch_name,
            commit_message="Add APIsec security testing configuration",
        )

        pr_body = _generate_default_pr_body(config_content)

        return self.create_pr(
            title="[APIsec] Initialize security testing configuration",
            body=pr_body,
            head_branch=branch_name,
            base_branch=base_branch,
            draft=draft,
        )
