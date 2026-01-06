"""GitHub pull request manager."""

import os
from pathlib import Path
from typing import Any, Dict, Optional

from github import Github, GithubException


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
        """Authenticate with GitHub.

        Args:
            token: GitHub token (optional, uses stored token if not provided)
        """
        if token:
            self.token = token

        if not self.token:
            raise ValueError("GitHub token is required. Set GITHUB_TOKEN env var or pass token directly.")

        self.github = Github(self.token)

        if self.repo_name:
            self.set_repo(self.repo_name)

    def set_repo(self, repo: str) -> None:
        """Set the target repository.

        Args:
            repo: Repository in format 'owner/repo'
        """
        if not self.github:
            raise RuntimeError("Not authenticated. Call authenticate() first.")

        self.repo_name = repo
        self.repo = self.github.get_repo(repo)

    def create_branch(self, branch_name: str, base_branch: str = "main") -> bool:
        """Create a new branch.

        Args:
            branch_name: Name for the new branch
            base_branch: Base branch to create from

        Returns:
            True if successful
        """
        if not self.repo:
            raise RuntimeError("Repository not set. Call set_repo() first.")

        try:
            # Get the base branch reference
            base_ref = self.repo.get_branch(base_branch)
            base_sha = base_ref.commit.sha

            # Create new branch
            ref = f"refs/heads/{branch_name}"
            self.repo.create_git_ref(ref=ref, sha=base_sha)
            return True

        except GithubException as e:
            if e.status == 422:  # Branch already exists
                return True
            raise

    def commit_file(
        self,
        file_path: str,
        content: str,
        branch: str,
        commit_message: str,
    ) -> bool:
        """Commit a file to a branch.

        Args:
            file_path: Path for the file in the repo
            content: File content
            branch: Target branch
            commit_message: Commit message

        Returns:
            True if successful
        """
        if not self.repo:
            raise RuntimeError("Repository not set. Call set_repo() first.")

        try:
            # Check if file exists
            try:
                existing_file = self.repo.get_contents(file_path, ref=branch)
                # Update existing file
                self.repo.update_file(
                    path=file_path,
                    message=commit_message,
                    content=content,
                    sha=existing_file.sha,
                    branch=branch,
                )
            except GithubException as e:
                if e.status == 404:
                    # Create new file
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
            raise RuntimeError(f"Failed to commit file: {e}")

    def create_pr(
        self,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str = "main",
        draft: bool = False,
    ) -> Optional[str]:
        """Create a pull request.

        Args:
            title: PR title
            body: PR description
            head_branch: Source branch
            base_branch: Target branch
            draft: Create as draft PR

        Returns:
            PR URL if successful, None otherwise
        """
        if not self.repo:
            raise RuntimeError("Repository not set. Call set_repo() first.")

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
                # PR might already exist
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
        """Create a PR with APIsec configuration.

        Convenience method that handles branch creation,
        file commit, and PR creation in one call.

        Args:
            config_content: APIsec configuration YAML content
            branch_name: Branch name for the PR
            config_path: Path for the config file in repo
            draft: Create as draft PR

        Returns:
            PR URL if successful, None otherwise
        """
        if not self.repo:
            raise RuntimeError("Repository not set. Call set_repo() first.")

        # Determine base branch
        base_branch = self.repo.default_branch

        # Create branch
        self.create_branch(branch_name, base_branch)

        # Commit config file
        self.commit_file(
            file_path=config_path,
            content=config_content,
            branch=branch_name,
            commit_message="Add APIsec security testing configuration",
        )

        # Create PR
        pr_title = "Add APIsec Security Testing Configuration"
        pr_body = self._generate_pr_body(config_content)

        return self.create_pr(
            title=pr_title,
            body=pr_body,
            head_branch=branch_name,
            base_branch=base_branch,
            draft=draft,
        )

    def _generate_pr_body(self, config_content: str) -> str:
        """Generate PR body from config content.

        Args:
            config_content: YAML configuration content

        Returns:
            Formatted PR body
        """
        return f"""## APIsec Security Testing Configuration

This PR adds the APIsec security testing configuration to enable automated API security scanning.

### What's Included

- `.apisec/config.yaml` - Configuration file for APIsec security testing

### Configuration Preview

```yaml
{config_content}
```

### Security Tests Enabled

- **BOLA Testing** - Broken Object Level Authorization
- **Authentication Bypass** - Testing auth mechanisms
- **Injection Testing** - SQL, NoSQL, Command injection

### Next Steps

1. Review the configuration
2. Ensure test credentials are set up in CI/CD secrets
3. Merge to enable security scanning on PRs

---
*Generated by [APIsec Agent](https://github.com/rajaramr7/apisec-agent)*
"""

    @staticmethod
    def generate_pr_body(config_summary: Dict[str, Any]) -> str:
        """Generate a PR description from config summary.

        Args:
            config_summary: Summary of the configuration

        Returns:
            Formatted PR body in markdown
        """
        api_name = config_summary.get("api_name", "Unknown API")
        base_url = config_summary.get("base_url", "Not specified")
        endpoint_count = config_summary.get("endpoint_count", 0)
        auth_type = config_summary.get("auth_type", "Not configured")

        return f"""## APIsec Configuration

This PR adds the APIsec security testing configuration.

### Configuration Summary

- **API Name:** {api_name}
- **Base URL:** {base_url}
- **Endpoints:** {endpoint_count}
- **Auth Type:** {auth_type}

### Security Tests

The following security tests will be performed:
- BOLA (Broken Object Level Authorization)
- Authentication Bypass
- Injection vulnerabilities

---
*Generated by APIsec Agent*
"""
