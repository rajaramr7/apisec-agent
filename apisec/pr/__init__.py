"""PR module - GitHub pull request operations."""

from .github import (
    GitHubPRManager,
    get_repo_info,
    create_config_pr,
    generate_pr_body,
)

__all__ = [
    "GitHubPRManager",
    "get_repo_info",
    "create_config_pr",
    "generate_pr_body",
]
