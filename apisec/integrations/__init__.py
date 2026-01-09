"""Integrations with external services."""

from .github import GitHubIntegration, GitHubError, RepoInfo

__all__ = ["GitHubIntegration", "GitHubError", "RepoInfo"]
