"""CLI entry point for APIsec Agent."""

import os
import sys
from pathlib import Path

import click

from . import __version__
from .agent import run_interactive_chat, run_interactive_chat_verbose
from .pr.github import GitHubPRManager


@click.group()
@click.version_option(version=__version__, prog_name="apisec")
def main():
    """APIsec Agent - AI-powered API security testing configuration.

    This tool helps developers configure API security testing through
    conversation and inference. It analyzes your API artifacts (OpenAPI specs,
    Postman collections, logs) and generates configuration for APIsec.

    \b
    Commands:
      agent    Start interactive configuration assistant
      pr-init  Create a GitHub PR with configuration
      scan     Quick scan of repository for API artifacts
    """
    pass


@main.command()
@click.option(
    "--repo-path",
    "-r",
    type=click.Path(exists=True),
    default=".",
    help="Path to the repository to analyze (default: current directory)",
)
@click.option(
    "--api-key",
    type=str,
    envvar="OPENAI_API_KEY",
    help="OpenAI API key (or set OPENAI_API_KEY env var)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output (show tool executions)",
)
def agent(repo_path: str, api_key: str, verbose: bool):
    """Start the interactive APIsec configuration agent.

    The agent will:

    \b
    1. Scan your repository for API artifacts
    2. Infer API configuration from discovered files
    3. Ask clarifying questions to fill gaps
    4. Generate an APIsec configuration file

    \b
    Example:
        apisec agent --repo-path ./my-api
        apisec agent -r ./my-api -v
    """
    # Check for API key
    if not api_key and not os.environ.get("OPENAI_API_KEY"):
        click.echo(
            click.style("Error: ", fg="red", bold=True) +
            "OpenAI API key required. Set OPENAI_API_KEY env var or use --api-key option."
        )
        sys.exit(1)

    api_key = api_key or os.environ.get("OPENAI_API_KEY")

    try:
        if verbose:
            run_interactive_chat_verbose(working_dir=repo_path, api_key=api_key)
        else:
            run_interactive_chat(working_dir=repo_path, api_key=api_key)

    except KeyboardInterrupt:
        click.echo("\n\nInterrupted.")
        sys.exit(130)
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"))
        sys.exit(1)


@main.command("pr-init")
@click.option(
    "--repo",
    "-r",
    type=str,
    required=True,
    help="GitHub repository (format: owner/repo)",
)
@click.option(
    "--branch",
    "-b",
    type=str,
    default="apisec-config",
    help="Branch name for the PR (default: apisec-config)",
)
@click.option(
    "--config-file",
    "-c",
    type=click.Path(exists=True),
    default="apisec-config.yaml",
    help="Path to the APIsec config file to commit",
)
@click.option(
    "--config-path",
    type=str,
    default=".apisec/config.yaml",
    help="Path in repo for config file (default: .apisec/config.yaml)",
)
@click.option(
    "--token",
    "-t",
    type=str,
    envvar="GITHUB_TOKEN",
    help="GitHub personal access token (or set GITHUB_TOKEN env var)",
)
@click.option(
    "--draft",
    is_flag=True,
    help="Create as draft PR",
)
def pr_init(repo: str, branch: str, config_file: str, config_path: str, token: str, draft: bool):
    """Create a GitHub PR with the APIsec configuration.

    This command will:

    \b
    1. Create a new branch in the specified repository
    2. Commit the APIsec configuration file
    3. Open a pull request for review

    \b
    Example:
        apisec pr-init --repo myorg/my-api --config-file apisec-config.yaml
        apisec pr-init -r myorg/my-api -c config.yaml --draft
    """
    # Check for token
    if not token and not os.environ.get("GITHUB_TOKEN"):
        click.echo(
            click.style("Error: ", fg="red", bold=True) +
            "GitHub token required. Set GITHUB_TOKEN env var or use --token option."
        )
        sys.exit(1)

    click.echo(f"Creating PR for APIsec configuration")
    click.echo(f"Repository: {repo}")
    click.echo(f"Branch: {branch}")
    click.echo(f"Config file: {config_file}")
    click.echo()

    try:
        # Read config file
        config_content = Path(config_file).read_text()

        # Create PR
        pr_manager = GitHubPRManager(token=token, repo=repo)
        pr_url = pr_manager.create_config_pr(
            config_content=config_content,
            branch_name=branch,
            config_path=config_path,
            draft=draft,
        )

        if pr_url:
            click.echo(click.style("Success! ", fg="green", bold=True) + "Pull request created:")
            click.echo(f"  {pr_url}")
        else:
            click.echo(click.style("Error: ", fg="red") + "Failed to create PR")
            sys.exit(1)

    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"))
        sys.exit(1)


@main.command()
@click.option(
    "--repo-path",
    "-r",
    type=click.Path(exists=True),
    default=".",
    help="Path to the repository to scan (default: current directory)",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    help="Output as JSON",
)
def scan(repo_path: str, output_json: bool):
    """Quick scan of repository for API artifacts.

    Scans the repository and reports what API artifacts were found,
    without starting the interactive agent.

    \b
    Example:
        apisec scan --repo-path ./my-api
        apisec scan -r ./my-api --json
    """
    import json as json_module
    from .inference import scan_repo, get_artifact_summary

    try:
        artifacts = scan_repo(repo_path)
        summary = get_artifact_summary(artifacts)

        if output_json:
            click.echo(json_module.dumps({
                "artifacts": artifacts,
                "summary": summary,
            }, indent=2))
        else:
            click.echo(f"Scanning: {Path(repo_path).resolve()}\n")

            # Show found artifacts
            total = 0
            for artifact_type, files in artifacts.items():
                if files:
                    click.echo(click.style(f"  {artifact_type}:", fg="cyan"))
                    for f in files:
                        click.echo(f"    - {f}")
                    total += len(files)

            if total == 0:
                click.echo(click.style("  No API artifacts found.", fg="yellow"))
            else:
                click.echo(f"\n{summary}")

    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"))
        sys.exit(1)


if __name__ == "__main__":
    main()
