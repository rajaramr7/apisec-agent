"""CLI entry point for APIsec Agent."""

import click

from . import __version__


@click.group()
@click.version_option(version=__version__, prog_name="apisec")
def main():
    """APIsec Agent - AI-powered API security testing configuration.

    This tool helps developers configure API security testing through
    conversation and inference. It analyzes your API artifacts (OpenAPI specs,
    Postman collections, logs) and generates configuration for APIsec.
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
    "--config-output",
    "-o",
    type=click.Path(),
    default="apisec-config.yaml",
    help="Output path for generated config (default: apisec-config.yaml)",
)
@click.option(
    "--model",
    "-m",
    type=str,
    default="gpt-4",
    help="LLM model to use (default: gpt-4)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
def agent(repo_path: str, config_output: str, model: str, verbose: bool):
    """Start the interactive APIsec configuration agent.

    The agent will:
    1. Scan your repository for API artifacts
    2. Infer API configuration from discovered files
    3. Ask clarifying questions to fill gaps
    4. Generate an APIsec configuration file

    Example:
        apisec agent --repo-path ./my-api --config-output config.yaml
    """
    click.echo(f"Starting APIsec Agent v{__version__}")
    click.echo(f"Repository: {repo_path}")
    click.echo(f"Output: {config_output}")
    click.echo(f"Model: {model}")

    # TODO: Implement agent logic
    click.echo("\n[Agent implementation pending]")


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
    "--draft",
    is_flag=True,
    help="Create as draft PR",
)
def pr_init(repo: str, branch: str, config_file: str, draft: bool):
    """Create a GitHub PR with the APIsec configuration.

    This command will:
    1. Create a new branch in the specified repository
    2. Commit the APIsec configuration file
    3. Open a pull request for review

    Example:
        apisec pr-init --repo myorg/my-api --config-file apisec-config.yaml
    """
    click.echo(f"Creating PR for APIsec configuration")
    click.echo(f"Repository: {repo}")
    click.echo(f"Branch: {branch}")
    click.echo(f"Config file: {config_file}")
    click.echo(f"Draft: {draft}")

    # TODO: Implement PR creation logic
    click.echo("\n[PR creation implementation pending]")


if __name__ == "__main__":
    main()
