"""CLI entry point for APIsec Agent."""

# Suppress urllib3 SSL warning on macOS (LibreSSL vs OpenSSL)
import warnings
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")

import os
import sys
from pathlib import Path

import click

from . import __version__
from .agent import run_interactive_chat, run_interactive_chat_verbose
from .inference import scan_repo, infer_api_config, generate_apisec_config
from .pr.github import get_repo_info, create_config_pr, generate_pr_body


def detect_api_project(path: Path) -> dict:
    """Detect if path contains API artifacts.

    Returns dict with detected artifacts and whether it looks like an API project.
    Only scans 2 levels deep to avoid slow scans on large directories like home.
    """
    # Skip detection for home directory or root - too slow
    home = Path.home()
    if path == home or path == Path("/"):
        return {
            "is_api_project": False,
            "artifacts": {},
            "total_count": 0,
        }

    # Quick shallow scan - only 2 levels deep
    indicators = {
        "openapi": (
            list(path.glob("openapi.yaml")) + list(path.glob("openapi.json")) +
            list(path.glob("*/openapi.yaml")) + list(path.glob("*/openapi.json")) +
            list(path.glob("docs/openapi.yaml")) + list(path.glob("api/openapi.yaml")) +
            list(path.glob("swagger.yaml")) + list(path.glob("swagger.json"))
        ),
        "postman": list(path.glob("*.postman_collection.json")) + list(path.glob("*/*.postman_collection.json")),
        "postman_env": list(path.glob("*.postman_environment.json")) + list(path.glob("*/*.postman_environment.json")),
        "fixtures": list(path.glob("fixtures/*.json")) + list(path.glob("fixtures/*.yaml")),
        "tests": list(path.glob("tests/*.py")) + list(path.glob("test/*.py")),
        "env_files": list(path.glob(".env")) + list(path.glob(".env.*")),
    }

    total_artifacts = sum(len(v) for v in indicators.values())

    return {
        "is_api_project": total_artifacts > 0,
        "artifacts": indicators,
        "total_count": total_artifacts,
    }


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="apisec")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True),
    default=".",
    help="Path to the repository",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
@click.option(
    "--slow",
    "-s",
    is_flag=True,
    help="Use slower but more capable model (gpt-4o instead of gpt-4o-mini)",
)
@click.pass_context
def cli(ctx, path: str, verbose: bool, slow: bool):
    """APIsec Agent — Configure API security testing through conversation.

    Run 'apisec' to start the interactive agent.
    Run 'apisec discover' to scan for API artifacts.
    Run 'apisec pr-init' to create a PR with config.
    """
    # If a subcommand is invoked, let it handle things
    if ctx.invoked_subcommand is not None:
        return

    # Default behavior: start the agent chat
    _run_agent(path, verbose, slow)


def _run_agent(path: str, verbose: bool, slow: bool = False):
    """Run the interactive agent chat."""
    # Validate OPENAI_API_KEY is set
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        click.echo(
            click.style("Error: ", fg="red", bold=True)
            + "OPENAI_API_KEY environment variable is required.\n"
            + "Set it with: export OPENAI_API_KEY=sk-..."
        )
        sys.exit(1)

    # Validate path is a directory
    repo_path = Path(path).resolve()
    if not repo_path.is_dir():
        click.echo(
            click.style("Error: ", fg="red", bold=True)
            + f"Path is not a directory: {repo_path}"
        )
        sys.exit(1)

    # Detect if this looks like an API project
    detection = detect_api_project(repo_path)

    # Determine model - fast (gpt-4o-mini) is default
    model = "gpt-4o" if slow else "gpt-4o-mini"

    try:
        if verbose:
            run_interactive_chat_verbose(working_dir=str(repo_path), api_key=api_key, model=model)
        else:
            run_interactive_chat(working_dir=str(repo_path), api_key=api_key, model=model)

    except KeyboardInterrupt:
        click.echo("\n\nInterrupted. Goodbye!")
        sys.exit(130)
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"))
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True),
    default=".",
    help="Path to the repository",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
def agent(path: str, verbose: bool):
    """Start interactive configuration chat.

    The agent will:

    \b
    1. Scan your repository for API artifacts
    2. Infer API configuration from discovered files
    3. Ask clarifying questions to fill gaps
    4. Generate an APIsec configuration file

    \b
    Example:
        apisec agent --path ./my-api
        apisec agent -p ./my-api -v
    """
    _run_agent(path, verbose)


@cli.command("pr-init")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True),
    default=".",
    help="Path to the repository",
)
@click.option(
    "--token",
    "-t",
    envvar="GITHUB_TOKEN",
    help="GitHub personal access token (or set GITHUB_TOKEN env var)",
)
@click.option(
    "--branch",
    "-b",
    default="apisec-init",
    help="Branch name for the PR",
)
def pr_init(path: str, token: str, branch: str):
    """Create a PR with scaffolded configuration.

    This command will:

    \b
    1. Scan the repository for API artifacts
    2. Infer configuration from discovered files
    3. Generate an APIsec config with TODOs for missing items
    4. Create a GitHub pull request

    \b
    Example:
        apisec pr-init --path ./my-api
        apisec pr-init -p ./my-api --token ghp_xxx
        apisec pr-init -p ./my-api -b feature/apisec-setup
    """
    # Validate OPENAI_API_KEY is set (needed for inference)
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        click.echo(
            click.style("Error: ", fg="red", bold=True)
            + "OPENAI_API_KEY environment variable is required.\n"
            + "Set it with: export OPENAI_API_KEY=sk-..."
        )
        sys.exit(1)

    # Validate GitHub token is provided
    if not token:
        click.echo(
            click.style("Error: ", fg="red", bold=True)
            + "GitHub token required. Set GITHUB_TOKEN env var or use --token option."
        )
        sys.exit(1)

    # Validate path exists
    repo_path = Path(path).resolve()
    if not repo_path.exists():
        click.echo(
            click.style("Error: ", fg="red", bold=True)
            + f"Path does not exist: {repo_path}"
        )
        sys.exit(1)

    try:
        # Get repo info first to validate it's a git repo
        click.echo(f"Analyzing repository: {repo_path}")
        try:
            owner, repo_name = get_repo_info(str(repo_path))
            click.echo(f"  Repository: {owner}/{repo_name}")
        except ValueError as e:
            click.echo(click.style(f"Error: {e}", fg="red"))
            sys.exit(1)

        # Step 1: Scan repository for artifacts
        click.echo("\nScanning for API artifacts...")
        artifacts = scan_repo(str(repo_path))

        artifact_count = sum(len(files) for files in artifacts.values())
        if artifact_count == 0:
            click.echo(
                click.style("Warning: ", fg="yellow")
                + "No API artifacts found. Creating minimal configuration."
            )

        for artifact_type, files in artifacts.items():
            if files:
                click.echo(f"  Found {len(files)} {artifact_type} file(s)")

        # Step 2: Infer configuration
        click.echo("\nInferring API configuration...")
        inferred = infer_api_config(str(repo_path), artifacts)

        # Track what was inferred vs what needs manual input
        inferred_items = {}
        todos = []

        # Check what was auto-configured
        if inferred.get("api_name"):
            inferred_items["api_name"] = inferred["api_name"]
            click.echo(f"  API Name: {inferred['api_name']}")
        else:
            todos.append("Set the API name in config")

        if inferred.get("base_url"):
            inferred_items["base_url"] = inferred["base_url"]
            click.echo(f"  Base URL: {inferred['base_url']}")
        else:
            todos.append("Configure the API base URL")

        if inferred.get("auth"):
            auth_type = inferred["auth"].get("type", "none")
            inferred_items["auth_type"] = auth_type
            click.echo(f"  Auth Type: {auth_type}")
            if auth_type != "none":
                todos.append("Add authentication credentials to CI/CD secrets")
        else:
            todos.append("Configure authentication settings")

        if inferred.get("spec_path"):
            inferred_items["spec_path"] = inferred["spec_path"]
            click.echo(f"  OpenAPI Spec: {inferred['spec_path']}")

        endpoints = inferred.get("endpoints", [])
        if endpoints:
            inferred_items["endpoints"] = len(endpoints)
            click.echo(f"  Endpoints: {len(endpoints)} discovered")

        users = inferred.get("users", [])
        if users:
            inferred_items["users"] = users
            click.echo(f"  Test Users: {len(users)} found")
            todos.append("Confirm BOLA test user mappings are correct")
        else:
            todos.append("Configure test users for BOLA testing")

        # Always add these TODOs
        todos.append("Review and customize security test settings")

        # Step 3: Generate config
        click.echo("\nGenerating configuration...")
        config_content = generate_apisec_config(inferred)

        # Step 4: Create PR
        click.echo(f"\nCreating pull request on branch '{branch}'...")

        pr_body = generate_pr_body(inferred_items, todos)

        pr_url = create_config_pr(
            repo_path=str(repo_path),
            config_content=config_content,
            github_token=token,
            branch_name=branch,
            pr_title="[APIsec] Initialize security testing configuration",
            pr_body=pr_body,
        )

        click.echo()
        click.echo(click.style("Success! ", fg="green", bold=True) + "Pull request created:")
        click.echo(f"  {pr_url}")
        click.echo()
        click.echo("Next steps:")
        click.echo("  1. Review the PR and configuration")
        click.echo("  2. Set up required secrets in your CI/CD")
        click.echo("  3. Merge the PR to enable security testing")

    except KeyboardInterrupt:
        click.echo("\n\nInterrupted.")
        sys.exit(130)
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"))
        sys.exit(1)


@cli.command()
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True),
    default=".",
    help="Path to the repository to discover artifacts in",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    help="Output as JSON",
)
def discover(path: str, output_json: bool):
    """Discover API artifacts in a repository.

    Searches the repository for API specs, collections, logs, fixtures,
    and other artifacts useful for security testing configuration.

    \b
    Example:
        apisec discover --path ./my-api
        apisec discover -p ./my-api --json
    """
    import json as json_module
    from .inference import get_artifact_summary

    try:
        repo_path = Path(path).resolve()
        artifacts = scan_repo(str(repo_path))
        summary = get_artifact_summary(artifacts)

        if output_json:
            click.echo(
                json_module.dumps(
                    {
                        "path": str(repo_path),
                        "artifacts": artifacts,
                        "summary": summary,
                    },
                    indent=2,
                )
            )
        else:
            click.echo(f"Discovering artifacts in: {repo_path}\n")

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


@cli.command()
@click.argument("config_path", type=click.Path(exists=True))
@click.option(
    "--token",
    "-t",
    envvar="APISEC_TOKEN",
    help="APIsec API token (or set APISEC_TOKEN env var)",
)
@click.option(
    "--update",
    "-u",
    is_flag=True,
    help="Update existing API if it exists",
)
@click.option(
    "--name",
    "-n",
    help="Override API name (defaults to name in config)",
)
def upload(config_path: str, token: str, update: bool, name: str):
    """Upload a config file to APIsec platform.

    Uploads your generated config to APIsec so you can run security scans.

    \b
    Example:
        apisec upload .apisec/config.yaml
        apisec upload config.yaml --token apt_xxx
        apisec upload config.yaml --update
        apisec upload config.yaml --name "My API"
    """
    import yaml
    from .connectors.apisec_platform import APIsecPlatformConnector

    # Load config file
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        click.echo(click.style(f"Error parsing YAML: {e}", fg="red"))
        sys.exit(1)
    except Exception as e:
        click.echo(click.style(f"Error reading file: {e}", fg="red"))
        sys.exit(1)

    # Get API name from config or override
    api_name = name or config.get('api_name', config.get('name', 'unnamed-api'))

    # Get token - prompt if not provided
    if not token:
        connector = APIsecPlatformConnector()
        click.echo(connector.get_token_instructions())
        click.echo()
        token = click.prompt('', hide_input=False)

    connector = APIsecPlatformConnector(api_token=token)

    # Validate token
    click.echo('Validating token...')
    is_valid, tenant_name, error = connector.validate_token(token)

    if not is_valid:
        click.echo(click.style(f"✗ {error}", fg="red"))
        sys.exit(1)

    click.echo(click.style(f"✓ Connected to tenant: {tenant_name}", fg="green"))

    # Upload config
    click.echo(f'Uploading {api_name}...')
    result = connector.upload_config(config, api_name, update_existing=update)

    if result.success:
        click.echo()
        click.echo(click.style("✓ Upload complete!", fg="green", bold=True))
        click.echo()
        click.echo(f"{api_name} is now in APIsec and ready for security scanning.")
        click.echo()
        click.echo(f"  • View: {result.api_url}")
        click.echo(f"  • Scan: {result.scan_url}")
        click.echo()
    else:
        click.echo(click.style(f"✗ {result.error}", fg="red"))
        if 'already exists' in result.error:
            click.echo("Use --update to overwrite the existing config.")
        sys.exit(1)


# Keep 'main' as an alias for backward compatibility
main = cli


if __name__ == "__main__":
    cli()
