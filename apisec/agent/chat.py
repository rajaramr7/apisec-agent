"""Terminal chat interface using Rich library."""

import os
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.status import Status
from rich.syntax import Syntax
from rich.text import Text
from rich.theme import Theme

from .llm import APIsecAgent
from ..tools import get_registry

# Custom theme for consistent styling
APISEC_THEME = Theme({
    "info": "cyan",
    "success": "green",
    "warning": "yellow",
    "error": "red bold",
    "agent": "blue",
    "user": "green",
    "tool": "magenta",
})

# Global console instance
console = Console(theme=APISEC_THEME)


def print_welcome() -> None:
    """Print welcome banner with APIsec branding."""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║     █████╗ ██████╗ ██╗███████╗███████╗ ██████╗           ║
    ║    ██╔══██╗██╔══██╗██║██╔════╝██╔════╝██╔════╝           ║
    ║    ███████║██████╔╝██║███████╗█████╗  ██║                ║
    ║    ██╔══██║██╔═══╝ ██║╚════██║██╔══╝  ██║                ║
    ║    ██║  ██║██║     ██║███████║███████╗╚██████╗           ║
    ║    ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝ ╚═════╝           ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="blue bold")
    console.print()


def print_agent_message(message: str) -> None:
    """Format and print agent responses with syntax highlighting.

    Args:
        message: The agent's response message (may contain markdown)
    """
    console.print()

    # Print header
    console.print("[bold blue]━━━ APIsec Agent ━━━[/bold blue]")
    console.print()

    # Render markdown directly (not in a panel) for better line wrapping
    md = Markdown(message)
    console.print(md)

    # Print footer
    console.print()
    console.print("[blue]━" * 40 + "[/blue]")


def print_user_prompt() -> str:
    """Show prompt for user input and return the input.

    Returns:
        User's input string, or empty string if interrupted
    """
    console.print()
    try:
        user_input = Prompt.ask("[bold green]You[/bold green]")
        return user_input.strip()
    except (KeyboardInterrupt, EOFError):
        return ""


def print_thinking() -> Status:
    """Show a thinking indicator.

    Returns:
        Rich Status context manager
    """
    return console.status(
        "[bold blue]Thinking...[/bold blue]",
        spinner="dots",
        spinner_style="blue",
    )


def print_tool_execution(tool_name: str) -> None:
    """Show which tool is being executed.

    Args:
        tool_name: Name of the tool being executed
    """
    tool_icons = {
        "scan_repo": "🔍",
        "parse_openapi": "📄",
        "parse_postman": "📮",
        "parse_logs": "📊",
        "parse_env": "⚙️",
        "generate_config": "📝",
        "create_pr": "🚀",
    }

    icon = tool_icons.get(tool_name, "🔧")
    console.print(f"  {icon} [magenta]Executing:[/magenta] [bold]{tool_name}[/bold]")


def print_success(message: str) -> None:
    """Print a success message with green checkmark.

    Args:
        message: Success message to display
    """
    console.print(f"[green]✓[/green] {message}")


def print_error(message: str) -> None:
    """Print an error message with red X.

    Args:
        message: Error message to display
    """
    console.print(f"[red]✗[/red] [red]{message}[/red]")


def print_warning(message: str) -> None:
    """Print a warning message.

    Args:
        message: Warning message to display
    """
    console.print(f"[yellow]⚠[/yellow] [yellow]{message}[/yellow]")


def print_info(message: str) -> None:
    """Print an info message.

    Args:
        message: Info message to display
    """
    console.print(f"[cyan]ℹ[/cyan] {message}")


def print_config_summary(config_path: str) -> None:
    """Show summary of generated config and next steps.

    Args:
        config_path: Path to the generated config file
    """
    config_file = Path(config_path)

    if not config_file.exists():
        print_error(f"Config file not found: {config_path}")
        return

    # Read and display the config
    config_content = config_file.read_text()

    console.print()
    console.print(
        Panel(
            Syntax(config_content, "yaml", theme="monokai", line_numbers=True),
            title="[bold green]Generated Configuration[/bold green]",
            title_align="left",
            border_style="green",
        )
    )

    console.print()
    console.print(
        Panel(
            "[bold]Next Steps:[/bold]\n\n"
            f"[cyan]1.[/cyan] Review the configuration at [bold]{config_path}[/bold]\n"
            "[cyan]2.[/cyan] Set up environment variables for credentials\n"
            "[cyan]3.[/cyan] Run [bold]apisec pr-init[/bold] to create a GitHub PR\n"
            "[cyan]4.[/cyan] Merge the PR to enable security testing\n\n"
            "[dim]For more information, visit https://apisec.ai/docs[/dim]",
            title="[bold cyan]What's Next?[/bold cyan]",
            title_align="left",
            border_style="cyan",
        )
    )


def print_help() -> None:
    """Print help information about available commands."""
    console.print()
    console.print(
        Panel(
            "[bold]Available Commands:[/bold]\n\n"
            "  [cyan]exit, quit, q[/cyan]  - Exit the agent\n"
            "  [cyan]help, ?[/cyan]        - Show this help message\n"
            "  [cyan]history[/cyan]        - Show conversation history\n"
            "  [cyan]clear[/cyan]          - Clear the screen\n"
            "  [cyan]done[/cyan]           - Generate config with current info\n"
            "  [cyan]config[/cyan]         - Show generated config if available\n\n"
            "[bold]Tips:[/bold]\n\n"
            "  • The agent will automatically scan your repository\n"
            "  • Answer questions to help configure security testing\n"
            "  • You can ask the agent to explain any concepts\n"
            "  • Type 'done' when ready to generate the config file",
            title="[bold blue]Help[/bold blue]",
            title_align="left",
            border_style="blue",
        )
    )


def print_history(history: list) -> None:
    """Print conversation history summary.

    Args:
        history: List of conversation messages
    """
    console.print()
    console.print(f"[bold]Conversation History[/bold] ({len(history)} messages)")
    console.print()

    for i, msg in enumerate(history):
        role = msg.get("role", "unknown")
        content = msg.get("content", "")

        if role == "user":
            style = "green"
            prefix = "You"
        elif role == "assistant":
            style = "blue"
            prefix = "Agent"
        elif role == "tool":
            style = "magenta"
            prefix = "Tool"
        else:
            style = "dim"
            prefix = role

        if content:
            preview = content[:80] + "..." if len(content) > 80 else content
            preview = preview.replace("\n", " ")
            console.print(f"  [{style}]{i+1}. {prefix}:[/{style}] {preview}")
        elif msg.get("tool_calls"):
            tools = [tc["function"]["name"] for tc in msg["tool_calls"]]
            console.print(f"  [{style}]{i+1}. {prefix}:[/{style}] [tool calls: {', '.join(tools)}]")

    console.print()


def print_goodbye() -> None:
    """Print a friendly goodbye message."""
    console.print()
    console.print(
        Panel(
            "[bold]Thanks for using APIsec Agent![/bold]\n\n"
            "Your configuration has been saved (if generated).\n"
            "Run [cyan]apisec pr-init[/cyan] to create a pull request.\n\n"
            "[dim]Happy secure coding! 🔐[/dim]",
            border_style="blue",
        )
    )


def get_grounding_message(working_path: Path) -> str:
    """Get the initial grounding message for the agent.

    Dynamically builds capabilities from the tool registry.

    Args:
        working_path: The current working directory path

    Returns:
        The grounding prompt to send to the agent
    """
    # Get available tools from registry
    registry = get_registry()
    tool_info = registry.build_opening_message_tools()

    # Build capabilities list based on actual working tools
    capabilities = []

    # Check for version control tools
    if registry.is_available("clone_github_repo"):
        capabilities.append("• GitHub repo or local folder")
    if registry.is_available("clone_gitlab_repo"):
        capabilities.append("• GitLab repositories")
    if registry.is_available("clone_bitbucket_repo"):
        capabilities.append("• Bitbucket repositories")

    # Check for spec parsing
    if registry.is_available("parse_openapi"):
        capabilities.append("• OpenAPI/Swagger specs")

    # Check for API client tools
    api_clients = []
    if registry.is_available("parse_postman") or registry.is_available("parse_postman_collection_v2"):
        api_clients.append("Postman")
    if registry.is_available("parse_insomnia"):
        api_clients.append("Insomnia")
    if registry.is_available("parse_bruno"):
        api_clients.append("Bruno")
    if api_clients:
        capabilities.append(f"• API clients ({', '.join(api_clients)})")

    # Check for test parsers
    if registry.is_available("parse_integration_tests"):
        capabilities.append("• Integration tests (I'll grab the working payloads)")
    if registry.is_available("parse_jest_tests"):
        capabilities.append("• Jest/Supertest tests")
    if registry.is_available("parse_fixtures"):
        capabilities.append("• Test fixtures (I'll find real IDs, not placeholders)")

    # Check for environment tools
    if registry.is_available("parse_env_file_v2") or registry.is_available("scan_env_files"):
        capabilities.append("• Environment files (.env) with credentials")

    # Check for HAR files
    if registry.is_available("parse_har_file"):
        capabilities.append("• HAR files (from browser DevTools/proxies)")

    # Check for API gateways
    gateways = []
    if registry.is_available("fetch_kong_config"):
        gateways.append("Kong")
    if registry.is_available("fetch_aws_api_gateway"):
        gateways.append("AWS API Gateway")
    if gateways:
        capabilities.append(f"• API gateways ({', '.join(gateways)})")

    # Check for secret managers
    secrets = []
    if registry.is_available("fetch_vault_credentials"):
        secrets.append("Vault")
    if registry.is_available("fetch_aws_secret"):
        secrets.append("AWS Secrets")
    if secrets:
        capabilities.append(f"• Secret managers ({', '.join(secrets)})")

    capabilities_text = "\n".join(capabilities) if capabilities else "• Local folders and files"

    # Build source options
    sources = []
    sources.append(f"• **Local:** `{working_path}` or any path")
    if registry.is_available("clone_github_repo"):
        sources.append("• **GitHub:** `acme-corp/orders-api`")
    if registry.is_available("clone_gitlab_repo"):
        sources.append("• **GitLab:** `group/project`")
    if registry.is_available("clone_bitbucket_repo"):
        sources.append("• **Bitbucket:** `workspace/repo`")
    if registry.is_available("fetch_postman_workspace"):
        sources.append("• **Postman workspace:** provide your Postman API key")
    sources.append("• **Spec URL:** `https://api.example.com/openapi.json`")

    sources_text = "\n".join(sources)

    # Count available tools
    available_count = len(registry.list_available())

    return f"""The user has just started the APIsec agent.

Display this exact opening message. Format bullet points on separate lines:

---

Hey! I'll generate an API security testing config by scanning your existing code and artifacts.

**I can pull from what you already have ({available_count} tools available):**

{capabilities_text}

**By the end, you'll have a config with:**

• Real endpoints & payloads that actually work
• Valid test IDs and tokens (I'll check they're not expired)
• BOLA tests auto-generated from ownership data

**Let's go! Point me to your code:**

{sources_text}

---

Wait for their response. When they provide a path, IMMEDIATELY call `scan_repo` with that path. Do not describe what you will do - just do it."""


def run_interactive_chat(working_dir: str = ".", api_key: Optional[str] = None, model: Optional[str] = None) -> None:
    """Run the interactive chat loop.

    Args:
        working_dir: Path to the repository to analyze
        api_key: OpenAI API key (uses env var if not provided)
        model: OpenAI model to use (default: gpt-4o)
    """
    # Get API key
    api_key = api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print_error("OpenAI API key required. Set OPENAI_API_KEY or use --api-key option.")
        sys.exit(1)

    # Resolve working directory
    working_path = Path(working_dir).resolve()

    # Print welcome
    print_welcome()

    # Create agent
    try:
        agent = APIsecAgent(
            openai_api_key=api_key,
            working_dir=str(working_path),
        )
        if model:
            agent.set_model(model)
    except Exception as e:
        print_error(f"Failed to initialize agent: {e}")
        sys.exit(1)

    # Send grounding message - ask ONE question first
    with print_thinking():
        try:
            initial_response = agent.chat(get_grounding_message(working_path))
        except Exception as e:
            print_error(f"Failed to start agent: {e}")
            sys.exit(1)

    print_agent_message(initial_response)

    # Main chat loop
    while True:
        try:
            # Get user input
            user_input = print_user_prompt()

            # Handle empty input
            if not user_input:
                continue

            # Handle special commands
            cmd = user_input.lower().strip()

            if cmd in ("exit", "quit", "q"):
                print_goodbye()
                break

            if cmd in ("help", "?"):
                print_help()
                continue

            if cmd == "history":
                print_history(agent.get_conversation_history())
                continue

            if cmd == "clear":
                console.clear()
                print_welcome()
                continue

            if cmd == "config":
                config_path = working_path / "apisec-config.yaml"
                if config_path.exists():
                    print_config_summary(str(config_path))
                else:
                    print_warning("No configuration generated yet. Continue the conversation to generate one.")
                continue

            if cmd == "done":
                user_input = "Please generate the APIsec configuration file now with what we have so far."

            # Send message to agent
            with print_thinking():
                try:
                    response = agent.chat(user_input)
                except Exception as e:
                    print_error(f"Error: {e}")
                    continue

            print_agent_message(response)

            # Check if config was generated
            config_path = working_path / "apisec-config.yaml"
            if config_path.exists() and "generate_config" in str(agent.get_conversation_history()[-5:]):
                print_success(f"Configuration saved to: {config_path}")

        except KeyboardInterrupt:
            console.print()
            print_warning("Interrupted. Type 'exit' to quit or continue chatting.")
            continue

        except EOFError:
            print_goodbye()
            break


# Verbose version that shows tool execution
class VerboseAPIsecAgent(APIsecAgent):
    """APIsec Agent with verbose output for tool execution."""

    def process_tool_calls(self, tool_calls: list):
        """Process tool calls with verbose output."""
        for tc in tool_calls:
            print_tool_execution(tc.function.name)

        return super().process_tool_calls(tool_calls)


def run_interactive_chat_verbose(working_dir: str = ".", api_key: Optional[str] = None, model: Optional[str] = None) -> None:
    """Run interactive chat with verbose tool execution output.

    Args:
        working_dir: Path to the repository to analyze
        api_key: OpenAI API key (uses env var if not provided)
        model: OpenAI model to use (default: gpt-4o)
    """
    # Get API key
    api_key = api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print_error("OpenAI API key required. Set OPENAI_API_KEY or use --api-key option.")
        sys.exit(1)

    # Resolve working directory
    working_path = Path(working_dir).resolve()

    # Print welcome
    print_welcome()
    print_info("Verbose mode enabled")
    console.print()

    # Create verbose agent
    try:
        agent = VerboseAPIsecAgent(
            openai_api_key=api_key,
            working_dir=str(working_path),
        )
        if model:
            agent.set_model(model)
    except Exception as e:
        print_error(f"Failed to initialize agent: {e}")
        sys.exit(1)

    # Send grounding message - ask ONE question first
    with print_thinking():
        try:
            initial_response = agent.chat(get_grounding_message(working_path))
        except Exception as e:
            print_error(f"Failed to start agent: {e}")
            sys.exit(1)

    print_agent_message(initial_response)

    # Main chat loop (same as non-verbose)
    while True:
        try:
            user_input = print_user_prompt()

            if not user_input:
                continue

            cmd = user_input.lower().strip()

            if cmd in ("exit", "quit", "q"):
                print_goodbye()
                break

            if cmd in ("help", "?"):
                print_help()
                continue

            if cmd == "history":
                print_history(agent.get_conversation_history())
                continue

            if cmd == "clear":
                console.clear()
                print_welcome()
                continue

            if cmd == "config":
                config_path = working_path / "apisec-config.yaml"
                if config_path.exists():
                    print_config_summary(str(config_path))
                else:
                    print_warning("No configuration generated yet.")
                continue

            if cmd == "done":
                user_input = "Please generate the APIsec configuration file now with what we have so far."

            console.print()
            with print_thinking():
                try:
                    response = agent.chat(user_input)
                except Exception as e:
                    print_error(f"Error: {e}")
                    continue

            print_agent_message(response)

            config_path = working_path / "apisec-config.yaml"
            if config_path.exists():
                # Check if config was just generated
                history = agent.get_conversation_history()
                recent = str(history[-5:]) if len(history) >= 5 else str(history)
                if "generate_config" in recent:
                    print_success(f"Configuration saved to: {config_path}")

        except KeyboardInterrupt:
            console.print()
            print_warning("Interrupted. Type 'exit' to quit or continue chatting.")
            continue

        except EOFError:
            print_goodbye()
            break
