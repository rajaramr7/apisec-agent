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
    """Print a welcome banner with APIsec branding."""
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
    ║           Configuration Agent                             ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="blue bold")

    console.print()
    console.print(
        Panel(
            "[bold]Welcome to the APIsec Configuration Agent![/bold]\n\n"
            "I'll help you set up API security testing by:\n"
            "  [cyan]1.[/cyan] Scanning your repository for API artifacts\n"
            "  [cyan]2.[/cyan] Analyzing OpenAPI specs, Postman collections, and logs\n"
            "  [cyan]3.[/cyan] Inferring authentication and authorization patterns\n"
            "  [cyan]4.[/cyan] Generating an APIsec configuration file\n\n"
            "[dim]Type [bold]'exit'[/bold] or [bold]'quit'[/bold] to stop, "
            "[bold]'help'[/bold] for commands[/dim]",
            border_style="blue",
            padding=(1, 2),
        )
    )
    console.print()


def print_agent_message(message: str) -> None:
    """Format and print agent responses with syntax highlighting.

    Args:
        message: The agent's response message (may contain markdown)
    """
    console.print()

    # Create a panel with the agent's response
    # Use Markdown rendering for nice formatting
    md = Markdown(message)

    console.print(
        Panel(
            md,
            title="[bold blue]APIsec Agent[/bold blue]",
            title_align="left",
            border_style="blue",
            padding=(1, 2),
        )
    )


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


def run_interactive_chat(working_dir: str = ".", api_key: Optional[str] = None) -> None:
    """Run the interactive chat loop.

    Args:
        working_dir: Path to the repository to analyze
        api_key: OpenAI API key (uses env var if not provided)
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

    # Show repository info
    print_info(f"Repository: [bold]{working_path}[/bold]")
    console.print()

    # Create agent
    try:
        agent = APIsecAgent(
            openai_api_key=api_key,
            working_dir=str(working_path),
        )
    except Exception as e:
        print_error(f"Failed to initialize agent: {e}")
        sys.exit(1)

    # Send initial message to trigger repo scan
    print_info("Starting repository analysis...")

    with print_thinking():
        try:
            initial_response = agent.chat(
                "I want to set up API security testing for my repository. "
                "Please scan it and tell me what you find."
            )
        except Exception as e:
            print_error(f"Failed to analyze repository: {e}")
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


def run_interactive_chat_verbose(working_dir: str = ".", api_key: Optional[str] = None) -> None:
    """Run interactive chat with verbose tool execution output.

    Args:
        working_dir: Path to the repository to analyze
        api_key: OpenAI API key (uses env var if not provided)
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

    # Show repository info
    print_info(f"Repository: [bold]{working_path}[/bold]")
    print_info("Verbose mode: Tool executions will be shown")
    console.print()

    # Create verbose agent
    try:
        agent = VerboseAPIsecAgent(
            openai_api_key=api_key,
            working_dir=str(working_path),
        )
    except Exception as e:
        print_error(f"Failed to initialize agent: {e}")
        sys.exit(1)

    # Send initial message
    print_info("Starting repository analysis...")
    console.print()

    with print_thinking():
        try:
            initial_response = agent.chat(
                "I want to set up API security testing for my repository. "
                "Please scan it and tell me what you find."
            )
        except Exception as e:
            print_error(f"Failed to analyze repository: {e}")
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
