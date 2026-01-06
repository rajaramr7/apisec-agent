"""Chat agent for interactive API configuration."""

import json
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax

from .llm import LLMClient
from .tools import AgentTools


class ChatAgent:
    """Interactive chat agent for API security configuration.

    The agent guides developers through configuring API security testing
    by asking questions and inferring from available artifacts.
    """

    def __init__(
        self,
        llm_client: LLMClient,
        tools: AgentTools,
        console: Optional[Console] = None,
        verbose: bool = False,
    ):
        """Initialize the chat agent.

        Args:
            llm_client: LLM client for generating responses
            tools: Agent tools for file operations and inference
            console: Rich console for output (optional)
            verbose: Enable verbose output for debugging
        """
        self.llm = llm_client
        self.tools = tools
        self.console = console or Console()
        self.verbose = verbose
        self.conversation_history: List[Dict[str, Any]] = []
        self.config_generated = False

    def start(self, repo_path: str) -> Optional[Dict[str, Any]]:
        """Start the interactive chat session.

        Args:
            repo_path: Path to the repository to analyze

        Returns:
            Generated configuration dict or None if user exits
        """
        self.console.print(Panel.fit(
            "[bold blue]APIsec Configuration Agent[/bold blue]\n\n"
            "I'll help you set up API security testing by analyzing your repo\n"
            "and asking a few questions. Type 'quit' or 'exit' to stop.",
            border_style="blue",
        ))
        self.console.print()

        # Initial message to start the conversation
        initial_message = f"I'm looking at the repository at `{repo_path}`. Let me scan for API artifacts..."

        self.console.print(Markdown(initial_message))
        self.console.print()

        # Add initial user context
        self.conversation_history.append({
            "role": "user",
            "content": f"I want to set up API security testing for my repository at {repo_path}. Please analyze it and help me configure APIsec.",
        })

        # Run initial tool calls to scan the repo
        self._run_agent_turn()

        # Main chat loop
        while not self.config_generated:
            try:
                user_input = Prompt.ask("\n[bold green]You[/bold green]")

                if user_input.lower() in ("quit", "exit", "q"):
                    self.console.print("\n[yellow]Exiting without saving configuration.[/yellow]")
                    return None

                if user_input.lower() == "done":
                    # Force config generation
                    self.conversation_history.append({
                        "role": "user",
                        "content": "Please generate the configuration file now with what we have so far.",
                    })
                else:
                    self.conversation_history.append({
                        "role": "user",
                        "content": user_input,
                    })

                self._run_agent_turn()

            except KeyboardInterrupt:
                self.console.print("\n\n[yellow]Interrupted. Exiting.[/yellow]")
                return None
            except EOFError:
                self.console.print("\n\n[yellow]Exiting.[/yellow]")
                return None

        return self.tools.get_generated_config()

    def _run_agent_turn(self) -> None:
        """Run a single agent turn with possible tool calls."""
        tool_defs = self.tools.get_tool_definitions()
        max_iterations = 10  # Prevent infinite loops

        for _ in range(max_iterations):
            # Get LLM response
            response = self.llm.chat(self.conversation_history, tools=tool_defs)

            # Check for tool calls
            if response.get("tool_calls"):
                # Add assistant message with tool calls to history
                self.conversation_history.append(response)

                # Execute each tool call
                for tool_call in response["tool_calls"]:
                    tool_name = tool_call["function"]["name"]
                    try:
                        arguments = json.loads(tool_call["function"]["arguments"])
                    except json.JSONDecodeError:
                        arguments = {}

                    if self.verbose:
                        self.console.print(f"[dim]Calling tool: {tool_name}[/dim]")
                        if arguments:
                            self.console.print(f"[dim]Arguments: {arguments}[/dim]")

                    # Execute tool
                    result = self.tools.execute_tool(tool_name, arguments)

                    if self.verbose:
                        # Show truncated result
                        result_preview = result[:500] + "..." if len(result) > 500 else result
                        self.console.print(f"[dim]Result: {result_preview}[/dim]")

                    # Add tool result to history
                    self.conversation_history.append({
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "content": result,
                    })

                    # Check if config was generated
                    if tool_name == "generate_config":
                        self.config_generated = True

                # Continue loop to get next response after tool execution
                continue

            # No tool calls - display content and break
            if response.get("content"):
                self.conversation_history.append({
                    "role": "assistant",
                    "content": response["content"],
                })
                self.console.print()
                self.console.print(Markdown(response["content"]))

            break

    def process_message(self, message: str) -> str:
        """Process a single user message and get response.

        Args:
            message: User input message

        Returns:
            Agent response text
        """
        self.conversation_history.append({
            "role": "user",
            "content": message,
        })

        self._run_agent_turn()

        # Return the last assistant message
        for msg in reversed(self.conversation_history):
            if msg.get("role") == "assistant" and msg.get("content"):
                return msg["content"]

        return ""

    def get_config(self) -> Optional[Dict[str, Any]]:
        """Get the generated configuration if available.

        Returns:
            Configuration dictionary or None
        """
        return self.tools.get_generated_config()

    def save_config(self, output_path: str) -> bool:
        """Save the generated configuration to a file.

        Args:
            output_path: Path to save the configuration

        Returns:
            True if saved successfully
        """
        config = self.tools.get_generated_config()
        if not config:
            self.console.print("[red]No configuration to save.[/red]")
            return False

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        self.console.print(f"\n[green]Configuration saved to: {output_path}[/green]")

        # Show the config
        self.console.print()
        yaml_content = yaml.dump(config, default_flow_style=False, sort_keys=False)
        self.console.print(Panel(
            Syntax(yaml_content, "yaml", theme="monokai"),
            title="Generated Configuration",
            border_style="green",
        ))

        return True

    def get_conversation_summary(self) -> str:
        """Get a summary of the conversation.

        Returns:
            Summary string
        """
        user_messages = sum(1 for m in self.conversation_history if m.get("role") == "user")
        assistant_messages = sum(1 for m in self.conversation_history if m.get("role") == "assistant")
        tool_calls = sum(1 for m in self.conversation_history if m.get("role") == "tool")

        return (
            f"Conversation: {user_messages} user messages, "
            f"{assistant_messages} assistant responses, "
            f"{tool_calls} tool calls"
        )


def create_agent(
    repo_path: str,
    model: str = "gpt-4",
    api_key: Optional[str] = None,
    verbose: bool = False,
) -> ChatAgent:
    """Create a configured chat agent.

    Args:
        repo_path: Path to the repository to analyze
        model: LLM model to use
        api_key: OpenAI API key (optional)
        verbose: Enable verbose output

    Returns:
        Configured ChatAgent instance
    """
    tools = AgentTools(repo_path)
    llm = LLMClient(model=model, api_key=api_key)

    return ChatAgent(
        llm_client=llm,
        tools=tools,
        verbose=verbose,
    )
