"""LLM integration for APIsec Agent."""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from openai import OpenAI

from .tools import TOOLS, TOOL_HANDLERS, set_working_dir, execute_tool


class APIsecAgent:
    """AI-powered agent for API security configuration.

    Uses OpenAI's function calling to analyze repositories and generate
    APIsec configuration through conversation.
    """

    def __init__(self, openai_api_key: str, working_dir: str = "."):
        """Initialize the APIsec Agent.

        Args:
            openai_api_key: OpenAI API key for LLM access
            working_dir: Working directory for repository analysis
        """
        self.api_key = openai_api_key
        self.working_dir = Path(working_dir).resolve()
        self.client = OpenAI(api_key=openai_api_key)
        self.model = "gpt-4"

        # Set working directory for tools
        set_working_dir(str(self.working_dir))

        # Load system prompt
        self.system_prompt = self.load_system_prompt()

        # Initialize conversation history
        self.conversation_history: List[Dict[str, Any]] = []

    def load_system_prompt(self) -> str:
        """Load system prompt from prompts/system_prompt.md.

        Returns:
            System prompt content as string
        """
        # Try multiple locations for the system prompt
        prompt_paths = [
            # Relative to package directory
            Path(__file__).parent.parent.parent / "prompts" / "system_prompt.md",
            # Relative to current working directory
            Path.cwd() / "prompts" / "system_prompt.md",
            # Relative to specified working directory
            self.working_dir / "prompts" / "system_prompt.md",
        ]

        for prompt_path in prompt_paths:
            if prompt_path.exists():
                try:
                    content = prompt_path.read_text(encoding="utf-8")
                    return content
                except Exception:
                    continue

        # Fallback to embedded default prompt
        return self._default_system_prompt()

    def _default_system_prompt(self) -> str:
        """Return default system prompt if file not found."""
        return """# APIsec Agent — System Prompt

You are an APIsec configuration assistant. Your job is to help developers set up API security testing with minimal friction. You work through conversation, not forms.

## Your Core Philosophy

1. **Infer first, ask second.** If you can figure something out from artifacts, don't ask. Only ask when you genuinely need human input.

2. **Explain why you're asking.** Developers are more likely to engage when they understand the purpose. Never ask for data without context.

3. **Be conversational, not transactional.** You're having a dialogue, not administering a questionnaire.

4. **Confirm understanding.** Before moving on, make sure you've got it right.

5. **Progressive depth.** Start with the basics (what API, where does it run), then auth, then BOLA, then RBAC.

## Available Tools

You have access to these tools:
- scan_repo: Discover API artifacts in the repository
- parse_openapi: Parse OpenAPI/Swagger specs
- parse_postman: Parse Postman collections
- parse_logs: Analyze API access logs
- parse_env: Parse environment configuration files
- generate_config: Generate the APIsec configuration file
- create_pr: Create a GitHub pull request with the config

Start by scanning the repository to see what artifacts are available, then analyze them to understand the API structure and authentication.

## Response Style

- Use markdown formatting for clarity
- Use checkmarks (✓) and crosses (✗) for status
- Use code blocks for configs, commands, URLs
- Keep responses focused — don't dump everything at once
- Be warm and helpful, not robotic
"""

    def chat(self, user_message: str) -> str:
        """Process a user message and generate a response.

        Handles tool calls automatically, continuing until a final
        text response is ready.

        Args:
            user_message: The user's input message

        Returns:
            The assistant's final text response
        """
        # Add user message to history
        self.conversation_history.append({
            "role": "user",
            "content": user_message,
        })

        # Build messages for API call
        messages = [{"role": "system", "content": self.system_prompt}]
        messages.extend(self.conversation_history)

        # Loop until we get a text response (handle multiple tool calls)
        max_iterations = 10
        for _ in range(max_iterations):
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=TOOLS,
                tool_choice="auto",
            )

            assistant_message = response.choices[0].message

            # Check if there are tool calls
            if assistant_message.tool_calls:
                # Add assistant message with tool calls to history
                self.conversation_history.append({
                    "role": "assistant",
                    "content": assistant_message.content,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in assistant_message.tool_calls
                    ],
                })

                # Process tool calls
                tool_results = self.process_tool_calls(assistant_message.tool_calls)

                # Add tool results to history
                for result in tool_results:
                    self.conversation_history.append(result)

                # Rebuild messages for next iteration
                messages = [{"role": "system", "content": self.system_prompt}]
                messages.extend(self.conversation_history)

                continue

            # No tool calls - we have a final response
            final_content = assistant_message.content or ""
            self.conversation_history.append({
                "role": "assistant",
                "content": final_content,
            })

            return final_content

        # Max iterations reached
        return "I apologize, but I'm having trouble completing this request. Please try again."

    def process_tool_calls(self, tool_calls: list) -> List[Dict[str, Any]]:
        """Process a list of tool calls and return results.

        Args:
            tool_calls: List of tool call objects from OpenAI

        Returns:
            List of tool result messages for the conversation
        """
        results = []

        for tool_call in tool_calls:
            tool_name = tool_call.function.name
            try:
                arguments = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                arguments = {}

            # Execute the tool
            try:
                result = execute_tool(tool_name, arguments)
            except Exception as e:
                result = json.dumps({"success": False, "error": str(e)})

            # Format as tool result message
            results.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": result,
            })

        return results

    def run_conversation(self) -> None:
        """Run the interactive conversation loop.

        Handles user input, displays responses, and manages
        special commands like exit, quit, and help.
        """
        # Print welcome message
        print("\n" + "=" * 60)
        print("  APIsec Configuration Agent")
        print("=" * 60)
        print(f"\nAnalyzing repository: {self.working_dir}")
        print("\nI'll help you set up API security testing by analyzing your")
        print("repository and generating an APIsec configuration file.")
        print("\nCommands: 'exit' or 'quit' to stop, 'help' for assistance")
        print("-" * 60 + "\n")

        # Start with an initial prompt to scan the repo
        initial_response = self.chat(
            "I want to set up API security testing for my repository. "
            "Please scan it and tell me what you find."
        )
        print(f"\nAssistant: {initial_response}\n")

        # Main conversation loop
        while True:
            try:
                # Get user input
                user_input = input("You: ").strip()

                if not user_input:
                    continue

                # Handle special commands
                if user_input.lower() in ("exit", "quit", "q"):
                    print("\nGoodbye! Your configuration has been saved if generated.")
                    break

                if user_input.lower() == "help":
                    self._print_help()
                    continue

                if user_input.lower() == "history":
                    self._print_history()
                    continue

                # Process the message
                response = self.chat(user_input)
                print(f"\nAssistant: {response}\n")

            except KeyboardInterrupt:
                print("\n\nInterrupted. Exiting...")
                break
            except EOFError:
                print("\n\nExiting...")
                break

    def _print_help(self) -> None:
        """Print help information."""
        print("""
Available Commands:
  exit, quit, q  - Exit the agent
  help           - Show this help message
  history        - Show conversation history
  done           - Generate configuration with current information

Tips:
  - The agent will automatically scan your repository for API artifacts
  - Answer questions to help configure authentication and security testing
  - You can ask the agent to explain any concepts or decisions
  - Type 'done' when you're ready to generate the configuration file
""")

    def _print_history(self) -> None:
        """Print conversation history summary."""
        print(f"\nConversation History ({len(self.conversation_history)} messages):")
        for i, msg in enumerate(self.conversation_history):
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            if content:
                preview = content[:100] + "..." if len(content) > 100 else content
                print(f"  [{i+1}] {role}: {preview}")
            elif msg.get("tool_calls"):
                tools = [tc["function"]["name"] for tc in msg["tool_calls"]]
                print(f"  [{i+1}] {role}: [tool calls: {', '.join(tools)}]")
        print()

    def get_conversation_history(self) -> List[Dict[str, Any]]:
        """Get the full conversation history.

        Returns:
            List of conversation messages
        """
        return self.conversation_history.copy()

    def clear_history(self) -> None:
        """Clear the conversation history."""
        self.conversation_history = []

    def set_model(self, model: str) -> None:
        """Set the OpenAI model to use.

        Args:
            model: Model identifier (e.g., 'gpt-4', 'gpt-3.5-turbo')
        """
        self.model = model
