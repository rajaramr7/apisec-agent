"""LLM integration for APIsec Agent."""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from openai import OpenAI

from .tools import TOOLS, TOOL_HANDLERS, set_working_dir, execute_tool
from .validator import validate_response, strip_consultant_speak
from ..tools import get_registry, ToolStatus


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
        self.model = "gpt-4o"  # Fast model with 128k context, good tool use

        # Set working directory for tools
        set_working_dir(str(self.working_dir))

        # Load system prompt
        self.system_prompt = self.load_system_prompt()

        # Initialize conversation history
        self.conversation_history: List[Dict[str, Any]] = []

        # Get tool registry for capability checking
        self._registry = get_registry()

        # Track tools called during current turn (for validator)
        self._tools_called_this_turn: List[str] = []

    def check_capability(self, user_message: str) -> Dict[str, Any]:
        """Check if the request can be fulfilled with available tools.

        Runs BEFORE the LLM to detect impossible requests early.

        Args:
            user_message: User's request text

        Returns:
            Dict with:
                - can_fulfill: bool
                - available_tools: list of available tools for request
                - missing_tools: list of tools needed but not available
                - suggestion: optional alternative suggestion
        """
        result = self._registry.check_capability(user_message)

        # Add suggestions for missing capabilities
        if not result["can_fulfill"] and result["missing_tools"]:
            missing_names = [t["name"] for t in result["missing_tools"]]
            suggestions = []

            # Suggest alternatives based on missing tools
            if "fetch_postman_workspace" in missing_names:
                suggestions.append(
                    "Postman API integration requires authentication. "
                    "You can export your Postman collection as JSON and use parse_postman instead."
                )
            if any(t in missing_names for t in ["clone_gitlab_repo", "clone_bitbucket_repo"]):
                suggestions.append(
                    "Repository cloning is available. Make sure to provide required authentication."
                )
            if any(t in missing_names for t in ["fetch_vault_credentials", "fetch_aws_secret"]):
                suggestions.append(
                    "Secret manager integration requires credentials. "
                    "You can also provide credentials directly via environment variables."
                )

            result["suggestion"] = " ".join(suggestions) if suggestions else None

        return result

    def validate_tool_calls(self, tool_calls: list) -> Dict[str, Any]:
        """Validate tool calls to catch hallucinated or unavailable tools.

        Args:
            tool_calls: List of tool call objects from OpenAI

        Returns:
            Dict with:
                - valid: bool (all calls are valid)
                - invalid_tools: list of tool names that don't exist
                - unavailable_tools: list of tools that exist but aren't available
                - valid_calls: list of validated tool calls to process
        """
        invalid_tools = []
        unavailable_tools = []
        valid_calls = []

        for tool_call in tool_calls:
            tool_name = tool_call.function.name

            # Check if tool exists
            tool_def = self._registry.get(tool_name)
            if not tool_def:
                invalid_tools.append(tool_name)
                continue

            # Check if tool is available
            if not tool_def.is_available():
                unavailable_tools.append({
                    "name": tool_name,
                    "status": tool_def.status.value,
                })
                continue

            valid_calls.append(tool_call)

        return {
            "valid": len(invalid_tools) == 0 and len(unavailable_tools) == 0,
            "invalid_tools": invalid_tools,
            "unavailable_tools": unavailable_tools,
            "valid_calls": valid_calls,
        }

    def build_error_response(
        self,
        invalid_tools: List[str],
        unavailable_tools: List[Dict[str, Any]],
    ) -> str:
        """Build a helpful error response for invalid tool calls.

        Args:
            invalid_tools: List of non-existent tool names
            unavailable_tools: List of dicts with name and status

        Returns:
            Error message to inject into conversation
        """
        parts = []

        if invalid_tools:
            parts.append(
                f"The following tools do not exist: {', '.join(invalid_tools)}. "
                "Please use only available tools."
            )

        if unavailable_tools:
            for tool in unavailable_tools:
                status = tool["status"]
                name = tool["name"]
                if status == "planned":
                    parts.append(f"Tool '{name}' is planned but not yet implemented.")
                elif status == "deprecated":
                    parts.append(f"Tool '{name}' is deprecated and should not be used.")
                elif status == "disabled":
                    parts.append(f"Tool '{name}' is temporarily disabled.")
                else:
                    parts.append(f"Tool '{name}' is not available (status: {status}).")

        # Add available alternatives
        available = self._registry.list_available()
        if available:
            parts.append(f"\nAvailable tools: {', '.join(sorted(available)[:10])}...")

        return " ".join(parts)

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
        """Return default system prompt with tools built from registry."""
        # Build tools section from registry
        tools_section = self._registry.build_capability_summary()

        # Honesty rules to prevent consultant-speak
        honesty_rules = """
## CRITICAL: No Describing — Only Doing

You have tools. USE THEM. Don't describe what you would do.

WRONG:
User: "Validate my token"
You: "I will validate your token by checking the JWT structure, verifying the expiration, and extracting the user info. This ensures the token is valid..."

RIGHT:
User: "Validate my token"
You: *calls validate_token tool*
You: "✓ Token valid. User: alice. Expires in 5 days."

BANNED PHRASES (never use these):
- "I will validate/parse/check by..."
- "The process involves..."
- "This ensures that..."
- "Here's how I would..."
- "First, I will... Next, I will..."
- "Step 1... Step 2..."
- Any numbered process explanation

REQUIRED BEHAVIOR:
1. User asks for something → Call a tool → Show result
2. Can't do it → Say "I can't do that yet. [X] isn't available."
3. Need more info → Ask one specific question

RESPONSE FORMAT:
- Use ✓ for success
- Use ✗ for failure
- Show actual data, not process
- Keep it short unless showing results

## NEVER Explain Processes — Even When Asked

WRONG:
User: "Explain how you validated the tokens"
You: "The validation involved the following steps:
      1. Token Format Check...
      2. Decoding Tokens...
      3. User Information Extraction..."

RIGHT:
User: "Explain how you validated the tokens"
You: "I called validate_token for each token. Here's what it returned:
      • admin_user_001: ✓ Valid, expires in 371 days
      • cust_alice_123: ✓ Valid, expires in 371 days
      • cust_bob_456: ✓ Valid, expires in 371 days"

When asked "how did you do X":
- Say which tool you called
- Show the output
- Do NOT explain the internal process

When asked "how would you do X" (hypothetical):
- Say "Give me [input] and I'll show you"
- Do NOT explain a theoretical process
"""

        return f"""# APIsec Agent — System Prompt

You are an AI agent with ACCESS TO TOOLS. You CAN and MUST use tools to interact with the filesystem.

**CRITICAL: You have tools. Use them. Do not say "I can't access the filesystem" - YOU CAN via tools.**

{honesty_rules}

## Your Approach: Ground, Scan, Then Ask About Gaps

### Step 1: One Grounding Question

Start with exactly ONE question: "Where's your API project?"
- This folder [show current path]
- A different local path
- GitHub repo
- Somewhere else

This grounds everything. Don't ask more questions yet.

### Step 2: Scan and Report

**IMPORTANT: When the user provides a path, IMMEDIATELY call the `scan_repo` tool with that path. Do not just say you will scan - actually call the tool NOW.**

Based on the answer:
- **Local folder:** Call `scan_repo(path="<the path>")` IMMEDIATELY. Do not describe - just do it.
- **GitHub:** Ask for repo and PAT, then use `validate_github_token` and `clone_github_repo`.
- **Somewhere else:** Ask clarifying question about where.

### Step 3: Show Value Immediately

After scanning, show what you found with checkmarks (✓) and crosses (✗).

### Step 4: Ask About Gaps (In Context)

Only now ask questions — and only about what's missing.

{tools_section}

## Response Style

- Use markdown formatting for clarity
- Use checkmarks (✓) and crosses (✗) for status
- Keep responses focused and direct
- Show results, not process
- Be warm and helpful, not robotic
"""

    def chat(self, user_message: str) -> str:
        """Process a user message and generate a response.

        Handles tool calls automatically, continuing until a final
        text response is ready.

        Includes:
        - Pre-LLM capability checking
        - Post-LLM response validation
        - Hallucination detection for tool calls
        - Bullshit detection (catches consultant-speak)

        Args:
            user_message: The user's input message

        Returns:
            The assistant's final text response
        """
        # Reset tools tracking for this turn
        self._tools_called_this_turn = []

        # Step 1: Pre-LLM capability check (optional - for impossible requests)
        capability = self.check_capability(user_message)
        if not capability["can_fulfill"] and capability["missing_tools"]:
            # We have missing tools - inject context into system prompt
            missing_info = []
            for tool in capability["missing_tools"]:
                missing_info.append(f"- {tool['name']} (status: {tool['status']})")
            capability_warning = (
                f"\n\n[SYSTEM: The user's request may reference unavailable tools:\n"
                f"{chr(10).join(missing_info)}\n"
                f"Please acknowledge this limitation and suggest alternatives.]\n"
            )
        else:
            capability_warning = ""

        # Add user message to history
        self.conversation_history.append({
            "role": "user",
            "content": user_message,
        })

        # Build messages for API call (with capability warning if needed)
        system_content = self.system_prompt + capability_warning
        messages = [{"role": "system", "content": system_content}]
        messages.extend(self.conversation_history)

        # Loop until we get a text response (handle multiple tool calls)
        max_iterations = 10
        debug = os.environ.get("APISEC_DEBUG", "").lower() in ("1", "true", "yes")

        for iteration in range(max_iterations):
            if debug:
                print(f"[DEBUG] Iteration {iteration + 1}/{max_iterations}")

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
                if debug:
                    tool_names = [tc.function.name for tc in assistant_message.tool_calls]
                    print(f"[DEBUG] Tool calls: {tool_names}")
                # Step 2: Validate tool calls (catch hallucinations)
                validation = self.validate_tool_calls(assistant_message.tool_calls)

                if not validation["valid"]:
                    # LLM tried to use invalid/unavailable tools
                    error_msg = self.build_error_response(
                        validation["invalid_tools"],
                        validation["unavailable_tools"],
                    )

                    # Add assistant's attempt to history
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

                    # Add error responses for invalid tools
                    for tool_call in assistant_message.tool_calls:
                        tool_name = tool_call.function.name
                        if tool_name in validation["invalid_tools"]:
                            error_content = json.dumps({
                                "success": False,
                                "error": f"Tool '{tool_name}' does not exist. {error_msg}",
                            })
                        elif any(t["name"] == tool_name for t in validation["unavailable_tools"]):
                            status = next(
                                t["status"] for t in validation["unavailable_tools"]
                                if t["name"] == tool_name
                            )
                            error_content = json.dumps({
                                "success": False,
                                "error": f"Tool '{tool_name}' is not available (status: {status}).",
                            })
                        else:
                            # Valid tool - will be processed
                            continue

                        self.conversation_history.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": error_content,
                        })

                    # Process only valid tool calls
                    if validation["valid_calls"]:
                        tool_results = self.process_tool_calls(validation["valid_calls"])
                        for result in tool_results:
                            self.conversation_history.append(result)

                    # Rebuild messages for retry
                    messages = [{"role": "system", "content": system_content}]
                    messages.extend(self.conversation_history)
                    continue

                # All tool calls are valid - process normally
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
                messages = [{"role": "system", "content": system_content}]
                messages.extend(self.conversation_history)

                continue

            # No tool calls - we have a final response
            final_content = assistant_message.content or ""

            if debug:
                print(f"[DEBUG] Final response (no tool calls), length={len(final_content)}")
                print(f"[DEBUG] Tools called this turn: {self._tools_called_this_turn}")

            # Step 3: Validate response for consultant-speak / bullshit
            is_valid, validated_content = validate_response(
                final_content,
                self._tools_called_this_turn,
                user_message,  # Pass context for context-aware rejection
            )

            if debug:
                print(f"[DEBUG] Validation result: is_valid={is_valid}")

            # If response was consultant-speak, strip any remaining fluff
            if not is_valid:
                final_content = validated_content
            else:
                # Light cleanup even on valid responses
                final_content = strip_consultant_speak(final_content) or final_content

            self.conversation_history.append({
                "role": "assistant",
                "content": final_content,
            })

            return final_content

        # Max iterations reached
        if debug:
            print(f"[DEBUG] Max iterations ({max_iterations}) reached!")
            print(f"[DEBUG] Tools called: {self._tools_called_this_turn}")
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

            # Track tool call for validator
            self._tools_called_this_turn.append(tool_name)

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
