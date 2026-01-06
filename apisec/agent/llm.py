"""LLM client for agent interactions."""

import os
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from openai import OpenAI


class LLMClient:
    """Client for LLM interactions.

    Handles communication with the LLM API for generating
    responses and processing tool calls.
    """

    def __init__(
        self,
        model: str = "gpt-4",
        api_key: Optional[str] = None,
        system_prompt: Optional[str] = None,
    ):
        """Initialize the LLM client.

        Args:
            model: Model identifier (default: gpt-4)
            api_key: OpenAI API key (uses env var if not provided)
            system_prompt: System prompt for the agent
        """
        self.model = model
        self.client = OpenAI(api_key=api_key) if api_key else OpenAI()
        self.system_prompt = system_prompt or self._load_system_prompt()

    def _load_system_prompt(self) -> str:
        """Load system prompt from file or use default."""
        # Try to load from prompts/system_prompt.md relative to package
        prompt_paths = [
            Path(__file__).parent.parent.parent / "prompts" / "system_prompt.md",
            Path.cwd() / "prompts" / "system_prompt.md",
        ]

        for prompt_path in prompt_paths:
            if prompt_path.exists():
                try:
                    return prompt_path.read_text(encoding="utf-8")
                except Exception:
                    continue

        # Fallback to default
        return self._default_system_prompt()

    def _default_system_prompt(self) -> str:
        """Get the default system prompt."""
        return """You are an APIsec configuration assistant. Your job is to help developers set up API security testing with minimal friction.

## Your Core Philosophy

1. **Infer first, ask second.** If you can figure something out from artifacts, don't ask.
2. **Explain why you're asking.** Developers are more likely to engage when they understand the purpose.
3. **Be conversational, not transactional.** You're having a dialogue, not administering a questionnaire.
4. **Confirm understanding.** Before moving on, make sure you've got it right.
5. **Progressive depth.** Start with basics (what API, where does it run), then auth, then BOLA, then RBAC.

## Available Tools

You have access to tools for:
- scan_repo: Discover API artifacts in the repository
- parse_openapi: Parse OpenAPI/Swagger specs
- parse_postman: Parse Postman collections
- parse_logs: Analyze API access logs
- parse_env: Parse environment configuration files
- read_file: Read any file in the repository
- generate_config: Generate the final APIsec configuration

Start by scanning the repository to see what artifacts are available, then analyze them to understand the API."""

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        """Send a chat completion request.

        Args:
            messages: Conversation messages
            tools: Available tools for the model

        Returns:
            Model response with message and optional tool calls
        """
        # Add system prompt if not present
        if not messages or messages[0].get("role") != "system":
            messages = [{"role": "system", "content": self.system_prompt}] + messages

        kwargs = {
            "model": self.model,
            "messages": messages,
        }

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = self.client.chat.completions.create(**kwargs)
        message = response.choices[0].message

        result = {
            "role": "assistant",
            "content": message.content,
        }

        if message.tool_calls:
            result["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in message.tool_calls
            ]

        return result

    def stream_chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict]] = None,
    ) -> Generator[Dict[str, Any], None, None]:
        """Stream a chat completion request.

        Args:
            messages: Conversation messages
            tools: Available tools for the model

        Yields:
            Response chunks with partial content or tool calls
        """
        # Add system prompt if not present
        if not messages or messages[0].get("role") != "system":
            messages = [{"role": "system", "content": self.system_prompt}] + messages

        kwargs = {
            "model": self.model,
            "messages": messages,
            "stream": True,
        }

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        stream = self.client.chat.completions.create(**kwargs)

        # Accumulate content and tool calls
        accumulated_content = ""
        tool_calls = {}

        for chunk in stream:
            delta = chunk.choices[0].delta

            # Handle content
            if delta.content:
                accumulated_content += delta.content
                yield {
                    "type": "content",
                    "content": delta.content,
                }

            # Handle tool calls
            if delta.tool_calls:
                for tc in delta.tool_calls:
                    tc_id = tc.index
                    if tc_id not in tool_calls:
                        tool_calls[tc_id] = {
                            "id": tc.id or "",
                            "type": "function",
                            "function": {
                                "name": tc.function.name or "",
                                "arguments": "",
                            },
                        }
                    if tc.id:
                        tool_calls[tc_id]["id"] = tc.id
                    if tc.function.name:
                        tool_calls[tc_id]["function"]["name"] = tc.function.name
                    if tc.function.arguments:
                        tool_calls[tc_id]["function"]["arguments"] += tc.function.arguments

        # Yield final message with tool calls if any
        if tool_calls:
            yield {
                "type": "tool_calls",
                "tool_calls": list(tool_calls.values()),
            }

        # Yield complete message
        yield {
            "type": "complete",
            "role": "assistant",
            "content": accumulated_content or None,
            "tool_calls": list(tool_calls.values()) if tool_calls else None,
        }

    def get_system_prompt(self) -> str:
        """Get the current system prompt.

        Returns:
            System prompt string
        """
        return self.system_prompt

    def set_system_prompt(self, prompt: str) -> None:
        """Set a new system prompt.

        Args:
            prompt: New system prompt
        """
        self.system_prompt = prompt
