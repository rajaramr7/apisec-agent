"""LLM client for agent interactions."""

from typing import List, Optional

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
        self.system_prompt = system_prompt or self._default_system_prompt()

    def _default_system_prompt(self) -> str:
        """Get the default system prompt."""
        # TODO: Load from prompts/system_prompt.md
        return "You are an API security configuration assistant."

    def chat(
        self,
        messages: List[dict],
        tools: Optional[List[dict]] = None,
    ) -> dict:
        """Send a chat completion request.

        Args:
            messages: Conversation messages
            tools: Available tools for the model

        Returns:
            Model response
        """
        # TODO: Implement chat completion
        pass

    def stream_chat(
        self,
        messages: List[dict],
        tools: Optional[List[dict]] = None,
    ):
        """Stream a chat completion request.

        Args:
            messages: Conversation messages
            tools: Available tools for the model

        Yields:
            Response chunks
        """
        # TODO: Implement streaming chat
        pass
