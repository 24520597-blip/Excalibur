"""Framework-agnostic agent backend protocol and implementations."""

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class MessageType(Enum):
    """Framework-agnostic message types from agent backends."""

    TEXT = "text"
    TOOL_START = "tool_start"
    TOOL_RESULT = "tool_result"
    RESULT = "result"
    ERROR = "error"


@dataclass
class AgentMessage:
    """Framework-agnostic message from any agent backend."""

    type: MessageType
    content: Any
    tool_name: str | None = None
    tool_args: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class AgentBackend(ABC):
    """
    Abstract interface for agent backends.

    Implement this to support different frameworks:
    - ClaudeCodeBackend (current)
    - OpenAIBackend (future)
    - LocalLLMBackend (future)
    """

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the agent."""
        ...

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection."""
        ...

    @abstractmethod
    async def query(self, prompt: str) -> None:
        """Send a query/instruction to the agent."""
        ...

    @abstractmethod
    def receive_messages(self) -> AsyncIterator[AgentMessage]:
        """Async iterator yielding messages from agent."""
        ...

    @property
    @abstractmethod
    def session_id(self) -> str | None:
        """Current session ID (if backend supports sessions)."""
        ...

    @property
    def supports_resume(self) -> bool:
        """Whether this backend supports session resume."""
        return False

    @abstractmethod
    async def resume(self, session_id: str) -> bool:
        """Resume a previous session. Returns success."""
        ...


class ClaudeCodeBackend(AgentBackend):
    """Claude Code SDK implementation of AgentBackend."""

    def __init__(
        self,
        working_directory: str,
        system_prompt: str,
        model: str,
        permission_mode: str = "bypassPermissions",
    ):
        self._cwd = working_directory
        self._system_prompt = system_prompt
        self._model = model
        self._permission_mode = permission_mode
        self._client: Any = None  # ClaudeSDKClient
        self._session_id: str | None = None

    async def connect(self) -> None:
        """Connect to Claude Code CLI."""
        import os

        from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient

        env_overrides = {}
        auth_mode = os.environ.get("EXCALIBUR_AUTH_MODE", "manual")

        # Only clear API key in manual mode (for OAuth)
        # For 'anthropic' mode, keep the key so SDK uses it directly
        # For 'openrouter' mode, ccr sets ANTHROPIC_BASE_URL and ANTHROPIC_AUTH_TOKEN
        if auth_mode == "manual" and os.environ.get("ANTHROPIC_API_KEY"):
            env_overrides["ANTHROPIC_API_KEY"] = ""

        # For OpenRouter mode, pass through ccr-set environment variables
        if auth_mode == "openrouter":
            for var in [
                "ANTHROPIC_BASE_URL",
                "ANTHROPIC_AUTH_TOKEN",
                "NO_PROXY",
                "DISABLE_TELEMETRY",
                "DISABLE_COST_WARNINGS",
                "API_TIMEOUT_MS",
            ]:
                if os.environ.get(var):
                    env_overrides[var] = os.environ[var]

        options = ClaudeAgentOptions(
            cwd=self._cwd,
            permission_mode=self._permission_mode,  # type: ignore[arg-type]
            system_prompt=self._system_prompt,
            model=self._model,
            env=env_overrides,
        )
        self._client = ClaudeSDKClient(options=options)
        result = self._client.connect()
        if result is not None:
            await result

    async def disconnect(self) -> None:
        """Disconnect from Claude Code CLI."""
        if self._client:
            result = self._client.disconnect()
            if result is not None:
                await result
            self._client = None

    async def query(self, prompt: str) -> None:
        """Send a query to Claude Code."""
        if not self._client:
            raise RuntimeError("Backend not connected")
        result = self._client.query(prompt)
        if result is not None:
            await result

    async def receive_messages(self) -> AsyncIterator[AgentMessage]:
        """Convert Claude SDK messages to framework-agnostic AgentMessage."""
        from claude_agent_sdk import (
            AssistantMessage,
            ResultMessage,
            TextBlock,
            ToolUseBlock,
        )

        if not self._client:
            raise RuntimeError("Backend not connected")

        async for msg in self._client.receive_response():
            if isinstance(msg, AssistantMessage):
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        yield AgentMessage(
                            type=MessageType.TEXT,
                            content=block.text,
                        )
                    elif isinstance(block, ToolUseBlock):
                        yield AgentMessage(
                            type=MessageType.TOOL_START,
                            content=None,
                            tool_name=block.name,
                            tool_args=block.input,
                        )
            elif isinstance(msg, ResultMessage):
                self._session_id = getattr(msg, "session_id", None) or self._session_id
                yield AgentMessage(
                    type=MessageType.RESULT,
                    content=None,
                    metadata={
                        "cost_usd": getattr(msg, "total_cost_usd", 0),
                        "session_id": getattr(msg, "session_id", None),
                    },
                )

    @property
    def session_id(self) -> str | None:
        """Get current session ID."""
        return self._session_id

    @property
    def supports_resume(self) -> bool:
        """Claude Code supports session resume."""
        return True

    async def resume(self, session_id: str) -> bool:
        """Resume a previous Claude Code session."""
        import os

        from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient

        # Disconnect existing client if any
        if self._client:
            result = self._client.disconnect()
            if result is not None:
                await result

        env_overrides = {}
        auth_mode = os.environ.get("EXCALIBUR_AUTH_MODE", "manual")

        # Only clear API key in manual mode (for OAuth)
        # For 'anthropic' mode, keep the key so SDK uses it directly
        # For 'openrouter' mode, ccr sets ANTHROPIC_BASE_URL and ANTHROPIC_AUTH_TOKEN
        if auth_mode == "manual" and os.environ.get("ANTHROPIC_API_KEY"):
            env_overrides["ANTHROPIC_API_KEY"] = ""

        # For OpenRouter mode, pass through ccr-set environment variables
        if auth_mode == "openrouter":
            for var in [
                "ANTHROPIC_BASE_URL",
                "ANTHROPIC_AUTH_TOKEN",
                "NO_PROXY",
                "DISABLE_TELEMETRY",
                "DISABLE_COST_WARNINGS",
                "API_TIMEOUT_MS",
            ]:
                if os.environ.get(var):
                    env_overrides[var] = os.environ[var]

        # Re-initialize with resume parameter
        options = ClaudeAgentOptions(
            cwd=self._cwd,
            permission_mode=self._permission_mode,  # type: ignore[arg-type]
            system_prompt=self._system_prompt,
            model=self._model,
            resume=session_id,
            env=env_overrides,
        )
        self._client = ClaudeSDKClient(options=options)
        result = self._client.connect()
        if result is not None:
            await result
        self._session_id = session_id
        return True


class GeminiBackend(AgentBackend):
    """Gemini API backend with an automatically callable local shell tool."""

    def __init__(
        self,
        working_directory: str,
        system_prompt: str,
        model: str = "gemini-2.5-flash",
        api_key: str | None = None,
        tool_timeout: int = 300,
    ) -> None:
        self._cwd = Path(working_directory)
        self._system_prompt = system_prompt
        self._model = model
        self._api_key = api_key
        self._tool_timeout = tool_timeout
        self._client: Any = None
        self._chat: Any = None
        self._pending_messages: list[AgentMessage] = []

    async def connect(self) -> None:
        """Create an asynchronous Gemini chat session."""
        import os

        from google import genai
        from google.genai import types

        api_key = self._api_key or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("Gemini API key not found. Set GEMINI_API_KEY or LLM_API_KEY.")

        self._cwd.mkdir(parents=True, exist_ok=True)
        self._client = genai.Client(api_key=api_key)
        self._chat = self._client.aio.chats.create(
            model=self._model,
            config=types.GenerateContentConfig(
                system_instruction=self._system_prompt,
                tools=[self._run_shell_command],
            ),
        )

    async def disconnect(self) -> None:
        """Close the Gemini API client."""
        if self._client is not None:
            close = getattr(self._client, "close", None)
            if callable(close):
                close()
        self._client = None
        self._chat = None

    async def query(self, prompt: str) -> None:
        """Send a prompt and let Gemini call the local shell tool when needed."""
        if self._chat is None:
            raise RuntimeError("Backend not connected")

        self._pending_messages.clear()
        try:
            response = await self._chat.send_message(prompt)
            text = getattr(response, "text", None)
            if text:
                self._pending_messages.append(AgentMessage(type=MessageType.TEXT, content=text))
            usage = getattr(response, "usage_metadata", None)
            self._pending_messages.append(
                AgentMessage(
                    type=MessageType.RESULT,
                    content=None,
                    metadata={"cost_usd": 0.0, "usage": str(usage) if usage else None},
                )
            )
        except Exception as exc:
            self._pending_messages.append(AgentMessage(type=MessageType.ERROR, content=str(exc)))
            raise

    async def receive_messages(self) -> AsyncIterator[AgentMessage]:
        """Yield messages generated by the most recent Gemini request."""
        messages = self._pending_messages[:]
        self._pending_messages.clear()
        for message in messages:
            yield message

    @property
    def session_id(self) -> str | None:
        """Gemini chats are in-memory and do not expose resumable IDs."""
        return None

    async def resume(self, session_id: str) -> bool:
        """Gemini API chat history is not persisted by this backend."""
        return False

    def _run_shell_command(self, command: str, timeout: int = 300) -> dict[str, Any]:
        """Run a shell command in the configured workspace.

        Args:
            command: Shell command to execute.
            timeout: Requested timeout in seconds.

        Returns:
            Command exit code and captured output.
        """
        import subprocess

        effective_timeout = max(1, min(timeout, self._tool_timeout))
        self._pending_messages.append(
            AgentMessage(
                type=MessageType.TOOL_START,
                content=None,
                tool_name="shell",
                tool_args={"command": command, "timeout": effective_timeout},
            )
        )
        try:
            completed = subprocess.run(
                command,
                shell=True,
                cwd=self._cwd,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                check=False,
            )
            result = {
                "exit_code": completed.returncode,
                "stdout": completed.stdout[-30000:],
                "stderr": completed.stderr[-30000:],
            }
        except subprocess.TimeoutExpired as exc:
            result = {
                "exit_code": -1,
                "stdout": (exc.stdout or "")[-30000:],
                "stderr": f"Command timed out after {effective_timeout} seconds",
            }

        self._pending_messages.append(
            AgentMessage(
                type=MessageType.TOOL_RESULT,
                content=result,
                tool_name="shell",
            )
        )
        return result
