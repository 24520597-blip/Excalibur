"""Tests for the direct Gemini API backend."""

from __future__ import annotations

import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, ClassVar

import pytest

from excalibur.core.backend import GeminiBackend, MessageType, _gemini_shell_tool


class _FakeResponse:
    text = "Gemini response"
    usage_metadata: ClassVar[dict[str, int]] = {"prompt_token_count": 10}


class _FakeChat:
    async def send_message(self, prompt: str) -> _FakeResponse:
        assert prompt == "test prompt"
        return _FakeResponse()


class _FakeChats:
    def create(self, **kwargs: Any) -> _FakeChat:
        return _FakeChat()


class _FakeClient:
    def __init__(self) -> None:
        self.aio = type("Aio", (), {"chats": _FakeChats()})()


@pytest.mark.unit
class TestGeminiBackend:
    """Gemini backend behavior without making network requests."""

    async def test_query_yields_text_and_result(self, tmp_path: Path) -> None:
        backend = GeminiBackend(str(tmp_path), "system", api_key="test")
        backend._chat = _FakeChat()

        await backend.query("test prompt")
        messages = [message async for message in backend.receive_messages()]

        assert [message.type for message in messages] == [
            MessageType.TEXT,
            MessageType.RESULT,
        ]
        assert messages[0].content == "Gemini response"

    def test_shell_tool_records_start_and_result(self, tmp_path: Path) -> None:
        backend = GeminiBackend(str(tmp_path), "system", api_key="test")
        command = f'"{sys.executable}" -c "print(\'gemini-ok\')"'

        result = backend._run_shell_command(command)

        assert result["exit_code"] == 0
        assert "gemini-ok" in result["stdout"]
        assert [message.type for message in backend._pending_messages] == [
            MessageType.TOOL_START,
            MessageType.TOOL_RESULT,
        ]

    async def test_connect_requires_api_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        backend = GeminiBackend(str(tmp_path), "system")

        with pytest.raises(RuntimeError, match="Gemini API key"):
            await backend.connect()

    async def test_vertex_mode_uses_vertex_api_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from google import genai

        seen: dict[str, Any] = {}

        def fake_client(**kwargs: Any) -> _FakeClient:
            seen.update(kwargs)
            return _FakeClient()

        monkeypatch.setattr(genai, "Client", fake_client)
        backend = GeminiBackend(
            str(tmp_path),
            "system",
            api_key="cloud-key",
            api_mode="vertex",
        )

        await backend.connect()

        assert seen == {"vertexai": True, "api_key": "cloud-key"}

    async def test_vertex_mode_supports_adc(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from google import genai

        seen: dict[str, Any] = {}

        def fake_client(**kwargs: Any) -> _FakeClient:
            seen.update(kwargs)
            return _FakeClient()

        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        monkeypatch.setattr(genai, "Client", fake_client)
        backend = GeminiBackend(
            str(tmp_path),
            "system",
            api_mode="vertex",
            google_cloud_project="project-id",
            google_cloud_location="us-central1",
        )

        await backend.connect()

        assert seen == {
            "vertexai": True,
            "project": "project-id",
            "location": "us-central1",
        }

    def test_function_tool_can_be_deep_copied(self) -> None:
        """Gemini SDK deep-copies tools before every request."""
        from google.genai import types

        config = types.GenerateContentConfig(tools=[_gemini_shell_tool])
        copied = deepcopy(config)
        assert copied.tools

    def test_shell_timeout_is_bounded(self, tmp_path: Path) -> None:
        backend = GeminiBackend(str(tmp_path), "system", api_key="test", tool_timeout=7)
        seen: dict[str, Any] = {}

        def fake_run(*args: Any, **kwargs: Any) -> Any:
            seen["timeout"] = kwargs["timeout"]
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        import subprocess

        original = subprocess.run
        subprocess.run = fake_run
        try:
            backend._run_shell_command("echo ok", timeout=100)
        finally:
            subprocess.run = original

        assert seen["timeout"] == 7
