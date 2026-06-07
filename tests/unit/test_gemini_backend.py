"""Tests for the direct Gemini API backend."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, ClassVar

import pytest

from excalibur.core.backend import GeminiBackend, MessageType


class _FakeResponse:
    text = "Gemini response"
    usage_metadata: ClassVar[dict[str, int]] = {"prompt_token_count": 10}


class _FakeChat:
    async def send_message(self, prompt: str) -> _FakeResponse:
        assert prompt == "test prompt"
        return _FakeResponse()


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
