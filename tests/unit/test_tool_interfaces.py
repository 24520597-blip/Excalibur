"""Tests for typed tool interface schema validation.

Unit tests covering TypedToolInterface creation, ToolParameter
validation, TypedSecurityTool.build_command, and ToolCategory enum.
"""

from __future__ import annotations

import pytest

from excalibur.tools.base import (
    ToolCategory,
    ToolParameter,
    TypedSecurityTool,
    TypedToolInterface,
)


@pytest.mark.unit
class TestToolCategory:
    """Tests for ToolCategory enum values."""

    def test_has_all_expected_categories(self) -> None:
        """All six expected categories are present."""
        expected = {
            "reconnaissance",
            "web_exploitation",
            "network_exploitation",
            "credential_attacks",
            "active_directory",
            "privilege_escalation",
        }
        actual = {cat.value for cat in ToolCategory}
        assert actual == expected

    def test_enum_is_string(self) -> None:
        """Each ToolCategory member is a string enum."""
        for cat in ToolCategory:
            assert isinstance(cat, str)
            assert isinstance(cat.value, str)


@pytest.mark.unit
class TestToolParameter:
    """Tests for ToolParameter validation model."""

    def test_creation_with_defaults(self) -> None:
        """ToolParameter has sensible defaults."""
        param = ToolParameter(name="target")
        assert param.name == "target"
        assert param.type == "string"
        assert param.required is False
        assert param.default is None
        assert param.description == ""
        assert param.validation_pattern is None
        assert param.choices is None

    def test_creation_with_full_spec(self) -> None:
        """ToolParameter stores all provided values."""
        param = ToolParameter(
            name="port",
            type="integer",
            required=True,
            default=80,
            description="Target port number",
            validation_pattern=r"^\d+$",
            choices=["80", "443", "8080"],
        )
        assert param.name == "port"
        assert param.type == "integer"
        assert param.required is True
        assert param.default == 80
        assert param.validation_pattern == r"^\d+$"
        assert param.choices == ["80", "443", "8080"]


@pytest.mark.unit
class TestTypedToolInterface:
    """Tests for TypedToolInterface model creation."""

    def test_creation_with_valid_schema(self) -> None:
        """Interface can be created with name, category, description."""
        iface = TypedToolInterface(
            name="nmap",
            category=ToolCategory.RECONNAISSANCE,
            description="Network port scanner",
            command_template="nmap {target}",
            timeout=120,
        )
        assert iface.name == "nmap"
        assert iface.category == ToolCategory.RECONNAISSANCE
        assert iface.description == "Network port scanner"
        assert iface.command_template == "nmap {target}"
        assert iface.timeout == 120

    def test_default_fields(self) -> None:
        """Default fields are populated as empty lists."""
        iface = TypedToolInterface(
            name="test",
            category=ToolCategory.WEB_EXPLOITATION,
            description="test tool",
        )
        assert iface.input_schema == []
        assert iface.output_schema == []
        assert iface.preconditions == []
        assert iface.postconditions == []
        assert iface.command_template == ""
        assert iface.timeout == 300

    def test_with_input_parameters(self) -> None:
        """Interface accepts input_schema with ToolParameter items."""
        params = [
            ToolParameter(name="target", required=True),
            ToolParameter(name="ports", default="1-1000"),
        ]
        iface = TypedToolInterface(
            name="scanner",
            category=ToolCategory.RECONNAISSANCE,
            description="Port scanner",
            input_schema=params,
        )
        assert len(iface.input_schema) == 2
        assert iface.input_schema[0].name == "target"
        assert iface.input_schema[1].default == "1-1000"


@pytest.mark.unit
class TestTypedSecurityTool:
    """Tests for TypedSecurityTool build_command and helpers."""

    def _make_tool(self) -> TypedSecurityTool:
        """Create a sample tool for testing."""
        iface = TypedToolInterface(
            name="nmap",
            category=ToolCategory.RECONNAISSANCE,
            description="Network mapper",
            input_schema=[
                ToolParameter(
                    name="target",
                    required=True,
                    description="Target IP",
                ),
                ToolParameter(
                    name="ports",
                    required=False,
                    default="1-1000",
                    description="Port range",
                ),
                ToolParameter(
                    name="script",
                    required=False,
                    default=None,
                    description="NSE script",
                ),
            ],
            command_template="nmap -p {ports} {target}",
        )
        return TypedSecurityTool(iface)

    def test_build_command_all_params(self) -> None:
        """build_command substitutes all provided parameters."""
        tool = self._make_tool()
        cmd = tool.build_command(target="10.0.0.1", ports="80,443")
        assert cmd == "nmap -p 80,443 10.0.0.1"

    def test_build_command_uses_defaults(self) -> None:
        """build_command fills in defaults for missing optional params."""
        tool = self._make_tool()
        cmd = tool.build_command(target="10.0.0.1")
        assert cmd == "nmap -p 1-1000 10.0.0.1"

    def test_build_command_leaves_missing_required(self) -> None:
        """Missing required params without defaults stay as-is."""
        tool = self._make_tool()
        cmd = tool.build_command(ports="22")
        # {target} has no default, left as placeholder
        assert "{target}" in cmd

    def test_name_property(self) -> None:
        """The name property delegates to the interface."""
        tool = self._make_tool()
        assert tool.name == "nmap"

    def test_category_property(self) -> None:
        """The category property delegates to the interface."""
        tool = self._make_tool()
        assert tool.category == ToolCategory.RECONNAISSANCE

    def test_get_documentation_returns_string(self) -> None:
        """get_documentation returns a non-empty readable string."""
        tool = self._make_tool()
        doc = tool.get_documentation()
        assert isinstance(doc, str)
        assert "nmap" in doc
        assert "Parameters" in doc

    def test_to_dict_serializes(self) -> None:
        """to_dict returns a dictionary with interface data."""
        tool = self._make_tool()
        d = tool.to_dict()
        assert isinstance(d, dict)
        assert d["name"] == "nmap"
        assert d["category"] == "reconnaissance"
