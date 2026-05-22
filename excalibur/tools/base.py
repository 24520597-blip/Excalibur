"""Typed tool interfaces for Excalibur security tools."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ToolCategory(str, Enum):
    """Categories of security tools available in Excalibur."""

    RECONNAISSANCE = "reconnaissance"
    WEB_EXPLOITATION = "web_exploitation"
    NETWORK_EXPLOITATION = "network_exploitation"
    CREDENTIAL_ATTACKS = "credential_attacks"
    ACTIVE_DIRECTORY = "active_directory"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class ToolParameter(BaseModel):
    """Definition of a single tool input parameter."""

    name: str
    type: str = "string"
    required: bool = False
    default: Any = None
    description: str = ""
    validation_pattern: str | None = None
    choices: list[str] | None = None


class ToolOutputField(BaseModel):
    """Definition of a single tool output field."""

    name: str
    type: str = "string"
    description: str = ""


class ToolPrecondition(BaseModel):
    """Condition that must hold before a tool can be executed."""

    description: str
    check_type: str  # e.g., "port_open", "service_running", "file_exists"
    parameters: dict[str, Any] = Field(default_factory=dict)


class ToolPostcondition(BaseModel):
    """Effect that a tool execution produces."""

    description: str
    effect_type: str  # e.g., "discovers_services", "gains_access", "reveals_data"


class TypedToolInterface(BaseModel):
    """Typed interface definition for a security tool.

    Captures the full schema of a tool including its inputs, outputs,
    preconditions, postconditions, and the command template used to
    build CLI invocations.
    """

    name: str
    category: ToolCategory
    description: str
    input_schema: list[ToolParameter] = Field(default_factory=list)
    output_schema: list[ToolOutputField] = Field(default_factory=list)
    preconditions: list[ToolPrecondition] = Field(default_factory=list)
    postconditions: list[ToolPostcondition] = Field(default_factory=list)
    command_template: str = ""
    timeout: int = 300


class TypedSecurityTool:
    """Base class for typed security tools.

    Execution delegates to the Claude Code backend. This class provides
    command building, documentation generation, and serialization.
    """

    def __init__(self, interface: TypedToolInterface) -> None:
        self.interface = interface

    @property
    def name(self) -> str:
        """Return the tool name."""
        return self.interface.name

    @property
    def category(self) -> ToolCategory:
        """Return the tool category."""
        return self.interface.category

    def build_command(self, **kwargs: Any) -> str:
        """Build a CLI command from the template and provided parameters.

        Substitutes ``{param_name}`` placeholders in the command template
        with actual values. Missing optional parameters are replaced with
        their defaults; missing required parameters are left as-is so the
        caller can detect them.
        """
        template = self.interface.command_template
        for param in self.interface.input_schema:
            key = param.name
            value = kwargs.get(key, param.default)
            if value is not None:
                template = template.replace(f"{{{key}}}", str(value))
        return template

    def get_documentation(self) -> str:
        """Return human-readable documentation for this tool."""
        lines: list[str] = [
            f"# {self.interface.name}",
            f"Category: {self.interface.category.value}",
            f"Description: {self.interface.description}",
            f"Timeout: {self.interface.timeout}s",
            "",
        ]

        if self.interface.input_schema:
            lines.append("## Parameters")
            for param in self.interface.input_schema:
                req = "REQUIRED" if param.required else "optional"
                default_str = f" (default: {param.default})" if param.default else ""
                lines.append(
                    f"  - {param.name} [{param.type}, {req}]{default_str}: {param.description}"
                )
            lines.append("")

        if self.interface.output_schema:
            lines.append("## Output Fields")
            for field in self.interface.output_schema:
                lines.append(f"  - {field.name} [{field.type}]: {field.description}")
            lines.append("")

        if self.interface.preconditions:
            lines.append("## Preconditions")
            for pre in self.interface.preconditions:
                lines.append(f"  - [{pre.check_type}] {pre.description}")
            lines.append("")

        if self.interface.postconditions:
            lines.append("## Postconditions")
            for post in self.interface.postconditions:
                lines.append(f"  - [{post.effect_type}] {post.description}")
            lines.append("")

        if self.interface.command_template:
            lines.append("## Command Template")
            lines.append(f"  {self.interface.command_template}")
            lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full interface to a dictionary."""
        return self.interface.model_dump()
