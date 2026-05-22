"""Skill composition engine for Excalibur.

Skills are higher-level abstractions that compose multiple tools into
reusable multi-step workflows.  The ``SkillEngine`` provides lookup,
listing, and documentation generation for registered skills.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from excalibur.tools.registry import ToolRegistry


class SkillStep(BaseModel):
    """A single step within a skill workflow.

    Each step references a registered tool by name and provides an
    optional mapping from skill-level inputs to tool parameters, as well
    as an optional condition that must be satisfied before executing the
    step.
    """

    tool_name: str
    parameter_mapping: dict[str, str] = Field(default_factory=dict)
    condition: str | None = None


class Skill(BaseModel):
    """A composed multi-tool workflow.

    Attributes:
        name: Unique skill identifier (e.g., ``"full_port_scan"``).
        description: Human-readable description of what the skill does.
        tool_sequence: Ordered list of ``SkillStep`` objects.
        fallback_logic: Free-text description of what to do when a step
            fails.
        result_aggregation: Strategy for combining step results.  Common
            values are ``"sequential"`` (default) and ``"merge"``.
    """

    name: str
    description: str
    tool_sequence: list[SkillStep] = Field(default_factory=list)
    fallback_logic: str = ""
    result_aggregation: str = "sequential"


class SkillEngine:
    """Engine for registering, retrieving, and documenting skills.

    Args:
        registry: The ``ToolRegistry`` used to validate tool references
            within skill definitions.
    """

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry
        self._skills: dict[str, Skill] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_skill(self, skill: Skill) -> None:
        """Register a skill.

        Args:
            skill: The ``Skill`` instance to register.
        """
        self._skills[skill.name] = skill

    def register_skills(self, skills: list[Skill]) -> None:
        """Register multiple skills at once."""
        for skill in skills:
            self.register_skill(skill)

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get_skill(self, name: str) -> Skill | None:
        """Retrieve a skill by name.

        Returns:
            The ``Skill`` instance or ``None``.
        """
        return self._skills.get(name)

    def list_skills(self) -> list[str]:
        """Return all registered skill names."""
        return list(self._skills.keys())

    # ------------------------------------------------------------------
    # Documentation
    # ------------------------------------------------------------------

    def get_skill_documentation(self, name: str) -> str:
        """Generate human-readable documentation for a skill.

        Args:
            name: The skill name.

        Returns:
            A formatted documentation string or an empty string if the
            skill is not found.
        """
        skill = self.get_skill(name)
        if skill is None:
            return ""

        lines: list[str] = [
            f"# Skill: {skill.name}",
            f"Description: {skill.description}",
            f"Result aggregation: {skill.result_aggregation}",
            "",
            "## Steps",
        ]
        for idx, step in enumerate(skill.tool_sequence, start=1):
            tool = self.registry.get(step.tool_name)
            tool_desc = tool.interface.description[:80] if tool else "unknown tool"
            lines.append(f"  {idx}. [{step.tool_name}] {tool_desc}")
            if step.parameter_mapping:
                for skill_param, tool_param in step.parameter_mapping.items():
                    lines.append(f"     - {skill_param} -> {tool_param}")
            if step.condition:
                lines.append(f"     Condition: {step.condition}")

        if skill.fallback_logic:
            lines.append("")
            lines.append(f"## Fallback: {skill.fallback_logic}")

        lines.append("")
        return "\n".join(lines)

    def get_all_documentation(self) -> str:
        """Return concatenated documentation for every registered skill."""
        parts: list[str] = []
        for name in sorted(self._skills):
            parts.append(self.get_skill_documentation(name))
        return "\n".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """Serialize all skills to a dictionary."""
        return {name: skill.model_dump() for name, skill in self._skills.items()}
