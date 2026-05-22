"""Tests for the skill composition engine.

Unit tests covering Skill model creation, SkillEngine listing,
and SkillEngine documentation generation.
"""

from __future__ import annotations

import pytest

from excalibur.tools.base import (
    ToolCategory,
    ToolParameter,
    TypedSecurityTool,
    TypedToolInterface,
)
from excalibur.tools.registry import ToolRegistry
from excalibur.tools.skill import Skill, SkillEngine, SkillStep


def _make_registry_with_tools() -> ToolRegistry:
    """Build a ToolRegistry with a couple of dummy tools."""
    reg = ToolRegistry(auto_register=False)
    nmap_iface = TypedToolInterface(
        name="nmap",
        category=ToolCategory.RECONNAISSANCE,
        description="Network port scanner for host discovery",
        input_schema=[
            ToolParameter(name="target", required=True),
            ToolParameter(name="ports", default="1-1000"),
        ],
        command_template="nmap -p {ports} {target}",
    )
    gobuster_iface = TypedToolInterface(
        name="gobuster",
        category=ToolCategory.WEB_EXPLOITATION,
        description="Directory brute-forcer for web applications",
        input_schema=[
            ToolParameter(name="url", required=True),
            ToolParameter(name="wordlist", default="/usr/share/dirb/common.txt"),
        ],
        command_template="gobuster dir -u {url} -w {wordlist}",
    )
    reg.register(TypedSecurityTool(nmap_iface))
    reg.register(TypedSecurityTool(gobuster_iface))
    return reg


@pytest.mark.unit
class TestSkillModel:
    """Tests for the Skill Pydantic model."""

    def test_basic_creation(self) -> None:
        """Skill can be created with name and description."""
        skill = Skill(
            name="full_recon",
            description="Complete reconnaissance workflow",
        )
        assert skill.name == "full_recon"
        assert skill.description == "Complete reconnaissance workflow"
        assert skill.tool_sequence == []
        assert skill.fallback_logic == ""
        assert skill.result_aggregation == "sequential"

    def test_creation_with_steps(self) -> None:
        """Skill can include a sequence of SkillStep objects."""
        steps = [
            SkillStep(
                tool_name="nmap",
                parameter_mapping={"target": "ip"},
            ),
            SkillStep(
                tool_name="gobuster",
                parameter_mapping={"url": "web_url"},
                condition="port_80_open",
            ),
        ]
        skill = Skill(
            name="web_recon",
            description="Web reconnaissance pipeline",
            tool_sequence=steps,
            fallback_logic="Skip gobuster if port 80 is closed",
            result_aggregation="merge",
        )
        assert len(skill.tool_sequence) == 2
        assert skill.tool_sequence[0].tool_name == "nmap"
        assert skill.tool_sequence[1].condition == "port_80_open"
        assert skill.result_aggregation == "merge"

    def test_skill_step_defaults(self) -> None:
        """SkillStep has sensible defaults."""
        step = SkillStep(tool_name="nmap")
        assert step.parameter_mapping == {}
        assert step.condition is None


@pytest.mark.unit
class TestSkillEngine:
    """Tests for SkillEngine registration, listing, and documentation."""

    def _make_engine(self) -> SkillEngine:
        """Create a SkillEngine with two registered skills."""
        registry = _make_registry_with_tools()
        engine = SkillEngine(registry)
        engine.register_skill(
            Skill(
                name="full_port_scan",
                description="Perform a full TCP port scan",
                tool_sequence=[
                    SkillStep(
                        tool_name="nmap",
                        parameter_mapping={"target": "ip"},
                    ),
                ],
            )
        )
        engine.register_skill(
            Skill(
                name="web_enum",
                description="Enumerate web directories",
                tool_sequence=[
                    SkillStep(
                        tool_name="gobuster",
                        parameter_mapping={"url": "web_url"},
                    ),
                ],
            )
        )
        return engine

    def test_list_skills_returns_names(self) -> None:
        """list_skills returns all registered skill names."""
        engine = self._make_engine()
        names = engine.list_skills()
        assert set(names) == {"full_port_scan", "web_enum"}

    def test_get_skill_returns_skill(self) -> None:
        """get_skill retrieves a skill by name."""
        engine = self._make_engine()
        skill = engine.get_skill("full_port_scan")
        assert skill is not None
        assert skill.name == "full_port_scan"

    def test_get_skill_returns_none_for_missing(self) -> None:
        """get_skill returns None for an unregistered name."""
        engine = self._make_engine()
        assert engine.get_skill("nonexistent") is None

    def test_get_skill_documentation_returns_string(self) -> None:
        """get_skill_documentation returns non-empty doc string."""
        engine = self._make_engine()
        doc = engine.get_skill_documentation("full_port_scan")
        assert isinstance(doc, str)
        assert "full_port_scan" in doc
        assert "Steps" in doc

    def test_get_skill_documentation_empty_for_missing(self) -> None:
        """Documentation for missing skill returns empty string."""
        engine = self._make_engine()
        doc = engine.get_skill_documentation("nope")
        assert doc == ""

    def test_register_skills_batch(self) -> None:
        """register_skills registers multiple skills at once."""
        registry = _make_registry_with_tools()
        engine = SkillEngine(registry)
        skills = [
            Skill(name="a", description="Skill A"),
            Skill(name="b", description="Skill B"),
        ]
        engine.register_skills(skills)
        assert set(engine.list_skills()) == {"a", "b"}

    def test_get_all_documentation(self) -> None:
        """get_all_documentation returns combined docs for all skills."""
        engine = self._make_engine()
        all_docs = engine.get_all_documentation()
        assert "full_port_scan" in all_docs
        assert "web_enum" in all_docs

    def test_to_dict_serializes(self) -> None:
        """to_dict returns a dictionary keyed by skill names."""
        engine = self._make_engine()
        d = engine.to_dict()
        assert "full_port_scan" in d
        assert "web_enum" in d
        assert d["full_port_scan"]["name"] == "full_port_scan"
