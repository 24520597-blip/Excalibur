"""Tool registry for managing available security tools."""

from __future__ import annotations

from typing import Any

from excalibur.tools.base import ToolCategory, TypedSecurityTool
from excalibur.tools.categories import (
    get_active_directory_tools,
    get_credential_attack_tools,
    get_network_exploitation_tools,
    get_privilege_escalation_tools,
    get_reconnaissance_tools,
    get_web_exploitation_tools,
)

# Mapping from mode strings to relevant tool categories.
_MODE_CATEGORY_MAP: dict[str, list[ToolCategory]] = {
    "recon": [ToolCategory.RECONNAISSANCE],
    "reconnaissance": [ToolCategory.RECONNAISSANCE],
    "web": [ToolCategory.WEB_EXPLOITATION],
    "web_exploitation": [ToolCategory.WEB_EXPLOITATION],
    "network": [ToolCategory.NETWORK_EXPLOITATION],
    "network_exploitation": [ToolCategory.NETWORK_EXPLOITATION],
    "credentials": [ToolCategory.CREDENTIAL_ATTACKS],
    "credential_attacks": [ToolCategory.CREDENTIAL_ATTACKS],
    "ad": [ToolCategory.ACTIVE_DIRECTORY],
    "active_directory": [ToolCategory.ACTIVE_DIRECTORY],
    "privesc": [ToolCategory.PRIVILEGE_ESCALATION],
    "privilege_escalation": [ToolCategory.PRIVILEGE_ESCALATION],
    "full": [
        ToolCategory.RECONNAISSANCE,
        ToolCategory.WEB_EXPLOITATION,
        ToolCategory.NETWORK_EXPLOITATION,
        ToolCategory.CREDENTIAL_ATTACKS,
        ToolCategory.ACTIVE_DIRECTORY,
        ToolCategory.PRIVILEGE_ESCALATION,
    ],
    "all": [
        ToolCategory.RECONNAISSANCE,
        ToolCategory.WEB_EXPLOITATION,
        ToolCategory.NETWORK_EXPLOITATION,
        ToolCategory.CREDENTIAL_ATTACKS,
        ToolCategory.ACTIVE_DIRECTORY,
        ToolCategory.PRIVILEGE_ESCALATION,
    ],
}


class ToolRegistry:
    """Registry for managing and accessing typed security tools.

    Supports category-based registration, lookup, filtering by engagement
    mode, and documentation generation.
    """

    def __init__(self, *, auto_register: bool = True) -> None:
        """Initialize the tool registry.

        Args:
            auto_register: If True, automatically registers all built-in
                security tools from the category modules.
        """
        self._tools: dict[str, TypedSecurityTool] = {}
        self._category_index: dict[ToolCategory, list[str]] = {cat: [] for cat in ToolCategory}
        if auto_register:
            self._register_all_tools()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, tool: TypedSecurityTool) -> None:
        """Register a single tool in the registry.

        Args:
            tool: A TypedSecurityTool instance to register.
        """
        self._tools[tool.name] = tool
        if tool.name not in self._category_index[tool.category]:
            self._category_index[tool.category].append(tool.name)

    def _register_all_tools(self) -> None:
        """Register all built-in security tools from category modules."""
        all_tool_factories = [
            get_reconnaissance_tools,
            get_web_exploitation_tools,
            get_network_exploitation_tools,
            get_credential_attack_tools,
            get_active_directory_tools,
            get_privilege_escalation_tools,
        ]
        for factory in all_tool_factories:
            for tool in factory():
                self.register(tool)

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, name: str) -> TypedSecurityTool | None:
        """Get a tool by name.

        Args:
            name: The tool name (e.g., ``"nmap"``).

        Returns:
            The tool instance or ``None`` if not found.
        """
        return self._tools.get(name)

    def list_tools(self) -> list[str]:
        """List all registered tool names."""
        return list(self._tools.keys())

    def list_tools_by_category(self, category: ToolCategory) -> list[TypedSecurityTool]:
        """Return tools belonging to a specific category.

        Args:
            category: The tool category to filter by.

        Returns:
            List of matching tools.
        """
        names = self._category_index.get(category, [])
        return [self._tools[n] for n in names if n in self._tools]

    def get_tools_for_mode(self, mode: str) -> list[TypedSecurityTool]:
        """Return tools appropriate for the given engagement mode.

        Modes are mapped to one or more categories via an internal lookup
        table.  Recognised modes include ``"recon"``, ``"web"``,
        ``"network"``, ``"credentials"``, ``"ad"``, ``"privesc"``,
        ``"full"`` (or ``"all"``).

        Args:
            mode: Engagement mode string (case-insensitive).

        Returns:
            List of matching tools.  Returns an empty list for unknown modes.
        """
        categories = _MODE_CATEGORY_MAP.get(mode.lower(), [])
        tools: list[TypedSecurityTool] = []
        for cat in categories:
            tools.extend(self.list_tools_by_category(cat))
        return tools

    # ------------------------------------------------------------------
    # Documentation helpers
    # ------------------------------------------------------------------

    def get_tool_documentation(self, tool_name: str) -> str:
        """Return the full documentation string for a single tool.

        Args:
            tool_name: Name of the tool.

        Returns:
            Documentation string or an empty string if the tool is not found.
        """
        tool = self.get(tool_name)
        if tool is None:
            return ""
        return tool.get_documentation()

    def get_tool_info(self, name: str) -> dict[str, Any] | None:
        """Get serialized information about a tool.

        Args:
            name: The tool name.

        Returns:
            A dict representation of the tool interface or ``None``.
        """
        tool = self.get(name)
        return tool.to_dict() if tool else None

    def get_all_documentation(self) -> str:
        """Return concatenated documentation for every registered tool."""
        sections: list[str] = []
        for cat in ToolCategory:
            tools = self.list_tools_by_category(cat)
            if not tools:
                continue
            sections.append(f"{'=' * 60}")
            sections.append(f"Category: {cat.value}")
            sections.append(f"{'=' * 60}\n")
            for tool in tools:
                sections.append(tool.get_documentation())
                sections.append("")
        return "\n".join(sections)

    def get_category_summary(self) -> dict[str, int]:
        """Return a mapping from category name to tool count."""
        return {cat.value: len(names) for cat, names in self._category_index.items()}


# ------------------------------------------------------------------
# Global registry singleton
# ------------------------------------------------------------------

_global_registry: ToolRegistry | None = None


def get_registry() -> ToolRegistry:
    """Get (or create) the global tool registry singleton."""
    global _global_registry
    if _global_registry is None:
        _global_registry = ToolRegistry()
    return _global_registry
