"""Simple text-based attack tree visualization widget."""

from __future__ import annotations

from typing import Any

from rich.text import Text
from textual.widgets import Static


class AttackTreeView(Static):
    """Text-based attack tree visualization for the TUI status area."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the tree view widget."""
        super().__init__(*args, **kwargs)
        self._tree_data: dict[str, Any] | None = None
        self._current_node_id: str | None = None
        self._tdi_value: float | None = None
        self._mode: str | None = None

    def update_tree(
        self,
        tree_data: dict[str, Any] | None = None,
        current_node_id: str | None = None,
        tdi_value: float | None = None,
        mode: str | None = None,
    ) -> None:
        """Update the tree display with new data.

        Args:
            tree_data: Serialized attack tree data.
            current_node_id: Currently active node ID.
            tdi_value: Current TDI score.
            mode: Current mode (reconnaissance/exploitation/llm_decide).
        """
        if tree_data is not None:
            self._tree_data = tree_data
        if current_node_id is not None:
            self._current_node_id = current_node_id
        if tdi_value is not None:
            self._tdi_value = tdi_value
        if mode is not None:
            self._mode = mode
        self.update(self._render_status())

    def _render_status(self) -> Text:
        """Render compact status line for the tree state."""
        text = Text()

        if self._tree_data is None:
            text.append("Tree: ", style="dim")
            text.append("Not initialized", style="dim italic")
            return text

        nodes = self._tree_data.get("nodes", {})
        total = len(nodes)
        active = sum(1 for n in nodes.values() if n.get("status") == "active")
        completed = sum(1 for n in nodes.values() if n.get("status") == "completed")
        pruned = sum(1 for n in nodes.values() if n.get("status") == "pruned")
        hosts = len(self._tree_data.get("compromised_hosts", []))
        budget = self._tree_data.get("budget_remaining", 0)

        # Node counts
        text.append("Nodes: ", style="dim")
        text.append(f"{total}", style="bold")
        text.append(f" ({active}a/{completed}c/{pruned}p)", style="dim")

        # Current node
        if self._current_node_id:
            text.append("  |  ", style="dim")
            text.append("Node: ", style="dim")
            text.append(self._current_node_id[:8], style="bold #6366f1")

        # TDI
        if self._tdi_value is not None:
            text.append("  |  ", style="dim")
            text.append("TDI: ", style="dim")
            tdi_color = _tdi_color(self._tdi_value)
            text.append(f"{self._tdi_value:.2f}", style=f"bold {tdi_color}")

        # Mode
        if self._mode:
            text.append("  |  ", style="dim")
            mode_style = _mode_style(self._mode)
            text.append(self._mode.upper(), style=mode_style)

        # Hosts compromised
        if hosts > 0:
            text.append("  |  ", style="dim")
            text.append(f"Hosts: {hosts}", style="bold #10b981")

        # Budget
        text.append("  |  ", style="dim")
        text.append(f"Budget: {budget}", style="dim")

        return text


def _tdi_color(tdi: float) -> str:
    """Get color for TDI value."""
    if tdi < 0.3:
        return "#10b981"  # green - easy
    if tdi < 0.6:
        return "#f59e0b"  # amber - moderate
    return "#ef4444"  # red - hard


def _mode_style(mode: str) -> str:
    """Get style for mode indicator."""
    styles = {
        "reconnaissance": "bold #3b82f6",
        "exploitation": "bold #ef4444",
        "llm_decide": "bold #f59e0b",
    }
    return styles.get(mode, "dim")
