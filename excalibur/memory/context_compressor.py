"""Context compression for managing LLM context window usage.

When the assembled context exceeds configurable thresholds the
compressor generates summaries for non-active branches, trims
older path segments, and prunes low-relevance state facts.

Two compression levels are supported:

* **Moderate** (context load > 40 %): summarise sibling branches,
  drop verbose tool output from ancestor nodes.
* **Aggressive** (context load > 70 %): keep only the active path
  and directly relevant state facts; all other branches are
  replaced by one-line summaries.
"""

from __future__ import annotations

from typing import Any

from excalibur.memory.branch_summary import BranchSummary, summarize_branch


class ContextCompressor:
    """Compresses context when context load exceeds thresholds.

    Attributes:
        ideal_threshold: Context-load fraction above which moderate
            compression is triggered.
        aggressive_threshold: Context-load fraction above which
            aggressive compression is triggered.
    """

    def __init__(
        self,
        ideal_threshold: float = 0.4,
        aggressive_threshold: float = 0.7,
    ) -> None:
        """Initialise the compressor with threshold values.

        Args:
            ideal_threshold: Moderate compression trigger (0..1).
            aggressive_threshold: Aggressive compression trigger (0..1).
        """
        self.ideal_threshold = ideal_threshold
        self.aggressive_threshold = aggressive_threshold

    def should_compress(self, context_load: float) -> bool:
        """Return ``True`` when the context load warrants compression.

        Args:
            context_load: Fraction of the context window consumed (0..1).

        Returns:
            Whether compression should be applied.
        """
        return context_load > self.ideal_threshold

    def compress(self, tree: Any, context_load: float) -> dict[str, Any]:
        """Generate summaries and compression metadata for *tree*.

        Args:
            tree: An ``AttackTree`` instance (duck-typed).
            context_load: Current fraction of context window consumed.

        Returns:
            Dictionary with keys:
                - ``summaries``: list of ``BranchSummary`` objects
                - ``compression_level``: ``"moderate"`` or ``"aggressive"``
                - ``branches_compressed``: number of branches summarised
                - ``estimated_savings_pct``: rough estimate of context saved
        """
        if context_load > self.aggressive_threshold:
            return self._aggressive_compress(tree)
        return self._moderate_compress(tree)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _moderate_compress(self, tree: Any) -> dict[str, Any]:
        """Moderate compression: summarise sibling branches.

        Non-active branches are replaced by compact summaries; the
        current active path is kept verbatim.

        Args:
            tree: An ``AttackTree`` instance (duck-typed).

        Returns:
            Compression result dictionary.
        """
        summaries: list[BranchSummary] = []
        nodes = getattr(tree, "nodes", {})
        active_id = getattr(tree, "active_node_id", None)

        # Build set of node ids on the active path (root -> active)
        active_path_ids = self._get_active_path_ids(tree, active_id)

        # Summarise every top-level branch that is NOT on the active path
        root_id = getattr(tree, "root_id", None)
        root_node = nodes.get(root_id) if root_id else None
        children = getattr(root_node, "children_ids", []) if root_node else []

        for child_id in children:
            if child_id not in active_path_ids:
                summaries.append(summarize_branch(tree, child_id))

        return {
            "summaries": summaries,
            "compression_level": "moderate",
            "branches_compressed": len(summaries),
            "estimated_savings_pct": min(len(summaries) * 10, 50),
        }

    def _aggressive_compress(self, tree: Any) -> dict[str, Any]:
        """Aggressive compression: keep only the active path.

        Every branch that is not on the direct path from root to the
        active node is collapsed into a one-line summary.  Tool
        outputs on ancestor nodes (excluding the active node) are
        also dropped.

        Args:
            tree: An ``AttackTree`` instance (duck-typed).

        Returns:
            Compression result dictionary.
        """
        summaries: list[BranchSummary] = []
        nodes = getattr(tree, "nodes", {})
        active_id = getattr(tree, "active_node_id", None)
        active_path_ids = self._get_active_path_ids(tree, active_id)

        for node_id in nodes:
            if node_id not in active_path_ids:
                summaries.append(summarize_branch(tree, node_id))

        return {
            "summaries": summaries,
            "compression_level": "aggressive",
            "branches_compressed": len(summaries),
            "estimated_savings_pct": min(len(summaries) * 15, 80),
        }

    @staticmethod
    def _get_active_path_ids(tree: Any, active_id: str | None) -> set[str]:
        """Walk from *active_id* up to the root and return all visited ids.

        Args:
            tree: An ``AttackTree`` instance.
            active_id: The currently active node id.

        Returns:
            Set of node-id strings on the active path.
        """
        path: set[str] = set()
        if active_id is None:
            return path

        nodes = getattr(tree, "nodes", {})
        current: str | None = active_id
        visited: set[str] = set()
        while current and current not in visited:
            visited.add(current)
            path.add(current)
            node = nodes.get(current)
            if node is None:
                break
            current = getattr(node, "parent_id", None)

        return path
