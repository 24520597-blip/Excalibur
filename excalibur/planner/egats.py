"""EGATS — Evidence-Guided Attack Tree Search orchestrator.

Combines TDA scoring, UCB node selection, backpropagation, pruning,
pivot spawning, and mode selection into a single high-level API that
the agent controller can drive.
"""

from __future__ import annotations

from typing import Any

from excalibur.planner.backpropagation import backpropagate
from excalibur.planner.mode_selector import select_mode
from excalibur.planner.models import (
    ActionOutcome,
    AttackNode,
    AttackTree,
    EvidenceLevel,
    NodeStatus,
    NodeType,
    TDIScore,
)
from excalibur.planner.pivot import propagate_credentials, spawn_pivot
from excalibur.planner.pruning import prune_branch, should_prune
from excalibur.planner.tda import TDAComputer
from excalibur.planner.ucb import select_node

# Default configuration for the EGATS planner.
_DEFAULT_CONFIG: dict[str, Any] = {
    "exploration_constant": 1.414,
    "difficulty_penalty": 0.5,
    "backprop_alpha": 0.7,
    "prune_threshold": 0.8,
    "min_prune_attempts": 3,
    "bfs_threshold": 0.6,
    "dfs_threshold": 0.3,
    "tda_weights": {
        "horizon": 0.3,
        "evidence": 0.3,
        "context": 0.2,
        "success": 0.2,
    },
}


class EGATSPlanner:
    """Evidence-Guided Attack Tree Search orchestrator.

    This class ties together every sub-component of the TDA-EGATS
    planning pipeline:

    * **TDA** -- Task Difficulty Assessment for each node.
    * **UCB** -- Upper Confidence Bound selection of the next node.
    * **Backpropagation** -- Reward propagation along the path to root.
    * **Pruning** -- Removal of high-difficulty, low-reward branches.
    * **Pivot spawning** -- Lateral movement to newly compromised hosts.
    * **Mode selection** -- BFS / DFS / LLM-decide switching.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config: dict[str, Any] = {**_DEFAULT_CONFIG, **(config or {})}
        self.tda = TDAComputer(weights=self.config["tda_weights"])

    # ------------------------------------------------------------------
    # Tree lifecycle
    # ------------------------------------------------------------------

    def init_tree(self, target: str) -> AttackTree:
        """Create a fresh attack tree with a root node for *target*.

        Args:
            target: The IP address or hostname of the initial target.

        Returns:
            A new ``AttackTree`` ready for planning.
        """
        root = AttackNode(
            node_type=NodeType.OBSERVATION,
            status=NodeStatus.ACTIVE,
            description=f"Initial reconnaissance of {target}",
            host=target,
            evidence_level=EvidenceLevel.VERIFIED,
            promise_score=0.5,
        )
        tree = AttackTree(root_id=root.id)
        tree.add_node(root)
        return tree

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def select_next_node(self, tree: AttackTree) -> AttackNode | None:
        """Select the next node to expand using UCB.

        Args:
            tree: The current attack tree.

        Returns:
            The best candidate node, or ``None`` if no candidates exist.
        """
        return select_node(
            tree,
            self.config["exploration_constant"],
            self.config["difficulty_penalty"],
        )

    # ------------------------------------------------------------------
    # TDA & mode
    # ------------------------------------------------------------------

    def compute_tdi(
        self,
        node: AttackNode,
        tree: AttackTree,
        context_load: float = 0.0,
    ) -> TDIScore:
        """Compute and attach the TDI score for *node*.

        Args:
            node: The node to evaluate.
            tree: The full attack tree.
            context_load: Current token-budget utilization (0..1).

        Returns:
            The computed ``TDIScore`` (also stored on ``node.tdi``).
        """
        tdi = self.tda.compute_tdi(node, tree, context_load)
        node.tdi = tdi
        return tdi

    def select_mode(self, tdi: TDIScore) -> str:
        """Map a TDI score to an execution mode string.

        Args:
            tdi: The TDI score to evaluate.

        Returns:
            One of ``"reconnaissance"``, ``"exploitation"``, or
            ``"llm_decide"``.
        """
        return select_mode(
            tdi.value,
            self.config["bfs_threshold"],
            self.config["dfs_threshold"],
        )

    # ------------------------------------------------------------------
    # Tree expansion
    # ------------------------------------------------------------------

    def expand_tree(
        self,
        tree: AttackTree,
        parent: AttackNode,
        findings: list[dict[str, Any]],
    ) -> list[AttackNode]:
        """Add child nodes to *parent* from a list of findings.

        Each entry in *findings* may contain:

        * ``type`` -- a :class:`NodeType` value (default ``ACTION``).
        * ``description`` -- free-text description.
        * ``host`` -- target host (defaults to parent's host).
        * ``evidence`` -- float evidence level (default 0.5).

        Args:
            tree: The attack tree to expand.
            parent: The parent node under which children are added.
            findings: A list of dicts describing discovered information.

        Returns:
            The list of newly created ``AttackNode`` instances.
        """
        new_nodes: list[AttackNode] = []
        for finding in findings:
            child = AttackNode(
                node_type=finding.get("type", NodeType.ACTION),
                description=finding.get("description", ""),
                parent_id=parent.id,
                host=finding.get("host", parent.host),
                evidence_level=EvidenceLevel(finding.get("evidence", 0.5)),
            )
            tree.add_node(child)
            new_nodes.append(child)
        return new_nodes

    # ------------------------------------------------------------------
    # Backpropagation
    # ------------------------------------------------------------------

    def backpropagate(
        self,
        tree: AttackTree,
        node: AttackNode,
        outcome: ActionOutcome,
    ) -> None:
        """Propagate an action outcome from *node* to the root.

        Args:
            tree: The attack tree.
            node: The node that produced the outcome.
            outcome: The observed action outcome.
        """
        backpropagate(tree, node, outcome, self.config["backprop_alpha"])

    # ------------------------------------------------------------------
    # Pruning
    # ------------------------------------------------------------------

    def check_pruning(self, tree: AttackTree) -> list[str]:
        """Scan the tree and prune branches exceeding the difficulty threshold.

        Args:
            tree: The attack tree to prune.

        Returns:
            A list of node IDs that were pruned.
        """
        pruned_ids: list[str] = []
        for node in list(tree.nodes.values()):
            if should_prune(
                node,
                self.config["prune_threshold"],
                self.config["min_prune_attempts"],
            ):
                pruned_ids.extend(prune_branch(tree, node))
        return pruned_ids

    # ------------------------------------------------------------------
    # Pivoting & credential propagation
    # ------------------------------------------------------------------

    def spawn_pivot(
        self,
        tree: AttackTree,
        host: str,
        parent: AttackNode,
    ) -> AttackNode:
        """Create a pivot sub-tree rooted at a newly compromised *host*.

        Args:
            tree: The attack tree.
            host: The compromised host address.
            parent: The action node that achieved the compromise.

        Returns:
            The newly created pivot ``AttackNode``.
        """
        return spawn_pivot(tree, host, parent)

    def propagate_credentials(
        self,
        tree: AttackTree,
        credentials: list[str],
    ) -> list[str]:
        """Re-evaluate pruned nodes given newly discovered *credentials*.

        Args:
            tree: The attack tree.
            credentials: Newly found credential strings.

        Returns:
            A list of node IDs that were reopened.
        """
        return propagate_credentials(tree, credentials)
