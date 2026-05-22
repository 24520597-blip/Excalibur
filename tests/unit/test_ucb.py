"""Tests for UCB (Upper Confidence Bound) node selection.

Unit tests covering select_node, empty-tree handling, and the
exploration vs exploitation trade-off.
"""

from __future__ import annotations

import pytest

from excalibur.planner.models import (
    AttackNode,
    AttackTree,
    NodeStatus,
    NodeType,
    TDIScore,
)
from excalibur.planner.ucb import select_node


def _make_leaf_tree(
    leaves: list[dict[str, object]],
) -> AttackTree:
    """Build a flat tree (root + N leaves) from leaf specs.

    Each dict in *leaves* may contain:
        id, promise_score, visit_count, tdi_value
    """
    root = AttackNode(
        id="root",
        node_type=NodeType.OBSERVATION,
        status=NodeStatus.ACTIVE,
    )
    tree = AttackTree(root_id="root", total_actions=10)
    tree.add_node(root)

    for spec in leaves:
        tdi = None
        if "tdi_value" in spec:
            tdi = TDIScore(
                horizon=float(spec["tdi_value"]),  # type: ignore[arg-type]
                success_rate=0.5,
                context_load=0.0,
                evidence_confidence=0.5,
            )
        node = AttackNode(
            id=str(spec.get("id", f"leaf-{id(spec)}")),
            parent_id="root",
            status=NodeStatus.PENDING,
            promise_score=float(
                spec.get("promise_score", 0.5)  # type: ignore[arg-type]
            ),
            visit_count=int(
                spec.get("visit_count", 1)  # type: ignore[arg-type]
            ),
            tdi=tdi,
        )
        tree.add_node(node)
    return tree


@pytest.mark.unit
class TestSelectNode:
    """Tests for the select_node UCB function."""

    def test_returns_none_for_empty_tree(self) -> None:
        """select_node returns None when no active leaves exist."""
        tree = AttackTree()
        assert select_node(tree) is None

    def test_returns_none_when_all_pruned(self) -> None:
        """Returns None when all leaves are pruned or failed."""
        root = AttackNode(id="root", status=NodeStatus.ACTIVE)
        pruned = AttackNode(
            id="p",
            parent_id="root",
            status=NodeStatus.PRUNED,
        )
        failed = AttackNode(
            id="f",
            parent_id="root",
            status=NodeStatus.FAILED,
        )
        tree = AttackTree(root_id="root", total_actions=1)
        tree.add_node(root)
        tree.add_node(pruned)
        tree.add_node(failed)
        assert select_node(tree) is None

    def test_single_candidate_returned(self) -> None:
        """A single active leaf is always selected."""
        tree = _make_leaf_tree([{"id": "only"}])
        result = select_node(tree)
        assert result is not None
        assert result.id == "only"

    def test_highest_promise_selected(self) -> None:
        """With equal visits the node with higher promise wins."""
        tree = _make_leaf_tree(
            [
                {
                    "id": "low",
                    "promise_score": 0.1,
                    "visit_count": 5,
                },
                {
                    "id": "high",
                    "promise_score": 0.9,
                    "visit_count": 5,
                },
            ]
        )
        result = select_node(tree)
        assert result is not None
        assert result.id == "high"


@pytest.mark.unit
class TestExplorationExploitation:
    """Tests verifying exploration vs exploitation trade-off."""

    def test_unvisited_node_preferred(self) -> None:
        """Rarely visited node is preferred over frequently visited."""
        tree = _make_leaf_tree(
            [
                {
                    "id": "visited",
                    "promise_score": 0.6,
                    "visit_count": 100,
                },
                {
                    "id": "fresh",
                    "promise_score": 0.5,
                    "visit_count": 1,
                },
            ]
        )
        # With high total_actions, the exploration term for
        # the fresh node should dominate.
        tree.total_actions = 200
        result = select_node(tree, exploration_constant=2.0)
        assert result is not None
        assert result.id == "fresh"

    def test_high_difficulty_penalised(self) -> None:
        """Node with high TDI is penalised and the easier node wins."""
        tree = _make_leaf_tree(
            [
                {
                    "id": "hard",
                    "promise_score": 0.7,
                    "visit_count": 5,
                    "tdi_value": 0.9,
                },
                {
                    "id": "easy",
                    "promise_score": 0.5,
                    "visit_count": 5,
                    "tdi_value": 0.1,
                },
            ]
        )
        result = select_node(
            tree,
            exploration_constant=0.0,
            difficulty_penalty=2.0,
        )
        assert result is not None
        assert result.id == "easy"

    def test_zero_exploration_pure_exploit(self) -> None:
        """With exploration_constant=0, selection is purely by promise."""
        tree = _make_leaf_tree(
            [
                {"id": "a", "promise_score": 0.3, "visit_count": 1},
                {"id": "b", "promise_score": 0.8, "visit_count": 1},
            ]
        )
        result = select_node(
            tree,
            exploration_constant=0.0,
            difficulty_penalty=0.0,
        )
        assert result is not None
        assert result.id == "b"
