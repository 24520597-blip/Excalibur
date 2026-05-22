"""Tests for backpropagation of action outcomes through the attack tree.

Unit tests covering promise score updates, different outcomes
(SUCCESS, PARTIAL, FAILURE), and visit count increments.
"""

from __future__ import annotations

import pytest

from excalibur.planner.backpropagation import backpropagate
from excalibur.planner.models import (
    ActionOutcome,
    AttackNode,
    AttackTree,
    NodeStatus,
    NodeType,
)


def _chain_tree(n: int = 3) -> tuple[AttackTree, list[AttackNode]]:
    """Build a linear chain of *n* nodes (index 0 = root).

    All nodes start with promise_score=0.5, visit_count=0.
    """
    nodes: list[AttackNode] = []
    for i in range(n):
        node = AttackNode(
            id=f"n{i}",
            node_type=NodeType.ACTION,
            status=NodeStatus.ACTIVE,
            parent_id=nodes[i - 1].id if i > 0 else None,
            promise_score=0.5,
        )
        nodes.append(node)
    tree = AttackTree(root_id=nodes[0].id)
    for nd in nodes:
        tree.add_node(nd)
    return tree, nodes


@pytest.mark.unit
class TestBackpropagate:
    """Tests for the backpropagate function."""

    def test_updates_promise_along_path(self) -> None:
        """All nodes on the path from leaf to root are updated."""
        tree, nodes = _chain_tree(3)
        leaf = nodes[-1]
        backpropagate(tree, leaf, ActionOutcome.SUCCESS, alpha=0.7)

        for node in nodes:
            assert node.promise_score != 0.5 or node.visit_count > 0

    def test_success_increases_promise(self) -> None:
        """SUCCESS outcome raises promise_score from its initial value."""
        tree, nodes = _chain_tree(2)
        leaf = nodes[-1]
        initial = leaf.promise_score
        backpropagate(tree, leaf, ActionOutcome.SUCCESS, alpha=0.5)
        # reward = 1.0, new = 0.5*0.5 + 0.5*1.0 = 0.75
        assert leaf.promise_score > initial

    def test_failure_decreases_promise(self) -> None:
        """FAILURE outcome lowers promise_score from its initial value."""
        tree, nodes = _chain_tree(2)
        leaf = nodes[-1]
        initial = leaf.promise_score
        backpropagate(tree, leaf, ActionOutcome.FAILURE, alpha=0.5)
        # reward = 0.1, new = 0.5*0.5 + 0.5*0.1 = 0.30
        assert leaf.promise_score < initial

    def test_partial_moderate_change(self) -> None:
        """PARTIAL outcome keeps promise roughly in the middle."""
        tree, nodes = _chain_tree(2)
        leaf = nodes[-1]
        backpropagate(tree, leaf, ActionOutcome.PARTIAL, alpha=0.5)
        # reward = 0.5, new = 0.5*0.5 + 0.5*0.5 = 0.5
        assert leaf.promise_score == pytest.approx(0.5)

    def test_visit_counts_increment(self) -> None:
        """Every node on the path gets its visit_count incremented."""
        tree, nodes = _chain_tree(4)
        leaf = nodes[-1]
        backpropagate(tree, leaf, ActionOutcome.SUCCESS)
        for node in nodes:
            assert node.visit_count == 1

    def test_success_count_incremented(self) -> None:
        """SUCCESS outcome increments success_count on path nodes."""
        tree, nodes = _chain_tree(3)
        backpropagate(tree, nodes[-1], ActionOutcome.SUCCESS)
        for node in nodes:
            assert node.success_count == 1
            assert node.failure_count == 0

    def test_failure_count_incremented(self) -> None:
        """FAILURE outcome increments failure_count on path nodes."""
        tree, nodes = _chain_tree(3)
        backpropagate(tree, nodes[-1], ActionOutcome.FAILURE)
        for node in nodes:
            assert node.failure_count == 1
            assert node.success_count == 0

    def test_partial_no_success_or_failure_count(self) -> None:
        """PARTIAL outcome does not increment success or failure counts."""
        tree, nodes = _chain_tree(2)
        backpropagate(tree, nodes[-1], ActionOutcome.PARTIAL)
        for node in nodes:
            assert node.success_count == 0
            assert node.failure_count == 0

    def test_multiple_backpropagations(self) -> None:
        """Repeated backpropagation accumulates visits correctly."""
        tree, nodes = _chain_tree(2)
        leaf = nodes[-1]
        for _ in range(5):
            backpropagate(tree, leaf, ActionOutcome.SUCCESS)
        assert leaf.visit_count == 5
        assert leaf.success_count == 5

    def test_alpha_controls_smoothing(self) -> None:
        """Higher alpha retains more history in the promise score."""
        tree_a, nodes_a = _chain_tree(1)
        tree_b, nodes_b = _chain_tree(1)

        backpropagate(tree_a, nodes_a[0], ActionOutcome.SUCCESS, alpha=0.9)
        backpropagate(tree_b, nodes_b[0], ActionOutcome.SUCCESS, alpha=0.1)

        # alpha=0.9: 0.9*0.5 + 0.1*1.0 = 0.55
        # alpha=0.1: 0.1*0.5 + 0.9*1.0 = 0.95
        assert nodes_a[0].promise_score < nodes_b[0].promise_score
