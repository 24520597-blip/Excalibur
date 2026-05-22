"""Tests for branch pruning and credential-driven re-evaluation.

Unit tests covering should_prune thresholds, prune_branch descendant
marking, and reevaluate_pruned reopening of auth-related branches.
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
from excalibur.planner.pruning import (
    prune_branch,
    reevaluate_pruned,
    should_prune,
)


def _high_tdi(value: float = 0.9) -> TDIScore:
    """Return a TDIScore whose .value property approximates *value*.

    We set horizon to a high value and other dimensions to make the
    composite close to *value*.
    """
    return TDIScore(
        horizon=value,
        success_rate=0.0,
        context_load=value,
        evidence_confidence=0.0,
        weight_horizon=0.3,
        weight_evidence=0.3,
        weight_context=0.2,
        weight_success=0.2,
    )


def _low_tdi() -> TDIScore:
    """Return a TDI score with a low composite value."""
    return TDIScore(
        horizon=0.0,
        success_rate=1.0,
        context_load=0.0,
        evidence_confidence=1.0,
    )


@pytest.mark.unit
class TestShouldPrune:
    """Tests for the should_prune decision function."""

    def test_prune_when_tdi_above_threshold_and_enough_visits(
        self,
    ) -> None:
        """Returns True when TDI > threshold and visits >= min."""
        node = AttackNode(tdi=_high_tdi(0.95), visit_count=5)
        assert should_prune(node, threshold=0.8, min_attempts=3)

    def test_no_prune_when_tdi_below_threshold(self) -> None:
        """Returns False when TDI is below the threshold."""
        node = AttackNode(tdi=_low_tdi(), visit_count=10)
        assert not should_prune(node, threshold=0.8, min_attempts=3)

    def test_no_prune_when_visits_below_minimum(self) -> None:
        """Returns False when visit_count is less than min_attempts."""
        node = AttackNode(tdi=_high_tdi(), visit_count=1)
        assert not should_prune(node, threshold=0.8, min_attempts=3)

    def test_no_prune_when_tdi_is_none(self) -> None:
        """Returns False when node has no TDI score at all."""
        node = AttackNode(tdi=None, visit_count=100)
        assert not should_prune(node, threshold=0.5, min_attempts=1)

    def test_prune_at_exact_threshold_boundary(self) -> None:
        """At exactly the threshold boundary: must exceed, not equal."""
        # Create a TDI with value == 0.8 exactly
        score = TDIScore(
            horizon=0.8,
            success_rate=0.8,
            context_load=0.8,
            evidence_confidence=0.2,
            weight_horizon=1.0,
            weight_evidence=0.0,
            weight_context=0.0,
            weight_success=0.0,
        )
        # value = 1.0*0.8 = 0.8, which is NOT > 0.8
        node = AttackNode(tdi=score, visit_count=5)
        assert not should_prune(node, threshold=0.8, min_attempts=3)


@pytest.mark.unit
class TestPruneBranch:
    """Tests for prune_branch marking descendants as PRUNED."""

    def _build_subtree(self) -> tuple[AttackTree, AttackNode]:
        """Build a tree: root -> A -> [B, C] for pruning tests."""
        root = AttackNode(
            id="root",
            node_type=NodeType.OBSERVATION,
            status=NodeStatus.ACTIVE,
        )
        a = AttackNode(
            id="a",
            parent_id="root",
            status=NodeStatus.PENDING,
        )
        b = AttackNode(
            id="b",
            parent_id="a",
            status=NodeStatus.PENDING,
        )
        c = AttackNode(
            id="c",
            parent_id="a",
            status=NodeStatus.PENDING,
        )
        tree = AttackTree(root_id="root")
        for nd in [root, a, b, c]:
            tree.add_node(nd)
        return tree, a

    def test_prune_sets_descendants_to_pruned(self) -> None:
        """prune_branch marks the node and all descendants."""
        tree, node_a = self._build_subtree()
        pruned_ids = prune_branch(tree, node_a)
        assert "a" in pruned_ids
        assert "b" in pruned_ids
        assert "c" in pruned_ids
        for nid in pruned_ids:
            assert tree.get_node(nid).status == NodeStatus.PRUNED

    def test_prune_returns_pruned_ids(self) -> None:
        """prune_branch returns the list of affected node IDs."""
        tree, node_a = self._build_subtree()
        result = prune_branch(tree, node_a)
        assert set(result) == {"a", "b", "c"}

    def test_prune_does_not_affect_root(self) -> None:
        """Pruning a subtree does not mark the root as PRUNED."""
        tree, node_a = self._build_subtree()
        prune_branch(tree, node_a)
        root = tree.get_node("root")
        assert root.status == NodeStatus.ACTIVE

    def test_prune_already_pruned_is_noop(self) -> None:
        """Pruning an already-pruned node returns empty list."""
        tree, node_a = self._build_subtree()
        prune_branch(tree, node_a)
        # Prune again
        result = prune_branch(tree, node_a)
        assert result == []


@pytest.mark.unit
class TestReevaluatePruned:
    """Tests for reevaluate_pruned reopening auth branches."""

    def _build_pruned_tree(self) -> AttackTree:
        """Build a tree with two pruned auth-related nodes."""
        root = AttackNode(id="root", status=NodeStatus.ACTIVE)
        ssh_node = AttackNode(
            id="ssh",
            parent_id="root",
            status=NodeStatus.PRUNED,
            description="Try SSH login on 10.10.10.1",
            visit_count=5,
            success_count=0,
            failure_count=5,
        )
        web_node = AttackNode(
            id="web",
            parent_id="root",
            status=NodeStatus.PRUNED,
            description="Enumerate web directory on port 80",
            visit_count=3,
        )
        tree = AttackTree(root_id="root")
        for nd in [root, ssh_node, web_node]:
            tree.add_node(nd)
        return tree

    def test_reopens_auth_related_branch(self) -> None:
        """Pruned SSH node is reopened when credentials arrive."""
        tree = self._build_pruned_tree()
        reopened = reevaluate_pruned(tree, ["admin:password123"])
        assert "ssh" in reopened
        node = tree.get_node("ssh")
        assert node.status == NodeStatus.PENDING

    def test_does_not_reopen_non_auth_branch(self) -> None:
        """Non-auth-related pruned node stays pruned."""
        tree = self._build_pruned_tree()
        reopened = reevaluate_pruned(tree, ["admin:password123"])
        assert "web" not in reopened
        node = tree.get_node("web")
        assert node.status == NodeStatus.PRUNED

    def test_resets_statistics_on_reopen(self) -> None:
        """Reopened node has visit/success/failure counts reset."""
        tree = self._build_pruned_tree()
        reevaluate_pruned(tree, ["root:toor"])
        node = tree.get_node("ssh")
        assert node.visit_count == 0
        assert node.success_count == 0
        assert node.failure_count == 0

    def test_empty_credentials_no_change(self) -> None:
        """Empty credential list produces no reopened nodes."""
        tree = self._build_pruned_tree()
        reopened = reevaluate_pruned(tree, [])
        assert reopened == []

    def test_non_pruned_nodes_unaffected(self) -> None:
        """Active nodes are never touched by reevaluate_pruned."""
        tree = self._build_pruned_tree()
        reevaluate_pruned(tree, ["cred"])
        root = tree.get_node("root")
        assert root.status == NodeStatus.ACTIVE
