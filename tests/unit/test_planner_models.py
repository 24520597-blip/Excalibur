"""Tests for planner models: TDI computation, attack tree operations, enums.

Unit tests covering TDIScore computed value, AttackNode defaults,
AttackTree traversal, and enum definitions.
"""

from __future__ import annotations

import pytest

from excalibur.planner.models import (
    ActionOutcome,
    AttackNode,
    AttackTree,
    EvidenceLevel,
    NodeStatus,
    NodeType,
    TDIScore,
)


@pytest.mark.unit
class TestTDIScore:
    """Tests for the TDI score model and its computed value."""

    def test_computed_value_with_defaults(self) -> None:
        """TDI value with default weights and inputs is deterministic."""
        score = TDIScore(
            horizon=0.5,
            success_rate=0.5,
            context_load=0.0,
            evidence_confidence=0.5,
        )
        # TDI = 0.3*0.5 + 0.3*(1-0.5) + 0.2*0.0 + 0.2*(1-0.5)
        #     = 0.15 + 0.15 + 0.0 + 0.1 = 0.4
        assert score.value == pytest.approx(0.4)

    def test_computed_value_with_known_weights(self) -> None:
        """TDI value computed correctly with explicit weights."""
        score = TDIScore(
            horizon=1.0,
            success_rate=0.0,
            context_load=1.0,
            evidence_confidence=0.0,
            weight_horizon=0.25,
            weight_evidence=0.25,
            weight_context=0.25,
            weight_success=0.25,
        )
        # TDI = 0.25*1.0 + 0.25*(1-0.0) + 0.25*1.0 + 0.25*(1-0.0)
        #     = 0.25 + 0.25 + 0.25 + 0.25 = 1.0
        assert score.value == pytest.approx(1.0)

    def test_minimum_difficulty(self) -> None:
        """TDI is zero when all dimensions indicate easiest case."""
        score = TDIScore(
            horizon=0.0,
            success_rate=1.0,
            context_load=0.0,
            evidence_confidence=1.0,
        )
        assert score.value == pytest.approx(0.0)

    def test_value_between_zero_and_one(self) -> None:
        """TDI value stays within [0, 1] for valid inputs."""
        score = TDIScore(
            horizon=0.7,
            success_rate=0.3,
            context_load=0.5,
            evidence_confidence=0.6,
        )
        assert 0.0 <= score.value <= 1.0


@pytest.mark.unit
class TestAttackNode:
    """Tests for AttackNode creation and defaults."""

    def test_default_values(self) -> None:
        """AttackNode has expected defaults."""
        node = AttackNode()
        assert node.node_type == NodeType.ACTION
        assert node.status == NodeStatus.PENDING
        assert node.description == ""
        assert node.parent_id is None
        assert node.children_ids == []
        assert node.promise_score == 0.5
        assert node.tdi is None
        assert node.evidence_level == EvidenceLevel.SPECULATIVE
        assert node.visit_count == 0
        assert node.success_count == 0
        assert node.failure_count == 0
        assert node.findings == []
        assert node.host is None
        assert node.tool_used is None

    def test_custom_creation(self) -> None:
        """AttackNode can be created with custom values."""
        node = AttackNode(
            id="test-node",
            node_type=NodeType.OBSERVATION,
            status=NodeStatus.ACTIVE,
            description="Scan port 80",
            host="10.10.10.1",
            evidence_level=EvidenceLevel.CONFIRMED,
            promise_score=0.8,
        )
        assert node.id == "test-node"
        assert node.node_type == NodeType.OBSERVATION
        assert node.status == NodeStatus.ACTIVE
        assert node.description == "Scan port 80"
        assert node.host == "10.10.10.1"
        assert node.evidence_level == EvidenceLevel.CONFIRMED
        assert node.promise_score == 0.8

    def test_auto_generated_id(self) -> None:
        """AttackNode generates a short unique ID by default."""
        node = AttackNode()
        assert isinstance(node.id, str)
        assert len(node.id) == 8

    def test_two_nodes_have_different_ids(self) -> None:
        """Two nodes created separately have distinct IDs."""
        n1 = AttackNode()
        n2 = AttackNode()
        assert n1.id != n2.id


@pytest.mark.unit
class TestAttackTree:
    """Tests for AttackTree add_node, get_node, paths, and leaves."""

    def _make_tree(self) -> tuple[AttackTree, AttackNode]:
        """Build a minimal tree with one root node."""
        root = AttackNode(
            id="root",
            node_type=NodeType.OBSERVATION,
            status=NodeStatus.ACTIVE,
            description="Root",
        )
        tree = AttackTree(root_id=root.id)
        tree.add_node(root)
        return tree, root

    def test_add_and_get_node(self) -> None:
        """Adding a node makes it retrievable via get_node."""
        tree, root = self._make_tree()
        assert tree.get_node("root") is root

    def test_get_node_returns_none_for_missing(self) -> None:
        """get_node returns None for an ID not in the tree."""
        tree, _ = self._make_tree()
        assert tree.get_node("nonexistent") is None

    def test_add_node_updates_parent_children(self) -> None:
        """Adding a child node appends its ID to the parent."""
        tree, root = self._make_tree()
        child = AttackNode(
            id="child1",
            parent_id="root",
            description="Child",
        )
        tree.add_node(child)
        assert "child1" in root.children_ids
        assert tree.get_node("child1") is child

    def test_add_node_no_duplicate_children(self) -> None:
        """Adding the same child twice does not duplicate in parent."""
        tree, root = self._make_tree()
        child = AttackNode(
            id="child1",
            parent_id="root",
            description="Child",
        )
        tree.add_node(child)
        tree.add_node(child)
        assert root.children_ids.count("child1") == 1

    def test_get_path_to_root(self) -> None:
        """Path from a leaf to root includes all ancestors."""
        tree, _root = self._make_tree()
        child = AttackNode(id="c1", parent_id="root")
        grandchild = AttackNode(id="gc1", parent_id="c1")
        tree.add_node(child)
        tree.add_node(grandchild)

        path = tree.get_path_to_root("gc1")
        ids = [n.id for n in path]
        assert ids == ["gc1", "c1", "root"]

    def test_get_path_to_root_for_root(self) -> None:
        """Path from the root is just the root itself."""
        tree, _root = self._make_tree()
        path = tree.get_path_to_root("root")
        assert len(path) == 1
        assert path[0].id == "root"

    def test_get_path_to_root_unknown_id(self) -> None:
        """Path for a nonexistent ID returns empty list."""
        tree, _ = self._make_tree()
        path = tree.get_path_to_root("does-not-exist")
        assert path == []

    def test_get_active_leaves(self) -> None:
        """Active leaves are non-pruned, non-failed leaf nodes."""
        tree, _root = self._make_tree()
        c1 = AttackNode(
            id="c1",
            parent_id="root",
            status=NodeStatus.PENDING,
        )
        c2 = AttackNode(
            id="c2",
            parent_id="root",
            status=NodeStatus.PRUNED,
        )
        c3 = AttackNode(
            id="c3",
            parent_id="root",
            status=NodeStatus.FAILED,
        )
        c4 = AttackNode(
            id="c4",
            parent_id="root",
            status=NodeStatus.ACTIVE,
        )
        for n in [c1, c2, c3, c4]:
            tree.add_node(n)

        leaves = tree.get_active_leaves()
        leaf_ids = {n.id for n in leaves}
        assert "c1" in leaf_ids
        assert "c4" in leaf_ids
        assert "c2" not in leaf_ids
        assert "c3" not in leaf_ids

    def test_get_active_leaves_excludes_non_leaf(self) -> None:
        """Nodes with children are not considered leaves."""
        tree, _root = self._make_tree()
        child = AttackNode(id="c1", parent_id="root")
        grandchild = AttackNode(id="gc1", parent_id="c1")
        tree.add_node(child)
        tree.add_node(grandchild)

        leaves = tree.get_active_leaves()
        leaf_ids = {n.id for n in leaves}
        assert "gc1" in leaf_ids
        assert "c1" not in leaf_ids


@pytest.mark.unit
class TestEnums:
    """Tests for planner enum types."""

    def test_node_type_values(self) -> None:
        """NodeType has the expected members."""
        assert NodeType.OBSERVATION == "observation"
        assert NodeType.HYPOTHESIS == "hypothesis"
        assert NodeType.ACTION == "action"

    def test_node_status_values(self) -> None:
        """NodeStatus has the expected members."""
        expected = {"pending", "active", "completed", "pruned", "failed"}
        actual = {s.value for s in NodeStatus}
        assert actual == expected

    def test_evidence_level_values(self) -> None:
        """EvidenceLevel has correct float values."""
        assert float(EvidenceLevel.VERIFIED) == 1.0
        assert float(EvidenceLevel.CONFIRMED) == 0.8
        assert float(EvidenceLevel.PLAUSIBLE) == 0.5
        assert float(EvidenceLevel.SPECULATIVE) == 0.3

    def test_action_outcome_values(self) -> None:
        """ActionOutcome has correct float values."""
        assert float(ActionOutcome.SUCCESS) == 1.0
        assert float(ActionOutcome.PARTIAL) == 0.5
        assert float(ActionOutcome.FAILURE) == 0.1
