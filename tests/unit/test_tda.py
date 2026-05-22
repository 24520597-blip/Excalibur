"""Tests for TDA (Task Difficulty Assessment) computation.

Unit tests covering TDAComputer.compute_tdi, _estimate_horizon,
_compute_success_rate (Laplace smoothing), and _compute_evidence_confidence.
"""

from __future__ import annotations

import pytest

from excalibur.planner.models import (
    AttackNode,
    AttackTree,
    EvidenceLevel,
    NodeStatus,
    NodeType,
    TDIScore,
)
from excalibur.planner.tda import TDAComputer


def _build_tree_with_chain(
    depth: int,
    evidence: EvidenceLevel = EvidenceLevel.SPECULATIVE,
) -> tuple[AttackTree, list[AttackNode]]:
    """Build a linear chain of *depth* nodes rooted at index 0.

    Returns:
        Tuple of (tree, ordered_nodes) where ordered_nodes[0] is root.
    """
    nodes: list[AttackNode] = []
    for i in range(depth):
        parent_id = nodes[i - 1].id if i > 0 else None
        node = AttackNode(
            id=f"n{i}",
            node_type=NodeType.ACTION,
            status=NodeStatus.ACTIVE,
            parent_id=parent_id,
            evidence_level=evidence,
        )
        nodes.append(node)

    tree = AttackTree(root_id=nodes[0].id)
    for n in nodes:
        tree.add_node(n)
    return tree, nodes


@pytest.mark.unit
class TestTDAComputerComputeTdi:
    """Tests for TDAComputer.compute_tdi producing valid scores."""

    def test_compute_tdi_returns_tdi_score(self) -> None:
        """compute_tdi returns an instance of TDIScore."""
        tree, nodes = _build_tree_with_chain(1)
        computer = TDAComputer()
        result = computer.compute_tdi(nodes[0], tree)
        assert isinstance(result, TDIScore)

    def test_tdi_value_in_range(self) -> None:
        """Computed TDI value is between 0 and 1."""
        tree, nodes = _build_tree_with_chain(3)
        computer = TDAComputer()
        for node in nodes:
            tdi = computer.compute_tdi(node, tree, context_load=0.5)
            assert 0.0 <= tdi.value <= 1.0

    def test_context_load_propagated(self) -> None:
        """context_load argument is reflected in the TDIScore."""
        tree, nodes = _build_tree_with_chain(1)
        computer = TDAComputer()
        tdi = computer.compute_tdi(nodes[0], tree, context_load=0.75)
        assert tdi.context_load == pytest.approx(0.75)

    def test_custom_weights_used(self) -> None:
        """Custom weights from the constructor are passed through."""
        custom = {
            "horizon": 0.1,
            "evidence": 0.2,
            "context": 0.3,
            "success": 0.4,
        }
        computer = TDAComputer(weights=custom)
        tree, nodes = _build_tree_with_chain(1)
        tdi = computer.compute_tdi(nodes[0], tree)
        assert tdi.weight_horizon == pytest.approx(0.1)
        assert tdi.weight_evidence == pytest.approx(0.2)
        assert tdi.weight_context == pytest.approx(0.3)
        assert tdi.weight_success == pytest.approx(0.4)


@pytest.mark.unit
class TestEstimateHorizon:
    """Tests for TDAComputer._estimate_horizon."""

    def test_single_node_horizon(self) -> None:
        """A single node has horizon == 1.0 (depth 1 / max 1)."""
        tree, nodes = _build_tree_with_chain(1)
        computer = TDAComputer()
        h = computer._estimate_horizon(nodes[0], tree)
        assert h == pytest.approx(1.0)

    def test_deeper_nodes_have_higher_horizon(self) -> None:
        """Deeper nodes receive a higher horizon value."""
        tree, nodes = _build_tree_with_chain(5)
        computer = TDAComputer()
        h_root = computer._estimate_horizon(nodes[0], tree)
        h_leaf = computer._estimate_horizon(nodes[-1], tree)
        assert h_leaf > h_root

    def test_horizon_bounded_zero_to_one(self) -> None:
        """Horizon values always stay in [0, 1]."""
        tree, nodes = _build_tree_with_chain(10)
        computer = TDAComputer()
        for node in nodes:
            h = computer._estimate_horizon(node, tree)
            assert 0.0 <= h <= 1.0


@pytest.mark.unit
class TestComputeSuccessRate:
    """Tests for TDAComputer._compute_success_rate (Laplace smoothing)."""

    def test_zero_visits(self) -> None:
        """With zero visits Laplace smoothing gives (0+1)/(0+2) = 0.5."""
        node = AttackNode(visit_count=0, success_count=0)
        rate = TDAComputer._compute_success_rate(node)
        assert rate == pytest.approx(0.5)

    def test_all_successes(self) -> None:
        """All successes approaches 1 but stays below due to smoothing."""
        node = AttackNode(visit_count=10, success_count=10)
        rate = TDAComputer._compute_success_rate(node)
        # (10+1)/(10+2) = 11/12 ~ 0.9167
        assert rate == pytest.approx(11.0 / 12.0)
        assert rate < 1.0

    def test_all_failures(self) -> None:
        """Zero successes approaches 0 but stays above due to smoothing."""
        node = AttackNode(visit_count=10, success_count=0)
        rate = TDAComputer._compute_success_rate(node)
        # (0+1)/(10+2) = 1/12 ~ 0.0833
        assert rate == pytest.approx(1.0 / 12.0)
        assert rate > 0.0

    def test_mixed_results(self) -> None:
        """Mixed success/visit counts are correctly smoothed."""
        node = AttackNode(visit_count=8, success_count=3)
        rate = TDAComputer._compute_success_rate(node)
        # (3+1)/(8+2) = 4/10 = 0.4
        assert rate == pytest.approx(0.4)


@pytest.mark.unit
class TestComputeEvidenceConfidence:
    """Tests for TDAComputer._compute_evidence_confidence."""

    def test_single_verified_node(self) -> None:
        """Single VERIFIED node produces confidence of 1.0."""
        tree, nodes = _build_tree_with_chain(1, evidence=EvidenceLevel.VERIFIED)
        computer = TDAComputer()
        ec = computer._compute_evidence_confidence(nodes[0], tree)
        assert ec == pytest.approx(1.0)

    def test_path_mean_confidence(self) -> None:
        """Confidence is the mean evidence level along the path."""
        root = AttackNode(
            id="r",
            evidence_level=EvidenceLevel.VERIFIED,
        )
        child = AttackNode(
            id="c",
            parent_id="r",
            evidence_level=EvidenceLevel.SPECULATIVE,
        )
        tree = AttackTree(root_id="r")
        tree.add_node(root)
        tree.add_node(child)

        computer = TDAComputer()
        ec = computer._compute_evidence_confidence(child, tree)
        expected = (EvidenceLevel.SPECULATIVE.value + EvidenceLevel.VERIFIED.value) / 2.0
        assert ec == pytest.approx(expected)

    def test_uniform_speculative(self) -> None:
        """All SPECULATIVE nodes yield confidence of 0.3."""
        tree, nodes = _build_tree_with_chain(4, evidence=EvidenceLevel.SPECULATIVE)
        computer = TDAComputer()
        ec = computer._compute_evidence_confidence(nodes[-1], tree)
        assert ec == pytest.approx(0.3)
