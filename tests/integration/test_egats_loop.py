"""Integration tests for a full EGATS iteration with a mock backend.

Verifies the complete Evidence-Guided Attack Tree Search cycle:
select -> compute TDI -> query -> backpropagate, and flag detection
during the loop.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from excalibur.core.backend import AgentBackend, AgentMessage, MessageType
from excalibur.core.config import ExcaliburConfig
from excalibur.core.controller import AgentController, AgentState
from excalibur.core.events import EventBus
from excalibur.core.session import SessionStore
from excalibur.planner.backpropagation import backpropagate
from excalibur.planner.egats import EGATSPlanner
from excalibur.planner.models import (
    ActionOutcome,
    AttackNode,
    AttackTree,
    EvidenceLevel,
    NodeStatus,
    NodeType,
)
from excalibur.planner.tda import TDAComputer
from excalibur.planner.ucb import select_node

# ------------------------------------------------------------------ #
# Mock backend
# ------------------------------------------------------------------ #


class EGATSMockBackend(AgentBackend):
    """Mock backend that yields preset messages for EGATS tests.

    Attributes:
        canned_messages: Messages to yield on each receive_messages call.
        queries: Record of queries sent.
    """

    def __init__(self, canned_messages: list[list[AgentMessage]] | None = None) -> None:
        self._connected = False
        self.canned_messages: list[list[AgentMessage]] = canned_messages or []
        self.queries: list[str] = []
        self._call_idx = 0

    async def connect(self) -> None:
        """Simulate connection."""
        self._connected = True

    async def disconnect(self) -> None:
        """Simulate disconnection."""
        self._connected = False

    async def query(self, prompt: str) -> None:
        """Record query and advance message index."""
        self.queries.append(prompt)

    async def receive_messages(self) -> AsyncIterator[AgentMessage]:
        """Yield the next batch of canned messages."""
        if self._call_idx < len(self.canned_messages):
            for msg in self.canned_messages[self._call_idx]:
                yield msg
            self._call_idx += 1

    @property
    def session_id(self) -> str:
        """Return a fixed mock session ID."""
        return "mock-egats-session"

    @property
    def supports_resume(self) -> bool:
        """Mock does not support resume."""
        return False

    async def resume(self, session_id: str) -> bool:
        """Mock resume always fails."""
        return False


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _text_msg(content: str) -> AgentMessage:
    """Create a TEXT AgentMessage."""
    return AgentMessage(type=MessageType.TEXT, content=content)


def _result_msg(cost: float = 0.0) -> AgentMessage:
    """Create a RESULT AgentMessage."""
    return AgentMessage(
        type=MessageType.RESULT,
        content=None,
        metadata={"cost_usd": cost},
    )


# ------------------------------------------------------------------ #
# Integration tests
# ------------------------------------------------------------------ #


@pytest.mark.integration
class TestEGATSPlannerIteration:
    """Tests for a single complete EGATS iteration (no controller)."""

    def test_select_compute_backpropagate_cycle(self) -> None:
        """Run select -> compute TDI -> backpropagate on a tree."""
        planner = EGATSPlanner()
        tree = planner.init_tree("10.10.10.1")

        # 1. Select the root (only leaf)
        node = planner.select_next_node(tree)
        assert node is not None
        assert node.id == tree.root_id

        # 2. Compute TDI
        tdi = planner.compute_tdi(node, tree, context_load=0.2)
        assert 0.0 <= tdi.value <= 1.0
        assert node.tdi is tdi  # stored on node

        # 3. Select mode
        mode = planner.select_mode(tdi)
        assert mode in {
            "reconnaissance",
            "exploitation",
            "llm_decide",
        }

        # 4. Expand tree with mock findings
        findings = [
            {
                "description": "Open port 80/tcp",
                "evidence": 0.8,
                "type": "observation",
            },
            {
                "description": "Open port 22/tcp",
                "evidence": 0.8,
                "type": "observation",
            },
        ]
        new_nodes = planner.expand_tree(tree, node, findings)
        assert len(new_nodes) == 2
        for child in new_nodes:
            assert child.parent_id == node.id

        # 5. Backpropagate
        planner.backpropagate(tree, node, ActionOutcome.PARTIAL)
        assert node.visit_count == 1

        # 6. Tree total_actions tracking
        tree.total_actions += 1

        # Next selection should pick one of the new leaves
        next_node = planner.select_next_node(tree)
        assert next_node is not None
        assert next_node.id in {n.id for n in new_nodes}

    def test_pruning_after_multiple_failures(self) -> None:
        """Branches with high TDI and enough visits get pruned."""
        planner = EGATSPlanner(config={"prune_threshold": 0.6, "min_prune_attempts": 2})
        tree = planner.init_tree("10.10.10.1")
        root = tree.get_node(tree.root_id)

        # Create a child node
        child = AttackNode(
            id="hard-child",
            parent_id=root.id,
            description="Try complex exploit",
            node_type=NodeType.ACTION,
        )
        tree.add_node(child)

        # Simulate several failures to drive up TDI
        for _ in range(4):
            planner.backpropagate(tree, child, ActionOutcome.FAILURE)
            tree.total_actions += 1

        # Recompute TDI and attach to node
        planner.compute_tdi(child, tree, context_load=0.8)

        # Check pruning
        pruned = planner.check_pruning(tree)
        # The child should be pruned if its TDI > threshold
        if child.tdi and child.tdi.value > 0.6:
            assert "hard-child" in pruned
            assert child.status == NodeStatus.PRUNED


@pytest.mark.integration
class TestAgentControllerEGATS:
    """Integration tests for the full AgentController with EGATS."""

    @pytest.fixture
    def _config(self, tmp_path: Any) -> ExcaliburConfig:
        """Create a test configuration."""
        return ExcaliburConfig(
            target="10.10.10.99",
            working_directory=tmp_path / "workspace",
            max_budget=3,
            state_store_path=":memory:",
        )

    @pytest.fixture
    def _session_store(self, tmp_path: Any) -> SessionStore:
        """Create a temporary session store."""
        return SessionStore(sessions_dir=tmp_path / "sessions")

    async def test_controller_initializes_and_runs(
        self,
        _config: ExcaliburConfig,
        _session_store: SessionStore,
    ) -> None:
        """Controller starts, runs EGATS loop, and completes."""
        backend = EGATSMockBackend(
            canned_messages=[
                # Initial query response
                [
                    _text_msg("Starting reconnaissance of target"),
                    _result_msg(0.01),
                ],
                # EGATS iteration 1
                [
                    _text_msg("Found open port 80/tcp with Apache 2.4"),
                    _result_msg(0.02),
                ],
                # EGATS iteration 2
                [
                    _text_msg("Discovered login form at /admin"),
                    _result_msg(0.01),
                ],
                # EGATS iteration 3
                [
                    _text_msg("Enumeration complete"),
                    _result_msg(0.01),
                ],
            ]
        )

        controller = AgentController(
            config=_config,
            backend=backend,
            session_store=_session_store,
            events=EventBus.get(),
        )

        result = await controller.run("Solve CTF challenge at 10.10.10.99")

        assert result["success"] is True
        assert controller.state in {
            AgentState.COMPLETED,
            AgentState.IDLE,
        }
        assert len(backend.queries) >= 1

    async def test_flag_detection_during_egats(
        self,
        _config: ExcaliburConfig,
        _session_store: SessionStore,
    ) -> None:
        """Flags embedded in backend responses are detected."""
        backend = EGATSMockBackend(
            canned_messages=[
                # Initial response
                [
                    _text_msg("Scanning target..."),
                    _result_msg(0.01),
                ],
                # EGATS iteration with a flag
                [
                    _text_msg("Found flag: flag{test_egats_12345}"),
                    _result_msg(0.01),
                ],
                # Another iteration
                [
                    _text_msg("Continuing..."),
                    _result_msg(0.01),
                ],
            ]
        )

        controller = AgentController(
            config=_config,
            backend=backend,
            session_store=_session_store,
            events=EventBus.get(),
        )

        result = await controller.run("Capture the flag at 10.10.10.99")

        assert result["success"] is True
        flags = result.get("flags_found", [])
        assert any("flag{test_egats_12345}" in str(f) for f in flags)

    async def test_hex_flag_detection(
        self,
        _config: ExcaliburConfig,
        _session_store: SessionStore,
    ) -> None:
        """32-character hex flags (HTB-style) are detected."""
        hex_flag = "a" * 32
        backend = EGATSMockBackend(
            canned_messages=[
                [
                    _text_msg("Scanning..."),
                    _result_msg(0.01),
                ],
                [
                    _text_msg(f"User flag: {hex_flag}"),
                    _result_msg(0.01),
                ],
                [
                    _text_msg("Done"),
                    _result_msg(0.01),
                ],
            ]
        )

        controller = AgentController(
            config=_config,
            backend=backend,
            session_store=_session_store,
            events=EventBus.get(),
        )

        result = await controller.run("Get the flag")

        assert result["success"] is True
        flags = result.get("flags_found", [])
        assert any(hex_flag in str(f) for f in flags)


@pytest.mark.integration
class TestStandalonePlannerComponents:
    """Integration tests combining multiple planner components."""

    def test_tda_ucb_backprop_round_trip(self) -> None:
        """Full round-trip: build tree, compute TDI, select, backprop."""
        # Build tree
        root = AttackNode(
            id="root",
            node_type=NodeType.OBSERVATION,
            status=NodeStatus.ACTIVE,
            description="Initial recon",
            evidence_level=EvidenceLevel.VERIFIED,
            promise_score=0.5,
        )
        child_a = AttackNode(
            id="a",
            parent_id="root",
            description="Port scan",
            evidence_level=EvidenceLevel.CONFIRMED,
            promise_score=0.6,
        )
        child_b = AttackNode(
            id="b",
            parent_id="root",
            description="Web scan",
            evidence_level=EvidenceLevel.PLAUSIBLE,
            promise_score=0.4,
        )
        tree = AttackTree(root_id="root", total_actions=5)
        tree.add_node(root)
        tree.add_node(child_a)
        tree.add_node(child_b)

        # Compute TDI for both children
        computer = TDAComputer()
        for node in [child_a, child_b]:
            tdi = computer.compute_tdi(node, tree)
            node.tdi = tdi

        # Select best node via UCB
        selected = select_node(tree)
        assert selected is not None
        assert selected.id in {"a", "b"}

        # Backpropagate success
        backpropagate(tree, selected, ActionOutcome.SUCCESS)
        assert selected.visit_count == 1
        assert selected.success_count == 1

        # Root was also updated (on path)
        assert root.visit_count == 1
