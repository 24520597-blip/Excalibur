"""Tests for the context assembler.

Unit tests covering assemble output, get_context_load, and
mode-specific context differences.
"""

from __future__ import annotations

import pytest

from excalibur.memory.context_assembler import ContextAssembler
from excalibur.memory.models import (
    HostEntity,
    ServiceEntity,
)
from excalibur.memory.state_store import StateStore
from excalibur.planner.models import (
    AttackNode,
    AttackTree,
    EvidenceLevel,
    NodeStatus,
    NodeType,
)


@pytest.fixture
def store_with_data() -> StateStore:
    """Create a populated in-memory StateStore."""
    store = StateStore(db_path=":memory:")
    store.add_host(
        HostEntity(
            id="h1",
            ip_address="10.10.10.1",
            hostname="target.htb",
            os_fingerprint="Linux",
        )
    )
    store.add_service(
        ServiceEntity(
            id="s1",
            host_id="h1",
            port=80,
            service_name="http",
            version="Apache 2.4",
        )
    )
    store.add_service(
        ServiceEntity(
            id="s2",
            host_id="h1",
            port=22,
            service_name="ssh",
        )
    )
    yield store
    store.close()


@pytest.fixture
def simple_tree() -> tuple[AttackTree, AttackNode]:
    """Build a minimal tree with a root and one child."""
    root = AttackNode(
        id="root",
        node_type=NodeType.OBSERVATION,
        status=NodeStatus.ACTIVE,
        description="Initial recon",
        host="10.10.10.1",
        evidence_level=EvidenceLevel.VERIFIED,
    )
    child = AttackNode(
        id="child1",
        node_type=NodeType.ACTION,
        status=NodeStatus.ACTIVE,
        description="Scan port 80",
        parent_id="root",
        host="10.10.10.1",
        evidence_level=EvidenceLevel.CONFIRMED,
    )
    tree = AttackTree(root_id="root")
    tree.add_node(root)
    tree.add_node(child)
    return tree, child


@pytest.mark.unit
class TestAssemble:
    """Tests for ContextAssembler.assemble."""

    def test_assemble_produces_non_empty_context(
        self,
        store_with_data: StateStore,
        simple_tree: tuple[AttackTree, AttackNode],
    ) -> None:
        """assemble returns a non-empty string with context."""
        tree, node = simple_tree
        assembler = ContextAssembler(store_with_data)
        ctx = assembler.assemble(node, tree, mode="bfs")
        assert isinstance(ctx, str)
        assert len(ctx) > 0

    def test_assemble_includes_path_section(
        self,
        store_with_data: StateStore,
        simple_tree: tuple[AttackTree, AttackNode],
    ) -> None:
        """Context includes the attack path section."""
        tree, node = simple_tree
        assembler = ContextAssembler(store_with_data)
        ctx = assembler.assemble(node, tree, mode="dfs")
        assert "Attack Path" in ctx

    def test_assemble_includes_state_facts(
        self,
        store_with_data: StateStore,
        simple_tree: tuple[AttackTree, AttackNode],
    ) -> None:
        """Context includes known state facts section."""
        tree, node = simple_tree
        assembler = ContextAssembler(store_with_data)
        ctx = assembler.assemble(node, tree, mode="bfs")
        assert "State Facts" in ctx
        assert "10.10.10.1" in ctx

    def test_assemble_includes_mode_section(
        self,
        store_with_data: StateStore,
        simple_tree: tuple[AttackTree, AttackNode],
    ) -> None:
        """Context includes mode guidance section."""
        tree, node = simple_tree
        assembler = ContextAssembler(store_with_data)
        ctx = assembler.assemble(node, tree, mode="bfs", tdi_value=0.4)
        assert "Exploration Mode" in ctx
        assert "BFS" in ctx

    def test_empty_store_still_produces_context(
        self,
        simple_tree: tuple[AttackTree, AttackNode],
    ) -> None:
        """Even with an empty store, path + mode context is built."""
        empty_store = StateStore(db_path=":memory:")
        try:
            tree, node = simple_tree
            assembler = ContextAssembler(empty_store)
            ctx = assembler.assemble(node, tree, mode="dfs")
            assert isinstance(ctx, str)
            assert len(ctx) > 0
        finally:
            empty_store.close()


@pytest.mark.unit
class TestGetContextLoad:
    """Tests for ContextAssembler.get_context_load."""

    def test_empty_context_zero_load(self) -> None:
        """Empty string yields a load of 0.0."""
        store = StateStore(db_path=":memory:")
        try:
            assembler = ContextAssembler(store)
            assert assembler.get_context_load("") == 0.0
        finally:
            store.close()

    def test_load_between_zero_and_one(
        self,
        store_with_data: StateStore,
        simple_tree: tuple[AttackTree, AttackNode],
    ) -> None:
        """Context load is a float in [0.0, 1.0]."""
        tree, node = simple_tree
        assembler = ContextAssembler(store_with_data)
        ctx = assembler.assemble(node, tree, mode="hybrid")
        load = assembler.get_context_load(ctx)
        assert 0.0 <= load <= 1.0

    def test_large_context_approaches_one(self) -> None:
        """Very large context string pushes load toward 1.0."""
        store = StateStore(db_path=":memory:")
        try:
            assembler = ContextAssembler(store)
            huge = "x" * 300_000
            load = assembler.get_context_load(huge)
            assert load == pytest.approx(1.0)
        finally:
            store.close()


@pytest.mark.unit
class TestModeDifferences:
    """Tests that different modes produce different context."""

    def test_bfs_vs_dfs_context_differs(
        self,
        store_with_data: StateStore,
        simple_tree: tuple[AttackTree, AttackNode],
    ) -> None:
        """BFS and DFS modes produce different guidance text."""
        tree, node = simple_tree
        assembler = ContextAssembler(store_with_data)
        ctx_bfs = assembler.assemble(node, tree, mode="bfs")
        ctx_dfs = assembler.assemble(node, tree, mode="dfs")
        assert ctx_bfs != ctx_dfs

    def test_hybrid_mode_contains_balanced(
        self,
        store_with_data: StateStore,
        simple_tree: tuple[AttackTree, AttackNode],
    ) -> None:
        """Hybrid mode with mid-range TDI mentions balance."""
        tree, node = simple_tree
        assembler = ContextAssembler(store_with_data)
        ctx = assembler.assemble(node, tree, mode="hybrid", tdi_value=0.5)
        assert "Hybrid" in ctx

    def test_bfs_context_mentions_breadth(
        self,
        store_with_data: StateStore,
        simple_tree: tuple[AttackTree, AttackNode],
    ) -> None:
        """BFS mode guidance mentions breadth-first strategy."""
        tree, node = simple_tree
        assembler = ContextAssembler(store_with_data)
        ctx = assembler.assemble(node, tree, mode="bfs")
        assert "Breadth" in ctx or "breadth" in ctx

    def test_dfs_context_mentions_depth(
        self,
        store_with_data: StateStore,
        simple_tree: tuple[AttackTree, AttackNode],
    ) -> None:
        """DFS mode guidance mentions depth-first strategy."""
        tree, node = simple_tree
        assembler = ContextAssembler(store_with_data)
        ctx = assembler.assemble(node, tree, mode="dfs")
        assert "Depth" in ctx or "depth" in ctx
