"""Regression tests for planner/controller integration fixes."""

from __future__ import annotations

from pathlib import Path

import pytest

from excalibur.core.config import ExcaliburConfig
from excalibur.core.controller import AgentController
from excalibur.memory.context_assembler import ContextAssembler
from excalibur.memory.context_compressor import ContextCompressor
from excalibur.memory.state_store import StateStore
from excalibur.planner.models import ActionOutcome, AttackNode, AttackTree, NodeStatus


@pytest.mark.unit
def test_completed_leaf_is_not_selected_again() -> None:
    node = AttackNode(id="done", status=NodeStatus.COMPLETED)
    tree = AttackTree(root_id=node.id)
    tree.add_node(node)
    assert tree.get_active_leaves() == []


@pytest.mark.unit
def test_controller_marks_new_flag_as_success(tmp_path: Path) -> None:
    config = ExcaliburConfig(target="example.com", working_directory=tmp_path)
    controller = AgentController(config)
    outcome = controller._assess_outcome(["Found flag{new}"], {"flag{old}"})
    assert outcome == ActionOutcome.SUCCESS


@pytest.mark.unit
def test_controller_records_hosts_services_and_vulnerabilities(tmp_path: Path) -> None:
    config = ExcaliburConfig(target="10.0.0.1", working_directory=tmp_path)
    controller = AgentController(config)
    controller._init_egats()
    node = AttackNode(id="node", host="10.0.0.1")

    controller._record_findings(
        node,
        [
            {"description": "Discovered host: 10.0.0.2", "host": "10.0.0.2"},
            {"description": "Open port 443/tcp"},
            {"description": "Potential vulnerability: sql injection"},
        ],
    )

    store = controller._state_store
    assert store.get_host_by_ip("10.0.0.2") is not None
    target = store.get_host_by_ip("10.0.0.1")
    assert target is not None
    assert store.get_services_for_host(target.id)[0].port == 443
    assert len(store.get_vulnerabilities_for_host(target.id)) == 1
    store.close()


@pytest.mark.unit
def test_context_accepts_controller_mode_names() -> None:
    store = StateStore(":memory:")
    try:
        node = AttackNode(id="root", status=NodeStatus.ACTIVE)
        tree = AttackTree(root_id=node.id)
        tree.add_node(node)
        assembler = ContextAssembler(store)

        assert "BFS" in assembler.assemble(node, tree, "reconnaissance")
        assert "DFS" in assembler.assemble(node, tree, "exploitation")
        assert "HYBRID" in assembler.assemble(node, tree, "llm_decide")
    finally:
        store.close()


@pytest.mark.unit
def test_context_compressor_uses_attack_tree_fields() -> None:
    root = AttackNode(id="root", status=NodeStatus.ACTIVE)
    active = AttackNode(id="active", parent_id="root", status=NodeStatus.ACTIVE)
    sibling = AttackNode(id="sibling", parent_id="root")
    tree = AttackTree(root_id="root", active_node_id="active")
    for node in (root, active, sibling):
        tree.add_node(node)

    result = ContextCompressor().compress(tree, context_load=0.5)
    assert result["branches_compressed"] == 1
