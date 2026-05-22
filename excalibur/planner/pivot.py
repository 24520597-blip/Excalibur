"""Pivot spawning for lateral movement across compromised hosts."""

from __future__ import annotations

from excalibur.planner.models import (
    AttackNode,
    AttackTree,
    EvidenceLevel,
    NodeStatus,
    NodeType,
)
from excalibur.planner.pruning import reevaluate_pruned


def spawn_pivot(
    tree: AttackTree,
    host: str,
    parent_node: AttackNode,
) -> AttackNode:
    """Create a new observation sub-tree rooted at a compromised *host*.

    When a host is compromised, a pivot node is added as a child of the
    action that achieved the compromise. This node becomes the root for
    further enumeration and exploitation of the newly accessible host.

    Args:
        tree: The attack tree.
        host: The IP or hostname of the compromised machine.
        parent_node: The action node that achieved the compromise.

    Returns:
        The newly created pivot ``AttackNode``.
    """
    pivot_node = AttackNode(
        node_type=NodeType.OBSERVATION,
        status=NodeStatus.PENDING,
        description=f"Pivot to compromised host: {host}",
        parent_id=parent_node.id,
        host=host,
        evidence_level=EvidenceLevel.VERIFIED,
        promise_score=0.7,
    )
    tree.add_node(pivot_node)
    if host not in tree.compromised_hosts:
        tree.compromised_hosts.append(host)
    return pivot_node


def propagate_credentials(
    tree: AttackTree,
    credentials: list[str],
) -> list[str]:
    """Re-evaluate all pruned nodes with newly discovered *credentials*.

    Delegates to :func:`excalibur.planner.pruning.reevaluate_pruned` to
    reopen authentication-related branches that were previously pruned.

    Args:
        tree: The attack tree.
        credentials: Newly discovered credential strings.

    Returns:
        A list of node IDs that were reopened.
    """
    return reevaluate_pruned(tree, credentials)
