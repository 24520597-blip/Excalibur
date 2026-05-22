"""Branch summary generation for context compression.

Produces compact summaries of attack-tree branches so that sibling
and ancestor context can be injected without consuming the full
conversation history.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class BranchSummary(BaseModel):
    """Compressed representation of an attack-tree branch."""

    node_id: str
    status: str
    key_findings: list[str] = Field(default_factory=list)
    tdi_score: float | None = None
    tools_used: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


def _collect_node_ids(tree: Any, node_id: str) -> list[str]:
    """Collect *node_id* and all its descendants from *tree*.

    Args:
        tree: An AttackTree (or any object with a ``nodes`` dict whose
              values expose a ``children`` list of node-id strings).
        node_id: Root of the sub-tree to collect.

    Returns:
        List of node-id strings (root first, then depth-first children).
    """
    ids: list[str] = [node_id]
    nodes = getattr(tree, "nodes", {})
    node = nodes.get(node_id)
    if node is None:
        return ids
    for child_id in getattr(node, "children", []):
        ids.extend(_collect_node_ids(tree, child_id))
    return ids


def summarize_branch(tree: Any, node_id: str) -> BranchSummary:
    """Generate a compressed execution summary for the sub-tree rooted at *node_id*.

    The function inspects the tree's node store (``tree.nodes``) and
    aggregates findings, tool usage, and status from the target node
    and all of its descendants.

    Args:
        tree: An AttackTree instance (duck-typed).
        node_id: The root node of the branch to summarize.

    Returns:
        A ``BranchSummary`` with aggregated data.
    """
    nodes = getattr(tree, "nodes", {})
    root_node = nodes.get(node_id)

    # Fallback when the tree / node is not available
    if root_node is None:
        return BranchSummary(node_id=node_id, status="unknown")

    all_ids = _collect_node_ids(tree, node_id)

    key_findings: list[str] = []
    tools_used: list[str] = []
    recommended_actions: list[str] = []
    statuses: list[str] = []

    for nid in all_ids:
        node = nodes.get(nid)
        if node is None:
            continue

        # Status
        status = getattr(node, "status", "unknown")
        statuses.append(str(status))

        # Findings stored on the node (list[str] or similar)
        for finding in getattr(node, "findings", []):
            entry = str(finding).strip()
            if entry and entry not in key_findings:
                key_findings.append(entry)

        # Tool outputs may also contain findings
        for tool_output in getattr(node, "tool_outputs", []):
            tool_name = ""
            if isinstance(tool_output, dict):
                tool_name = tool_output.get("tool", "")
            else:
                tool_name = str(getattr(tool_output, "tool", ""))
            if tool_name and tool_name not in tools_used:
                tools_used.append(tool_name)

        # Recommended next actions (if the node exposes them)
        for action in getattr(node, "recommended_actions", []):
            entry = str(action).strip()
            if entry and entry not in recommended_actions:
                recommended_actions.append(entry)

    # Derive overall branch status from collected statuses
    if "exploited" in statuses:
        overall_status = "exploited"
    elif "running" in statuses:
        overall_status = "running"
    elif "failed" in statuses and all(s in ("failed", "unknown") for s in statuses):
        overall_status = "failed"
    elif statuses:
        overall_status = statuses[0]
    else:
        overall_status = "unknown"

    tdi_score = getattr(root_node, "tdi_score", None)

    return BranchSummary(
        node_id=node_id,
        status=overall_status,
        key_findings=key_findings[:20],  # cap to avoid bloat
        tdi_score=tdi_score,
        tools_used=tools_used[:30],
        recommended_actions=recommended_actions[:10],
    )
