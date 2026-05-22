"""Branch pruning and credential-driven re-evaluation for the attack tree."""

from __future__ import annotations

from excalibur.planner.models import AttackNode, AttackTree, NodeStatus


def should_prune(
    node: AttackNode,
    threshold: float = 0.8,
    min_attempts: int = 3,
) -> bool:
    """Decide whether *node* should be pruned.

    A node is prunable when its TDI exceeds *threshold* **and** it has
    been visited at least *min_attempts* times, indicating enough
    evidence that this branch is unlikely to succeed.

    Args:
        node: The candidate node.
        threshold: TDI value above which pruning is considered.
        min_attempts: Minimum visit count before pruning is allowed.

    Returns:
        ``True`` if the node meets the pruning criteria.
    """
    if node.tdi is None:
        return False
    return node.tdi.value > threshold and node.visit_count >= min_attempts


def prune_branch(tree: AttackTree, node: AttackNode) -> list[str]:
    """Set *node* and all of its descendants to ``PRUNED`` status.

    Args:
        tree: The attack tree.
        node: The root of the sub-tree to prune.

    Returns:
        A list of node IDs that were pruned.
    """
    pruned: list[str] = []
    stack = [node.id]
    while stack:
        nid = stack.pop()
        n = tree.get_node(nid)
        if n and n.status != NodeStatus.PRUNED:
            n.status = NodeStatus.PRUNED
            pruned.append(nid)
            stack.extend(n.children_ids)
    return pruned


def reevaluate_pruned(
    tree: AttackTree,
    new_credentials: list[str],
) -> list[str]:
    """Re-open pruned branches that might benefit from *new_credentials*.

    When new credentials are discovered during an engagement, previously
    pruned authentication-related branches may become viable again. This
    function resets their status and statistics so they can be revisited.

    Args:
        tree: The attack tree.
        new_credentials: Newly discovered credential strings.

    Returns:
        A list of node IDs that were reopened.
    """
    reopened: list[str] = []
    if not new_credentials:
        return reopened
    for node in tree.nodes.values():
        if node.status == NodeStatus.PRUNED and any(
            _cred_relevant(node, cred) for cred in new_credentials
        ):
            node.status = NodeStatus.PENDING
            node.visit_count = 0
            node.success_count = 0
            node.failure_count = 0
            reopened.append(node.id)
    return reopened


def _cred_relevant(node: AttackNode, credential: str) -> bool:
    """Check whether *credential* might be relevant to a pruned *node*.

    Uses a simple keyword heuristic: if the node's description mentions
    authentication-related services, the credential is considered
    potentially relevant.

    Args:
        node: The pruned attack node.
        credential: The credential string (unused in heuristic, reserved
            for future pattern matching).

    Returns:
        ``True`` if the node description contains auth-related keywords.
    """
    auth_keywords = [
        "login",
        "auth",
        "ssh",
        "rdp",
        "smb",
        "ftp",
        "password",
        "credential",
        "winrm",
    ]
    desc_lower = node.description.lower()
    return any(kw in desc_lower for kw in auth_keywords)
