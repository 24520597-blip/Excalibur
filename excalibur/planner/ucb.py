"""UCB (Upper Confidence Bound) node selection for the attack tree."""

from __future__ import annotations

import math

from excalibur.planner.models import AttackNode, AttackTree


def select_node(
    tree: AttackTree,
    exploration_constant: float = 1.414,
    difficulty_penalty: float = 0.5,
) -> AttackNode | None:
    """Select the active leaf with the highest UCB score.

    The UCB formula balances exploitation (promise score), exploration
    (visit-count bonus), and difficulty (TDI penalty)::

        UCB(n) = phi(n) + c * sqrt(ln(N) / N_n) - dp * delta(n)

    Args:
        tree: The attack tree to search.
        exploration_constant: Weight *c* for the exploration term.
        difficulty_penalty: Weight *dp* for the TDI difficulty term.

    Returns:
        The best candidate ``AttackNode``, or ``None`` when no
        candidates remain.
    """
    candidates = tree.get_active_leaves()
    if not candidates:
        return None

    best_node: AttackNode | None = None
    best_score = float("-inf")
    total_actions = max(tree.total_actions, 1)

    for node in candidates:
        visits = max(node.visit_count, 1)
        exploration = exploration_constant * math.sqrt(math.log(total_actions) / visits)
        tdi_value = node.tdi.value if node.tdi else 0.5
        ucb = node.promise_score + exploration - difficulty_penalty * tdi_value
        if ucb > best_score:
            best_score = ucb
            best_node = node

    return best_node
