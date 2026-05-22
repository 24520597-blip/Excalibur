"""Pydantic data models for the TDA-EGATS attack tree planner."""

from __future__ import annotations

import uuid
from enum import Enum

from pydantic import BaseModel, Field, computed_field


class NodeType(str, Enum):
    """Classification of attack tree nodes."""

    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    ACTION = "action"


class NodeStatus(str, Enum):
    """Lifecycle status of an attack tree node."""

    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    PRUNED = "pruned"
    FAILED = "failed"


class EvidenceLevel(float, Enum):
    """Confidence level for evidence supporting a node."""

    VERIFIED = 1.0
    CONFIRMED = 0.8
    PLAUSIBLE = 0.5
    SPECULATIVE = 0.3


class ActionOutcome(float, Enum):
    """Outcome of an executed action node."""

    SUCCESS = 1.0
    PARTIAL = 0.5
    FAILURE = 0.1


class TDIScore(BaseModel):
    """Task Difficulty Index score with 4 weighted dimensions.

    The TDI combines horizon depth, evidence confidence, context load,
    and success rate into a single difficulty estimate used for node
    selection and pruning decisions.
    """

    horizon: float = Field(default=0.5, ge=0.0, le=1.0, description="Normalized horizon estimate")
    success_rate: float = Field(
        default=0.5, ge=0.0, le=1.0, description="Laplace-smoothed success rate"
    )
    context_load: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Token budget utilization ratio"
    )
    evidence_confidence: float = Field(
        default=0.5, ge=0.0, le=1.0, description="Mean evidence confidence along path"
    )
    weight_horizon: float = 0.3
    weight_evidence: float = 0.3
    weight_context: float = 0.2
    weight_success: float = 0.2

    @computed_field
    @property
    def value(self) -> float:
        """Compute composite TDI value.

        Formula: TDI = w_h*H + w_e*(1-E) + w_c*C + w_s*(1-S)

        Higher values indicate greater difficulty.
        """
        return (
            self.weight_horizon * self.horizon
            + self.weight_evidence * (1.0 - self.evidence_confidence)
            + self.weight_context * self.context_load
            + self.weight_success * (1.0 - self.success_rate)
        )


def _generate_short_id() -> str:
    """Generate a short unique identifier."""
    return str(uuid.uuid4())[:8]


class AttackNode(BaseModel):
    """A single node in the attack tree.

    Each node represents an observation, hypothesis, or action in the
    penetration testing workflow. Nodes track visit statistics for UCB
    selection and backpropagation.
    """

    id: str = Field(default_factory=_generate_short_id)
    node_type: NodeType = NodeType.ACTION
    status: NodeStatus = NodeStatus.PENDING
    description: str = ""
    parent_id: str | None = None
    children_ids: list[str] = Field(default_factory=list)
    promise_score: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="UCB promise score phi(n)",
    )
    tdi: TDIScore | None = None
    evidence_level: EvidenceLevel = EvidenceLevel.SPECULATIVE
    visit_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    findings: list[str] = Field(default_factory=list)
    host: str | None = None
    tool_used: str | None = None


class AttackTree(BaseModel):
    """The full attack tree for an engagement.

    Maintains a dictionary of nodes, tracks compromised hosts, and
    provides helper methods for tree traversal, node insertion, and
    leaf enumeration.
    """

    nodes: dict[str, AttackNode] = Field(default_factory=dict)
    root_id: str = ""
    total_actions: int = 0
    compromised_hosts: list[str] = Field(default_factory=list)
    budget_remaining: int = 300

    def get_node(self, node_id: str) -> AttackNode | None:
        """Retrieve a node by its ID, or None if not found."""
        return self.nodes.get(node_id)

    def add_node(self, node: AttackNode) -> None:
        """Insert a node and update its parent's children list."""
        self.nodes[node.id] = node
        if node.parent_id and node.parent_id in self.nodes:
            parent = self.nodes[node.parent_id]
            if node.id not in parent.children_ids:
                parent.children_ids.append(node.id)

    def get_path_to_root(self, node_id: str) -> list[AttackNode]:
        """Return the path from *node_id* up to the root (inclusive)."""
        path: list[AttackNode] = []
        current_id: str | None = node_id
        while current_id is not None:
            node = self.nodes.get(current_id)
            if node is None:
                break
            path.append(node)
            current_id = node.parent_id
        return path

    def get_active_leaves(self) -> list[AttackNode]:
        """Return leaf nodes that are neither pruned nor failed."""
        excluded = {NodeStatus.PRUNED, NodeStatus.FAILED}
        return [
            node
            for node in self.nodes.values()
            if not node.children_ids and node.status not in excluded
        ]
