"""Selective context injection for LLM prompts.

The ``ContextAssembler`` pulls together information from the attack
tree, the state store, and the current exploration mode into a single
context string that is prepended (or appended) to the next LLM query.

Sections produced:

1. **Attack Path** -- the path from root to the current node with
   status annotations.
2. **State Facts** -- hosts, services, credentials, sessions, and
   vulnerabilities relevant to the current target host.
3. **Mode Guidance** -- BFS / DFS / hybrid instructions and the
   current TDI value.
4. **Sibling Summaries** -- compressed summaries of sibling branches
   to provide lateral awareness.
"""

from __future__ import annotations

from typing import Any

from excalibur.memory.branch_summary import summarize_branch
from excalibur.memory.state_store import StateStore


class ContextAssembler:
    """Assembles context for LLM prompts based on current state.

    Attributes:
        state_store: The entity store to pull facts from.
    """

    # Rough character budget for context window estimation.
    # ~200 k chars approximates a 50 k-token window.
    _MAX_CONTEXT_CHARS: int = 200_000

    def __init__(self, state_store: StateStore) -> None:
        """Initialise the assembler.

        Args:
            state_store: Backing ``StateStore`` instance.
        """
        self.state_store = state_store

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def assemble(
        self,
        node: Any,  # AttackNode (avoid circular import)
        tree: Any,  # AttackTree
        mode: str,
        tdi_value: float = 0.5,
    ) -> str:
        """Build a context prompt from current state.

        Args:
            node: The currently active ``AttackNode``.
            tree: The ``AttackTree`` that owns *node*.
            mode: Exploration mode (``"bfs"``, ``"dfs"``, or ``"hybrid"``).
            tdi_value: Current Target Difficulty Index (0..1).

        Returns:
            A multi-section context string ready for prompt injection.
        """
        sections: list[str] = []

        # 1. Current attack path from root to active node
        path_ctx = self._build_path_context(node, tree)
        if path_ctx:
            sections.append(path_ctx)

        # 2. Relevant state facts from the entity store
        state_ctx = self._build_state_context(node)
        if state_ctx:
            sections.append(state_ctx)

        # 3. Mode-specific exploration guidance
        mode_ctx = self._build_mode_context(mode, tdi_value)
        if mode_ctx:
            sections.append(mode_ctx)

        # 4. Sibling branch summaries (lateral awareness)
        sibling_ctx = self._build_sibling_context(node, tree)
        if sibling_ctx:
            sections.append(sibling_ctx)

        return "\n\n".join(sections)

    def get_context_load(self, context: str) -> float:
        """Estimate the fraction of the context window consumed.

        This is a rough character-based heuristic; exact token counts
        require a tokeniser.

        Args:
            context: The assembled context string.

        Returns:
            A float between 0.0 and 1.0.
        """
        return min(len(context) / self._MAX_CONTEXT_CHARS, 1.0)

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------

    def _build_path_context(self, node: Any, tree: Any) -> str:
        """Build the attack-path section.

        Walks from the root down to *node* and formats each ancestor
        as a line showing its id, description, and status.

        Args:
            node: The active attack node.
            tree: The owning attack tree.

        Returns:
            Formatted path context string.
        """
        nodes_map = getattr(tree, "nodes", {})
        if not nodes_map:
            return ""

        # Walk from node up to root, then reverse.
        path_ids: list[str] = []
        current = node
        visited: set[str] = set()
        while current is not None:
            nid = getattr(current, "id", None) or getattr(current, "node_id", None)
            if nid is None or nid in visited:
                break
            visited.add(nid)
            path_ids.append(nid)
            parent_id = getattr(current, "parent_id", None)
            current = nodes_map.get(parent_id) if parent_id else None
        path_ids.reverse()

        if not path_ids:
            return ""

        lines = ["## Current Attack Path"]
        for depth, nid in enumerate(path_ids):
            n = nodes_map.get(nid)
            desc = getattr(n, "description", nid) if n else nid
            status = getattr(n, "status", "?") if n else "?"
            indent = "  " * depth
            marker = ">> " if nid == path_ids[-1] else "   "
            lines.append(f"{indent}{marker}[{status}] {desc} (id={nid})")

        return "\n".join(lines)

    def _build_state_context(self, node: Any) -> str:
        """Build the state-facts section from the entity store.

        Selects facts relevant to the current node's target host
        (determined via ``node.target_host_id`` or falls back to
        listing all known entities).

        Args:
            node: The active attack node.

        Returns:
            Formatted state context string.
        """
        target_host_id: str | None = getattr(node, "target_host_id", None)
        lines: list[str] = ["## Known State Facts"]
        has_content = False

        # --- Hosts ---
        hosts = self.state_store.get_hosts()
        if hosts:
            has_content = True
            lines.append("### Hosts")
            for h in hosts:
                parts = [f"  - {h.ip_address}"]
                if h.hostname:
                    parts.append(f"({h.hostname})")
                if h.os_fingerprint:
                    parts.append(f"[OS: {h.os_fingerprint}]")
                lines.append(" ".join(parts))

        # --- Services (scoped to target host when available) ---
        if target_host_id:
            services = self.state_store.get_services_for_host(target_host_id)
        else:
            services = []
            for h in hosts:
                services.extend(self.state_store.get_services_for_host(h.id))
        if services:
            has_content = True
            lines.append("### Services")
            for s in services:
                svc = s.service_name or "unknown"
                ver = f" {s.version}" if s.version else ""
                lines.append(f"  - {s.port}/{s.protocol} {svc}{ver} (host={s.host_id})")

        # --- Credentials ---
        if target_host_id:
            creds = self.state_store.get_credentials_for_host(target_host_id)
        else:
            creds = self.state_store.get_credentials()
        if creds:
            has_content = True
            lines.append("### Credentials")
            for c in creds:
                domain_part = f"{c.domain}\\" if c.domain else ""
                lines.append(
                    f"  - {domain_part}{c.username} [{c.credential_type}] valid_for={c.valid_for}"
                )

        # --- Active Sessions ---
        active_sessions = self.state_store.get_active_sessions()
        if active_sessions:
            has_content = True
            lines.append("### Active Sessions")
            for sess in active_sessions:
                lines.append(
                    f"  - {sess.session_type} on host={sess.host_id} "
                    f"priv={sess.privilege_level} (id={sess.id})"
                )

        # --- Vulnerabilities ---
        if target_host_id:
            vulns = self.state_store.get_vulnerabilities_for_host(target_host_id)
        else:
            vulns = []
            for h in hosts:
                vulns.extend(self.state_store.get_vulnerabilities_for_host(h.id))
        if vulns:
            has_content = True
            lines.append("### Vulnerabilities")
            for v in vulns:
                cve = f" ({v.cve_id})" if v.cve_id else ""
                lines.append(f"  - [{v.exploitation_status}]{cve} {v.description[:120]}")

        if not has_content:
            return ""
        return "\n".join(lines)

    @staticmethod
    def _build_mode_context(mode: str, tdi_value: float) -> str:
        """Build mode-specific guidance text.

        Args:
            mode: ``"bfs"``, ``"dfs"``, or ``"hybrid"``.
            tdi_value: Current Target Difficulty Index.

        Returns:
            Formatted mode guidance string.
        """
        header = f"## Exploration Mode: {mode.upper()} (TDI={tdi_value:.2f})"

        if mode == "bfs":
            guidance = (
                "Breadth-first: enumerate all attack surfaces before "
                "going deep on any single vector. Prioritise discovery "
                "of new hosts, services, and potential entry points."
            )
        elif mode == "dfs":
            guidance = (
                "Depth-first: focus on the most promising vector and "
                "exploit it fully before backtracking. Prioritise "
                "escalation and lateral movement along the current path."
            )
        else:
            if tdi_value < 0.3:
                bias = "leaning BFS (low difficulty -- broad recon recommended)"
            elif tdi_value > 0.7:
                bias = "leaning DFS (high difficulty -- commit to best vector)"
            else:
                bias = "balanced"
            guidance = (
                f"Hybrid mode ({bias}): alternate between breadth and "
                f"depth based on TDI. Current TDI={tdi_value:.2f}."
            )

        return f"{header}\n{guidance}"

    @staticmethod
    def _build_sibling_context(node: Any, tree: Any) -> str:
        """Build compressed sibling-branch summaries.

        For each sibling of *node* (i.e. nodes sharing the same
        parent), produce a one-paragraph summary so the LLM is aware
        of what other branches have tried.

        Args:
            node: The active attack node.
            tree: The owning attack tree.

        Returns:
            Formatted sibling summary string, or empty string if none.
        """
        nodes_map = getattr(tree, "nodes", {})
        parent_id = getattr(node, "parent_id", None)
        node_id = getattr(node, "id", None) or getattr(node, "node_id", None)

        if parent_id is None or not nodes_map:
            return ""

        parent = nodes_map.get(parent_id)
        if parent is None:
            return ""

        sibling_ids = [cid for cid in getattr(parent, "children", []) if cid != node_id]

        if not sibling_ids:
            return ""

        lines = ["## Sibling Branch Summaries"]
        for sid in sibling_ids:
            summary = summarize_branch(tree, sid)
            findings_str = "; ".join(summary.key_findings[:5]) or "none"
            tools_str = ", ".join(summary.tools_used[:5]) or "none"
            tdi_str = f", TDI={summary.tdi_score:.2f}" if summary.tdi_score is not None else ""
            lines.append(
                f"- **{sid}** [{summary.status}{tdi_str}]: "
                f"findings=[{findings_str}] tools=[{tools_str}]"
            )

        return "\n".join(lines)
