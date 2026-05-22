"""Agent controller with EGATS planner, lifecycle management, and session persistence."""

from __future__ import annotations

import asyncio
import logging
import re
from enum import Enum
from typing import Any, ClassVar

from excalibur.core.backend import (
    AgentBackend,
    AgentMessage,
    ClaudeCodeBackend,
    MessageType,
)
from excalibur.core.config import ExcaliburConfig
from excalibur.core.events import Event, EventBus, EventType
from excalibur.core.session import SessionStatus, SessionStore

logger = logging.getLogger(__name__)


class AgentState(Enum):
    """Simple 5-state model for agent lifecycle."""

    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


class AgentController:
    """Central orchestrator with EGATS planner and lifecycle management.

    Features:
    - TDA-EGATS planning loop (attack tree search)
    - Framework-agnostic via AgentBackend
    - Pause/resume/stop control
    - Instruction injection
    - Session persistence with attack tree state
    - Memory subsystem integration (state store + context assembly)
    """

    # Flag detection patterns
    FLAG_PATTERNS: ClassVar[list[str]] = [
        r"flag\{[^\}]+\}",  # flag{...}
        r"FLAG\{[^\}]+\}",  # FLAG{...}
        r"HTB\{[^\}]+\}",  # HTB{...}
        r"CTF\{[^\}]+\}",  # CTF{...}
        r"[A-Za-z0-9_]+\{[^\}]+\}",  # Generic CTF format
        r"\b[a-f0-9]{32}\b",  # 32-char hex (HTB user/root flags)
    ]

    def __init__(
        self,
        config: ExcaliburConfig,
        backend: AgentBackend | None = None,
        session_store: SessionStore | None = None,
        events: EventBus | None = None,
    ):
        """Initialize controller.

        Args:
            config: Excalibur configuration.
            backend: Optional custom backend (defaults to ClaudeCodeBackend).
            session_store: Optional custom session store.
            events: Optional custom event bus.
        """
        self.config = config
        self.backend = backend
        self.sessions = session_store or SessionStore()
        self.events = events or EventBus.get()

        # State management
        self._state = AgentState.IDLE
        self._pause_requested = False
        self._stop_requested = False
        self._resume_event = asyncio.Event()
        self._pending_instruction: str | None = None

        # EGATS components (lazy-initialized)
        self._planner: Any = None
        self._state_store: Any = None
        self._context_assembler: Any = None
        self._context_compressor: Any = None
        self._tool_registry: Any = None
        self._attack_tree: Any = None

        # Subscribe to user events
        self.events.subscribe(EventType.USER_COMMAND, self._on_user_command)
        self.events.subscribe(EventType.USER_INPUT, self._on_user_input)

    def _init_egats(self) -> None:
        """Lazy-initialize EGATS planner and memory components."""
        from excalibur.memory.context_assembler import ContextAssembler
        from excalibur.memory.context_compressor import ContextCompressor
        from excalibur.memory.state_store import StateStore
        from excalibur.planner.egats import EGATSPlanner
        from excalibur.tools.registry import get_registry

        self._planner = EGATSPlanner(config=self.config.egats_config)
        self._state_store = StateStore(db_path=self.config.state_store_path)
        self._context_assembler = ContextAssembler(self._state_store)
        self._context_compressor = ContextCompressor(
            ideal_threshold=self.config.context_ideal_threshold,
            aggressive_threshold=self.config.context_aggressive_threshold,
        )
        self._tool_registry = get_registry()

    @property
    def state(self) -> AgentState:
        """Get current agent state."""
        return self._state

    def _set_state(
        self,
        state: AgentState,
        details: str = "",
        target: str | None = None,
        task: str | None = None,
    ) -> None:
        """Update state and emit event."""
        self._state = state
        self.events.emit_state(state.value, details, target=target, task=task)

    # === Control Methods (called from TUI) ===

    def pause(self) -> bool:
        """Request pause at next safe point."""
        if self._state == AgentState.RUNNING:
            self._pause_requested = True
            return True
        return False

    def resume(self, instruction: str | None = None) -> bool:
        """Resume from paused state."""
        if self._state == AgentState.PAUSED:
            self._pending_instruction = instruction
            self._pause_requested = False
            self._resume_event.set()
            return True
        return False

    def stop(self) -> bool:
        """Request stop."""
        self._stop_requested = True
        self._resume_event.set()  # Unblock if paused
        return True

    def inject(self, instruction: str) -> bool:
        """Queue instruction for next pause point."""
        if self._state in (AgentState.RUNNING, AgentState.PAUSED):
            self._pending_instruction = instruction
            if self._state == AgentState.RUNNING:
                self._pause_requested = True
            return True
        return False

    # === Event Handlers ===

    def _on_user_command(self, event: Event) -> None:
        """Handle user command events."""
        cmd = event.data.get("command")
        if cmd == "pause":
            self.pause()
        elif cmd == "resume":
            self.resume()
        elif cmd == "stop":
            self.stop()

    def _on_user_input(self, event: Event) -> None:
        """Handle user input events."""
        text = event.data.get("text", "")
        if text:
            self.inject(text)

    # === Pause/Resume Check ===

    async def _check_pause_stop(self) -> bool:
        """Check for pause/stop between EGATS iterations.

        Returns:
            True if stop was requested (caller should exit loop).
        """
        if self._stop_requested:
            return True

        if self._pause_requested:
            self._pause_requested = False
            self._set_state(AgentState.PAUSED, "Paused - waiting for input")
            self.sessions.update_status(SessionStatus.PAUSED)

            await self._resume_event.wait()
            self._resume_event.clear()

            if self._stop_requested:
                return True

            self._set_state(AgentState.RUNNING, "Resumed")
            self.sessions.update_status(SessionStatus.RUNNING)

            if self._pending_instruction:
                self.sessions.add_instruction(self._pending_instruction)
                self.events.emit_message(f"Injecting: {self._pending_instruction[:50]}...", "info")
                await self.backend.query(self._pending_instruction)
                self._pending_instruction = None

        return False

    # === Main Execution ===

    async def run(self, task: str, resume_session_id: str | None = None) -> dict[str, Any]:
        """Run agent with EGATS planning loop.

        Args:
            task: Task description for the agent.
            resume_session_id: Optional session ID to resume.

        Returns:
            Result dictionary with success, output, flags, etc.
        """
        # Reset state
        self._pause_requested = False
        self._stop_requested = False
        self._resume_event.clear()

        # Create or resume session
        if resume_session_id:
            session = self.sessions.load(resume_session_id)
            if not session:
                return {
                    "success": False,
                    "error": f"Session {resume_session_id} not found",
                }
            if not task:
                task = session.task
        else:
            session = self.sessions.create(
                target=self.config.target,
                task=task,
                model=self.config.llm_model,
            )

        # Initialize EGATS components
        self._init_egats()

        # Create backend if needed
        if self.backend is None:
            from excalibur.prompts.pentesting import get_ctf_prompt

            self.backend = ClaudeCodeBackend(
                working_directory=str(self.config.working_directory),
                system_prompt=get_ctf_prompt(self.config.custom_instruction),
                model=self.config.llm_model,
            )

        try:
            self._set_state(
                AgentState.RUNNING,
                "Connecting...",
                target=self.config.target,
                task=task,
            )

            # Connect (or resume)
            if resume_session_id and self.backend.supports_resume:
                backend_session = session.backend_session_id or resume_session_id
                await self.backend.resume(backend_session)
                self.events.emit_message(f"Resumed session {resume_session_id}", "info")
            else:
                await self.backend.connect()

            # Store backend session ID
            if self.backend.session_id:
                self.sessions.set_backend_session_id(self.backend.session_id)

            # Initialize attack tree
            self._attack_tree = self._planner.init_tree(self.config.target)

            # Run EGATS planning loop
            result = await self._egats_loop(task)

            return {
                "success": True,
                "output": "\n".join(result["output_parts"]),
                "flags_found": result["flags_found"],
                "session_id": session.session_id,
                "cost_usd": session.total_cost_usd,
            }

        except Exception as e:
            self._set_state(AgentState.ERROR, str(e))
            self.sessions.set_error(str(e))
            self.sessions.update_status(SessionStatus.ERROR)
            return {"success": False, "error": str(e)}

        finally:
            if self.backend:
                await self.backend.disconnect()
            if self._state_store:
                self._state_store.close()

    async def _egats_loop(self, initial_task: str) -> dict[str, Any]:
        """Run the EGATS planning loop.

        This replaces the simple linear message loop with an evidence-guided
        attack tree search. Each iteration:
        1. Select node (UCB)
        2. Compute TDI
        3. Select mode (BFS/DFS/LLMDecide)
        4. Assemble context prompt
        5. Query backend
        6. Parse results -> update tree + state store
        7. Backpropagate promise scores
        8. Check pivot spawning + credential propagation
        9. Check pruning
        10. Check context compression

        Args:
            initial_task: The initial task description.

        Returns:
            Dict with output_parts and flags_found.
        """
        from excalibur.planner.models import NodeStatus

        output_parts: list[str] = []
        flags_found: list[str] = []
        tree = self._attack_tree
        budget = self.config.max_budget

        # Send initial query
        await self.backend.query(initial_task)
        self.sessions.update_status(SessionStatus.RUNNING)

        # Process initial response
        async for msg in self.backend.receive_messages():
            if await self._check_pause_stop():
                self.sessions.update_status(SessionStatus.PAUSED)
                return {"output_parts": output_parts, "flags_found": flags_found}
            await self._process_message(msg, output_parts, flags_found)

        tree.total_actions += 1
        budget -= 1

        # EGATS iteration loop
        while budget > 0 and not self._stop_requested:
            # Check for flags found -> goal reached
            if flags_found:
                logger.info("Flags found, continuing to verify completeness")

            # 1. Select node via UCB
            current_node = self._planner.select_next_node(tree)
            if current_node is None:
                self.events.emit_message("All attack tree branches exhausted", "warning")
                break

            current_node.status = NodeStatus.ACTIVE
            self.events.emit(
                Event(
                    EventType.TREE_NODE_SELECTED,
                    {"node_id": current_node.id, "description": current_node.description},
                )
            )

            # 2. Compute TDI
            context_load = 0.0
            if self._context_assembler:
                ctx = self._context_assembler.assemble(current_node, tree, "reconnaissance")
                context_load = self._context_assembler.get_context_load(ctx)

            tdi = self._planner.compute_tdi(current_node, tree, context_load)
            self.events.emit(
                Event(
                    EventType.TDI_COMPUTED,
                    {"node_id": current_node.id, "tdi_value": tdi.value},
                )
            )

            # 3. Select mode
            mode = self._planner.select_mode(tdi)
            self.events.emit(
                Event(
                    EventType.MODE_SELECTED,
                    {"mode": mode, "tdi_value": tdi.value},
                )
            )

            # 4. Assemble context prompt
            context_prompt = ""
            if self._context_assembler:
                context_prompt = self._context_assembler.assemble(
                    current_node, tree, mode, tdi.value
                )

            # Build query from context + node description
            query = self._build_egats_query(current_node, mode, context_prompt, tdi.value)

            # 5. Check pause/stop before querying
            if await self._check_pause_stop():
                self.sessions.update_status(SessionStatus.PAUSED)
                return {"output_parts": output_parts, "flags_found": flags_found}

            # 6. Query backend
            await self.backend.query(query)

            # 7. Process response and collect findings
            iteration_findings: list[str] = []
            async for msg in self.backend.receive_messages():
                if await self._check_pause_stop():
                    self.sessions.update_status(SessionStatus.PAUSED)
                    return {
                        "output_parts": output_parts,
                        "flags_found": flags_found,
                    }
                await self._process_message(msg, output_parts, flags_found)
                # Collect text findings for tree expansion
                if msg.type == MessageType.TEXT and msg.content:
                    iteration_findings.append(msg.content)

            tree.total_actions += 1
            budget -= 1
            tree.budget_remaining = budget

            # 8. Update tree with findings
            if iteration_findings:
                current_node.findings.extend(iteration_findings[:3])

            # 9. Backpropagate
            outcome = self._assess_outcome(iteration_findings, flags_found)
            self._planner.backpropagate(tree, current_node, outcome)
            self.events.emit(
                Event(
                    EventType.TREE_BACKPROPAGATE,
                    {
                        "node_id": current_node.id,
                        "outcome": outcome.value,
                        "promise": current_node.promise_score,
                    },
                )
            )

            # 10. Expand tree with child nodes for new findings
            new_findings = self._extract_findings(iteration_findings)
            if new_findings:
                new_nodes = self._planner.expand_tree(tree, current_node, new_findings)
                if new_nodes:
                    self.events.emit(
                        Event(
                            EventType.TREE_NODE_EXPANDED,
                            {
                                "parent_id": current_node.id,
                                "new_nodes": [n.id for n in new_nodes],
                            },
                        )
                    )

            # 11. Check pruning
            pruned = self._planner.check_pruning(tree)
            if pruned:
                self.events.emit(
                    Event(
                        EventType.TREE_NODE_PRUNED,
                        {"pruned_ids": pruned},
                    )
                )

            # 12. Check context compression
            if (
                self._context_compressor
                and context_load > 0
                and self._context_compressor.should_compress(context_load)
            ):
                self._context_compressor.compress(tree, context_load)
                self.events.emit(
                    Event(
                        EventType.CONTEXT_COMPRESSED,
                        {"context_load": context_load},
                    )
                )

            # Mark current node as completed
            current_node.status = NodeStatus.COMPLETED

        # Finalize
        if not self._stop_requested:
            self._set_state(AgentState.COMPLETED)
            self.sessions.update_status(SessionStatus.COMPLETED)
        else:
            self._set_state(AgentState.IDLE, "Stopped by user")
            self.sessions.update_status(SessionStatus.PAUSED)

        return {"output_parts": output_parts, "flags_found": flags_found}

    def _build_egats_query(
        self,
        node: Any,
        mode: str,
        context: str,
        tdi_value: float,
    ) -> str:
        """Build a query for the backend based on EGATS state.

        Args:
            node: Current attack tree node.
            mode: Current mode (reconnaissance/exploitation/llm_decide).
            context: Assembled context from memory subsystem.
            tdi_value: Current TDI value.

        Returns:
            Query string for the backend.
        """
        parts = []

        # Mode directive
        if mode == "reconnaissance":
            parts.append(
                "FOCUS: Broad reconnaissance and enumeration. "
                "Discover services, ports, vulnerabilities, and attack surfaces."
            )
        elif mode == "exploitation":
            parts.append(
                "FOCUS: Deep exploitation. Leverage known findings to gain access, "
                "escalate privileges, and capture flags."
            )
        else:
            parts.append(
                "FOCUS: Assess the situation and decide whether to enumerate "
                "further or exploit known vulnerabilities."
            )

        # Node description
        parts.append(f"\nCurrent objective: {node.description}")

        # Target host
        if node.host:
            parts.append(f"Target host: {node.host}")

        # Context from memory
        if context:
            parts.append(f"\n--- CONTEXT ---\n{context}\n--- END CONTEXT ---")

        # Previous findings on this node
        if node.findings:
            recent = node.findings[-3:]
            parts.append(
                "\nRecent findings on this path:\n" + "\n".join(f"- {f[:200]}" for f in recent)
            )

        return "\n".join(parts)

    def _assess_outcome(self, findings: list[str], flags_found: list[str]) -> Any:
        """Assess the outcome of an EGATS iteration.

        Args:
            findings: Text findings from the iteration.
            flags_found: List of flags found so far.

        Returns:
            ActionOutcome value.
        """
        from excalibur.planner.models import ActionOutcome

        # Check if new flags were found in this iteration
        combined = " ".join(findings)
        new_flags = self._detect_flags(combined)
        if any(f not in flags_found for f in new_flags):
            return ActionOutcome.SUCCESS

        # Check for meaningful progress indicators
        progress_keywords = [
            "found",
            "discovered",
            "vulnerable",
            "access",
            "shell",
            "credential",
            "password",
            "exploit",
            "port",
            "service",
            "version",
        ]
        combined_lower = combined.lower()
        hits = sum(1 for kw in progress_keywords if kw in combined_lower)
        if hits >= 3:
            return ActionOutcome.PARTIAL

        return ActionOutcome.FAILURE

    def _extract_findings(self, text_findings: list[str]) -> list[dict[str, Any]]:
        """Extract structured findings from text for tree expansion.

        Args:
            text_findings: Raw text findings from backend.

        Returns:
            List of finding dicts suitable for tree expansion.
        """
        findings = []
        combined = " ".join(text_findings).lower()

        # Look for host/service discoveries
        ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
        port_pattern = r"\b(\d{1,5})/(tcp|udp)\b"

        ips = set(re.findall(ip_pattern, combined))
        ports = set(re.findall(port_pattern, combined))

        for ip in ips:
            findings.append(
                {
                    "description": f"Discovered host: {ip}",
                    "host": ip,
                    "evidence": 0.8,
                    "type": "observation",
                }
            )

        for port, proto in ports:
            findings.append(
                {
                    "description": f"Open port {port}/{proto}",
                    "evidence": 0.8,
                    "type": "observation",
                }
            )

        # Look for vulnerability indicators
        vuln_keywords = [
            "sql injection",
            "xss",
            "rce",
            "lfi",
            "rfi",
            "ssrf",
            "buffer overflow",
            "command injection",
            "authentication bypass",
        ]
        for kw in vuln_keywords:
            if kw in combined:
                findings.append(
                    {
                        "description": f"Potential vulnerability: {kw}",
                        "evidence": 0.5,
                        "type": "hypothesis",
                    }
                )

        return findings[:10]  # Limit expansion

    async def _process_message(
        self,
        msg: AgentMessage,
        output_parts: list[str],
        flags_found: list[str],
    ) -> None:
        """Process a single agent message.

        Args:
            msg: Message to process.
            output_parts: List to append text output to.
            flags_found: List to append found flags to.
        """
        if msg.type == MessageType.TEXT:
            output_parts.append(msg.content)
            self.events.emit_message(msg.content)

            # Detect flags
            detected = self._detect_flags(msg.content)
            for flag in detected:
                if flag not in flags_found:
                    flags_found.append(flag)
                    self.sessions.add_flag(flag, msg.content[:200])
                    self.events.emit_flag(flag, msg.content[:200])

        elif msg.type == MessageType.TOOL_START:
            self.events.emit_tool(
                status="start",
                name=msg.tool_name or "unknown",
                args=msg.tool_args,
            )

        elif msg.type == MessageType.TOOL_RESULT:
            self.events.emit_tool(
                status="complete",
                name=msg.tool_name or "unknown",
                result=msg.content,
            )

        elif msg.type == MessageType.RESULT:
            cost = msg.metadata.get("cost_usd", 0)
            if cost > 0:
                self.sessions.add_cost(cost)

    def _detect_flags(self, text: str) -> list[str]:
        """Detect potential flags in text."""
        flags = []
        for pattern in self.FLAG_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                flag = match.group(0)
                if flag not in flags:
                    flags.append(flag)
        return flags
