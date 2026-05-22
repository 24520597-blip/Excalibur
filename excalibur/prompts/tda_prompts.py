"""TDA-EGATS prompt templates for mode-aware penetration testing."""

HORIZON_ESTIMATION_PROMPT = """Given the current attack tree state and the following node:

Node: {node_description}
Path from root: {path_description}
Current findings: {findings}

Estimate how many more steps are likely needed to achieve the objective from this node.
Provide a relative difficulty ranking from 0.0 (very close to goal) to 1.0 (very far from goal).

Consider:
- Number of remaining attack surfaces to explore
- Complexity of required exploits
- Privilege escalation steps remaining
- Network pivoting requirements

Respond with only a float between 0.0 and 1.0."""


LLM_DECIDE_PROMPT = """The current Task Difficulty Index is in the intermediate range ({tdi_value:.2f}).
This means the situation is ambiguous - neither clearly requiring broad reconnaissance
nor deep exploitation.

Current state:
- Node: {node_description}
- Host: {host}
- Known services: {services}
- Known credentials: {credentials}
- Active sessions: {sessions}

Based on the above, should the agent:
1. RECONNAISSANCE - Broad enumeration to discover more attack surfaces
2. EXPLOITATION - Deep exploitation of a known vulnerability or access vector

Explain your reasoning briefly, then state your choice: RECONNAISSANCE or EXPLOITATION."""


EVIDENCE_ASSESSMENT_PROMPT = """Classify the confidence level of the following finding:

Finding: {finding}
Source tool: {tool_name}
Context: {context}

Classify as one of:
- VERIFIED (1.0): Directly confirmed through exploitation or multiple independent sources
- CONFIRMED (0.8): Strong evidence from reliable tool output
- PLAUSIBLE (0.5): Reasonable inference but not directly confirmed
- SPECULATIVE (0.3): Weak evidence or uncertain interpretation

Respond with only the classification level."""


BFS_RECONNAISSANCE_ADDENDUM = """MODE: RECONNAISSANCE (Breadth-First)
Your current task difficulty is HIGH ({tdi_value:.2f}), indicating significant uncertainty.

PRIORITIES:
1. Enumerate broadly - discover ALL services, ports, and attack surfaces
2. Map the network topology and identify all reachable hosts
3. Gather version information for service fingerprinting
4. Identify potential credentials, configuration files, and sensitive data
5. Do NOT attempt exploitation yet - focus on intelligence gathering

TOOLS TO PREFER:
- nmap (comprehensive port scans, service detection, scripts)
- gobuster/ffuf (directory and file enumeration)
- enum4linux (SMB/AD enumeration)
- nikto/whatweb (web fingerprinting)
- DNS enumeration, SNMP walks, banner grabbing

After enumeration, report your findings so the planner can update the attack tree."""


DFS_EXPLOITATION_ADDENDUM = """MODE: EXPLOITATION (Depth-First)
Your current task difficulty is LOW ({tdi_value:.2f}), indicating high confidence in the path.

PRIORITIES:
1. Exploit the most promising vulnerability or access vector FIRST
2. Leverage known credentials and sessions
3. Escalate privileges systematically
4. Capture flags and sensitive data
5. If exploitation fails, try alternative payloads/techniques before moving on

TOOLS TO PREFER:
- sqlmap (SQL injection exploitation)
- metasploit/netcat (exploitation and shells)
- hydra/hashcat/john (credential attacks)
- linpeas/winpeas (privilege escalation enumeration)
- Custom exploit scripts as needed

Focus on depth - fully exploit one path before branching."""


def get_system_prompt(
    custom_instruction: str | None = None,
    mode: str | None = None,
    tdi_value: float = 0.5,
) -> str:
    """Build the system prompt with optional mode-aware addendum.

    Args:
        custom_instruction: Optional custom instructions to append.
        mode: Optional mode ("reconnaissance", "exploitation", "llm_decide").
        tdi_value: Current TDI value for mode context.

    Returns:
        Complete system prompt with mode-specific guidance.
    """
    from excalibur.prompts.pentesting import CTF_SYSTEM_PROMPT

    prompt = CTF_SYSTEM_PROMPT

    # Add mode-specific guidance
    if mode == "reconnaissance":
        prompt += "\n\n" + BFS_RECONNAISSANCE_ADDENDUM.format(tdi_value=tdi_value)
    elif mode == "exploitation":
        prompt += "\n\n" + DFS_EXPLOITATION_ADDENDUM.format(tdi_value=tdi_value)

    if custom_instruction:
        prompt += f"\n\nADDITIONAL CHALLENGE CONTEXT:\n{custom_instruction}"

    return prompt
