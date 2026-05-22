"""Web exploitation skills for Excalibur.

Defines composed workflows: sqli_chain, auth_bypass, file_inclusion.
"""

from __future__ import annotations

from excalibur.tools.skill import Skill, SkillStep


def _sqli_chain() -> Skill:
    """SQL injection chain: detection through to data extraction."""
    return Skill(
        name="sqli_chain",
        description=(
            "End-to-end SQL injection exploitation workflow. Begins with nuclei "
            "template scanning for SQLi indicators, then uses sqlmap for "
            "automated detection and exploitation, and finally extracts "
            "database contents and credentials."
        ),
        tool_sequence=[
            SkillStep(
                tool_name="nuclei",
                parameter_mapping={
                    "target": "url",
                    "tags": "tags",
                },
            ),
            SkillStep(
                tool_name="sqlmap",
                parameter_mapping={
                    "url": "injectable_url",
                    "data": "post_data",
                    "cookie": "cookie",
                },
                condition="nuclei detected potential SQL injection indicators",
            ),
            SkillStep(
                tool_name="sqlmap",
                parameter_mapping={
                    "url": "injectable_url",
                    "dump": "dump",
                },
                condition="sqlmap confirmed SQL injection vulnerability",
            ),
        ],
        fallback_logic=(
            "If nuclei misses the injection, run sqlmap directly with --level=3 "
            "and --risk=2. If sqlmap fails, attempt manual injection with wfuzz "
            "using common SQLi payloads."
        ),
        result_aggregation="sequential",
    )


def _auth_bypass() -> Skill:
    """Authentication bypass: fuzzing + command injection testing."""
    return Skill(
        name="auth_bypass",
        description=(
            "Authentication bypass workflow. Uses wfuzz to test login forms "
            "with common bypass payloads, then nuclei to scan for default "
            "credentials and known auth bypasses, and finally commix to "
            "test for command injection in auth-adjacent parameters."
        ),
        tool_sequence=[
            SkillStep(
                tool_name="wfuzz",
                parameter_mapping={
                    "url": "login_url",
                    "data": "login_data",
                    "wordlist": "bypass_wordlist",
                },
            ),
            SkillStep(
                tool_name="nuclei",
                parameter_mapping={
                    "target": "url",
                    "tags": "tags",
                },
                condition="wfuzz identified interesting response variations",
            ),
            SkillStep(
                tool_name="commix",
                parameter_mapping={
                    "url": "url",
                    "data": "injectable_data",
                },
                condition="parameters appear injectable based on prior results",
            ),
        ],
        fallback_logic=(
            "If automated bypass fails, attempt manual testing with known "
            "default credentials from SecLists. Also try SQL injection "
            "payloads in login fields using sqlmap."
        ),
        result_aggregation="sequential",
    )


def _file_inclusion() -> Skill:
    """Local/Remote file inclusion exploitation chain."""
    return Skill(
        name="file_inclusion",
        description=(
            "File inclusion exploitation workflow. Uses ffuf to discover "
            "file inclusion parameters via LFI/RFI wordlists, then confirms "
            "the vulnerability with targeted wfuzz payloads, and finally "
            "attempts command execution through log poisoning or PHP wrappers."
        ),
        tool_sequence=[
            SkillStep(
                tool_name="ffuf",
                parameter_mapping={
                    "url": "fuzz_url",
                    "wordlist": "lfi_wordlist",
                },
            ),
            SkillStep(
                tool_name="wfuzz",
                parameter_mapping={
                    "url": "url",
                    "wordlist": "lfi_payloads",
                },
                condition="ffuf discovered parameter accepting file paths",
            ),
            SkillStep(
                tool_name="commix",
                parameter_mapping={
                    "url": "url",
                    "data": "injectable_param",
                },
                condition="LFI confirmed and log poisoning or wrapper exploitation viable",
            ),
        ],
        fallback_logic=(
            "If automated LFI detection fails, manually test common paths "
            "like /etc/passwd with different traversal depths and encoding "
            "variations. Try PHP wrappers (php://filter, expect://) as well."
        ),
        result_aggregation="sequential",
    )


def get_web_skills() -> list[Skill]:
    """Return all web exploitation skills."""
    return [
        _sqli_chain(),
        _auth_bypass(),
        _file_inclusion(),
    ]
