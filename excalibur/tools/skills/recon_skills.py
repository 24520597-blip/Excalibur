"""Reconnaissance skills for Excalibur.

Defines composed workflows: full_port_scan, service_enumeration, web_discovery.
"""

from __future__ import annotations

from excalibur.tools.skill import Skill, SkillStep


def _full_port_scan() -> Skill:
    """Full port scan skill: masscan fast sweep followed by nmap deep scan."""
    return Skill(
        name="full_port_scan",
        description=(
            "Comprehensive port discovery workflow. Starts with a fast masscan "
            "sweep across all 65535 TCP ports, then performs a detailed nmap "
            "service version and script scan on the discovered open ports."
        ),
        tool_sequence=[
            SkillStep(
                tool_name="masscan",
                parameter_mapping={
                    "target": "target",
                    "ports": "ports",
                },
                condition=None,
            ),
            SkillStep(
                tool_name="nmap",
                parameter_mapping={
                    "target": "target",
                    "ports": "discovered_ports",
                },
                condition="masscan found at least one open port",
            ),
        ],
        fallback_logic=(
            "If masscan fails (e.g., no root access), fall back to nmap -sS "
            "scan across the full port range with -T4 timing."
        ),
        result_aggregation="merge",
    )


def _service_enumeration() -> Skill:
    """Service enumeration skill: nmap version scan + technology fingerprinting."""
    return Skill(
        name="service_enumeration",
        description=(
            "Detailed service enumeration workflow. Runs nmap with version "
            "detection and default scripts, then uses whatweb for web technology "
            "fingerprinting on any discovered HTTP/HTTPS services, and "
            "enum4linux for any discovered SMB services."
        ),
        tool_sequence=[
            SkillStep(
                tool_name="nmap",
                parameter_mapping={
                    "target": "target",
                    "ports": "ports",
                },
            ),
            SkillStep(
                tool_name="whatweb",
                parameter_mapping={
                    "target": "http_url",
                },
                condition="nmap detected HTTP or HTTPS service",
            ),
            SkillStep(
                tool_name="enum4linux",
                parameter_mapping={
                    "target": "target",
                },
                condition="nmap detected SMB service (port 139 or 445)",
            ),
        ],
        fallback_logic=(
            "If nmap script scan fails, retry with -sV only. "
            "If whatweb fails, try nikto as an alternative."
        ),
        result_aggregation="merge",
    )


def _web_discovery() -> Skill:
    """Web discovery skill: directory brute-force + technology fingerprint."""
    return Skill(
        name="web_discovery",
        description=(
            "Web content and technology discovery workflow. Starts with whatweb "
            "to fingerprint technologies, then runs feroxbuster for recursive "
            "directory/file discovery, and finally uses ffuf for parameter and "
            "vhost fuzzing if initial results warrant it."
        ),
        tool_sequence=[
            SkillStep(
                tool_name="whatweb",
                parameter_mapping={
                    "target": "url",
                },
            ),
            SkillStep(
                tool_name="feroxbuster",
                parameter_mapping={
                    "url": "url",
                    "wordlist": "wordlist",
                    "extensions": "extensions",
                },
            ),
            SkillStep(
                tool_name="ffuf",
                parameter_mapping={
                    "url": "fuzz_url",
                    "wordlist": "wordlist",
                },
                condition="feroxbuster discovered application endpoints",
            ),
        ],
        fallback_logic=(
            "If feroxbuster is unavailable, fall back to gobuster dir mode. "
            "If both fail, use ffuf with a common wordlist."
        ),
        result_aggregation="merge",
    )


def get_recon_skills() -> list[Skill]:
    """Return all reconnaissance skills."""
    return [
        _full_port_scan(),
        _service_enumeration(),
        _web_discovery(),
    ]
