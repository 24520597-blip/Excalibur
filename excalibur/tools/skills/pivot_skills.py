"""Pivoting and lateral movement skills for Excalibur.

Defines composed workflows: network_pivot, credential_spray.
"""

from __future__ import annotations

from excalibur.tools.skill import Skill, SkillStep


def _network_pivot() -> Skill:
    """Network pivoting skill: tunnel setup + internal network scanning."""
    return Skill(
        name="network_pivot",
        description=(
            "Network pivoting workflow for reaching internal networks through "
            "a compromised host. Sets up a chisel reverse SOCKS proxy through "
            "the compromised host, configures proxychains, then performs an "
            "nmap scan of the internal network through the tunnel."
        ),
        tool_sequence=[
            SkillStep(
                tool_name="chisel",
                parameter_mapping={
                    "mode": "mode",
                    "host": "pivot_host",
                    "port": "listen_port",
                    "tunnel_spec": "tunnel_spec",
                },
            ),
            SkillStep(
                tool_name="proxychains",
                parameter_mapping={
                    "command": "scan_command",
                    "config_file": "proxychains_config",
                },
                condition="chisel tunnel established successfully",
            ),
            SkillStep(
                tool_name="nmap",
                parameter_mapping={
                    "target": "internal_range",
                    "ports": "ports",
                },
                condition="proxychains configured and working through tunnel",
            ),
        ],
        fallback_logic=(
            "If chisel is unavailable, try SSH dynamic port forwarding "
            "(ssh -D 1080 user@pivot) or socat for simple port forwards. "
            "If proxychains fails, configure the SOCKS proxy in nmap directly."
        ),
        result_aggregation="sequential",
    )


def _credential_spray() -> Skill:
    """Credential spraying skill: enumerate users then spray passwords."""
    return Skill(
        name="credential_spray",
        description=(
            "Credential spraying workflow across network services. First uses "
            "kerbrute to enumerate valid AD usernames via Kerberos, then "
            "performs a password spray with CrackMapExec across SMB using "
            "common passwords and the discovered user list."
        ),
        tool_sequence=[
            SkillStep(
                tool_name="kerbrute",
                parameter_mapping={
                    "mode": "mode",
                    "domain": "domain",
                    "dc": "dc_ip",
                    "users_file": "users_file",
                },
            ),
            SkillStep(
                tool_name="crackmapexec",
                parameter_mapping={
                    "protocol": "protocol",
                    "target": "dc_ip",
                    "username": "valid_users_file",
                    "password": "spray_password",
                    "domain": "domain",
                },
                condition="kerbrute discovered valid usernames",
            ),
            SkillStep(
                tool_name="hydra",
                parameter_mapping={
                    "target": "target",
                    "service": "service",
                    "username_file": "valid_users_file",
                    "password_file": "password_file",
                },
                condition=(
                    "CrackMapExec spray did not find valid credentials and "
                    "other services (SSH, RDP, etc.) are available"
                ),
            ),
        ],
        fallback_logic=(
            "If kerbrute is unavailable, enumerate users via LDAP using "
            "ldapdomaindump or enum4linux. Be cautious with password spraying "
            "to avoid account lockouts -- respect lockout policies."
        ),
        result_aggregation="sequential",
    )


def get_pivot_skills() -> list[Skill]:
    """Return all pivoting and lateral movement skills."""
    return [
        _network_pivot(),
        _credential_spray(),
    ]
