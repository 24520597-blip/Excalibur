"""Privilege escalation skills for Excalibur.

Defines composed workflows: linux_enum, windows_enum.
"""

from __future__ import annotations

from excalibur.tools.skill import Skill, SkillStep


def _linux_enum() -> Skill:
    """Linux privilege escalation enumeration chain."""
    return Skill(
        name="linux_enum",
        description=(
            "Comprehensive Linux privilege escalation enumeration workflow. "
            "Runs linpeas for automated enumeration of SUID binaries, cron "
            "jobs, writable paths, capabilities, and kernel exploits. "
            "Follows up with pspy to monitor processes for cron-triggered "
            "commands run by root or other privileged users."
        ),
        tool_sequence=[
            SkillStep(
                tool_name="linpeas",
                parameter_mapping={
                    "output_file": "output_file",
                },
            ),
            SkillStep(
                tool_name="pspy",
                parameter_mapping={
                    "directories": "watch_dirs",
                },
                condition=(
                    "linpeas found potential cron-based escalation vectors or writable script paths"
                ),
            ),
        ],
        fallback_logic=(
            "If linpeas cannot be uploaded, manually check: "
            "find / -perm -4000 2>/dev/null (SUID), "
            "cat /etc/crontab, ls -la /etc/cron.*, "
            "getcap -r / 2>/dev/null (capabilities), "
            "and sudo -l for sudo misconfigurations."
        ),
        result_aggregation="merge",
    )


def _windows_enum() -> Skill:
    """Windows privilege escalation enumeration chain."""
    return Skill(
        name="windows_enum",
        description=(
            "Comprehensive Windows privilege escalation enumeration workflow. "
            "Runs winpeas for automated enumeration of token privileges, "
            "unquoted service paths, AlwaysInstallElevated, stored credentials, "
            "and DLL hijacking opportunities. Follows up with Seatbelt for "
            "detailed security configuration checks."
        ),
        tool_sequence=[
            SkillStep(
                tool_name="winpeas",
                parameter_mapping={
                    "mode": "mode",
                    "output_file": "output_file",
                },
            ),
            SkillStep(
                tool_name="seatbelt",
                parameter_mapping={
                    "group": "check_group",
                },
                condition=(
                    "winpeas identified interesting token privileges or misconfigured services"
                ),
            ),
        ],
        fallback_logic=(
            "If winpeas cannot be executed, manually check: "
            "whoami /priv, wmic service get name,displayname,pathname,startmode, "
            "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer, "
            "and cmdkey /list for stored credentials."
        ),
        result_aggregation="merge",
    )


def get_privesc_skills() -> list[Skill]:
    """Return all privilege escalation skills."""
    return [
        _linux_enum(),
        _windows_enum(),
    ]
