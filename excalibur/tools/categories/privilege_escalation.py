"""Privilege escalation tools for Excalibur.

Provides typed interfaces for 4 privilege escalation tools:
linpeas, winpeas, pspy, seatbelt.
"""

from __future__ import annotations

from excalibur.tools.base import (
    ToolCategory,
    ToolOutputField,
    ToolParameter,
    ToolPostcondition,
    ToolPrecondition,
    TypedSecurityTool,
    TypedToolInterface,
)


def linpeas_tool() -> TypedSecurityTool:
    """LinPEAS Linux privilege escalation enumeration tool."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="linpeas",
            category=ToolCategory.PRIVILEGE_ESCALATION,
            description=(
                "Linux Privilege Escalation Awesome Script. Enumerates system "
                "information, processes, cron jobs, SUID/SGID binaries, writable "
                "files, capabilities, kernel exploits, and other privilege "
                "escalation vectors on Linux/Unix systems."
            ),
            input_schema=[
                ToolParameter(
                    name="intensity",
                    type="string",
                    required=False,
                    default="normal",
                    description="Scan intensity level",
                    choices=["quiet", "normal", "intense"],
                ),
                ToolParameter(
                    name="checks",
                    type="string",
                    required=False,
                    description=(
                        "Specific check categories to run "
                        "(e.g., 'SysI,Devs,AvaSof,ProCronSrworworworworv')"
                    ),
                ),
                ToolParameter(
                    name="password",
                    type="string",
                    required=False,
                    description="Current user password for sudo checks",
                ),
                ToolParameter(
                    name="network",
                    type="boolean",
                    required=False,
                    default="true",
                    description="Include network enumeration checks",
                ),
                ToolParameter(
                    name="output_file",
                    type="string",
                    required=False,
                    description="Path to save output",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional linpeas flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="suid_binaries",
                    type="list[str]",
                    description="SUID/SGID binaries found",
                ),
                ToolOutputField(
                    name="writable_paths",
                    type="list[str]",
                    description="Writable paths in sensitive locations",
                ),
                ToolOutputField(
                    name="cron_jobs",
                    type="list[dict]",
                    description="Discovered cron jobs and scheduled tasks",
                ),
                ToolOutputField(
                    name="kernel_exploits",
                    type="list[str]",
                    description="Potential kernel exploit suggestions",
                ),
                ToolOutputField(
                    name="credentials_found",
                    type="list[dict]",
                    description="Passwords and credentials found in files",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full linpeas output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Must have shell access on a Linux/Unix system",
                    check_type="os_type",
                    parameters={"os": "linux"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Identifies privilege escalation vectors on Linux",
                    effect_type="reveals_data",
                ),
            ],
            command_template=(
                "curl -fsSL https://github.com/peass-ng/PEASS-ng/releases/"
                "latest/download/linpeas.sh | bash -s -- "
                "-a {extra_flags} 2>&1 | tee {output_file}"
            ),
            timeout=600,
        )
    )


def winpeas_tool() -> TypedSecurityTool:
    """WinPEAS Windows privilege escalation enumeration tool."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="winpeas",
            category=ToolCategory.PRIVILEGE_ESCALATION,
            description=(
                "Windows Privilege Escalation Awesome Script. Enumerates system "
                "info, running processes, services, scheduled tasks, registry "
                "keys, unquoted service paths, token privileges, and other "
                "Windows privilege escalation vectors."
            ),
            input_schema=[
                ToolParameter(
                    name="mode",
                    type="string",
                    required=False,
                    default="all",
                    description="Check category to run",
                    choices=[
                        "all",
                        "systeminfo",
                        "userinfo",
                        "processinfo",
                        "servicesinfo",
                        "applicationsinfo",
                        "networkinfo",
                        "windowscreds",
                        "browserinfo",
                        "filesinfo",
                    ],
                ),
                ToolParameter(
                    name="quiet",
                    type="boolean",
                    required=False,
                    default="false",
                    description="Quiet mode (less output)",
                ),
                ToolParameter(
                    name="wait",
                    type="boolean",
                    required=False,
                    default="false",
                    description="Wait for user input between checks",
                ),
                ToolParameter(
                    name="output_file",
                    type="string",
                    required=False,
                    description="Path to save output",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional winpeas flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="vulnerable_services",
                    type="list[dict]",
                    description="Services with escalation potential",
                ),
                ToolOutputField(
                    name="unquoted_paths",
                    type="list[str]",
                    description="Unquoted service paths",
                ),
                ToolOutputField(
                    name="token_privileges",
                    type="list[str]",
                    description="Exploitable token privileges",
                ),
                ToolOutputField(
                    name="credentials_found",
                    type="list[dict]",
                    description="Discovered stored credentials",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full winpeas output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Must have shell access on a Windows system",
                    check_type="os_type",
                    parameters={"os": "windows"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Identifies privilege escalation vectors on Windows",
                    effect_type="reveals_data",
                ),
            ],
            command_template=("winPEASx64.exe {mode} {extra_flags} | tee {output_file}"),
            timeout=600,
        )
    )


def pspy_tool() -> TypedSecurityTool:
    """pspy unprivileged Linux process monitor."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="pspy",
            category=ToolCategory.PRIVILEGE_ESCALATION,
            description=(
                "Unprivileged Linux process snooping tool. Monitors running "
                "processes, cron jobs, and commands executed by other users "
                "without requiring root privileges. Uses inotify to detect "
                "process creation events."
            ),
            input_schema=[
                ToolParameter(
                    name="print_commands",
                    type="boolean",
                    required=False,
                    default="true",
                    description="Print commands run by processes",
                ),
                ToolParameter(
                    name="print_file_events",
                    type="boolean",
                    required=False,
                    default="true",
                    description="Print file system events",
                ),
                ToolParameter(
                    name="directories",
                    type="string",
                    required=False,
                    default="/tmp,/var,/home,/usr,/opt",
                    description="Directories to watch (comma-separated)",
                ),
                ToolParameter(
                    name="color",
                    type="boolean",
                    required=False,
                    default="true",
                    description="Enable colored output",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional pspy flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="processes",
                    type="list[dict]",
                    description="Observed process executions with user and command",
                ),
                ToolOutputField(
                    name="cron_commands",
                    type="list[dict]",
                    description="Detected cron job executions",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full pspy output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Must have shell access on a Linux system",
                    check_type="os_type",
                    parameters={"os": "linux"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Reveals processes, cron jobs, and commands by other users",
                    effect_type="reveals_data",
                ),
            ],
            command_template=("./pspy64 -p -f -d {directories} {extra_flags}"),
            timeout=300,
        )
    )


def seatbelt_tool() -> TypedSecurityTool:
    """Seatbelt Windows security enumeration tool."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="seatbelt",
            category=ToolCategory.PRIVILEGE_ESCALATION,
            description=(
                "C# security enumeration tool for Windows hosts. Performs "
                "numerous safety checks to identify misconfigurations, "
                "installed software, credential storage, token privileges, "
                "and other security-relevant system settings."
            ),
            input_schema=[
                ToolParameter(
                    name="group",
                    type="string",
                    required=False,
                    default="all",
                    description="Check group to run",
                    choices=[
                        "all",
                        "system",
                        "user",
                        "misc",
                        "chrome",
                        "remote",
                        "slack",
                    ],
                ),
                ToolParameter(
                    name="checks",
                    type="string",
                    required=False,
                    description=(
                        "Specific checks to run (e.g., 'TokenPrivileges,AutoRuns,CredFiles')"
                    ),
                ),
                ToolParameter(
                    name="full",
                    type="boolean",
                    required=False,
                    default="false",
                    description="Return complete, unfiltered results",
                ),
                ToolParameter(
                    name="output_file",
                    type="string",
                    required=False,
                    description="Path to save output file",
                ),
                ToolParameter(
                    name="remote_host",
                    type="string",
                    required=False,
                    description="Remote host to enumerate (requires admin access)",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional Seatbelt flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="token_privileges",
                    type="list[str]",
                    description="Current token privileges",
                ),
                ToolOutputField(
                    name="auto_runs",
                    type="list[dict]",
                    description="Auto-run entries (registry, startup, services)",
                ),
                ToolOutputField(
                    name="credential_files",
                    type="list[str]",
                    description="Paths to credential storage files",
                ),
                ToolOutputField(
                    name="installed_products",
                    type="list[dict]",
                    description="Installed software products",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full Seatbelt output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Must have shell access on a Windows system",
                    check_type="os_type",
                    parameters={"os": "windows"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Enumerates Windows security settings and misconfigurations",
                    effect_type="reveals_data",
                ),
            ],
            command_template=(
                "Seatbelt.exe -group={group} -{checks} "
                "-outputfile={output_file} -computername={remote_host} "
                "{extra_flags}"
            ),
            timeout=300,
        )
    )


def get_privilege_escalation_tools() -> list[TypedSecurityTool]:
    """Return all privilege escalation tools."""
    return [
        linpeas_tool(),
        winpeas_tool(),
        pspy_tool(),
        seatbelt_tool(),
    ]
