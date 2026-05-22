"""Reconnaissance tools for Excalibur.

Provides typed interfaces for 8 reconnaissance tools:
nmap, masscan, gobuster, ffuf, feroxbuster, nikto, whatweb, enum4linux.
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


def nmap_tool() -> TypedSecurityTool:
    """Nmap network scanner for host discovery and service enumeration."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="nmap",
            category=ToolCategory.RECONNAISSANCE,
            description=(
                "Network exploration and security auditing tool. Discovers hosts, "
                "open ports, running services, OS versions, and potential "
                "vulnerabilities using various scan techniques."
            ),
            input_schema=[
                ToolParameter(
                    name="target",
                    type="string",
                    required=True,
                    description="Target IP, hostname, CIDR range, or IP range to scan",
                    validation_pattern=r"^[\w.\-/:\[\],\s]+$",
                ),
                ToolParameter(
                    name="ports",
                    type="string",
                    required=False,
                    default=None,
                    description="Port specification (e.g., '80,443', '1-1000', '-' for all)",
                ),
                ToolParameter(
                    name="scan_type",
                    type="string",
                    required=False,
                    default="-sV",
                    description="Scan type flags",
                    choices=[
                        "-sS",
                        "-sT",
                        "-sU",
                        "-sV",
                        "-sC",
                        "-sn",
                        "-A",
                    ],
                ),
                ToolParameter(
                    name="scripts",
                    type="string",
                    required=False,
                    description="NSE scripts to run (e.g., 'vuln', 'default,safe')",
                ),
                ToolParameter(
                    name="timing",
                    type="string",
                    required=False,
                    default="-T4",
                    description="Timing template",
                    choices=["-T0", "-T1", "-T2", "-T3", "-T4", "-T5"],
                ),
                ToolParameter(
                    name="output_file",
                    type="string",
                    required=False,
                    description="Path to save output (uses -oN for normal output)",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional nmap flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="open_ports",
                    type="list[int]",
                    description="List of discovered open ports",
                ),
                ToolOutputField(
                    name="services",
                    type="list[dict]",
                    description="Service details per port (name, version, protocol)",
                ),
                ToolOutputField(
                    name="os_detection",
                    type="string",
                    description="Detected operating system information",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full nmap text output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Target host must be reachable on the network",
                    check_type="host_reachable",
                    parameters={"target": "{target}"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Discovers open ports and running services on the target",
                    effect_type="discovers_services",
                ),
                ToolPostcondition(
                    description="May reveal OS version and software versions",
                    effect_type="reveals_data",
                ),
            ],
            command_template=(
                "nmap {scan_type} {timing} "
                "-p {ports} --script={scripts} "
                "-oN {output_file} {extra_flags} {target}"
            ),
            timeout=600,
        )
    )


def masscan_tool() -> TypedSecurityTool:
    """Masscan high-speed port scanner."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="masscan",
            category=ToolCategory.RECONNAISSANCE,
            description=(
                "High-speed TCP port scanner. Can scan the entire Internet in "
                "under 6 minutes. Ideal for quickly identifying open ports on "
                "large networks before doing detailed nmap scans."
            ),
            input_schema=[
                ToolParameter(
                    name="target",
                    type="string",
                    required=True,
                    description="Target IP address or CIDR range",
                    validation_pattern=r"^[\d./\-,\s]+$",
                ),
                ToolParameter(
                    name="ports",
                    type="string",
                    required=True,
                    description="Port specification (e.g., '0-65535', '80,443')",
                ),
                ToolParameter(
                    name="rate",
                    type="string",
                    required=False,
                    default="1000",
                    description="Packet transmission rate (packets per second)",
                ),
                ToolParameter(
                    name="output_file",
                    type="string",
                    required=False,
                    description="Path to save results",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional masscan flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="open_ports",
                    type="list[int]",
                    description="List of discovered open ports",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full masscan output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Requires root/sudo for raw socket access",
                    check_type="root_access",
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Discovers open TCP ports at high speed",
                    effect_type="discovers_services",
                ),
            ],
            command_template=(
                "masscan {target} -p{ports} --rate={rate} -oL {output_file} {extra_flags}"
            ),
            timeout=300,
        )
    )


def gobuster_tool() -> TypedSecurityTool:
    """Gobuster directory and DNS brute-forcer."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="gobuster",
            category=ToolCategory.RECONNAISSANCE,
            description=(
                "Directory/file, DNS, and vhost brute-forcing tool. Discovers "
                "hidden web paths, subdomains, and virtual hosts using wordlists."
            ),
            input_schema=[
                ToolParameter(
                    name="mode",
                    type="string",
                    required=True,
                    description="Gobuster mode",
                    choices=["dir", "dns", "vhost", "fuzz"],
                ),
                ToolParameter(
                    name="url",
                    type="string",
                    required=True,
                    description="Target URL (for dir/vhost) or domain (for dns)",
                    validation_pattern=r"^https?://[\w.\-:]+",
                ),
                ToolParameter(
                    name="wordlist",
                    type="string",
                    required=True,
                    description="Path to wordlist file",
                    default="/usr/share/wordlists/dirb/common.txt",
                ),
                ToolParameter(
                    name="extensions",
                    type="string",
                    required=False,
                    description="File extensions to search for (e.g., 'php,html,txt')",
                ),
                ToolParameter(
                    name="threads",
                    type="string",
                    required=False,
                    default="50",
                    description="Number of concurrent threads",
                ),
                ToolParameter(
                    name="status_codes",
                    type="string",
                    required=False,
                    default="200,204,301,302,307,401,403",
                    description="HTTP status codes to match",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional gobuster flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="discovered_paths",
                    type="list[dict]",
                    description="Discovered paths with status codes and sizes",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full gobuster output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Target web server must be running and accessible",
                    check_type="service_running",
                    parameters={"url": "{url}"},
                ),
                ToolPrecondition(
                    description="Wordlist file must exist on disk",
                    check_type="file_exists",
                    parameters={"path": "{wordlist}"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Discovers hidden directories, files, and endpoints",
                    effect_type="discovers_services",
                ),
            ],
            command_template=(
                "gobuster {mode} -u {url} -w {wordlist} "
                "-x {extensions} -t {threads} "
                "-s {status_codes} {extra_flags}"
            ),
            timeout=600,
        )
    )


def ffuf_tool() -> TypedSecurityTool:
    """FFUF fast web fuzzer."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="ffuf",
            category=ToolCategory.RECONNAISSANCE,
            description=(
                "Fast web fuzzer written in Go. Supports directory discovery, "
                "parameter fuzzing, vhost discovery, and POST data fuzzing "
                "with flexible filtering options."
            ),
            input_schema=[
                ToolParameter(
                    name="url",
                    type="string",
                    required=True,
                    description="Target URL with FUZZ keyword (e.g., 'http://target/FUZZ')",
                ),
                ToolParameter(
                    name="wordlist",
                    type="string",
                    required=True,
                    description="Path to wordlist file",
                    default="/usr/share/wordlists/dirb/common.txt",
                ),
                ToolParameter(
                    name="method",
                    type="string",
                    required=False,
                    default="GET",
                    description="HTTP method to use",
                    choices=["GET", "POST", "PUT", "DELETE", "PATCH"],
                ),
                ToolParameter(
                    name="data",
                    type="string",
                    required=False,
                    description="POST data (e.g., 'user=FUZZ&pass=FUZZ')",
                ),
                ToolParameter(
                    name="headers",
                    type="string",
                    required=False,
                    description="Custom headers (e.g., 'Content-Type: application/json')",
                ),
                ToolParameter(
                    name="filter_code",
                    type="string",
                    required=False,
                    description="Filter HTTP status codes (e.g., '404,500')",
                ),
                ToolParameter(
                    name="match_code",
                    type="string",
                    required=False,
                    default="200,204,301,302,307,401,403,405",
                    description="Match HTTP status codes",
                ),
                ToolParameter(
                    name="filter_size",
                    type="string",
                    required=False,
                    description="Filter response size",
                ),
                ToolParameter(
                    name="threads",
                    type="string",
                    required=False,
                    default="40",
                    description="Number of concurrent threads",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional ffuf flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="results",
                    type="list[dict]",
                    description="Matched results with status, size, and words",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full ffuf output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Target web server must be accessible",
                    check_type="service_running",
                    parameters={"url": "{url}"},
                ),
                ToolPrecondition(
                    description="Wordlist file must exist on disk",
                    check_type="file_exists",
                    parameters={"path": "{wordlist}"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Discovers hidden endpoints, parameters, or vhosts",
                    effect_type="discovers_services",
                ),
            ],
            command_template=(
                "ffuf -u {url} -w {wordlist} -X {method} "
                "-mc {match_code} -fc {filter_code} -fs {filter_size} "
                "-t {threads} -H '{headers}' -d '{data}' {extra_flags}"
            ),
            timeout=600,
        )
    )


def feroxbuster_tool() -> TypedSecurityTool:
    """Feroxbuster recursive content discovery tool."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="feroxbuster",
            category=ToolCategory.RECONNAISSANCE,
            description=(
                "Fast, recursive content discovery tool written in Rust. "
                "Automatically discovers directories and recursively scans them, "
                "making it effective for deep web application enumeration."
            ),
            input_schema=[
                ToolParameter(
                    name="url",
                    type="string",
                    required=True,
                    description="Target URL to scan",
                    validation_pattern=r"^https?://[\w.\-:]+",
                ),
                ToolParameter(
                    name="wordlist",
                    type="string",
                    required=False,
                    default="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
                    description="Path to wordlist file",
                ),
                ToolParameter(
                    name="extensions",
                    type="string",
                    required=False,
                    description="File extensions to search for (e.g., 'php,html,txt,bak')",
                ),
                ToolParameter(
                    name="threads",
                    type="string",
                    required=False,
                    default="50",
                    description="Number of concurrent threads",
                ),
                ToolParameter(
                    name="depth",
                    type="string",
                    required=False,
                    default="4",
                    description="Maximum recursion depth",
                ),
                ToolParameter(
                    name="filter_status",
                    type="string",
                    required=False,
                    description="Status codes to filter out (e.g., '404,500')",
                ),
                ToolParameter(
                    name="output_file",
                    type="string",
                    required=False,
                    description="Path to save results",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional feroxbuster flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="discovered_paths",
                    type="list[dict]",
                    description="Discovered paths with response details",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full feroxbuster output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Target web server must be accessible",
                    check_type="service_running",
                    parameters={"url": "{url}"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Recursively discovers web directories and files",
                    effect_type="discovers_services",
                ),
            ],
            command_template=(
                "feroxbuster -u {url} -w {wordlist} -x {extensions} "
                "-t {threads} -d {depth} -C {filter_status} "
                "-o {output_file} {extra_flags}"
            ),
            timeout=900,
        )
    )


def nikto_tool() -> TypedSecurityTool:
    """Nikto web server vulnerability scanner."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="nikto",
            category=ToolCategory.RECONNAISSANCE,
            description=(
                "Open-source web server scanner that tests for dangerous files, "
                "outdated server software, version-specific problems, and "
                "server configuration issues."
            ),
            input_schema=[
                ToolParameter(
                    name="host",
                    type="string",
                    required=True,
                    description="Target host or URL to scan",
                ),
                ToolParameter(
                    name="port",
                    type="string",
                    required=False,
                    default="80",
                    description="Target port",
                ),
                ToolParameter(
                    name="ssl",
                    type="boolean",
                    required=False,
                    default="false",
                    description="Use SSL/TLS for the connection",
                ),
                ToolParameter(
                    name="tuning",
                    type="string",
                    required=False,
                    description="Scan tuning options (1-9, a-c)",
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
                    description="Additional nikto flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="vulnerabilities",
                    type="list[dict]",
                    description="Discovered vulnerabilities and misconfigurations",
                ),
                ToolOutputField(
                    name="server_info",
                    type="dict",
                    description="Server software and header information",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full nikto output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Web server must be running on target port",
                    check_type="port_open",
                    parameters={"host": "{host}", "port": "{port}"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Identifies web server vulnerabilities and misconfigurations",
                    effect_type="reveals_data",
                ),
            ],
            command_template=(
                "nikto -h {host} -p {port} -T {tuning} -o {output_file} {extra_flags}"
            ),
            timeout=600,
        )
    )


def whatweb_tool() -> TypedSecurityTool:
    """WhatWeb web technology fingerprinter."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="whatweb",
            category=ToolCategory.RECONNAISSANCE,
            description=(
                "Web technology fingerprinting tool. Identifies content management "
                "systems, web frameworks, server software, JavaScript libraries, "
                "and other technologies used by a website."
            ),
            input_schema=[
                ToolParameter(
                    name="target",
                    type="string",
                    required=True,
                    description="Target URL or hostname",
                ),
                ToolParameter(
                    name="aggression",
                    type="string",
                    required=False,
                    default="1",
                    description="Aggression level (1=stealthy, 3=aggressive, 4=heavy)",
                    choices=["1", "2", "3", "4"],
                ),
                ToolParameter(
                    name="verbose",
                    type="boolean",
                    required=False,
                    default="true",
                    description="Enable verbose output",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional whatweb flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="technologies",
                    type="list[dict]",
                    description="Detected technologies with versions",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full whatweb output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Target web server must be accessible",
                    check_type="service_running",
                    parameters={"url": "{target}"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Identifies web technologies, frameworks, and server software",
                    effect_type="reveals_data",
                ),
            ],
            command_template="whatweb -a {aggression} -v {extra_flags} {target}",
            timeout=120,
        )
    )


def enum4linux_tool() -> TypedSecurityTool:
    """Enum4linux SMB/NetBIOS enumeration tool."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="enum4linux",
            category=ToolCategory.RECONNAISSANCE,
            description=(
                "Tool for enumerating information from Windows and Samba systems. "
                "Extracts user lists, share information, group membership, password "
                "policies, and other data via SMB/NetBIOS."
            ),
            input_schema=[
                ToolParameter(
                    name="target",
                    type="string",
                    required=True,
                    description="Target IP address",
                    validation_pattern=r"^[\d.]+$",
                ),
                ToolParameter(
                    name="username",
                    type="string",
                    required=False,
                    description="Username for authenticated enumeration",
                ),
                ToolParameter(
                    name="password",
                    type="string",
                    required=False,
                    description="Password for authenticated enumeration",
                ),
                ToolParameter(
                    name="enum_all",
                    type="boolean",
                    required=False,
                    default="true",
                    description="Run all enumeration options",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional enum4linux flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="users",
                    type="list[str]",
                    description="Discovered user accounts",
                ),
                ToolOutputField(
                    name="shares",
                    type="list[dict]",
                    description="SMB shares with access information",
                ),
                ToolOutputField(
                    name="groups",
                    type="list[str]",
                    description="Discovered groups",
                ),
                ToolOutputField(
                    name="password_policy",
                    type="dict",
                    description="Password policy details",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full enum4linux output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="SMB service (port 445 or 139) must be open on target",
                    check_type="port_open",
                    parameters={"host": "{target}", "port": "445"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Enumerates users, shares, groups from SMB/NetBIOS",
                    effect_type="reveals_data",
                ),
            ],
            command_template=("enum4linux -a -u {username} -p {password} {extra_flags} {target}"),
            timeout=300,
        )
    )


def get_reconnaissance_tools() -> list[TypedSecurityTool]:
    """Return all reconnaissance tools."""
    return [
        nmap_tool(),
        masscan_tool(),
        gobuster_tool(),
        ffuf_tool(),
        feroxbuster_tool(),
        nikto_tool(),
        whatweb_tool(),
        enum4linux_tool(),
    ]
