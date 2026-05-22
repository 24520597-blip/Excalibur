"""Credential attack tools for Excalibur.

Provides typed interfaces for 5 credential attack tools:
hashcat, john, hydra, impacket_collection, kerbrute.
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


def hashcat_tool() -> TypedSecurityTool:
    """Hashcat advanced password recovery tool."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="hashcat",
            category=ToolCategory.CREDENTIAL_ATTACKS,
            description=(
                "World's fastest and most advanced password recovery utility. "
                "Supports over 300 hash types and five attack modes including "
                "dictionary, combinator, brute-force, rule-based, and hybrid. "
                "GPU-accelerated for maximum performance."
            ),
            input_schema=[
                ToolParameter(
                    name="hash_file",
                    type="string",
                    required=True,
                    description="Path to file containing hashes to crack",
                ),
                ToolParameter(
                    name="hash_type",
                    type="string",
                    required=True,
                    description=(
                        "Hash type code (e.g., '0' for MD5, '1000' for NTLM, "
                        "'13100' for Kerberoasting)"
                    ),
                ),
                ToolParameter(
                    name="attack_mode",
                    type="string",
                    required=False,
                    default="0",
                    description="Attack mode (0=dict, 1=combinator, 3=brute, 6=hybrid, 7=hybrid)",
                    choices=["0", "1", "3", "6", "7"],
                ),
                ToolParameter(
                    name="wordlist",
                    type="string",
                    required=False,
                    default="/usr/share/wordlists/rockyou.txt",
                    description="Path to wordlist (for dictionary/hybrid attacks)",
                ),
                ToolParameter(
                    name="rules",
                    type="string",
                    required=False,
                    description="Path to rules file for mangling",
                ),
                ToolParameter(
                    name="mask",
                    type="string",
                    required=False,
                    description="Brute-force mask (e.g., '?u?l?l?l?l?d?d?d')",
                ),
                ToolParameter(
                    name="output_file",
                    type="string",
                    required=False,
                    description="Path to save cracked passwords",
                ),
                ToolParameter(
                    name="force",
                    type="boolean",
                    required=False,
                    default="false",
                    description="Force execution even with warnings (CPU-only mode)",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional hashcat flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="cracked",
                    type="list[dict]",
                    description="Cracked hash:password pairs",
                ),
                ToolOutputField(
                    name="stats",
                    type="dict",
                    description="Cracking statistics (speed, progress, recovered)",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full hashcat output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Hash file must exist",
                    check_type="file_exists",
                    parameters={"path": "{hash_file}"},
                ),
                ToolPrecondition(
                    description="Wordlist must exist (for dictionary-based attacks)",
                    check_type="file_exists",
                    parameters={"path": "{wordlist}"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Recovers plaintext passwords from hashes",
                    effect_type="reveals_data",
                ),
            ],
            command_template=(
                "hashcat -m {hash_type} -a {attack_mode} {hash_file} {wordlist} "
                "-r {rules} --mask {mask} -o {output_file} "
                "--force {extra_flags}"
            ),
            timeout=3600,
        )
    )


def john_tool() -> TypedSecurityTool:
    """John the Ripper password cracker."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="john",
            category=ToolCategory.CREDENTIAL_ATTACKS,
            description=(
                "Open-source password security auditing and recovery tool. "
                "Supports cracking password hashes for Unix, Windows, Kerberos, "
                "and many other formats. Includes wordlist, incremental, and "
                "rule-based attack modes."
            ),
            input_schema=[
                ToolParameter(
                    name="hash_file",
                    type="string",
                    required=True,
                    description="Path to file containing hashes to crack",
                ),
                ToolParameter(
                    name="format",
                    type="string",
                    required=False,
                    description="Hash format (e.g., 'NT', 'raw-md5', 'krb5tgs')",
                ),
                ToolParameter(
                    name="wordlist",
                    type="string",
                    required=False,
                    default="/usr/share/wordlists/rockyou.txt",
                    description="Path to wordlist file",
                ),
                ToolParameter(
                    name="rules",
                    type="string",
                    required=False,
                    description="Word mangling rules section name",
                ),
                ToolParameter(
                    name="incremental",
                    type="boolean",
                    required=False,
                    default="false",
                    description="Use incremental (brute-force) mode",
                ),
                ToolParameter(
                    name="show",
                    type="boolean",
                    required=False,
                    default="false",
                    description="Show previously cracked passwords",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional john flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="cracked",
                    type="list[dict]",
                    description="Cracked user:password pairs",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full john output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Hash file must exist",
                    check_type="file_exists",
                    parameters={"path": "{hash_file}"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Recovers plaintext passwords from hashes",
                    effect_type="reveals_data",
                ),
            ],
            command_template=(
                "john --wordlist={wordlist} --format={format} "
                "--rules={rules} {extra_flags} {hash_file}"
            ),
            timeout=3600,
        )
    )


def hydra_tool() -> TypedSecurityTool:
    """THC Hydra online password brute-forcer."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="hydra",
            category=ToolCategory.CREDENTIAL_ATTACKS,
            description=(
                "Fast and flexible online password brute-forcing tool. Supports "
                "over 50 protocols including SSH, FTP, HTTP, SMB, RDP, MySQL, "
                "MSSQL, and more. Performs dictionary attacks against remote "
                "authentication services."
            ),
            input_schema=[
                ToolParameter(
                    name="target",
                    type="string",
                    required=True,
                    description="Target IP address or hostname",
                ),
                ToolParameter(
                    name="service",
                    type="string",
                    required=True,
                    description="Target service protocol",
                    choices=[
                        "ssh",
                        "ftp",
                        "http-get",
                        "http-post-form",
                        "smb",
                        "rdp",
                        "mysql",
                        "mssql",
                        "vnc",
                        "telnet",
                        "smtp",
                        "pop3",
                        "imap",
                        "ldap",
                    ],
                ),
                ToolParameter(
                    name="username",
                    type="string",
                    required=False,
                    description="Single username or -L for file",
                ),
                ToolParameter(
                    name="username_file",
                    type="string",
                    required=False,
                    description="File containing list of usernames",
                ),
                ToolParameter(
                    name="password",
                    type="string",
                    required=False,
                    description="Single password or -P for file",
                ),
                ToolParameter(
                    name="password_file",
                    type="string",
                    required=False,
                    default="/usr/share/wordlists/rockyou.txt",
                    description="File containing list of passwords",
                ),
                ToolParameter(
                    name="port",
                    type="string",
                    required=False,
                    description="Target port (overrides default for service)",
                ),
                ToolParameter(
                    name="threads",
                    type="string",
                    required=False,
                    default="16",
                    description="Number of parallel connections",
                ),
                ToolParameter(
                    name="http_path",
                    type="string",
                    required=False,
                    description="HTTP form path and parameters for http-post-form",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional hydra flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="valid_credentials",
                    type="list[dict]",
                    description="Discovered valid username/password combinations",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full hydra output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Target service must be accessible",
                    check_type="port_open",
                    parameters={"host": "{target}", "port": "{port}"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Discovers valid credentials through brute-force",
                    effect_type="reveals_data",
                ),
                ToolPostcondition(
                    description="Valid credentials enable authentication to services",
                    effect_type="gains_access",
                ),
            ],
            command_template=(
                "hydra -l {username} -L {username_file} -p {password} "
                "-P {password_file} -s {port} -t {threads} "
                "{extra_flags} {target} {service} {http_path}"
            ),
            timeout=1800,
        )
    )


def impacket_collection_tool() -> TypedSecurityTool:
    """Impacket collection of network protocol tools."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="impacket",
            category=ToolCategory.CREDENTIAL_ATTACKS,
            description=(
                "Collection of Python classes and scripts for working with "
                "network protocols. Includes tools for credential dumping "
                "(secretsdump), remote execution (psexec, wmiexec, smbexec), "
                "Kerberos attacks (GetNPUsers, GetUserSPNs), and more."
            ),
            input_schema=[
                ToolParameter(
                    name="script",
                    type="string",
                    required=True,
                    description="Impacket script to run",
                    choices=[
                        "secretsdump.py",
                        "psexec.py",
                        "wmiexec.py",
                        "smbexec.py",
                        "atexec.py",
                        "dcomexec.py",
                        "GetNPUsers.py",
                        "GetUserSPNs.py",
                        "getTGT.py",
                        "getST.py",
                        "smbclient.py",
                        "mssqlclient.py",
                        "ntlmrelayx.py",
                    ],
                ),
                ToolParameter(
                    name="target",
                    type="string",
                    required=True,
                    description="Target specification (e.g., 'domain/user:pass@target')",
                ),
                ToolParameter(
                    name="domain",
                    type="string",
                    required=False,
                    description="Active Directory domain name",
                ),
                ToolParameter(
                    name="username",
                    type="string",
                    required=False,
                    description="Username for authentication",
                ),
                ToolParameter(
                    name="password",
                    type="string",
                    required=False,
                    description="Password for authentication",
                ),
                ToolParameter(
                    name="hash",
                    type="string",
                    required=False,
                    description="NTLM hash (LM:NT format) for pass-the-hash",
                ),
                ToolParameter(
                    name="dc_ip",
                    type="string",
                    required=False,
                    description="Domain Controller IP address",
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
                    description="Additional script-specific flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="credentials",
                    type="list[dict]",
                    description="Dumped credentials (hashes, tickets, etc.)",
                ),
                ToolOutputField(
                    name="command_output",
                    type="string",
                    description="Output from remote command execution",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full impacket script output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Target must be accessible on the network",
                    check_type="host_reachable",
                    parameters={"target": "{target}"},
                ),
                ToolPrecondition(
                    description="Impacket must be installed",
                    check_type="tool_installed",
                    parameters={"tool": "impacket-secretsdump"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Dumps credentials, executes commands, or performs Kerberos attacks",
                    effect_type="gains_access",
                ),
                ToolPostcondition(
                    description="Extracts password hashes and Kerberos tickets",
                    effect_type="reveals_data",
                ),
            ],
            command_template=(
                "impacket-{script} {domain}/{username}:{password}@{target} "
                "-hashes {hash} -dc-ip {dc_ip} "
                "-outputfile {output_file} {extra_flags}"
            ),
            timeout=600,
        )
    )


def kerbrute_tool() -> TypedSecurityTool:
    """Kerbrute Kerberos brute-force tool."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="kerbrute",
            category=ToolCategory.CREDENTIAL_ATTACKS,
            description=(
                "Tool for brute-forcing and enumerating valid Active Directory "
                "accounts through Kerberos pre-authentication. Faster and "
                "stealthier than traditional brute-force methods as it does "
                "not generate Windows logon events."
            ),
            input_schema=[
                ToolParameter(
                    name="mode",
                    type="string",
                    required=True,
                    description="Kerbrute mode",
                    choices=[
                        "userenum",
                        "passwordspray",
                        "bruteuser",
                        "bruteforce",
                    ],
                ),
                ToolParameter(
                    name="domain",
                    type="string",
                    required=True,
                    description="Target Active Directory domain",
                ),
                ToolParameter(
                    name="dc",
                    type="string",
                    required=False,
                    description="Domain Controller IP address",
                ),
                ToolParameter(
                    name="users_file",
                    type="string",
                    required=False,
                    description="File containing list of usernames",
                ),
                ToolParameter(
                    name="password",
                    type="string",
                    required=False,
                    description="Password for password spraying",
                ),
                ToolParameter(
                    name="passwords_file",
                    type="string",
                    required=False,
                    description="File containing list of passwords",
                ),
                ToolParameter(
                    name="threads",
                    type="string",
                    required=False,
                    default="10",
                    description="Number of concurrent threads",
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
                    description="Additional kerbrute flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="valid_users",
                    type="list[str]",
                    description="Discovered valid usernames",
                ),
                ToolOutputField(
                    name="valid_credentials",
                    type="list[dict]",
                    description="Discovered valid username/password pairs",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full kerbrute output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Kerberos service (port 88) must be accessible on DC",
                    check_type="port_open",
                    parameters={"host": "{dc}", "port": "88"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Enumerates valid AD accounts via Kerberos",
                    effect_type="reveals_data",
                ),
                ToolPostcondition(
                    description="Discovers valid credentials through spraying/brute-force",
                    effect_type="gains_access",
                ),
            ],
            command_template=(
                "kerbrute {mode} --dc {dc} -d {domain} "
                "{users_file} --password '{password}' "
                "--passwords {passwords_file} -t {threads} "
                "-o {output_file} {extra_flags}"
            ),
            timeout=600,
        )
    )


def get_credential_attack_tools() -> list[TypedSecurityTool]:
    """Return all credential attack tools."""
    return [
        hashcat_tool(),
        john_tool(),
        hydra_tool(),
        impacket_collection_tool(),
        kerbrute_tool(),
    ]
