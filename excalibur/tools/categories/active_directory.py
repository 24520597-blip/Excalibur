"""Active Directory tools for Excalibur.

Provides typed interfaces for 8 Active Directory tools:
bloodhound, sharphound, rubeus, mimikatz, powerview,
ldapdomaindump, pingcastle, adrecon.
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


def bloodhound_tool() -> TypedSecurityTool:
    """BloodHound Active Directory relationship mapper."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="bloodhound",
            category=ToolCategory.ACTIVE_DIRECTORY,
            description=(
                "Active Directory reconnaissance tool that uses graph theory to "
                "reveal hidden and unintended relationships within AD environments. "
                "Identifies attack paths to Domain Admin, misconfigurations, "
                "and privilege escalation opportunities."
            ),
            input_schema=[
                ToolParameter(
                    name="collection_method",
                    type="string",
                    required=False,
                    default="All",
                    description="Data collection method",
                    choices=[
                        "All",
                        "DCOnly",
                        "Group",
                        "LocalAdmin",
                        "Session",
                        "Trusts",
                        "ACL",
                        "ObjectProps",
                        "RDP",
                        "DCOM",
                        "PSRemote",
                    ],
                ),
                ToolParameter(
                    name="domain",
                    type="string",
                    required=True,
                    description="Target AD domain name",
                ),
                ToolParameter(
                    name="username",
                    type="string",
                    required=False,
                    description="Domain username for authentication",
                ),
                ToolParameter(
                    name="password",
                    type="string",
                    required=False,
                    description="Domain password for authentication",
                ),
                ToolParameter(
                    name="dc_ip",
                    type="string",
                    required=False,
                    description="Domain Controller IP address",
                ),
                ToolParameter(
                    name="output_dir",
                    type="string",
                    required=False,
                    default="./bloodhound_output",
                    description="Directory to save collected data",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional bloodhound-python flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="json_files",
                    type="list[str]",
                    description="Generated BloodHound JSON data files",
                ),
                ToolOutputField(
                    name="attack_paths",
                    type="list[dict]",
                    description="Identified attack paths to high-value targets",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full bloodhound-python output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Domain controller must be accessible",
                    check_type="port_open",
                    parameters={"host": "{dc_ip}", "port": "389"},
                ),
                ToolPrecondition(
                    description="Valid domain credentials required",
                    check_type="credentials_available",
                    parameters={"domain": "{domain}"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Maps AD relationships and identifies attack paths",
                    effect_type="reveals_data",
                ),
            ],
            command_template=(
                "bloodhound-python -c {collection_method} -d {domain} "
                "-u '{username}' -p '{password}' --dns-tcp -ns {dc_ip} "
                "--output-dir {output_dir} {extra_flags}"
            ),
            timeout=600,
        )
    )


def sharphound_tool() -> TypedSecurityTool:
    """SharpHound Active Directory data collector."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="sharphound",
            category=ToolCategory.ACTIVE_DIRECTORY,
            description=(
                "Official BloodHound data collector for Windows environments. "
                "Runs natively on Windows to collect AD objects, ACLs, sessions, "
                "and group memberships for BloodHound analysis."
            ),
            input_schema=[
                ToolParameter(
                    name="collection_method",
                    type="string",
                    required=False,
                    default="All",
                    description="Data collection method",
                    choices=[
                        "All",
                        "DCOnly",
                        "Group",
                        "LocalAdmin",
                        "Session",
                        "Trusts",
                        "ACL",
                        "ObjectProps",
                        "Default",
                    ],
                ),
                ToolParameter(
                    name="domain",
                    type="string",
                    required=False,
                    description="Target AD domain (auto-detected if omitted)",
                ),
                ToolParameter(
                    name="domain_controller",
                    type="string",
                    required=False,
                    description="Specific domain controller to query",
                ),
                ToolParameter(
                    name="output_dir",
                    type="string",
                    required=False,
                    description="Directory to save output zip file",
                ),
                ToolParameter(
                    name="stealth",
                    type="boolean",
                    required=False,
                    default="false",
                    description="Use stealth collection (single DC, no sessions)",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional SharpHound flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="zip_file",
                    type="string",
                    description="Path to generated BloodHound data zip",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full SharpHound output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Must be running on a domain-joined Windows host",
                    check_type="os_type",
                    parameters={"os": "windows"},
                ),
                ToolPrecondition(
                    description="Must have valid domain authentication context",
                    check_type="credentials_available",
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Collects comprehensive AD data for BloodHound analysis",
                    effect_type="reveals_data",
                ),
            ],
            command_template=(
                "SharpHound.exe -c {collection_method} -d {domain} "
                "--domaincontroller {domain_controller} "
                "--outputdirectory {output_dir} {extra_flags}"
            ),
            timeout=600,
        )
    )


def rubeus_tool() -> TypedSecurityTool:
    """Rubeus Kerberos interaction and abuse tool."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="rubeus",
            category=ToolCategory.ACTIVE_DIRECTORY,
            description=(
                "C# toolset for raw Kerberos interaction and abuse. Supports "
                "ticket requests (TGT/TGS), Kerberoasting, AS-REP roasting, "
                "S4U delegation abuse, ticket extraction, pass-the-ticket, "
                "and overpass-the-hash attacks."
            ),
            input_schema=[
                ToolParameter(
                    name="action",
                    type="string",
                    required=True,
                    description="Rubeus action to perform",
                    choices=[
                        "kerberoast",
                        "asreproast",
                        "harvest",
                        "tgtdeleg",
                        "s4u",
                        "ptt",
                        "dump",
                        "monitor",
                        "triage",
                        "hash",
                        "renew",
                        "brute",
                    ],
                ),
                ToolParameter(
                    name="domain",
                    type="string",
                    required=False,
                    description="Target domain",
                ),
                ToolParameter(
                    name="username",
                    type="string",
                    required=False,
                    description="Target username (for specific attacks)",
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
                    description="NTLM/AES hash for overpass-the-hash",
                ),
                ToolParameter(
                    name="ticket",
                    type="string",
                    required=False,
                    description="Base64-encoded Kerberos ticket",
                ),
                ToolParameter(
                    name="dc",
                    type="string",
                    required=False,
                    description="Domain Controller address",
                ),
                ToolParameter(
                    name="output_format",
                    type="string",
                    required=False,
                    default="hashcat",
                    description="Output format for hashes",
                    choices=["hashcat", "john"],
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional Rubeus flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="hashes",
                    type="list[str]",
                    description="Extracted Kerberos hashes",
                ),
                ToolOutputField(
                    name="tickets",
                    type="list[dict]",
                    description="Extracted or forged Kerberos tickets",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full Rubeus output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Must be on a domain-joined Windows host or have DC access",
                    check_type="os_type",
                    parameters={"os": "windows"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Extracts Kerberos tickets and hashes for cracking",
                    effect_type="reveals_data",
                ),
                ToolPostcondition(
                    description="May enable lateral movement via ticket manipulation",
                    effect_type="gains_access",
                ),
            ],
            command_template=(
                "Rubeus.exe {action} /domain:{domain} /user:{username} "
                "/password:{password} /rc4:{hash} /ticket:{ticket} "
                "/dc:{dc} /format:{output_format} {extra_flags}"
            ),
            timeout=300,
        )
    )


def mimikatz_tool() -> TypedSecurityTool:
    """Mimikatz credential extraction tool."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="mimikatz",
            category=ToolCategory.ACTIVE_DIRECTORY,
            description=(
                "Windows credential extraction and manipulation tool. Extracts "
                "plaintext passwords, hashes, PIN codes, and Kerberos tickets "
                "from memory. Also supports pass-the-hash, pass-the-ticket, "
                "Golden/Silver ticket forging, and DCSync attacks."
            ),
            input_schema=[
                ToolParameter(
                    name="command",
                    type="string",
                    required=True,
                    description="Mimikatz command to execute",
                    choices=[
                        "sekurlsa::logonpasswords",
                        "sekurlsa::wdigest",
                        "sekurlsa::kerberos",
                        "sekurlsa::msv",
                        "lsadump::sam",
                        "lsadump::dcsync",
                        "lsadump::lsa",
                        "kerberos::golden",
                        "kerberos::silver",
                        "kerberos::ptt",
                        "token::elevate",
                        "vault::cred",
                    ],
                ),
                ToolParameter(
                    name="target_user",
                    type="string",
                    required=False,
                    description="Target user for DCSync or specific extraction",
                ),
                ToolParameter(
                    name="domain",
                    type="string",
                    required=False,
                    description="Target domain for domain-specific operations",
                ),
                ToolParameter(
                    name="dc_ip",
                    type="string",
                    required=False,
                    description="Domain Controller IP for DCSync",
                ),
                ToolParameter(
                    name="sid",
                    type="string",
                    required=False,
                    description="Domain SID for ticket forging",
                ),
                ToolParameter(
                    name="krbtgt_hash",
                    type="string",
                    required=False,
                    description="krbtgt NTLM hash for Golden Ticket",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional mimikatz parameters",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="credentials",
                    type="list[dict]",
                    description="Extracted credentials (usernames, passwords, hashes)",
                ),
                ToolOutputField(
                    name="tickets",
                    type="list[dict]",
                    description="Extracted or forged Kerberos tickets",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full mimikatz output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Requires SYSTEM or Administrator privileges on Windows",
                    check_type="elevated_privileges",
                    parameters={"os": "windows"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Extracts credentials from Windows memory",
                    effect_type="reveals_data",
                ),
                ToolPostcondition(
                    description="Enables lateral movement via credential reuse",
                    effect_type="gains_access",
                ),
            ],
            command_template=(
                'mimikatz.exe "privilege::debug" "{command} '
                "/user:{target_user} /domain:{domain} "
                "/dc:{dc_ip} /sid:{sid} /rc4:{krbtgt_hash} "
                '{extra_flags}" "exit"'
            ),
            timeout=120,
        )
    )


def powerview_tool() -> TypedSecurityTool:
    """PowerView Active Directory enumeration tool."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="powerview",
            category=ToolCategory.ACTIVE_DIRECTORY,
            description=(
                "PowerShell tool for Active Directory enumeration and exploitation. "
                "Enumerates domain users, groups, computers, GPOs, ACLs, trusts, "
                "and shares. Identifies privilege escalation paths and "
                "misconfigurations."
            ),
            input_schema=[
                ToolParameter(
                    name="command",
                    type="string",
                    required=True,
                    description="PowerView cmdlet to execute",
                    choices=[
                        "Get-DomainUser",
                        "Get-DomainGroup",
                        "Get-DomainComputer",
                        "Get-DomainGPO",
                        "Get-DomainOU",
                        "Get-DomainTrust",
                        "Get-DomainACL",
                        "Find-DomainShare",
                        "Find-LocalAdminAccess",
                        "Get-NetSession",
                        "Get-DomainSID",
                        "Get-DomainPolicy",
                    ],
                ),
                ToolParameter(
                    name="identity",
                    type="string",
                    required=False,
                    description="Specific identity to query (username, group, etc.)",
                ),
                ToolParameter(
                    name="domain",
                    type="string",
                    required=False,
                    description="Target domain to query",
                ),
                ToolParameter(
                    name="server",
                    type="string",
                    required=False,
                    description="Specific DC to query",
                ),
                ToolParameter(
                    name="properties",
                    type="string",
                    required=False,
                    description="Specific properties to return",
                ),
                ToolParameter(
                    name="filter",
                    type="string",
                    required=False,
                    description="LDAP filter to apply",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional PowerView parameters",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="results",
                    type="list[dict]",
                    description="Query results with requested properties",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full PowerShell output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Must have domain authentication context",
                    check_type="credentials_available",
                ),
                ToolPrecondition(
                    description="PowerShell execution policy must allow script execution",
                    check_type="os_type",
                    parameters={"os": "windows"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Enumerates AD objects, ACLs, and relationships",
                    effect_type="reveals_data",
                ),
            ],
            command_template=(
                'powershell -ep bypass -c "Import-Module PowerView.ps1; '
                "{command} -Identity '{identity}' -Domain '{domain}' "
                "-Server '{server}' -Properties '{properties}' "
                "-LDAPFilter '{filter}' {extra_flags}\""
            ),
            timeout=300,
        )
    )


def ldapdomaindump_tool() -> TypedSecurityTool:
    """LDAPDomainDump Active Directory LDAP enumeration tool."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="ldapdomaindump",
            category=ToolCategory.ACTIVE_DIRECTORY,
            description=(
                "Active Directory information dumper via LDAP. Collects and "
                "parses domain information including users, groups, computers, "
                "policies, and trusts. Generates HTML, JSON, and grep-friendly "
                "output formats."
            ),
            input_schema=[
                ToolParameter(
                    name="target",
                    type="string",
                    required=True,
                    description="Domain Controller IP or hostname",
                ),
                ToolParameter(
                    name="username",
                    type="string",
                    required=True,
                    description="Domain username (DOMAIN\\user or user@domain)",
                ),
                ToolParameter(
                    name="password",
                    type="string",
                    required=False,
                    description="Domain password",
                ),
                ToolParameter(
                    name="auth_method",
                    type="string",
                    required=False,
                    default="simple",
                    description="Authentication method",
                    choices=["simple", "ntlm"],
                ),
                ToolParameter(
                    name="output_dir",
                    type="string",
                    required=False,
                    default="./ldap_dump",
                    description="Output directory for dump files",
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional ldapdomaindump flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="users",
                    type="list[dict]",
                    description="Enumerated domain users",
                ),
                ToolOutputField(
                    name="groups",
                    type="list[dict]",
                    description="Enumerated domain groups",
                ),
                ToolOutputField(
                    name="computers",
                    type="list[dict]",
                    description="Enumerated domain computers",
                ),
                ToolOutputField(
                    name="output_files",
                    type="list[str]",
                    description="Generated output file paths",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full ldapdomaindump output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="LDAP service (port 389/636) must be accessible on DC",
                    check_type="port_open",
                    parameters={"host": "{target}", "port": "389"},
                ),
                ToolPrecondition(
                    description="Valid domain credentials required",
                    check_type="credentials_available",
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Dumps comprehensive AD information via LDAP",
                    effect_type="reveals_data",
                ),
            ],
            command_template=(
                "ldapdomaindump -u '{username}' -p '{password}' "
                "-o {output_dir} {extra_flags} ldap://{target}"
            ),
            timeout=300,
        )
    )


def pingcastle_tool() -> TypedSecurityTool:
    """PingCastle Active Directory security assessment tool."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="pingcastle",
            category=ToolCategory.ACTIVE_DIRECTORY,
            description=(
                "Active Directory security assessment tool. Generates a risk "
                "score and identifies security weaknesses in AD configurations, "
                "trust relationships, group policies, and user account settings. "
                "Produces detailed HTML reports."
            ),
            input_schema=[
                ToolParameter(
                    name="mode",
                    type="string",
                    required=False,
                    default="healthcheck",
                    description="Assessment mode to run",
                    choices=[
                        "healthcheck",
                        "conso",
                        "carto",
                        "scanner",
                    ],
                ),
                ToolParameter(
                    name="server",
                    type="string",
                    required=False,
                    description="Domain Controller to query",
                ),
                ToolParameter(
                    name="domain",
                    type="string",
                    required=False,
                    description="Target domain (auto-detected if omitted)",
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
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional PingCastle flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="risk_score",
                    type="int",
                    description="Overall AD risk score (0-100)",
                ),
                ToolOutputField(
                    name="findings",
                    type="list[dict]",
                    description="Security findings with severity levels",
                ),
                ToolOutputField(
                    name="report_path",
                    type="string",
                    description="Path to generated HTML report",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full PingCastle output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Domain controller must be accessible",
                    check_type="port_open",
                    parameters={"host": "{server}", "port": "389"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Generates AD security health assessment report",
                    effect_type="reveals_data",
                ),
            ],
            command_template=(
                "PingCastle.exe --{mode} --server {server} "
                "--user '{username}' --password '{password}' {extra_flags}"
            ),
            timeout=600,
        )
    )


def adrecon_tool() -> TypedSecurityTool:
    """ADRecon Active Directory reconnaissance tool."""
    return TypedSecurityTool(
        interface=TypedToolInterface(
            name="adrecon",
            category=ToolCategory.ACTIVE_DIRECTORY,
            description=(
                "Active Directory reconnaissance framework that generates "
                "comprehensive Excel/CSV reports. Collects information about "
                "the AD forest, domain, trusts, sites, subnets, password "
                "policies, GPOs, users, groups, computers, and more."
            ),
            input_schema=[
                ToolParameter(
                    name="domain_controller",
                    type="string",
                    required=False,
                    description="Domain Controller to query",
                ),
                ToolParameter(
                    name="domain",
                    type="string",
                    required=False,
                    description="Target AD domain",
                ),
                ToolParameter(
                    name="username",
                    type="string",
                    required=False,
                    description="Domain username for authentication",
                ),
                ToolParameter(
                    name="password",
                    type="string",
                    required=False,
                    description="Domain password for authentication",
                ),
                ToolParameter(
                    name="collect",
                    type="string",
                    required=False,
                    default="Default",
                    description="Data to collect (comma-separated modules)",
                    choices=[
                        "Default",
                        "DomainPolicy",
                        "Users",
                        "Groups",
                        "Computers",
                        "GPO",
                        "OU",
                        "ACL",
                        "Trusts",
                        "All",
                    ],
                ),
                ToolParameter(
                    name="output_dir",
                    type="string",
                    required=False,
                    default="./adrecon_output",
                    description="Directory to save output reports",
                ),
                ToolParameter(
                    name="output_type",
                    type="string",
                    required=False,
                    default="CSV",
                    description="Output format",
                    choices=["CSV", "Excel", "HTML"],
                ),
                ToolParameter(
                    name="extra_flags",
                    type="string",
                    required=False,
                    default="",
                    description="Additional ADRecon flags",
                ),
            ],
            output_schema=[
                ToolOutputField(
                    name="output_files",
                    type="list[str]",
                    description="Generated report file paths",
                ),
                ToolOutputField(
                    name="domain_info",
                    type="dict",
                    description="Collected domain information summary",
                ),
                ToolOutputField(
                    name="raw_output",
                    type="string",
                    description="Full ADRecon output",
                ),
            ],
            preconditions=[
                ToolPrecondition(
                    description="Domain controller must be accessible",
                    check_type="port_open",
                    parameters={"host": "{domain_controller}", "port": "389"},
                ),
                ToolPrecondition(
                    description="PowerShell with AD module or LDAP access required",
                    check_type="tool_installed",
                    parameters={"tool": "powershell"},
                ),
            ],
            postconditions=[
                ToolPostcondition(
                    description="Generates comprehensive AD reconnaissance reports",
                    effect_type="reveals_data",
                ),
            ],
            command_template=(
                'powershell -ep bypass -c "Import-Module ADRecon.ps1; '
                "Invoke-ADRecon -DomainController '{domain_controller}' "
                "-Domain '{domain}' -Credential (New-Object "
                "PSCredential('{username}',(ConvertTo-SecureString "
                "'{password}' -AsPlainText -Force))) "
                "-Collect {collect} -OutputDir {output_dir} "
                '-OutputType {output_type} {extra_flags}"'
            ),
            timeout=600,
        )
    )


def get_active_directory_tools() -> list[TypedSecurityTool]:
    """Return all Active Directory tools."""
    return [
        bloodhound_tool(),
        sharphound_tool(),
        rubeus_tool(),
        mimikatz_tool(),
        powerview_tool(),
        ldapdomaindump_tool(),
        pingcastle_tool(),
        adrecon_tool(),
    ]
