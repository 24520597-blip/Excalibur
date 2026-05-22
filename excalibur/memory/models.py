"""Pydantic entity models for the penetration testing state store.

Defines five core entity types that represent the structured knowledge
accumulated during a penetration test: hosts, services, credentials,
sessions, and vulnerabilities.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class HostEntity(BaseModel):
    """A discovered network host."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    ip_address: str
    hostname: str | None = None
    os_fingerprint: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.now)
    discovery_node_id: str | None = None


class ServiceEntity(BaseModel):
    """A network service running on a host."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    host_id: str
    port: int
    protocol: str = "tcp"
    service_name: str | None = None
    version: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.now)
    discovery_node_id: str | None = None


class CredentialEntity(BaseModel):
    """A credential (password, hash, key, or token) discovered during testing."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    username: str
    credential_type: str = "password"  # password, hash, key, token
    credential_value: str = ""
    domain: str | None = None
    valid_for: list[str] = Field(default_factory=list)  # host_ids
    discovered_at: datetime = Field(default_factory=datetime.now)
    discovery_node_id: str | None = None


class SessionEntity(BaseModel):
    """An active or historical interactive session on a host."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    host_id: str
    session_type: str = "shell"  # shell, meterpreter, ssh, rdp, winrm
    privilege_level: str = "user"  # user, admin, root, system
    credential_id: str | None = None
    active: bool = True
    established_at: datetime = Field(default_factory=datetime.now)
    node_id: str | None = None


class VulnerabilityEntity(BaseModel):
    """A vulnerability discovered on a host/service."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    host_id: str
    service_id: str | None = None
    cve_id: str | None = None
    description: str = ""
    exploitation_status: str = "discovered"  # discovered, attempted, exploited, failed
    discovered_at: datetime = Field(default_factory=datetime.now)
    discovery_node_id: str | None = None
