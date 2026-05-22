"""Tests for the SQLite-backed state store CRUD operations.

Unit tests covering add/get for hosts, services, credentials,
sessions, and vulnerabilities, plus to_dict/from_dict serialisation.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from excalibur.memory.models import (
    CredentialEntity,
    HostEntity,
    ServiceEntity,
    SessionEntity,
    VulnerabilityEntity,
)
from excalibur.memory.state_store import StateStore


@pytest.fixture
def store() -> StateStore:
    """Create an in-memory StateStore for each test."""
    s = StateStore(db_path=":memory:")
    yield s
    s.close()


@pytest.mark.unit
class TestHostCRUD:
    """Tests for host add and get operations."""

    def test_add_and_get_host(self, store: StateStore) -> None:
        """Added host is retrievable by its ID."""
        host = HostEntity(
            id="h1",
            ip_address="10.10.10.1",
            hostname="target.htb",
            os_fingerprint="Linux",
        )
        returned_id = store.add_host(host)
        assert returned_id == "h1"

        fetched = store.get_host("h1")
        assert fetched is not None
        assert fetched.ip_address == "10.10.10.1"
        assert fetched.hostname == "target.htb"
        assert fetched.os_fingerprint == "Linux"

    def test_get_host_returns_none_for_missing(self, store: StateStore) -> None:
        """get_host returns None when ID does not exist."""
        assert store.get_host("nonexistent") is None

    def test_get_hosts_returns_all(self, store: StateStore) -> None:
        """get_hosts returns every host in the store."""
        for i in range(3):
            store.add_host(HostEntity(id=f"h{i}", ip_address=f"10.0.0.{i}"))
        hosts = store.get_hosts()
        assert len(hosts) == 3

    def test_get_host_by_ip(self, store: StateStore) -> None:
        """get_host_by_ip finds host by IP address."""
        store.add_host(HostEntity(id="h1", ip_address="192.168.1.10"))
        found = store.get_host_by_ip("192.168.1.10")
        assert found is not None
        assert found.id == "h1"


@pytest.mark.unit
class TestServiceCRUD:
    """Tests for service add and get operations."""

    def test_add_and_get_services_for_host(self, store: StateStore) -> None:
        """Services are correctly associated with their host."""
        store.add_host(HostEntity(id="h1", ip_address="10.10.10.1"))
        svc = ServiceEntity(
            id="s1",
            host_id="h1",
            port=80,
            protocol="tcp",
            service_name="http",
            version="Apache 2.4",
        )
        returned_id = store.add_service(svc)
        assert returned_id == "s1"

        services = store.get_services_for_host("h1")
        assert len(services) == 1
        assert services[0].port == 80
        assert services[0].service_name == "http"
        assert services[0].version == "Apache 2.4"

    def test_get_services_for_host_empty(self, store: StateStore) -> None:
        """No services returns empty list."""
        result = store.get_services_for_host("h_missing")
        assert result == []

    def test_get_services_by_port(self, store: StateStore) -> None:
        """get_services_by_port returns services across hosts."""
        store.add_host(HostEntity(id="h1", ip_address="10.0.0.1"))
        store.add_host(HostEntity(id="h2", ip_address="10.0.0.2"))
        store.add_service(ServiceEntity(id="s1", host_id="h1", port=22))
        store.add_service(ServiceEntity(id="s2", host_id="h2", port=22))
        store.add_service(ServiceEntity(id="s3", host_id="h1", port=80))
        results = store.get_services_by_port(22)
        assert len(results) == 2


@pytest.mark.unit
class TestCredentialCRUD:
    """Tests for credential add and get operations."""

    def test_add_and_get_credential(self, store: StateStore) -> None:
        """Credential is retrievable after insertion."""
        cred = CredentialEntity(
            id="c1",
            username="admin",
            credential_type="password",
            credential_value="P@ssw0rd!",
            valid_for=["h1"],
        )
        returned_id = store.add_credential(cred)
        assert returned_id == "c1"

        fetched = store.get_credential("c1")
        assert fetched is not None
        assert fetched.username == "admin"
        assert fetched.credential_value == "P@ssw0rd!"

    def test_get_credentials_for_host(self, store: StateStore) -> None:
        """Credentials valid for a host are returned correctly."""
        store.add_credential(
            CredentialEntity(
                id="c1",
                username="root",
                valid_for=["h1", "h2"],
            )
        )
        store.add_credential(
            CredentialEntity(
                id="c2",
                username="guest",
                valid_for=["h3"],
            )
        )
        creds = store.get_credentials_for_host("h1")
        assert len(creds) == 1
        assert creds[0].username == "root"

    def test_get_credentials_for_host_empty(self, store: StateStore) -> None:
        """No matching credentials returns empty list."""
        store.add_credential(
            CredentialEntity(
                id="c1",
                username="u",
                valid_for=["other"],
            )
        )
        assert store.get_credentials_for_host("h99") == []


@pytest.mark.unit
class TestSessionCRUD:
    """Tests for session add and get operations."""

    def test_add_and_get_active_sessions(self, store: StateStore) -> None:
        """Active sessions are returned; inactive are excluded."""
        store.add_host(HostEntity(id="h1", ip_address="10.0.0.1"))
        active = SessionEntity(
            id="sess1",
            host_id="h1",
            session_type="shell",
            privilege_level="root",
            active=True,
        )
        inactive = SessionEntity(
            id="sess2",
            host_id="h1",
            session_type="ssh",
            privilege_level="user",
            active=False,
        )
        store.add_session(active)
        store.add_session(inactive)

        active_sessions = store.get_active_sessions()
        assert len(active_sessions) == 1
        assert active_sessions[0].id == "sess1"
        assert active_sessions[0].privilege_level == "root"

    def test_get_session_by_id(self, store: StateStore) -> None:
        """Individual session is retrievable by its ID."""
        store.add_session(SessionEntity(id="s1", host_id="h1", active=True))
        fetched = store.get_session("s1")
        assert fetched is not None
        assert fetched.id == "s1"

    def test_get_session_returns_none(self, store: StateStore) -> None:
        """Missing session returns None."""
        assert store.get_session("nope") is None


@pytest.mark.unit
class TestVulnerabilityCRUD:
    """Tests for vulnerability add and get operations."""

    def test_add_and_get_vulnerabilities_for_host(self, store: StateStore) -> None:
        """Vulnerabilities are associated with the correct host."""
        store.add_host(HostEntity(id="h1", ip_address="10.0.0.1"))
        vuln = VulnerabilityEntity(
            id="v1",
            host_id="h1",
            cve_id="CVE-2024-1234",
            description="SQL Injection in login form",
            exploitation_status="discovered",
        )
        returned_id = store.add_vulnerability(vuln)
        assert returned_id == "v1"

        vulns = store.get_vulnerabilities_for_host("h1")
        assert len(vulns) == 1
        assert vulns[0].cve_id == "CVE-2024-1234"
        assert "SQL Injection" in vulns[0].description

    def test_get_vulnerabilities_for_host_empty(self, store: StateStore) -> None:
        """No vulnerabilities returns empty list."""
        assert store.get_vulnerabilities_for_host("h_none") == []

    def test_get_vulnerability_by_id(self, store: StateStore) -> None:
        """Single vulnerability is retrievable by ID."""
        store.add_vulnerability(
            VulnerabilityEntity(
                id="v1",
                host_id="h1",
                description="XSS",
            )
        )
        fetched = store.get_vulnerability("v1")
        assert fetched is not None
        assert fetched.description == "XSS"


@pytest.mark.unit
class TestSerialization:
    """Tests for to_dict / from_dict round-trip serialisation."""

    def test_empty_store_serializes(self, store: StateStore) -> None:
        """Empty store serialises to dict with empty lists."""
        data = store.to_dict()
        assert isinstance(data, dict)
        assert data["hosts"] == []
        assert data["services"] == []
        assert data["credentials"] == []
        assert data["sessions"] == []
        assert data["vulnerabilities"] == []

    def test_round_trip(self, store: StateStore) -> None:
        """Data survives a to_dict -> from_dict round trip."""
        now = datetime.now()
        store.add_host(
            HostEntity(
                id="h1",
                ip_address="10.0.0.1",
                hostname="box.htb",
                discovered_at=now,
            )
        )
        store.add_service(
            ServiceEntity(
                id="s1",
                host_id="h1",
                port=443,
                service_name="https",
                discovered_at=now,
            )
        )
        store.add_credential(
            CredentialEntity(
                id="c1",
                username="admin",
                credential_value="secret",
                valid_for=["h1"],
                discovered_at=now,
            )
        )
        store.add_session(
            SessionEntity(
                id="se1",
                host_id="h1",
                active=True,
                established_at=now,
            )
        )
        store.add_vulnerability(
            VulnerabilityEntity(
                id="v1",
                host_id="h1",
                description="RCE",
                discovered_at=now,
            )
        )

        data = store.to_dict()

        restored = StateStore.from_dict(data)
        try:
            assert restored.get_host("h1") is not None
            assert restored.get_host("h1").ip_address == "10.0.0.1"
            assert len(restored.get_services_for_host("h1")) == 1
            assert len(restored.get_credentials_for_host("h1")) == 1
            assert len(restored.get_active_sessions()) == 1
            assert len(restored.get_vulnerabilities_for_host("h1")) == 1
        finally:
            restored.close()
