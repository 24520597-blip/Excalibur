"""SQLite-backed state store for penetration testing entities.

Uses Python's built-in ``sqlite3`` module -- no extra dependencies.
The default database lives in-memory (``:memory:``); pass a file path
for persistence across process restarts.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from excalibur.memory.models import (
    CredentialEntity,
    HostEntity,
    ServiceEntity,
    SessionEntity,
    VulnerabilityEntity,
)


class StateStore:
    """SQLite-backed state store for penetration testing entities.

    In-memory by default (``:memory:``), file-backed for persistence.
    All mutations use parameterised queries to prevent SQL injection.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        """Initialise the store and create tables if they do not exist.

        Args:
            db_path: Path to SQLite database file, or ``:memory:``.
        """
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _create_tables(self) -> None:
        """Create all entity tables (idempotent)."""
        cur = self._conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS hosts (
                id            TEXT PRIMARY KEY,
                ip_address    TEXT NOT NULL,
                hostname      TEXT,
                os_fingerprint TEXT,
                discovered_at TEXT NOT NULL,
                discovery_node_id TEXT
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS services (
                id            TEXT PRIMARY KEY,
                host_id       TEXT NOT NULL,
                port          INTEGER NOT NULL,
                protocol      TEXT NOT NULL DEFAULT 'tcp',
                service_name  TEXT,
                version       TEXT,
                discovered_at TEXT NOT NULL,
                discovery_node_id TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id              TEXT PRIMARY KEY,
                username        TEXT NOT NULL,
                credential_type TEXT NOT NULL DEFAULT 'password',
                credential_value TEXT NOT NULL DEFAULT '',
                domain          TEXT,
                valid_for       TEXT NOT NULL DEFAULT '[]',
                discovered_at   TEXT NOT NULL,
                discovery_node_id TEXT
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id              TEXT PRIMARY KEY,
                host_id         TEXT NOT NULL,
                session_type    TEXT NOT NULL DEFAULT 'shell',
                privilege_level TEXT NOT NULL DEFAULT 'user',
                credential_id   TEXT,
                active          INTEGER NOT NULL DEFAULT 1,
                established_at  TEXT NOT NULL,
                node_id         TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id                  TEXT PRIMARY KEY,
                host_id             TEXT NOT NULL,
                service_id          TEXT,
                cve_id              TEXT,
                description         TEXT NOT NULL DEFAULT '',
                exploitation_status TEXT NOT NULL DEFAULT 'discovered',
                discovered_at       TEXT NOT NULL,
                discovery_node_id   TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts(id),
                FOREIGN KEY (service_id) REFERENCES services(id)
            )
            """
        )

        self._conn.commit()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dt_to_str(dt: datetime) -> str:
        """Serialise a datetime to ISO-8601 string."""
        return dt.isoformat()

    @staticmethod
    def _str_to_dt(s: str) -> datetime:
        """Deserialise an ISO-8601 string to datetime."""
        return datetime.fromisoformat(s)

    # ------------------------------------------------------------------
    # Host CRUD
    # ------------------------------------------------------------------

    def add_host(self, host: HostEntity) -> str:
        """Insert a host entity.

        Args:
            host: The host to insert.

        Returns:
            The host id.
        """
        self._conn.execute(
            """
            INSERT INTO hosts (id, ip_address, hostname, os_fingerprint,
                               discovered_at, discovery_node_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                host.id,
                host.ip_address,
                host.hostname,
                host.os_fingerprint,
                self._dt_to_str(host.discovered_at),
                host.discovery_node_id,
            ),
        )
        self._conn.commit()
        return host.id

    def get_host(self, host_id: str) -> HostEntity | None:
        """Retrieve a host by id.

        Args:
            host_id: Primary key.

        Returns:
            The entity or ``None``.
        """
        row = self._conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        if row is None:
            return None
        return HostEntity(
            id=row["id"],
            ip_address=row["ip_address"],
            hostname=row["hostname"],
            os_fingerprint=row["os_fingerprint"],
            discovered_at=self._str_to_dt(row["discovered_at"]),
            discovery_node_id=row["discovery_node_id"],
        )

    def get_hosts(self) -> list[HostEntity]:
        """Return all hosts."""
        rows = self._conn.execute("SELECT * FROM hosts").fetchall()
        return [
            HostEntity(
                id=r["id"],
                ip_address=r["ip_address"],
                hostname=r["hostname"],
                os_fingerprint=r["os_fingerprint"],
                discovered_at=self._str_to_dt(r["discovered_at"]),
                discovery_node_id=r["discovery_node_id"],
            )
            for r in rows
        ]

    def get_host_by_ip(self, ip: str) -> HostEntity | None:
        """Retrieve a host by IP address.

        Args:
            ip: IP address to search for.

        Returns:
            The first matching entity or ``None``.
        """
        row = self._conn.execute("SELECT * FROM hosts WHERE ip_address = ?", (ip,)).fetchone()
        if row is None:
            return None
        return HostEntity(
            id=row["id"],
            ip_address=row["ip_address"],
            hostname=row["hostname"],
            os_fingerprint=row["os_fingerprint"],
            discovered_at=self._str_to_dt(row["discovered_at"]),
            discovery_node_id=row["discovery_node_id"],
        )

    # ------------------------------------------------------------------
    # Service CRUD
    # ------------------------------------------------------------------

    def add_service(self, service: ServiceEntity) -> str:
        """Insert a service entity.

        Args:
            service: The service to insert.

        Returns:
            The service id.
        """
        self._conn.execute(
            """
            INSERT INTO services (id, host_id, port, protocol, service_name,
                                  version, discovered_at, discovery_node_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                service.id,
                service.host_id,
                service.port,
                service.protocol,
                service.service_name,
                service.version,
                self._dt_to_str(service.discovered_at),
                service.discovery_node_id,
            ),
        )
        self._conn.commit()
        return service.id

    def get_service(self, service_id: str) -> ServiceEntity | None:
        """Retrieve a service by id.

        Args:
            service_id: Primary key.

        Returns:
            The entity or ``None``.
        """
        row = self._conn.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()
        if row is None:
            return None
        return ServiceEntity(
            id=row["id"],
            host_id=row["host_id"],
            port=row["port"],
            protocol=row["protocol"],
            service_name=row["service_name"],
            version=row["version"],
            discovered_at=self._str_to_dt(row["discovered_at"]),
            discovery_node_id=row["discovery_node_id"],
        )

    def get_services_for_host(self, host_id: str) -> list[ServiceEntity]:
        """Return all services associated with a given host.

        Args:
            host_id: Host foreign key.

        Returns:
            List of service entities.
        """
        rows = self._conn.execute("SELECT * FROM services WHERE host_id = ?", (host_id,)).fetchall()
        return [
            ServiceEntity(
                id=r["id"],
                host_id=r["host_id"],
                port=r["port"],
                protocol=r["protocol"],
                service_name=r["service_name"],
                version=r["version"],
                discovered_at=self._str_to_dt(r["discovered_at"]),
                discovery_node_id=r["discovery_node_id"],
            )
            for r in rows
        ]

    def get_services_by_port(self, port: int) -> list[ServiceEntity]:
        """Return all services on a given port across all hosts.

        Args:
            port: Port number to search for.

        Returns:
            List of service entities.
        """
        rows = self._conn.execute("SELECT * FROM services WHERE port = ?", (port,)).fetchall()
        return [
            ServiceEntity(
                id=r["id"],
                host_id=r["host_id"],
                port=r["port"],
                protocol=r["protocol"],
                service_name=r["service_name"],
                version=r["version"],
                discovered_at=self._str_to_dt(r["discovered_at"]),
                discovery_node_id=r["discovery_node_id"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Credential CRUD
    # ------------------------------------------------------------------

    def add_credential(self, credential: CredentialEntity) -> str:
        """Insert a credential entity.

        Args:
            credential: The credential to insert.

        Returns:
            The credential id.
        """
        self._conn.execute(
            """
            INSERT INTO credentials (id, username, credential_type,
                                     credential_value, domain, valid_for,
                                     discovered_at, discovery_node_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                credential.id,
                credential.username,
                credential.credential_type,
                credential.credential_value,
                credential.domain,
                json.dumps(credential.valid_for),
                self._dt_to_str(credential.discovered_at),
                credential.discovery_node_id,
            ),
        )
        self._conn.commit()
        return credential.id

    def get_credential(self, cred_id: str) -> CredentialEntity | None:
        """Retrieve a credential by id.

        Args:
            cred_id: Primary key.

        Returns:
            The entity or ``None``.
        """
        row = self._conn.execute("SELECT * FROM credentials WHERE id = ?", (cred_id,)).fetchone()
        if row is None:
            return None
        return CredentialEntity(
            id=row["id"],
            username=row["username"],
            credential_type=row["credential_type"],
            credential_value=row["credential_value"],
            domain=row["domain"],
            valid_for=json.loads(row["valid_for"]),
            discovered_at=self._str_to_dt(row["discovered_at"]),
            discovery_node_id=row["discovery_node_id"],
        )

    def get_credentials(self) -> list[CredentialEntity]:
        """Return all stored credentials."""
        rows = self._conn.execute("SELECT * FROM credentials").fetchall()
        return [
            CredentialEntity(
                id=r["id"],
                username=r["username"],
                credential_type=r["credential_type"],
                credential_value=r["credential_value"],
                domain=r["domain"],
                valid_for=json.loads(r["valid_for"]),
                discovered_at=self._str_to_dt(r["discovered_at"]),
                discovery_node_id=r["discovery_node_id"],
            )
            for r in rows
        ]

    def get_credentials_for_host(self, host_id: str) -> list[CredentialEntity]:
        """Return credentials that are valid for a specific host.

        This performs a JSON-contains check against the ``valid_for`` list.

        Args:
            host_id: Host id to match.

        Returns:
            List of matching credential entities.
        """
        all_creds = self.get_credentials()
        return [c for c in all_creds if host_id in c.valid_for]

    # ------------------------------------------------------------------
    # Session CRUD
    # ------------------------------------------------------------------

    def add_session(self, session: SessionEntity) -> str:
        """Insert a session entity.

        Args:
            session: The session to insert.

        Returns:
            The session id.
        """
        self._conn.execute(
            """
            INSERT INTO sessions (id, host_id, session_type, privilege_level,
                                  credential_id, active, established_at, node_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session.id,
                session.host_id,
                session.session_type,
                session.privilege_level,
                session.credential_id,
                1 if session.active else 0,
                self._dt_to_str(session.established_at),
                session.node_id,
            ),
        )
        self._conn.commit()
        return session.id

    def get_session(self, session_id: str) -> SessionEntity | None:
        """Retrieve a session by id.

        Args:
            session_id: Primary key.

        Returns:
            The entity or ``None``.
        """
        row = self._conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if row is None:
            return None
        return SessionEntity(
            id=row["id"],
            host_id=row["host_id"],
            session_type=row["session_type"],
            privilege_level=row["privilege_level"],
            credential_id=row["credential_id"],
            active=bool(row["active"]),
            established_at=self._str_to_dt(row["established_at"]),
            node_id=row["node_id"],
        )

    def get_active_sessions(self) -> list[SessionEntity]:
        """Return all currently active sessions."""
        rows = self._conn.execute("SELECT * FROM sessions WHERE active = 1").fetchall()
        return [
            SessionEntity(
                id=r["id"],
                host_id=r["host_id"],
                session_type=r["session_type"],
                privilege_level=r["privilege_level"],
                credential_id=r["credential_id"],
                active=True,
                established_at=self._str_to_dt(r["established_at"]),
                node_id=r["node_id"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Vulnerability CRUD
    # ------------------------------------------------------------------

    def add_vulnerability(self, vuln: VulnerabilityEntity) -> str:
        """Insert a vulnerability entity.

        Args:
            vuln: The vulnerability to insert.

        Returns:
            The vulnerability id.
        """
        self._conn.execute(
            """
            INSERT INTO vulnerabilities (id, host_id, service_id, cve_id,
                                         description, exploitation_status,
                                         discovered_at, discovery_node_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                vuln.id,
                vuln.host_id,
                vuln.service_id,
                vuln.cve_id,
                vuln.description,
                vuln.exploitation_status,
                self._dt_to_str(vuln.discovered_at),
                vuln.discovery_node_id,
            ),
        )
        self._conn.commit()
        return vuln.id

    def get_vulnerability(self, vuln_id: str) -> VulnerabilityEntity | None:
        """Retrieve a vulnerability by id.

        Args:
            vuln_id: Primary key.

        Returns:
            The entity or ``None``.
        """
        row = self._conn.execute(
            "SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,)
        ).fetchone()
        if row is None:
            return None
        return VulnerabilityEntity(
            id=row["id"],
            host_id=row["host_id"],
            service_id=row["service_id"],
            cve_id=row["cve_id"],
            description=row["description"],
            exploitation_status=row["exploitation_status"],
            discovered_at=self._str_to_dt(row["discovered_at"]),
            discovery_node_id=row["discovery_node_id"],
        )

    def get_vulnerabilities_for_host(self, host_id: str) -> list[VulnerabilityEntity]:
        """Return all vulnerabilities for a given host.

        Args:
            host_id: Host foreign key.

        Returns:
            List of vulnerability entities.
        """
        rows = self._conn.execute(
            "SELECT * FROM vulnerabilities WHERE host_id = ?", (host_id,)
        ).fetchall()
        return [
            VulnerabilityEntity(
                id=r["id"],
                host_id=r["host_id"],
                service_id=r["service_id"],
                cve_id=r["cve_id"],
                description=r["description"],
                exploitation_status=r["exploitation_status"],
                discovered_at=self._str_to_dt(r["discovered_at"]),
                discovery_node_id=r["discovery_node_id"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    # ------------------------------------------------------------------
    # Serialisation (for session persistence)
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialise the entire state to a plain dict.

        Useful for embedding inside a JSON session file.

        Returns:
            Dictionary with lists of serialised entities keyed by table name.
        """
        return {
            "hosts": [h.model_dump(mode="json") for h in self.get_hosts()],
            "services": [s.model_dump(mode="json") for s in self._all_services()],
            "credentials": [c.model_dump(mode="json") for c in self.get_credentials()],
            "sessions": [s.model_dump(mode="json") for s in self._all_sessions()],
            "vulnerabilities": [v.model_dump(mode="json") for v in self._all_vulnerabilities()],
        }

    def _all_services(self) -> list[ServiceEntity]:
        """Return every service across all hosts."""
        rows = self._conn.execute("SELECT * FROM services").fetchall()
        return [
            ServiceEntity(
                id=r["id"],
                host_id=r["host_id"],
                port=r["port"],
                protocol=r["protocol"],
                service_name=r["service_name"],
                version=r["version"],
                discovered_at=self._str_to_dt(r["discovered_at"]),
                discovery_node_id=r["discovery_node_id"],
            )
            for r in rows
        ]

    def _all_sessions(self) -> list[SessionEntity]:
        """Return every session (active and inactive)."""
        rows = self._conn.execute("SELECT * FROM sessions").fetchall()
        return [
            SessionEntity(
                id=r["id"],
                host_id=r["host_id"],
                session_type=r["session_type"],
                privilege_level=r["privilege_level"],
                credential_id=r["credential_id"],
                active=bool(r["active"]),
                established_at=self._str_to_dt(r["established_at"]),
                node_id=r["node_id"],
            )
            for r in rows
        ]

    def _all_vulnerabilities(self) -> list[VulnerabilityEntity]:
        """Return every vulnerability."""
        rows = self._conn.execute("SELECT * FROM vulnerabilities").fetchall()
        return [
            VulnerabilityEntity(
                id=r["id"],
                host_id=r["host_id"],
                service_id=r["service_id"],
                cve_id=r["cve_id"],
                description=r["description"],
                exploitation_status=r["exploitation_status"],
                discovered_at=self._str_to_dt(r["discovered_at"]),
                discovery_node_id=r["discovery_node_id"],
            )
            for r in rows
        ]

    @classmethod
    def from_dict(cls, data: dict[str, Any], db_path: str = ":memory:") -> StateStore:
        """Restore a ``StateStore`` from a previously serialised dict.

        Args:
            data: Dictionary produced by :meth:`to_dict`.
            db_path: Database path for the new store.

        Returns:
            A fully populated ``StateStore``.
        """
        store = cls(db_path=db_path)

        for raw in data.get("hosts", []):
            store.add_host(HostEntity.model_validate(raw))

        for raw in data.get("services", []):
            store.add_service(ServiceEntity.model_validate(raw))

        for raw in data.get("credentials", []):
            store.add_credential(CredentialEntity.model_validate(raw))

        for raw in data.get("sessions", []):
            store.add_session(SessionEntity.model_validate(raw))

        for raw in data.get("vulnerabilities", []):
            store.add_vulnerability(VulnerabilityEntity.model_validate(raw))

        return store
