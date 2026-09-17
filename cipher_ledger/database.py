"""SQLite connection, schema and service metadata foundation."""

import sqlite3
from pathlib import Path


def connect(database: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(database), timeout=15, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=15000")
    return connection


def initialize(database: str | Path, initial_version: int | None = None) -> None:
    """Create base schema.

    When ``initial_version`` is given (service startup with record support
    enabled) it also creates the public ``records`` table and seeds the
    persisted active key version the first time records are enabled. On later
    restarts the database value wins and the config seed is ignored.
    """
    Path(database).parent.mkdir(parents=True, exist_ok=True)
    connection = connect(database)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        with connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS service_metadata "
                "(name TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO service_metadata(name, value) VALUES (?, ?)",
                ("service_name", "cipher-ledger"),
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS records ("
                "tenant TEXT NOT NULL, "
                "id TEXT NOT NULL, "
                "key_version INTEGER NOT NULL, "
                "nonce BLOB NOT NULL, "
                "ciphertext BLOB NOT NULL, "
                "wrap_nonce BLOB NOT NULL, "
                "wrapped_key BLOB NOT NULL, "
                "PRIMARY KEY (tenant, id))"
            )
            # Per-tenant append-only verifiable audit log. Sequence numbers
            # restart at 1 for each tenant and never repeat; previous/digest
            # form a per-tenant hash chain.
            connection.execute(
                "CREATE TABLE IF NOT EXISTS audit_events ("
                "tenant TEXT NOT NULL, "
                "sequence INTEGER NOT NULL, "
                "kind TEXT NOT NULL, "
                "record_id TEXT, "
                "key_version INTEGER, "
                "from_version INTEGER, "
                "to_version INTEGER, "
                "rewrapped INTEGER, "
                "previous TEXT NOT NULL, "
                "digest TEXT NOT NULL, "
                "PRIMARY KEY (tenant, sequence))"
            )
            if initial_version is not None:
                connection.execute(
                    "INSERT OR IGNORE INTO service_metadata(name, value) VALUES (?, ?)",
                    ("active_version", str(initial_version)),
                )
    finally:
        connection.close()
