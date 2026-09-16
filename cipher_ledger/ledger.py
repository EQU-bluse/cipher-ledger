"""Tenant-scoped record storage with envelope encryption and key rotation.

All operations take one process-wide re-entrant lock so the results of
concurrent creates, reads and rotations are equivalent to some total serial
ordering. Rotation verifies every old envelope first and only then performs a
single transactional write, so a damaged envelope or a storage failure leaves
the active version and all records exactly as they were before the request.
"""

import sqlite3
import threading

from . import envelope
from .config import Config
from .database import connect, initialize

# Extended SQLite result codes that specifically mean a row with the same
# PRIMARY KEY / UNIQUE value already exists. Only these map to 409 conflict;
# every other write failure (trigger RAISE(ABORT), NOT NULL, CHECK, I/O, ...)
# maps to 503 storage_error. sqlite3 exposes extended codes by default.
_UNIQUE_VIOLATION_CODES = frozenset(
    getattr(sqlite3, name, fallback)
    for name, fallback in (
        ("SQLITE_CONSTRAINT_PRIMARYKEY", 1555),
        ("SQLITE_CONSTRAINT_UNIQUE", 2067),
    )
)


class LedgerError(Exception):
    """Application-level error mapped to an HTTP status and code."""

    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


def conflict() -> LedgerError:
    return LedgerError(409, "conflict")


def not_found() -> LedgerError:
    return LedgerError(404, "not_found")


def integrity() -> LedgerError:
    return LedgerError(422, "integrity_error")


def storage() -> LedgerError:
    return LedgerError(503, "storage_error")


class Ledger:
    def __init__(self, config: Config):
        initialize(config.database, config.active_version)
        self._keys = dict(config.keys)
        self._connection = connect(config.database)
        self._lock = threading.RLock()
        try:
            row = self._connection.execute(
                "SELECT value FROM service_metadata WHERE name='active_version'"
            ).fetchone()
            active = int(row[0])
        except (TypeError, ValueError, sqlite3.Error) as exc:
            raise ValueError("Invalid persisted active version") from exc
        if active not in self._keys:
            raise ValueError("Invalid keyring configuration")
        self._active_version = active

    @property
    def active_version(self) -> int:
        with self._lock:
            return self._active_version

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    # -- records -----------------------------------------------------------

    def create(self, tenant: str, record_id: str, plaintext: str) -> int:
        """Create a record. Returns the key version used. Duplicate -> 409."""
        with self._lock:
            version = self._active_version
            sealed = envelope.seal(self._keys, version, tenant, record_id, plaintext)
            try:
                with self._connection:
                    self._connection.execute(
                        "INSERT INTO records "
                        "(tenant, id, key_version, nonce, ciphertext, wrap_nonce, wrapped_key) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            tenant,
                            record_id,
                            sealed["key_version"],
                            sealed["nonce"],
                            sealed["ciphertext"],
                            sealed["wrap_nonce"],
                            sealed["wrapped_key"],
                        ),
                    )
            except sqlite3.IntegrityError as exc:
                # Only the (tenant, id) PRIMARY KEY / UNIQUE collision is a
                # conflict. Trigger RAISE(ABORT) and other constraints arrive
                # here too but with different extended codes: those are storage
                # failures and must never be reported as 409.
                if exc.sqlite_errorcode in _UNIQUE_VIOLATION_CODES:
                    raise conflict() from None
                raise storage() from None
            except sqlite3.Error:
                raise storage() from None
            return version

    def read(self, tenant: str, record_id: str) -> dict:
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT key_version, nonce, ciphertext, wrap_nonce, wrapped_key "
                    "FROM records WHERE tenant=? AND id=?",
                    (tenant, record_id),
                ).fetchone()
            except sqlite3.Error:
                raise storage() from None
            if row is None:
                raise not_found()
            try:
                plaintext = envelope.open_envelope(self._keys, tenant, record_id, row)
            except envelope.EnvelopeIntegrityError:
                raise integrity() from None
            return {"id": record_id, "plaintext": plaintext, "key_version": row["key_version"]}

    def inventory(self, tenant: str) -> dict:
        """List this tenant's record ids with their key versions.

        Every envelope of the tenant is fully authenticated (wrapping and
        body) before the list is returned; a single damaged envelope aborts
        the whole request with 422 and no partial list. Other tenants are
        never read, so their damaged envelopes cannot block this query. The
        operation holds the same lock as create/rotate, so the active version
        and every entry come from one complete serial point in time.
        """
        with self._lock:
            try:
                rows = self._connection.execute(
                    "SELECT id, key_version, nonce, ciphertext, wrap_nonce, wrapped_key "
                    "FROM records WHERE tenant=? ORDER BY id ASC",
                    (tenant,),
                ).fetchall()
            except sqlite3.Error:
                raise storage() from None
            records = []
            for row in rows:
                record_id = row["id"]
                try:
                    version = envelope.verify(
                        self._keys, tenant, record_id, row
                    )
                except envelope.EnvelopeIntegrityError:
                    raise integrity() from None
                records.append({"id": record_id, "key_version": version})
            return {
                "tenant": tenant,
                "active_version": self._active_version,
                "records": records,
            }

    # -- keys --------------------------------------------------------------

    def rotate(self, target: int) -> tuple[int, int]:
        """Rotate all records to ``target``. Returns (active_version, rewrapped)."""
        with self._lock:
            if target < self._active_version:
                raise LedgerError(409, "version_conflict")
            if target == self._active_version:
                return self._active_version, 0
            if target not in self._keys:
                raise LedgerError(400, "invalid_version")

            try:
                rows = self._connection.execute(
                    "SELECT tenant, id, key_version, nonce, ciphertext, wrap_nonce, wrapped_key "
                    "FROM records"
                ).fetchall()
            except sqlite3.Error:
                raise storage() from None

            # Verify and rewrap every envelope before any write. A single bad
            # envelope aborts the whole request with nothing changed.
            rewrapped: list[tuple] = []
            for row in rows:
                try:
                    new_wrap_nonce, new_wrapped = envelope.rewrap(
                        self._keys, row["tenant"], row["id"], row, target
                    )
                except envelope.EnvelopeIntegrityError:
                    raise integrity() from None
                rewrapped.append((new_wrap_nonce, new_wrapped, target, row["tenant"], row["id"]))

            try:
                with self._connection:
                    for new_wrap_nonce, new_wrapped, version, tenant, record_id in rewrapped:
                        self._connection.execute(
                            "UPDATE records SET wrap_nonce=?, wrapped_key=?, key_version=? "
                            "WHERE tenant=? AND id=?",
                            (new_wrap_nonce, new_wrapped, version, tenant, record_id),
                        )
                    self._connection.execute(
                        "UPDATE service_metadata SET value=? WHERE name='active_version'",
                        (str(target),),
                    )
            except sqlite3.Error:
                raise storage() from None

            self._active_version = target
            return target, len(rewrapped)
