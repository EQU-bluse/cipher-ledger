"""Tenant-scoped record storage with envelope encryption and key rotation.

All operations take one process-wide re-entrant lock so the results of
concurrent creates, reads, rotations, inventory/audit reads and keyring
reloads are equivalent to some total serial ordering. Rotation verifies every
old envelope first and only then performs a single transactional write, so a
damaged envelope or a storage failure leaves the active version and all
records exactly as they were before the request. A keyring reload validates
the new file and authenticates every existing envelope against the candidate
keys before swapping the in-memory snapshot in one assignment; any failure
leaves the running snapshot, active version, records and audit chain untouched.
"""

import binascii
import json
import sqlite3
import threading

from . import audit, envelope
from .config import Config, parse_keyring
from .database import connect, initialize


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


def invalid_keyring() -> LedgerError:
    return LedgerError(400, "invalid_keyring")


# Only the composite (tenant, id) primary-key collision is a client conflict.
# Every other write failure -- including a BEFORE INSERT trigger aborting with
# RAISE(ABORT), which also surfaces as sqlite3.IntegrityError but carries the
# SQLITE_CONSTRAINT_TRIGGER extended code -- is a transient storage failure.
_UNIQUE_CONFLICT_CODES = frozenset(
    code
    for code in (
        getattr(sqlite3, "SQLITE_CONSTRAINT_PRIMARYKEY", None),
        getattr(sqlite3, "SQLITE_CONSTRAINT_UNIQUE", None),
    )
    if code is not None
)


def _is_unique_conflict(exc: sqlite3.Error) -> bool:
    return getattr(exc, "sqlite_errorcode", None) in _UNIQUE_CONFLICT_CODES


class Ledger:
    def __init__(self, config: Config):
        initialize(config.database, config.active_version)
        self._keys = dict(config.keys)
        self._keyring_path = config.keyring_path
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
        """Create a record. Returns the key version used. Duplicate -> 409.

        The record and its ``create`` audit event are inserted in one
        transaction: a duplicate id, a storage failure or any other write
        error rolls both back, so failed or repeated creates never append an
        event.
        """
        with self._lock:
            version = self._active_version
            sealed = envelope.seal(self._keys, version, tenant, record_id, plaintext)
            try:
                head = self._audit_heads((tenant,))[tenant]
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
                    sequence = head[0] + 1
                    previous = head[1]
                    digest = audit.create_digest(
                        tenant, sequence, record_id, sealed["key_version"], previous
                    )
                    self._connection.execute(
                        "INSERT INTO audit_events "
                        "(tenant, sequence, kind, record_id, key_version, previous, digest) "
                        "VALUES (?, ?, 'create', ?, ?, ?, ?)",
                        (tenant, sequence, record_id, sealed["key_version"], previous, digest),
                    )
            except sqlite3.Error as exc:
                # A trigger RAISE(ABORT) is also an IntegrityError, so the
                # exception type alone cannot distinguish a duplicate id. Only a
                # composite (tenant, id) uniqueness violation is a 409.
                if _is_unique_conflict(exc):
                    raise conflict() from None
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
        """Return the tenant's key-usage inventory.

        Every one of the tenant's envelopes is fully authenticated before
        anything is returned, so the response is either the complete list or
        integrity_error -- never a partial list. Only this tenant's rows are
        read, so damage in another tenant cannot block the query. The whole
        check runs under the same lock as create/rotate, so the active version
        and every entry correspond to one complete serial point in time.
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
            entries = []
            for row in rows:
                record_id = row["id"]
                try:
                    envelope.open_envelope(self._keys, tenant, record_id, row)
                except envelope.EnvelopeIntegrityError:
                    raise integrity() from None
                entries.append({"id": record_id, "key_version": row["key_version"]})
            return {
                "tenant": tenant,
                "active_version": self._active_version,
                "records": entries,
            }

    # -- audit -------------------------------------------------------------

    def _audit_heads(self, tenants) -> dict[str, tuple[int, str]]:
        """Latest (sequence, digest) per requested tenant, (0, zeros) if none."""
        heads = {tenant: (0, audit.GENESIS_PREVIOUS) for tenant in tenants}
        try:
            rows = self._connection.execute(
                "SELECT e.tenant, e.sequence, e.digest "
                "FROM audit_events e "
                "JOIN (SELECT tenant, MAX(sequence) AS last_sequence "
                "FROM audit_events GROUP BY tenant) h "
                "ON e.tenant = h.tenant AND e.sequence = h.last_sequence"
            ).fetchall()
        except sqlite3.Error:
            raise storage() from None
        for row in rows:
            if row["tenant"] in heads:
                heads[row["tenant"]] = (row["sequence"], row["digest"])
        return heads

    def audit(self, tenant: str) -> dict:
        """Return the tenant's verifiable event chain in ascending order."""
        with self._lock:
            try:
                rows = self._connection.execute(
                    "SELECT kind, sequence, record_id, key_version, from_version, "
                    "to_version, rewrapped, previous, digest "
                    "FROM audit_events WHERE tenant=? ORDER BY sequence ASC",
                    (tenant,),
                ).fetchall()
            except sqlite3.Error:
                raise storage() from None
            return {"tenant": tenant, "events": [audit.event_array(row) for row in rows]}

    # -- keys --------------------------------------------------------------

    def rotate(self, target: int) -> tuple[int, int]:
        """Rotate all records to ``target``. Returns (active_version, rewrapped).

        An effective rotation appends one chained ``rotate`` event per tenant
        that owns records, with that tenant's affected count, in the same
        transaction as the rewraps. Idempotent same-version calls, rollback
        requests and failed rotations append nothing.
        """
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
            counts: dict[str, int] = {}
            for row in rows:
                try:
                    new_wrap_nonce, new_wrapped = envelope.rewrap(
                        self._keys, row["tenant"], row["id"], row, target
                    )
                except envelope.EnvelopeIntegrityError:
                    raise integrity() from None
                rewrapped.append((new_wrap_nonce, new_wrapped, target, row["tenant"], row["id"]))
                counts[row["tenant"]] = counts.get(row["tenant"], 0) + 1

            # One rotate event per tenant that owns records, chained on that
            # tenant's history. Everything below commits in a single
            # transaction with the envelope updates, so a storage failure rolls
            # back records, active version and audit events together.
            heads = self._audit_heads(counts)
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
                    for tenant, count in counts.items():
                        sequence, previous = heads[tenant]
                        sequence += 1
                        digest = audit.rotate_digest(
                            tenant, sequence, self._active_version, target, count, previous
                        )
                        self._connection.execute(
                            "INSERT INTO audit_events "
                            "(tenant, sequence, kind, from_version, to_version, "
                            "rewrapped, previous, digest) "
                            "VALUES (?, ?, 'rotate', ?, ?, ?, ?, ?)",
                            (
                                tenant,
                                sequence,
                                self._active_version,
                                target,
                                count,
                                previous,
                                digest,
                            ),
                        )
            except sqlite3.Error:
                raise storage() from None

            self._active_version = target
            return target, len(rewrapped)

    # -- online keyring reload --------------------------------------------

    def reload_keyring(self) -> tuple[int, list[int]]:
        """Atomically reload the keyring file from ``--keyring``.

        Re-reads the UTF-8 JSON file and applies the same version, Base64 and
        32-byte key validation as startup, then requires the persisted active
        version and every version referenced by an existing record to be
        present, and authenticates every existing envelope (wrap and body)
        against the candidate keys. Only when all of that succeeds is the
        in-memory snapshot replaced in one assignment; the persisted active
        version, records and audit chain are never modified. The file's own
        ``active_version`` is validated for format and key presence but never
        overrides the database state.

        Returns ``(persisted_active_version, sorted_loaded_versions)``. Any
        failure raises invalid_keyring (400); storage errors stay 503.
        """
        with self._lock:
            if self._keyring_path is None:
                raise invalid_keyring()
            try:
                raw = json.loads(self._keyring_path.read_text(encoding="utf-8"))
                _file_active, candidate_keys = parse_keyring(raw)
            except (OSError, ValueError, TypeError, KeyError, binascii.Error):
                raise invalid_keyring() from None

            # The currently active version and every version a record still
            # references must be available in the candidate snapshot.
            if self._active_version not in candidate_keys:
                raise invalid_keyring()

            try:
                rows = self._connection.execute(
                    "SELECT tenant, id, key_version, nonce, ciphertext, "
                    "wrap_nonce, wrapped_key FROM records"
                ).fetchall()
            except sqlite3.Error:
                raise storage() from None

            for row in rows:
                if row["key_version"] not in candidate_keys:
                    raise invalid_keyring()
                try:
                    envelope.open_envelope(
                        candidate_keys, row["tenant"], row["id"], row
                    )
                except envelope.EnvelopeIntegrityError:
                    raise invalid_keyring() from None

            # One-shot replacement: concurrent operations under this same lock
            # can only ever see the old snapshot or the complete new one.
            self._keys = candidate_keys
            return self._active_version, sorted(candidate_keys)
