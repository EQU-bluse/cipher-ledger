"""Hash-chained, per-tenant verifiable audit events.

Each tenant owns an independent event chain whose sequences start at 1. An
event is stored as individual columns; the public wire format is rebuilt on
read so that the digest chain is the only source of truth.

The digest of an event is the SHA-256 of the compact, whitespace-free UTF-8
JSON array obtained by dropping the digest from the wire event and placing the
ledger format version and tenant at the front, e.g. for a create event::

    [1, tenant, sequence, "create", id, key_version, previous]

The first event of a chain has ``previous`` equal to 64 ASCII zeroes; every
later event's ``previous`` is the previous event's digest.
"""

import hashlib
import json

AUDIT_FORMAT_VERSION = 1
GENESIS_PREVIOUS = "0" * 64


def _digest_input(tenant: str, event: list) -> bytes:
    payload = list(event[:-1])  # the last element is the digest
    return json.dumps(
        [AUDIT_FORMAT_VERSION, tenant, *payload],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def create_digest(tenant: str, sequence: int, record_id: str, key_version: int, previous: str) -> str:
    event = [sequence, "create", record_id, key_version, previous, ""]
    return hashlib.sha256(_digest_input(tenant, event)).hexdigest()


def rotate_digest(
    tenant: str,
    sequence: int,
    from_version: int,
    to_version: int,
    rewrapped: int,
    previous: str,
) -> str:
    event = [sequence, "rotate", from_version, to_version, rewrapped, previous, ""]
    return hashlib.sha256(_digest_input(tenant, event)).hexdigest()
