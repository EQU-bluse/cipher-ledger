"""Tenant-level verifiable audit events.

Every successful create and every effective key rotation appends one audit
event per affected tenant. Events are linked into a per-tenant hash chain:
each event stores the hex digest of its predecessor (64 zeroes for the first),
so the whole tenant history can be verified offline.

The digest input is the event array with the digest field removed and
``[1, tenant]`` prepended, serialized as compact UTF-8 JSON with no
insignificant whitespace; the digest is its lowercase SHA-256 hex digest.
"""

import hashlib
import json

AUDIT_FORMAT_VERSION = 1
GENESIS_PREVIOUS = "0" * 64


def _canonical(value: list) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def create_digest(
    tenant: str,
    sequence: int,
    record_id: str,
    key_version: int,
    previous: str,
) -> str:
    message = [AUDIT_FORMAT_VERSION, tenant, sequence, "create", record_id, key_version, previous]
    return hashlib.sha256(_canonical(message)).hexdigest()


def rotate_digest(
    tenant: str,
    sequence: int,
    from_version: int,
    to_version: int,
    rewrapped: int,
    previous: str,
) -> str:
    message = [
        AUDIT_FORMAT_VERSION,
        tenant,
        sequence,
        "rotate",
        from_version,
        to_version,
        rewrapped,
        previous,
    ]
    return hashlib.sha256(_canonical(message)).hexdigest()


def event_array(row: dict | object) -> list:
    """Render a persisted audit row in the public event-array format."""
    kind = row["kind"]
    sequence = row["sequence"]
    previous = row["previous"]
    digest = row["digest"]
    if kind == "create":
        return [sequence, "create", row["record_id"], row["key_version"], previous, digest]
    return [
        sequence,
        "rotate",
        row["from_version"],
        row["to_version"],
        row["rewrapped"],
        previous,
        digest,
    ]
