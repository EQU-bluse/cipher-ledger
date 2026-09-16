"""Envelope encryption: per-record AES-256-GCM data keys and key wrapping.

The database stores only envelopes. The body is encrypted under a fresh random
32-byte data key; that key is itself wrapped with a keyring key. Each AEAD
operation uses a fresh random 12-byte nonce, and tenant/record/version are
cryptographically bound with AAD so that moving or mutating any envelope field
fails authentication on read.
"""

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVELOPE_FORMAT_VERSION = 1
KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16


class EnvelopeIntegrityError(Exception):
    """Raised when an envelope cannot be authenticated."""


def body_aad(tenant: str, record_id: str) -> bytes:
    return json.dumps(
        [ENVELOPE_FORMAT_VERSION, tenant, record_id],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def wrap_aad(tenant: str, record_id: str, version: int) -> bytes:
    return json.dumps(
        [ENVELOPE_FORMAT_VERSION, tenant, record_id, version],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def seal(
    keys: dict[int, bytes],
    version: int,
    tenant: str,
    record_id: str,
    plaintext: str,
) -> dict:
    """Encrypt ``plaintext`` and wrap a fresh data key with key ``version``."""
    data_key = os.urandom(KEY_SIZE)
    body_nonce = os.urandom(NONCE_SIZE)
    wrap_nonce = os.urandom(NONCE_SIZE)
    body = AESGCM(data_key).encrypt(body_nonce, plaintext.encode("utf-8"), body_aad(tenant, record_id))
    wrapped = AESGCM(keys[version]).encrypt(
        wrap_nonce, data_key, wrap_aad(tenant, record_id, version)
    )
    return {
        "key_version": version,
        "nonce": body_nonce,
        "ciphertext": body,
        "wrap_nonce": wrap_nonce,
        "wrapped_key": wrapped,
    }


def _unwrap_data_key(keys, tenant, record_id, row):
    """Authenticate the wrapping and return the enclosed data key + body fields.

    Raises EnvelopeIntegrityError if the stored row is malformed, its key
    version is unavailable, or the wrapping cannot be authenticated.
    """
    try:
        version = row["key_version"]
        body_nonce = row["nonce"]
        body = row["ciphertext"]
        wrap_nonce = row["wrap_nonce"]
        wrapped_key = row["wrapped_key"]
    except (KeyError, IndexError, TypeError):
        raise EnvelopeIntegrityError("malformed envelope") from None
    kek = keys.get(version) if type(version) is int else None
    if kek is None:
        raise EnvelopeIntegrityError("wrap version unavailable")
    try:
        data_key = AESGCM(kek).decrypt(
            wrap_nonce, wrapped_key, wrap_aad(tenant, record_id, version)
        )
    except (InvalidTag, ValueError):
        raise EnvelopeIntegrityError("envelope authentication failed") from None
    return data_key, body_nonce, body, version


def open_envelope(
    keys: dict[int, bytes],
    tenant: str,
    record_id: str,
    row: dict | object,
) -> str:
    """Authenticate and decrypt a stored envelope row.

    Any mismatch between the AAD bindings (tenant, id, key version) or any
    tampering with the nonce, ciphertext or wrapped key raises
    EnvelopeIntegrityError. No partial plaintext is returned.
    """
    data_key, body_nonce, body, _ = _unwrap_data_key(keys, tenant, record_id, row)
    try:
        plaintext = AESGCM(data_key).decrypt(
            body_nonce, body, body_aad(tenant, record_id)
        )
        return plaintext.decode("utf-8")
    except (InvalidTag, UnicodeDecodeError, ValueError):
        raise EnvelopeIntegrityError("envelope authentication failed") from None


def verify(
    keys: dict[int, bytes],
    tenant: str,
    record_id: str,
    row: dict | object,
) -> int:
    """Authenticate every part of an envelope without returning plaintext.

    Both the data-key wrapping and the body are verified. Used by operations
    that need proof of integrity without exposing content (the tenant key
    usage inventory). Returns the envelope's key version.
    """
    data_key, body_nonce, body, version = _unwrap_data_key(keys, tenant, record_id, row)
    try:
        AESGCM(data_key).decrypt(body_nonce, body, body_aad(tenant, record_id))
    except (InvalidTag, ValueError):
        raise EnvelopeIntegrityError("envelope authentication failed") from None
    return version


def rewrap(
    keys: dict[int, bytes],
    tenant: str,
    record_id: str,
    row: dict | object,
    new_version: int,
) -> tuple[bytes, bytes]:
    """Verify a record end to end and return a fresh wrap under ``new_version``.

    Both the body and the old wrapping are authenticated before anything is
    returned. The body nonce and ciphertext are never touched; only the data
    key is re-wrapped with a fresh wrap nonce.
    """
    data_key, body_nonce, body, _ = _unwrap_data_key(keys, tenant, record_id, row)
    try:
        # Authenticate the body too: a damaged body must fail the whole rotation.
        AESGCM(data_key).decrypt(body_nonce, body, body_aad(tenant, record_id))
        new_wrap_nonce = os.urandom(NONCE_SIZE)
        new_wrapped = AESGCM(keys[new_version]).encrypt(
            new_wrap_nonce, data_key, wrap_aad(tenant, record_id, new_version)
        )
        return new_wrap_nonce, new_wrapped
    except (InvalidTag, ValueError, KeyError):
        raise EnvelopeIntegrityError("envelope authentication failed") from None
