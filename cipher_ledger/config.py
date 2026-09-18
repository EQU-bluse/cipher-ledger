"""Read local service configuration without exposing secret values."""

import base64
import binascii
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Config:
    database: Path
    active_version: int
    keys: dict[int, bytes]
    keyring: Path | None = None


def parse_keyring(raw: Any, *, active_must_exist: bool) -> tuple[int, dict[int, bytes]]:
    """Validate a keyring JSON value.

    Shares the exact version, Base64 and 32-byte key checks used at startup.
    Booleans are never accepted as integer versions. When
    ``active_must_exist`` is false (online reload) the ``active_version``
    entry is validated for format and presence only; the persisted database
    state stays authoritative and the config value never overrides it.
    """
    if not isinstance(raw, dict):
        raise ValueError("invalid keyring")
    active = raw.get("active_version")
    if type(active) is not int or active < 1:
        raise ValueError("invalid active version")
    encoded_keys = raw.get("keys")
    if not isinstance(encoded_keys, dict) or not encoded_keys:
        raise ValueError("empty key set")
    keys = {}
    for name, encoded in encoded_keys.items():
        if not isinstance(name, str) or not name.isascii() or not name.isdecimal():
            raise ValueError("invalid version")
        version = int(name)
        if version < 1 or str(version) != name or not isinstance(encoded, str):
            raise ValueError("invalid key entry")
        material = base64.b64decode(encoded, validate=True)
        if len(material) != 32:
            raise ValueError("invalid key length")
        keys[version] = material
    if active_must_exist and active not in keys:
        raise ValueError("active version unavailable")
    return active, keys


def load_keyring_file(keyring: str | Path) -> tuple[int, dict[int, bytes]]:
    """Re-read the keyring file for an online reload.

    Returns ``(active_version, keys)`` after the same structural validation
    as startup, except that the ``active_version`` value only needs to be a
    well-formed present entry. Any unreadable or malformed input raises
    ValueError and the caller keeps the previous in-memory snapshot.
    """
    try:
        raw = json.loads(Path(keyring).read_text(encoding="utf-8"))
        return parse_keyring(raw, active_must_exist=False)
    except (OSError, ValueError, TypeError, binascii.Error) as exc:
        raise ValueError("Invalid keyring configuration") from exc


def load_config(database: str | Path, keyring: str | Path) -> Config:
    try:
        raw = json.loads(Path(keyring).read_text(encoding="utf-8"))
        active, keys = parse_keyring(raw, active_must_exist=True)
        return Config(Path(database).resolve(), active, keys, Path(keyring))
    except (OSError, ValueError, TypeError, KeyError, binascii.Error) as exc:
        raise ValueError("Invalid keyring configuration") from exc
