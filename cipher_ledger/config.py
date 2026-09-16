"""Read local service configuration without exposing secret values."""

import base64
import binascii
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    database: Path
    active_version: int
    keys: dict[int, bytes]


def load_config(database: str | Path, keyring: str | Path) -> Config:
    try:
        raw = json.loads(Path(keyring).read_text(encoding="utf-8"))
        active = raw["active_version"]
        if type(active) is not int or active < 1:
            raise ValueError("invalid active version")
        encoded_keys = raw["keys"]
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
        if active not in keys:
            raise ValueError("active version unavailable")
        return Config(Path(database).resolve(), active, keys)
    except (OSError, ValueError, TypeError, KeyError, binascii.Error) as exc:
        raise ValueError("Invalid keyring configuration") from exc
