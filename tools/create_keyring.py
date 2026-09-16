"""Create local development keys. Existing files are never overwritten."""

import argparse
import base64
import json
import os
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="keyring.json")
    args = parser.parse_args()
    value = {
        "active_version": 1,
        "keys": {str(version): base64.b64encode(os.urandom(32)).decode("ascii") for version in (1, 2, 3)},
    }
    with Path(args.output).open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
    print("Development keyring created.")


if __name__ == "__main__":
    main()
