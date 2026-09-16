import argparse

from .config import load_config
from .server import LedgerServer


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Cipher Ledger")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8087)
    parser.add_argument("--db", default="data/ledger.sqlite3")
    parser.add_argument("--keyring", required=True)
    args = parser.parse_args()
    try:
        config = load_config(args.db, args.keyring)
        server = LedgerServer((args.host, args.port), config)
    except ValueError:
        parser.error("Invalid keyring configuration")
    with server:
        print(f"Cipher Ledger listening on {args.host}:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
