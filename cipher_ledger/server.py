"""Small threaded HTTP foundation; record operations are not implemented yet."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .config import Config
from .database import initialize


class LedgerServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], config: Config):
        initialize(config.database)
        self.config = config
        super().__init__(address, LedgerHandler)


class LedgerHandler(BaseHTTPRequestHandler):
    server: LedgerServer

    def send_json(self, status: int, value: dict) -> None:
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        if urlsplit(self.path).path == "/health":
            self.send_json(200, {"status": "ok", "service": "cipher-ledger"})
        else:
            self.send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        self.send_json(404, {"error": "not_found"})

    def log_message(self, format: str, *args) -> None:
        # Access logs contain only the usual request line and status information.
        super().log_message(format, *args)
