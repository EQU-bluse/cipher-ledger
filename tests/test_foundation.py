import base64
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from cipher_ledger.config import Config, load_config
from cipher_ledger.database import connect, initialize
from cipher_ledger.server import LedgerServer


class FoundationTests(unittest.TestCase):
    def test_configuration_reads_256_bit_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keys.json"
            path.write_text(json.dumps({"active_version": 1, "keys": {"1": base64.b64encode(bytes(32)).decode()}}))
            config = load_config(Path(directory) / "ledger.sqlite3", path)
            self.assertEqual(config.active_version, 1)
            self.assertEqual(config.keys[1], bytes(32))

    def test_configuration_rejects_invalid_material_without_echoing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keys.json"
            path.write_text('{"active_version":1,"keys":{"1":"private-invalid-value"}}')
            with self.assertRaisesRegex(ValueError, "^Invalid keyring configuration$"):
                load_config(Path(directory) / "ledger.sqlite3", path)

    def test_database_initialization_preserves_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "ledger.sqlite3"
            initialize(database)
            connection = connect(database)
            with connection:
                connection.execute("INSERT INTO service_metadata VALUES ('probe','preserved')")
            connection.close()
            initialize(database)
            connection = connect(database)
            try:
                self.assertEqual(connection.execute("SELECT value FROM service_metadata WHERE name='probe'").fetchone()[0], "preserved")
            finally:
                connection.close()

    def test_health_over_http(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Config(Path(directory) / "ledger.sqlite3", 1, {1: bytes(32)})
            with LedgerServer(("127.0.0.1", 0), config) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/health") as response:
                        self.assertEqual(response.status, 200)
                        self.assertEqual(json.load(response), {"status": "ok", "service": "cipher-ledger"})
                finally:
                    server.shutdown()
                    thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
