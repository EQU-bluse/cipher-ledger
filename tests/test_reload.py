import base64
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from cipher_ledger.config import load_config
from cipher_ledger.server import LedgerServer

KEY_MATERIAL = {v: bytes([v]) * 16 + bytes([100 + v]) * 16 for v in (1, 2, 3, 4)}


def encode_key(material: bytes) -> str:
    return base64.b64encode(material).decode("ascii")


def keyring_json(active: int = 1, versions=(1, 2, 3)) -> str:
    return json.dumps(
        {
            "active_version": active,
            "keys": {str(v): encode_key(KEY_MATERIAL[v]) for v in versions},
        }
    )


class ServerHarness:
    def __init__(self, config):
        self.server = LedgerServer(("127.0.0.1", 0), config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self._closed = False

    def close(self):
        if self._closed:
            return
        self._closed = True
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()


class ReloadTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.directory = Path(self._dir.name)
        self.keyring_path = self.directory / "keyring.json"
        self.keyring_path.write_text(keyring_json())
        self.harness = ServerHarness(load_config(self.directory / "ledger.sqlite3", self.keyring_path))
        self.addCleanup(self.harness.close)

    def request(self, method, path, body=None, tenant=None):
        headers = {}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
        data = None
        if body is not None:
            if isinstance(body, (bytes, str)):
                data = body if isinstance(body, bytes) else body.encode("utf-8")
            else:
                data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.harness.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def reload(self):
        return self.request("POST", "/v1/keys/reload", body="")

    def write_keyring(self, content):
        self.keyring_path.write_text(content, encoding="utf-8")

    def create(self, record_id, plaintext="x", tenant="acme"):
        return self.request("POST", "/v1/records", {"id": record_id, "plaintext": plaintext}, tenant=tenant)

    def read(self, record_id, tenant="acme"):
        return self.request("GET", f"/v1/records/{record_id}", tenant=tenant)

    def rotate(self, version):
        return self.request("POST", "/v1/keys/rotate", {"version": version})

    def inventory(self, tenant="acme"):
        return self.request("GET", "/v1/records", tenant=tenant)

    # -- success cases -----------------------------------------------------

    def test_reload_returns_persisted_active_and_sorted_versions(self):
        status, body = self.reload()
        self.assertEqual(status, 200)
        self.assertEqual(body, {"active_version": 1, "versions": [1, 2, 3]})

    def test_reload_picks_up_new_version_for_rotation(self):
        # A higher version in the keyring file becomes available without a
        # restart and can then be used for rotation.
        self.write_keyring(keyring_json(versions=(1, 2, 3, 4)))
        self.assertEqual(self.reload(), (200, {"active_version": 1, "versions": [1, 2, 3, 4]}))
        self.create("r1", "secret")
        self.assertEqual(self.rotate(4), (200, {"active_version": 4, "rewrapped": 1}))
        self.assertEqual(self.read("r1"), (200, {"id": "r1", "plaintext": "secret", "key_version": 4}))

    def test_unused_old_version_can_be_removed_after_rotation(self):
        self.create("r1", "secret")
        self.rotate(2)
        # Version 1 is now inactive and no longer referenced; dropping it and
        # even pointing the file's active_version at another present version
        # must not change the database state.
        self.write_keyring(keyring_json(active=3, versions=(2, 3)))
        status, body = self.reload()
        self.assertEqual(status, 200)
        self.assertEqual(body, {"active_version": 2, "versions": [2, 3]})
        self.assertEqual(self.request("GET", "/v1/keys"), (200, {"active_version": 2}))
        self.assertEqual(self.read("r1")[1]["key_version"], 2)

    def test_reload_can_add_and_remove_repeatedly(self):
        self.write_keyring(keyring_json(versions=(1, 2, 3, 4)))
        self.assertEqual(self.reload()[1]["versions"], [1, 2, 3, 4])
        self.write_keyring(keyring_json(versions=(1,)))
        self.assertEqual(self.reload(), (200, {"active_version": 1, "versions": [1]}))
        self.create("r1")
        self.assertEqual(self.read("r1")[0], 200)

    # -- failure cases -----------------------------------------------------

    def _assert_reload_failed_unchanged(self, active=1):
        status, body = self.reload()
        self.assertEqual((status, body), (400, {"error": "invalid_keyring"}))
        self.assertEqual(self.request("GET", "/v1/keys"), (200, {"active_version": active}))

    def test_missing_file_fails_and_keeps_snapshot(self):
        self.create("r1", "still-readable")
        self.keyring_path.unlink()
        self._assert_reload_failed_unchanged()
        self.assertEqual(self.read("r1")[1]["plaintext"], "still-readable")
        self.assertEqual(self.reload()[0], 400)

    def test_invalid_json_structure_fails(self):
        self.create("r1")
        for bad in ("not json", "[]", "null", "42", '"x"'):
            self.write_keyring(bad)
            self._assert_reload_failed_unchanged()
        # A fixed file makes the retry succeed.
        self.write_keyring(keyring_json())
        self.assertEqual(self.reload()[0], 200)

    def test_active_version_format_only_validation(self):
        self.create("r1")
        for bad in (
            {"keys": {"1": encode_key(KEY_MATERIAL[1])}},
            {"active_version": None, "keys": {"1": encode_key(KEY_MATERIAL[1])}},
            {"active_version": True, "keys": {"1": encode_key(KEY_MATERIAL[1])}},
            {"active_version": 0, "keys": {"1": encode_key(KEY_MATERIAL[1])}},
            {"active_version": "1", "keys": {"1": encode_key(KEY_MATERIAL[1])}},
        ):
            self.write_keyring(json.dumps(bad))
            self._assert_reload_failed_unchanged()

    def test_key_entry_validation_matches_startup(self):
        self.create("r1")
        valid = encode_key(KEY_MATERIAL[1])
        for bad in (
            {"active_version": 1, "keys": {}},
            {"active_version": 1, "keys": {"0": valid}},
            {"active_version": 1, "keys": {"1": encode_key(bytes(31))}},
            {"active_version": 1, "keys": {"1": valid + "??"}},
            {"active_version": 1, "keys": {"1": 123}},
            {"active_version": 1},
        ):
            self.write_keyring(json.dumps(bad))
            self._assert_reload_failed_unchanged()
        # A leading-zero version name cannot round-trip to the same name.
        self.write_keyring('{"active_version":1,"keys":{"01":' + json.dumps(valid) + "}}")
        self._assert_reload_failed_unchanged()

    def test_missing_database_active_version_fails(self):
        self.create("r1", "secret")
        # Database active version is 1; a file lacking key 1 is rejected even
        # though the file's own active_version field is valid.
        self.write_keyring(keyring_json(active=2, versions=(2, 3)))
        self._assert_reload_failed_unchanged()
        self.assertEqual(self.read("r1")[1]["plaintext"], "secret")
        self.write_keyring(keyring_json())
        self.assertEqual(self.reload()[0], 200)

    def test_missing_record_referenced_version_fails(self):
        self.create("r1", "secret")
        self.rotate(2)
        self.write_keyring(keyring_json(active=2, versions=(1, 3)))
        self._assert_reload_failed_unchanged(active=2)
        # Fix: restore version 2 and retry.
        self.write_keyring(keyring_json(active=2, versions=(1, 2, 3)))
        self.assertEqual(self.reload()[0], 200)
        self.assertEqual(self.read("r1")[1]["plaintext"], "secret")

    def test_wrong_key_material_fails_authentication(self):
        self.create("r1", "secret")
        # Same versions present, but key 1 material differs: no envelope can
        # authenticate against the candidate snapshot.
        wrong = dict(KEY_MATERIAL)
        wrong[1] = bytes(32)
        self.write_keyring(
            json.dumps({"active_version": 1, "keys": {str(v): encode_key(wrong[v]) for v in (1, 2, 3)}})
        )
        self._assert_reload_failed_unchanged()
        self.assertEqual(self.read("r1")[1]["plaintext"], "secret")

    def test_reload_body_must_be_empty(self):
        for payload in ("{}", "null", "x"):
            status, body = self.request("POST", "/v1/keys/reload", body=payload)
            self.assertEqual((status, body), (400, {"error": "invalid_request"}))

    def test_response_never_contains_key_material(self):
        self.write_keyring(keyring_json(versions=(1, 2, 3, 4)))
        _, body = self.reload()
        serialized = json.dumps(body)
        for material in KEY_MATERIAL.values():
            self.assertNotIn(encode_key(material), serialized)
            self.assertNotIn(base64.b64encode(material).decode(), serialized)

    # -- concurrency -------------------------------------------------------

    def test_concurrent_reload_create_rotate_observe_consistent_state(self):
        # Structurally complete keyring files are swapped on disk by a pacer
        # thread; occasional malformed files must produce 400 only and never a
        # half-updated snapshot.
        full = keyring_json(versions=(1, 2, 3, 4))
        valid = keyring_json()
        broken = '{"active_version": 1, "keys": {"1": "private-invalid-value"}}'
        files = (full, broken, valid, broken, full)
        errors = []

        def swap_loop():
            for i in range(100):
                self.write_keyring(files[i % len(files)])

        def reload_loop():
            for _ in range(80):
                status, body = self.reload()
                if status == 200:
                    if set(body) != {"active_version", "versions"}:
                        errors.append(("reload-body", body))
                    if body["active_version"] != 1:
                        errors.append(("reload-active", body))
                elif status != 400:
                    errors.append(("reload-status", status, body))

        def writer_loop():
            for i in range(40):
                status, body = self.create(f"r_{threading.get_ident()}_{i}")
                if status not in (201, 409):
                    errors.append(("create", status, body))

        self.write_keyring(full)
        threads = [
            threading.Thread(target=swap_loop),
            threading.Thread(target=reload_loop),
            threading.Thread(target=reload_loop),
            threading.Thread(target=writer_loop),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

        # Restore a clean file, reload, then rotate: every record must be at
        # the final active version and stay readable (serial ordering).
        self.write_keyring(keyring_json(versions=(1, 2, 3)))
        self.assertEqual(self.reload()[0], 200)
        status, body = self.rotate(2)
        self.assertEqual(status, 200)
        status, listing = self.inventory()
        self.assertEqual(status, 200)
        self.assertEqual(listing["active_version"], 2)
        self.assertTrue(listing["records"])
        self.assertTrue(all(entry["key_version"] == 2 for entry in listing["records"]))

    def test_concurrent_rotate_and_reload_no_failures(self):
        for i in range(10):
            self.create(f"seed_{i}", "payload")
        self.write_keyring(keyring_json(versions=(1, 2, 3)))
        errors = []

        def rotate_to_2():
            status, body = self.rotate(2)
            if status not in (200, 409):
                errors.append(("rotate", status, body))

        def reload_concurrently():
            status, body = self.reload()
            if status != 200:
                errors.append(("reload", status, body))

        threads = [threading.Thread(target=rotate_to_2)]
        threads += [threading.Thread(target=reload_concurrently) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

        status, body = self.request("GET", "/v1/keys")
        self.assertEqual((status, body), (200, {"active_version": 2}))
        status, listing = self.inventory()
        self.assertEqual(status, 200)
        self.assertTrue(all(entry["key_version"] == 2 for entry in listing["records"]))
        # Audit chain untouched by reload: only creates, no rotate-reload event.
        status, events = self.request("GET", "/v1/audit", tenant="acme")
        self.assertEqual(status, 200)
        self.assertTrue(events["events"])
        self.assertEqual(len([e for e in events["events"] if e[1] == "create"]), 10)
        self.assertEqual(len([e for e in events["events"] if e[1] == "rotate"]), 1)


if __name__ == "__main__":
    unittest.main()
