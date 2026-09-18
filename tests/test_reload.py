import base64
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from cipher_ledger.config import load_config
from cipher_ledger.database import connect
from tests.test_records import KEY_MATERIAL, ServerHarness
from tests.test_audit import verify_chain


def encoded(version: int) -> str:
    return base64.b64encode(RELOAD_KEY_MATERIAL[version]).decode("ascii")


RELOAD_KEY_MATERIAL = dict(KEY_MATERIAL)
RELOAD_KEY_MATERIAL[4] = bytes([4]) * 16 + bytes([104]) * 16


def write_keyring(path: Path, versions, file_active: int) -> None:
    path.write_text(
        json.dumps(
            {
                "active_version": file_active,
                "keys": {str(v): encoded(v) for v in versions},
            }
        ),
        encoding="utf-8",
    )


class KeyringReloadTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.directory = Path(self._dir.name)
        self.db_path = self.directory / "ledger.sqlite3"
        self.keyring_path = self.directory / "keyring.json"
        write_keyring(self.keyring_path, (1, 2, 3), file_active=1)
        config = load_config(self.db_path, self.keyring_path)
        self.harness = ServerHarness(config)
        self.addCleanup(self.harness.close)

    def request(self, method, path, body=None, tenant=None):
        headers = {}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.harness.base + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request) as response:
                raw = response.read()
                return response.status, (json.loads(raw) if raw else {}), raw
        except urllib.error.HTTPError as exc:
            with exc:
                raw = exc.read()
                return exc.code, json.loads(raw), raw

    def reload(self, body=None):
        return self.request("POST", "/v1/keys/reload", body=body)

    def create(self, record_id, plaintext="p", tenant="acme", version_expected=1):
        status, payload, _ = self.request(
            "POST", "/v1/records",
            {"id": record_id, "plaintext": plaintext}, tenant=tenant,
        )
        self.assertEqual(status, 201, payload)
        self.assertEqual(payload["key_version"], version_expected)
        return payload

    def rotate(self, version):
        return self.request("POST", "/v1/keys/rotate", {"version": version})

    # -- success cases -----------------------------------------------------

    def test_reload_reports_persisted_active_and_sorted_versions(self):
        status, body, raw = self.reload()
        self.assertEqual(status, 200)
        self.assertEqual(body, {"active_version": 1, "versions": [1, 2, 3]})
        self.assertEqual(set(body), {"active_version", "versions"})
        for material in KEY_MATERIAL.values():
            self.assertNotIn(material, raw)
            self.assertNotIn(base64.b64encode(material), raw)

    def test_reload_with_body_is_tolerated(self):
        # The endpoint takes no request body; a stray body must not break it.
        status, body, _ = self.reload(body=b'{"ignored":true}')
        self.assertEqual((status, body), (200, {"active_version": 1, "versions": [1, 2, 3]}))

    def test_reload_adds_higher_version_available_for_rotation(self):
        self.create("rec1", "payload 内容")
        write_keyring(self.keyring_path, (1, 2, 3, 4), file_active=1)
        self.assertEqual(
            self.reload()[:2], (200, {"active_version": 1, "versions": [1, 2, 3, 4]})
        )
        # The newly loaded version 4 can be used immediately, skipping 2/3.
        self.assertEqual(
            self.rotate(4)[:2], (200, {"active_version": 4, "rewrapped": 1})
        )
        self.create("rec2", "new at four", version_expected=4)
        status, body, _ = self.request("GET", "/v1/records/rec1", tenant="acme")
        self.assertEqual(body, {"id": "rec1", "plaintext": "payload 内容", "key_version": 4})

    def test_reload_can_drop_unreferenced_old_version(self):
        self.create("rec", "payload")
        self.rotate(3)
        # Nothing references 1/2 anymore; shrink the file down to version 3.
        write_keyring(self.keyring_path, (3,), file_active=3)
        self.assertEqual(self.reload()[:2], (200, {"active_version": 3, "versions": [3]}))
        status, body, _ = self.request("GET", "/v1/records/rec", tenant="acme")
        self.assertEqual((status, body["plaintext"]), (200, "payload"))
        self.assertEqual(body["key_version"], 3)

    def test_file_active_version_never_overrides_database(self):
        # Database active version moves to 2; the file may keep saying 1.
        self.create("rec")
        self.rotate(2)
        write_keyring(self.keyring_path, (1, 2, 3), file_active=1)
        status, body, _ = self.reload()
        self.assertEqual(status, 200)
        self.assertEqual(body["active_version"], 2)  # persisted value wins
        self.assertEqual(
            self.request("GET", "/v1/keys")[:2], (200, {"active_version": 2})
        )
        self.create("after", version_expected=2)

    # -- failure cases -----------------------------------------------------

    def test_unreadable_file_is_invalid_keyring_and_retriable(self):
        self.create("rec", "still readable")
        self.keyring_path.unlink()
        status, body, _ = self.reload()
        self.assertEqual((status, body), (400, {"error": "invalid_keyring"}))
        # Snapshot, active version and records are untouched.
        self.assertEqual(
            self.request("GET", "/v1/keys")[:2], (200, {"active_version": 1})
        )
        status, body, _ = self.request("GET", "/v1/records/rec", tenant="acme")
        self.assertEqual((status, body["plaintext"]), (200, "still readable"))
        # Fix the file and retry: same request now succeeds.
        write_keyring(self.keyring_path, (1, 2, 3), file_active=1)
        self.assertEqual(
            self.reload()[:2], (200, {"active_version": 1, "versions": [1, 2, 3]})
        )

    def test_malformed_files_are_rejected_without_detail_leak(self):
        self.create("rec")
        cases = [
            "not json at all",
            '{"active_version":1,"keys":',
            json.dumps({"active_version": 1}),  # missing keys
            json.dumps({"keys": {"1": encoded(1)}}),  # missing active_version
            json.dumps({"active_version": "1", "keys": {"1": encoded(1)}}),
            json.dumps({"active_version": 0, "keys": {"1": encoded(1)}}),
            json.dumps({"active_version": True, "keys": {"1": encoded(1)}}),
            json.dumps({"active_version": 1, "keys": {}}),
            json.dumps({"active_version": 1, "keys": {"1": "not-base64!!"}}),
            json.dumps({"active_version": 1, "keys": {"1": base64.b64encode(bytes(31)).decode()}}),
            json.dumps({"active_version": 1, "keys": {"01": encoded(1)}}),
            json.dumps({"active_version": 1, "keys": {"1": 42}}),
            json.dumps({"active_version": 9, "keys": {"1": encoded(1)}}),
            json.dumps([]),
        ]
        for content in cases:
            with self.subTest(content=content[:40]):
                self.keyring_path.write_text(content, encoding="utf-8")
                status, body, raw = self.reload()
                self.assertEqual((status, body), (400, {"error": "invalid_keyring"}))
                self.assertNotIn(b"Traceback", raw)
        # Snapshot stayed usable after every rejection.
        status, body, _ = self.request("GET", "/v1/records/rec", tenant="acme")
        self.assertEqual((status, body["plaintext"]), (200, "p"))
        write_keyring(self.keyring_path, (1, 2, 3), file_active=1)
        self.assertEqual(self.reload()[0], 200)

    def test_missing_persisted_active_version_rejected(self):
        self.rotate(2)
        # File lacks version 2, which is the database's active version, even
        # though its own active_version field points elsewhere.
        write_keyring(self.keyring_path, (1, 3), file_active=1)
        self.assertEqual(self.reload()[:2], (400, {"error": "invalid_keyring"}))
        self.assertEqual(
            self.request("GET", "/v1/keys")[:2], (200, {"active_version": 2})
        )

    def test_missing_referenced_version_rejected(self):
        self.create("rec", "sealed at one")
        # File active 2, keys {2,3}: database active 1 and record reference 1
        # are both unsupported.
        write_keyring(self.keyring_path, (2, 3), file_active=2)
        self.assertEqual(self.reload()[:2], (400, {"error": "invalid_keyring"}))
        # Old snapshot is still in place: rotation to a previously loaded 2
        # still works and the v1 record remains readable.
        self.assertEqual(
            self.request("GET", "/v1/records/rec", tenant="acme")[1]["key_version"], 1
        )
        self.assertEqual(self.rotate(2)[0], 200)

    def test_wrong_key_material_rejected_and_old_snapshot_kept(self):
        self.create("rec", "secret 密")
        bogus = {
            "active_version": 1,
            "keys": {
                "1": base64.b64encode(os.urandom(32)).decode("ascii"),
                "2": encoded(2),
                "3": encoded(3),
            },
        }
        self.keyring_path.write_text(json.dumps(bogus), encoding="utf-8")
        self.assertEqual(self.reload()[:2], (400, {"error": "invalid_keyring"}))
        # The in-memory snapshot is still the original key material.
        status, body, _ = self.request("GET", "/v1/records/rec", tenant="acme")
        self.assertEqual(body["plaintext"], "secret 密")
        self.rotate(2)
        status, body, _ = self.request("GET", "/v1/records/rec", tenant="acme")
        self.assertEqual((status, body["key_version"]), (200, 2))

    def test_candidate_keys_must_authenticate_every_envelope(self):
        self.create("good", "fine")
        self.create("bad", "also fine")
        raw = connect(self.db_path)
        blob = bytearray(raw.execute("SELECT ciphertext FROM records WHERE id='bad'").fetchone()[0])
        blob[0] ^= 0xFF
        with raw:
            raw.execute("UPDATE records SET ciphertext=? WHERE id='bad'", (bytes(blob),))
        raw.close()
        # A perfectly valid file still fails: one envelope cannot authenticate.
        write_keyring(self.keyring_path, (1, 2, 3), file_active=1)
        self.assertEqual(self.reload()[:2], (400, {"error": "invalid_keyring"}))
        # Restore the envelope; the same reload request then succeeds.
        raw = connect(self.db_path)
        restored = bytearray(blob)
        restored[0] ^= 0xFF
        with raw:
            raw.execute("UPDATE records SET ciphertext=? WHERE id='bad'", (bytes(restored),))
        raw.close()
        self.assertEqual(self.reload()[0], 200)

    def test_failed_reload_changes_no_database_state(self):
        self.create("rec")
        self.rotate(2)
        before_keys = self.request("GET", "/v1/keys")
        write_keyring(self.keyring_path, (4,), file_active=4)
        self.assertEqual(self.reload()[0], 400)
        self.assertEqual(self.request("GET", "/v1/keys"), before_keys)
        raw = connect(self.db_path)
        try:
            self.assertEqual(
                raw.execute(
                    "SELECT value FROM service_metadata WHERE name='active_version'"
                ).fetchone()[0],
                "2",
            )
            self.assertEqual(
                raw.execute("SELECT key_version FROM records").fetchone()[0], 2
            )
        finally:
            raw.close()

    def test_reload_appends_no_audit_events(self):
        self.create("rec")
        _, before, _ = self.request("GET", "/v1/audit", tenant="acme")
        self.reload()
        write_keyring(self.keyring_path, (1, 2, 3, 4), file_active=1)
        self.reload()
        self.keyring_path.unlink()
        self.reload()  # failed reloads also append nothing
        _, after, _ = self.request("GET", "/v1/audit", tenant="acme")
        self.assertEqual(json.dumps(after), json.dumps(before))
        self.assertIsNone(verify_chain("acme", after["events"]))

    # -- concurrency -------------------------------------------------------

    def test_reload_concurrent_with_create_and_rotation_is_always_consistent(self):
        for i in range(5):
            self.create(f"old{i}", f"old {i}")
        barrier = threading.Barrier(9)  # 5 creates + rotate + writer + 2 reload/list
        failures = []
        variants = ((1, 2, 3), (1, 2, 3, 4))

        def make_new(index):
            barrier.wait()
            status, body, _ = self.request(
                "POST", "/v1/records",
                {"id": f"new{index}", "plaintext": f"new {index}"},
                tenant="acme",
            )
            if status != 201:
                failures.append(("create", status, body))

        def rotate():
            barrier.wait()
            status, body, _ = self.rotate(2)
            if status != 200 or body["active_version"] != 2:
                failures.append(("rotate", status, body))

        def write_loop():
            # Sole writer of the keyring file: toggles between the two valid
            # shapes, reloading after each write so the on-disk file and the
            # service can never disagree for long.
            barrier.wait()
            for i in range(30):
                versions = variants[i % 2]
                write_keyring(self.keyring_path, versions, file_active=1)
                status, body, _ = self.reload()
                if status != 200:
                    failures.append(("reload", status, body))
                    continue
                if body["active_version"] not in (1, 2) or body["versions"] != list(versions):
                    failures.append(("reload-body", body))

        def reload_loop():
            barrier.wait()
            valid = {list(v) for v in variants}
            for _ in range(60):
                status, body, _ = self.reload()
                # The file is being rewritten non-atomically next door, so a
                # transiently unreadable/partial file may yield the documented
                # 400; what matters is that it is never a 5xx and that the
                # snapshot stays serviceable.
                if status == 400 and body == {"error": "invalid_keyring"}:
                    continue
                if status != 200:
                    failures.append(("reload", status, body))
                    continue
                if body["active_version"] not in (1, 2) or body["versions"] not in valid:
                    failures.append(("reload-body", body))

        def list_loop():
            barrier.wait()
            for _ in range(60):
                status, body, _ = self.request("GET", "/v1/records", tenant="acme")
                if status != 200:
                    failures.append(("list", status, body))
                    continue
                active = body["active_version"]
                versions = {entry["key_version"] for entry in body["records"]}
                # No half-rotated or half-reloaded snapshot.
                if versions and versions != {active}:
                    failures.append(("mixed", active, versions))

        threads = (
            [threading.Thread(target=make_new, args=(i,)) for i in range(5)]
            + [threading.Thread(target=rotate)]
            + [threading.Thread(target=write_loop)]
            + [threading.Thread(target=reload_loop)]
            + [threading.Thread(target=list_loop)]
        )
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(failures, [])
        # Final state is coherent: everything at version 2, all records read,
        # audit chain still verifies.
        write_keyring(self.keyring_path, (1, 2, 3, 4), file_active=1)
        self.assertEqual(self.reload()[1]["active_version"], 2)
        self.assertEqual(
            self.request("GET", "/v1/keys")[:2], (200, {"active_version": 2})
        )
        for record_id in [f"old{i}" for i in range(5)] + [f"new{i}" for i in range(5)]:
            status, _, _ = self.request("GET", f"/v1/records/{record_id}", tenant="acme")
            self.assertEqual(status, 200, record_id)
        _, audit_body, _ = self.request("GET", "/v1/audit", tenant="acme")
        self.assertIsNone(verify_chain("acme", audit_body["events"]))
        # Version 4 picked up during the race remains available afterwards.
        self.assertEqual(self.rotate(4)[0], 200)


if __name__ == "__main__":
    unittest.main()
