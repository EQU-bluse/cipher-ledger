import hashlib
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from cipher_ledger import audit as audit_mod
from cipher_ledger.database import connect
from tests.test_records import ServerHarness, make_config


def digest_of(message):
    raw = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def verify_chain(tenant, events):
    """Independently verify the event chain; return None when valid."""
    previous = "0" * 64
    for index, event in enumerate(events, start=1):
        if event[0] != index:
            return f"bad sequence at {index}: {event[0]}"
        kind = event[1]
        if kind == "create":
            _, _, record_id, key_version, prev, digest = event
            if prev != previous:
                return f"broken previous link at {index}"
            expected = digest_of([1, tenant, index, "create", record_id, key_version, prev])
            if digest != expected:
                return f"bad create digest at {index}"
            previous = digest
        elif kind == "rotate":
            (_, _, from_version, to_version, rewrapped, prev, digest) = event
            if prev != previous:
                return f"broken previous link at {index}"
            expected = digest_of(
                [1, tenant, index, "rotate", from_version, to_version, rewrapped, prev]
            )
            if digest != expected:
                return f"bad rotate digest at {index}"
            previous = digest
        else:
            return f"unknown kind {kind}"
    return None


class AuditProtocolTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.directory = Path(self._dir.name)
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

    def request(self, method, path, body=None, tenant=None):
        headers = {}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
        data = json.dumps(body).encode("utf-8") if body is not None else None
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.harness.base + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def create(self, record_id, plaintext="p", tenant="acme"):
        return self.request("POST", "/v1/records",
                            {"id": record_id, "plaintext": plaintext}, tenant=tenant)

    def rotate(self, version):
        return self.request("POST", "/v1/keys/rotate", {"version": version})

    def audit(self, tenant="acme"):
        return self.request("GET", "/v1/audit", tenant=tenant)

    # -- request validation ------------------------------------------------

    def test_audit_requires_valid_tenant(self):
        self.assertEqual(self.request("GET", "/v1/audit"), (400, {"error": "invalid_request"}))
        self.assertEqual(
            self.request("GET", "/v1/audit", tenant="bad tenant!"),
            (400, {"error": "invalid_request"}),
        )

    def test_audit_empty_tenant_is_empty_list(self):
        self.assertEqual(self.audit(), (200, {"tenant": "acme", "events": []}))
        # Activity by another tenant does not populate this tenant's log.
        self.create("x", tenant="alpha")
        self.assertEqual(self.audit(tenant="beta"), (200, {"tenant": "beta", "events": []}))

    # -- create events -----------------------------------------------------

    def test_successful_create_appends_verifiable_event(self):
        self.assertEqual(self.create("invoice_1", "待保存文字")[0], 201)
        status, body = self.audit()
        self.assertEqual(status, 200)
        self.assertEqual(body["tenant"], "acme")
        self.assertEqual(len(body["events"]), 1)
        event = body["events"][0]
        self.assertEqual(event[0], 1)
        self.assertEqual(event[1], "create")
        self.assertEqual(event[2], "invoice_1")
        self.assertEqual(event[3], 1)
        self.assertEqual(event[4], "0" * 64)
        self.assertEqual(len(event[5]), 64)
        self.assertIsNone(verify_chain("acme", body["events"]))

    def test_create_chain_is_continuous_and_verifiable(self):
        for i in range(5):
            self.create(f"rec{i}", f"payload {i} 内容")
        _, body = self.audit()
        events = body["events"]
        self.assertEqual([e[0] for e in events], [1, 2, 3, 4, 5])
        self.assertEqual([e[2] for e in events], [f"rec{i}" for i in range(5)])
        self.assertEqual(events[0][4], "0" * 64)
        for earlier, later in zip(events, events[1:]):
            self.assertEqual(later[4], earlier[5])
        self.assertIsNone(verify_chain("acme", events))

    def test_duplicate_create_appends_no_event(self):
        self.create("dup", "first")
        self.assertEqual(self.create("dup", "second"), (409, {"error": "conflict"}))
        _, body = self.audit()
        self.assertEqual(len(body["events"]), 1)
        self.assertEqual(body["events"][0][2], "dup")

    def test_failed_create_appends_no_event_and_rolls_record_back(self):
        self.create("before", "kept")
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("CREATE TRIGGER block_records_insert BEFORE INSERT ON records "
                        "BEGIN SELECT RAISE(ABORT, 'inserts disabled'); END")
        raw.close()
        self.assertEqual(self.create("blocked"), (503, {"error": "storage_error"}))
        raw = connect(self.directory / "ledger.sqlite3")
        self.assertEqual(raw.execute("SELECT COUNT(*) FROM records").fetchone()[0], 1)
        raw.close()
        _, body = self.audit()
        self.assertEqual([e[2] for e in body["events"]], ["before"])

    def test_audit_insert_failure_rolls_record_back_too(self):
        # If the audit write fails the business insert must commit neither.
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("CREATE TRIGGER block_audit_insert BEFORE INSERT ON audit_events "
                        "BEGIN SELECT RAISE(ABORT, 'audit disabled'); END")
        raw.close()
        self.assertEqual(self.create("orphan"), (503, {"error": "storage_error"}))
        raw = connect(self.directory / "ledger.sqlite3")
        self.assertEqual(raw.execute("SELECT COUNT(*) FROM records").fetchone()[0], 0)
        self.assertEqual(raw.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 0)
        raw.close()
        # Recovery: dropping the trigger restores atomic create+audit.
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("DROP TRIGGER block_audit_insert")
        raw.close()
        self.assertEqual(self.create("fine")[0], 201)
        _, body = self.audit()
        self.assertEqual(len(body["events"]), 1)

    # -- rotate events -----------------------------------------------------

    def test_effective_rotation_appends_per_tenant_events(self):
        self.create("a1", tenant="alpha")
        self.create("a2", tenant="alpha")
        self.create("b1", tenant="beta")
        status, body = self.rotate(2)
        self.assertEqual((status, body["rewrapped"]), (200, 3))

        _, alpha = self.audit("alpha")
        _, beta = self.audit("beta")
        self.assertEqual(len(alpha["events"]), 3)
        self.assertEqual(len(beta["events"]), 2)

        ra = alpha["events"][-1]
        self.assertEqual(ra[0], 3)
        self.assertEqual(ra[1], "rotate")
        self.assertEqual(ra[2], 1)  # from_version
        self.assertEqual(ra[3], 2)  # to_version
        self.assertEqual(ra[4], 2)  # rewrapped for alpha
        self.assertEqual(ra[5], alpha["events"][-2][5])  # previous create digest
        self.assertIsNone(verify_chain("alpha", alpha["events"]))

        rb = beta["events"][-1]
        self.assertEqual(rb[:5], [2, "rotate", 1, 2, 1])
        self.assertIsNone(verify_chain("beta", beta["events"]))

    def test_empty_database_rotation_appends_nothing(self):
        self.assertEqual(self.rotate(3), (200, {"active_version": 3, "rewrapped": 0}))
        self.assertEqual(self.audit(), (200, {"tenant": "acme", "events": []}))

    def test_rotation_skips_tenant_without_records(self):
        self.create("a1", tenant="alpha")
        self.rotate(2)
        # beta has never owned a record: no rotate event, empty log.
        self.assertEqual(self.audit(tenant="beta"),
                         (200, {"tenant": "beta", "events": []}))

    def test_idempotent_rotation_appends_nothing(self):
        self.create("rec", "payload")
        self.assertEqual(self.rotate(2)[1]["rewrapped"], 1)
        _, before = self.audit()
        self.assertEqual(len(before["events"]), 2)
        snapshot = json.dumps(before)
        self.assertEqual(self.rotate(2), (200, {"active_version": 2, "rewrapped": 0}))
        _, after = self.audit()
        self.assertEqual(json.dumps(after), snapshot)

    def test_rollback_request_appends_nothing(self):
        self.create("rec")
        self.rotate(2)
        self.assertEqual(self.rotate(1), (409, {"error": "version_conflict"}))
        _, body = self.audit()
        self.assertEqual([e[1] for e in body["events"]], ["create", "rotate"])

    def test_failed_rotation_appends_nothing_and_changes_nothing(self):
        self.create("good", "fine")
        self.create("bad", "also fine")
        raw = connect(self.directory / "ledger.sqlite3")
        blob = bytearray(raw.execute("SELECT ciphertext FROM records WHERE id='bad'").fetchone()[0])
        blob[0] ^= 0xFF
        with raw:
            raw.execute("UPDATE records SET ciphertext=? WHERE id='bad'", (bytes(blob),))
        raw.close()
        self.assertEqual(self.rotate(2), (422, {"error": "integrity_error"}))
        _, body = self.audit()
        self.assertEqual([e[1] for e in body["events"]], ["create", "create"])
        self.assertEqual(self.request("GET", "/v1/keys"), (200, {"active_version": 1}))

    def test_rotation_storage_failure_rolls_back_everything_including_audit(self):
        for i in range(3):
            self.create(f"rec{i}")
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("CREATE TRIGGER block_records_update BEFORE UPDATE ON records "
                        "BEGIN SELECT RAISE(ABORT, 'rotations disabled'); END")
        raw.close()
        self.assertEqual(self.rotate(2), (503, {"error": "storage_error"}))
        raw = connect(self.directory / "ledger.sqlite3")
        self.assertEqual(raw.execute("SELECT COUNT(*) FROM audit_events WHERE kind='rotate'").fetchone()[0], 0)
        versions = {r[0] for r in raw.execute("SELECT DISTINCT key_version FROM records")}
        raw.close()
        self.assertEqual(versions, {1})
        _, body = self.audit()
        self.assertEqual(len(body["events"]), 3)  # only the three creates
        self.assertIsNone(verify_chain("acme", body["events"]))

        # Recovery.
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("DROP TRIGGER block_records_update")
        raw.close()
        self.assertEqual(self.rotate(2)[0], 200)
        _, body = self.audit()
        self.assertEqual([e[1] for e in body["events"]],
                         ["create", "create", "create", "rotate"])
        self.assertEqual(body["events"][-1][4], 3)
        self.assertIsNone(verify_chain("acme", body["events"]))

    def test_audit_insert_failure_during_rotation_rolls_back_rewraps(self):
        self.create("rec", "payload")
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("CREATE TRIGGER block_audit_insert BEFORE INSERT ON audit_events "
                        "BEGIN SELECT RAISE(ABORT, 'audit disabled'); END")
        raw.close()
        self.assertEqual(self.rotate(2), (503, {"error": "storage_error"}))
        raw = connect(self.directory / "ledger.sqlite3")
        self.assertEqual(raw.execute("SELECT key_version FROM records").fetchone()[0], 1)
        self.assertEqual(
            raw.execute("SELECT value FROM service_metadata WHERE name='active_version'").fetchone()[0],
            "1",
        )
        kinds = [r[0] for r in raw.execute("SELECT kind FROM audit_events")]
        raw.close()
        self.assertEqual(kinds, ["create"])
        self.assertEqual(self.request("GET", "/v1/keys"), (200, {"active_version": 1}))

    # -- isolation, persistence, digest specifics --------------------------

    def test_chains_are_independent_per_tenant(self):
        self.create("s1", tenant="alpha")
        self.create("t1", tenant="beta")
        self.create("t2", tenant="beta")
        self.rotate(2)
        self.create("s2", tenant="alpha")
        self.create("u1", tenant="gamma")

        _, alpha = self.audit("alpha")
        _, beta = self.audit("beta")
        _, gamma = self.audit("gamma")

        self.assertEqual([e[0] for e in alpha["events"]], [1, 2, 3])
        self.assertEqual([e[1] for e in alpha["events"]], ["create", "rotate", "create"])
        # Rotation event carries alpha's own count (1).
        self.assertEqual(alpha["events"][1][2:5], [1, 2, 1])
        # alpha's post-rotation create is sealed at v2.
        self.assertEqual(alpha["events"][2][3], 2)
        self.assertEqual([e[0] for e in beta["events"]], [1, 2, 3])
        self.assertEqual(beta["events"][2][4], 2)  # beta count
        self.assertEqual([e[1] for e in gamma["events"]], ["create"])
        for tenant, body in (("alpha", alpha), ("beta", beta), ("gamma", gamma)):
            self.assertIsNone(verify_chain(tenant, body["events"]))

    def test_audit_exposes_only_this_tenant(self):
        self.create("alpha_rec", tenant="alpha")
        self.create("beta_rec", tenant="beta")
        status, body = self.audit("alpha")
        self.assertEqual(status, 200)
        self.assertEqual(body["tenant"], "alpha")
        self.assertEqual([e[2] for e in body["events"]], ["alpha_rec"])
        encoded = json.dumps(body)
        self.assertNotIn("beta_rec", encoded)
        self.assertNotIn("beta", encoded)

    def test_digest_input_is_canonical_compact_json(self):
        # Pin the exact digest computation against a hand-computed value.
        digest = audit_mod.create_digest("acme", 1, "doc", 1, "0" * 64)
        message = '[1,"acme",1,"create","doc",1,' + '"' + "0" * 64 + '"]'
        self.assertEqual(digest, hashlib.sha256(message.encode("utf-8")).hexdigest())

        digest = audit_mod.rotate_digest("acme", 2, 1, 2, 3, "a" * 64)
        message = '[1,"acme",2,"rotate",1,2,3,' + '"' + "a" * 64 + '"]'
        self.assertEqual(digest, hashlib.sha256(message.encode("utf-8")).hexdigest())

    def test_chain_persists_across_restart(self):
        self.create("rec1", "persist 内容")
        self.rotate(2)
        self.create("rec2", "more")
        _, before = self.audit()
        self.assertIsNone(verify_chain("acme", before["events"]))
        self.harness.close()

        restarted = ServerHarness(make_config(self.directory, active=1))
        try:
            status, body = self._call(restarted, "GET", "/v1/audit", tenant="acme")
            self.assertEqual(status, 200)
            self.assertEqual(json.dumps(body), json.dumps(before))
            self.assertIsNone(verify_chain("acme", body["events"]))
            # New events continue the persisted chain without renumbering.
            status, _ = self._call(restarted, "POST", "/v1/records",
                                   {"id": "rec3", "plaintext": "x"}, tenant="acme")
            self.assertEqual(status, 201)
            status, body = self._call(restarted, "GET", "/v1/audit", tenant="acme")
            events = body["events"]
            self.assertEqual([e[0] for e in events], [1, 2, 3, 4])
            self.assertEqual(events[-1][:4], [4, "create", "rec3", 2])
            self.assertEqual(events[-1][4], events[-2][5])
            self.assertIsNone(verify_chain("acme", events))
        finally:
            restarted.close()

    def test_concurrent_creates_keep_chain_continuous(self):
        barrier = threading.Barrier(8)
        statuses = []

        def create(index):
            barrier.wait()
            status, _ = self.create(f"race{index}")
            statuses.append(status)

        threads = [threading.Thread(target=create, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(statuses), [201] * 8)
        _, body = self.audit()
        events = body["events"]
        self.assertEqual([e[0] for e in events], list(range(1, 9)))
        self.assertEqual([e[1] for e in events], ["create"] * 8)
        self.assertIsNone(verify_chain("acme", events))

    # -- helper ------------------------------------------------------------

    def _call(self, harness, method, path, body=None, tenant=None):
        headers = {}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
        data = json.dumps(body).encode("utf-8") if body is not None else None
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(harness.base + path, data=data,
                                         headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())


if __name__ == "__main__":
    unittest.main()
