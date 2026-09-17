import hashlib
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from cipher_ledger.config import Config
from cipher_ledger.database import connect
from cipher_ledger.server import LedgerServer

KEY_MATERIAL = {v: bytes([v]) * 16 + bytes([100 + v]) * 16 for v in (1, 2, 3)}
GENESIS = "0" * 64


def make_config(directory: Path, active: int = 1, versions=(1, 2, 3)) -> Config:
    return Config(
        directory / "ledger.sqlite3",
        active,
        {v: KEY_MATERIAL[v] for v in versions},
    )


def expected_digest(tenant: str, event_without_digest: list) -> str:
    payload = [1, tenant] + event_without_digest
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class ServerHarness:
    def __init__(self, config: Config):
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
        request = urllib.request.Request(self.harness.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def create(self, record_id, plaintext="p", tenant="acme"):
        return self.request("POST", "/v1/records", {"id": record_id, "plaintext": plaintext}, tenant=tenant)

    def rotate(self, version):
        return self.request("POST", "/v1/keys/rotate", {"version": version})

    def audit(self, tenant="acme"):
        return self.request("GET", "/v1/audit", tenant=tenant)

    def db(self):
        return connect(self.directory / "ledger.sqlite3")

    def verify_chain(self, tenant, events):
        """Independently verify sequence continuity, chaining and every digest."""
        previous = GENESIS
        for index, event in enumerate(events, start=1):
            self.assertEqual(event[0], index)  # continuous from 1, ascending
            kind = event[1]
            digest = event[-1]
            self.assertEqual(event[-2], previous)  # previous links to prior digest
            self.assertRegex(digest, r"[0-9a-f]{64}")
            self.assertEqual(expected_digest(tenant, event[:-1]), digest)
            previous = digest
        return previous

    # -- endpoint validation & shape --------------------------------------

    def test_requires_tenant_header(self):
        self.assertEqual(self.request("GET", "/v1/audit"), (400, {"error": "invalid_request"}))
        self.assertEqual(
            self.request("GET", "/v1/audit", tenant="bad tenant!"),
            (400, {"error": "invalid_request"}),
        )
        self.assertEqual(
            self.request("GET", "/v1/audit", tenant="x" * 65),
            (400, {"error": "invalid_request"}),
        )

    def test_empty_tenant_has_empty_events(self):
        self.assertEqual(
            self.audit(),
            (200, {"tenant": "acme", "events": []}),
        )
        # Activity in another tenant must not create events for this tenant.
        self.create("r1", tenant="other")
        self.assertEqual(self.audit(), (200, {"tenant": "acme", "events": []}))

    # -- create events -----------------------------------------------------

    def test_successful_create_appends_create_event(self):
        self.create("invoice_1", "密文载荷", tenant="acme")
        status, body = self.audit()
        self.assertEqual(status, 200)
        self.assertEqual(body["tenant"], "acme")
        self.assertEqual(len(body["events"]), 1)
        event = body["events"][0]
        self.assertEqual(len(event), 6)
        self.assertEqual(event[:5], [1, "create", "invoice_1", 1, GENESIS])
        self.assertEqual(
            event[5],
            expected_digest("acme", [1, "create", "invoice_1", 1, GENESIS]),
        )
        self.verify_chain("acme", body["events"])

    def test_duplicate_create_appends_no_event(self):
        self.assertEqual(self.create("dup", "first")[0], 201)
        self.assertEqual(self.create("dup", "second"), (409, {"error": "conflict"}))
        _, body = self.audit()
        self.assertEqual(len(body["events"]), 1)
        self.assertEqual(body["events"][0][1:4], ["create", "dup", 1])
        # A later successful create continues the chain without a gap.
        self.create("next", "third")
        _, body = self.audit()
        sequences = [event[0] for event in body["events"]]
        self.assertEqual(sequences, [1, 2])
        self.verify_chain("acme", body["events"])

    # -- rotate events -----------------------------------------------------

    def test_rotate_appends_one_event_per_tenant_with_records(self):
        self.create("a1", tenant="alpha")
        self.create("a2", tenant="alpha")
        self.create("b1", tenant="beta")
        self.rotate(2)
        _, alpha = self.audit("alpha")
        _, beta = self.audit("beta")
        self.assertEqual(
            alpha["events"][-1],
            [
                3,
                "rotate",
                1,
                2,
                2,
                alpha["events"][-2][-1],
                expected_digest("alpha", [3, "rotate", 1, 2, 2, alpha["events"][-2][-1]]),
            ],
        )
        self.assertEqual(len(beta["events"]), 2)
        self.assertEqual(beta["events"][1][:6], [2, "rotate", 1, 2, 1, beta["events"][0][-1]])
        self.verify_chain("alpha", alpha["events"])
        self.verify_chain("beta", beta["events"])
        # A tenant with no records at all gets no rotate event.
        self.assertEqual(self.audit("empty"), (200, {"tenant": "empty", "events": []}))

    def test_rotation_over_empty_database_appends_nothing(self):
        self.assertEqual(self.rotate(3), (200, {"active_version": 3, "rewrapped": 0}))
        self.assertEqual(self.audit(), (200, {"tenant": "acme", "events": []}))

    def test_idempotent_rotation_appends_no_event(self):
        self.create("r", tenant="acme")
        self.rotate(2)
        self.assertEqual(self.rotate(2), (200, {"active_version": 2, "rewrapped": 0}))
        _, body = self.audit()
        self.assertEqual([event[1] for event in body["events"]], ["create", "rotate"])
        self.assertEqual(self.rotate(2), (200, {"active_version": 2, "rewrapped": 0}))
        _, body = self.audit()
        self.assertEqual(len(body["events"]), 2)

    def test_failed_rotation_appends_no_events(self):
        self.create("good", "fine")
        self.create("bad", "also fine")
        raw = self.db()
        blob = bytearray(raw.execute("SELECT ciphertext FROM records WHERE id='bad'").fetchone()[0])
        blob[0] ^= 0xFF
        with raw:
            raw.execute("UPDATE records SET ciphertext=? WHERE id='bad'", (bytes(blob),))
        raw.close()
        self.assertEqual(self.rotate(2), (422, {"error": "integrity_error"}))
        _, body = self.audit()
        self.assertEqual([event[1] for event in body["events"]], ["create", "create"])
        self.verify_chain("acme", body["events"])

    # -- atomicity ---------------------------------------------------------

    def test_audit_insert_failure_rolls_back_record_create(self):
        raw = self.db()
        with raw:
            raw.execute(
                "CREATE TRIGGER block_audit_insert BEFORE INSERT ON audit_events "
                "BEGIN SELECT RAISE(ABORT, 'audit disabled'); END"
            )
        raw.close()
        # Business write and audit write share one transaction: the aborted
        # audit insert must roll back the record insert too.
        self.assertEqual(self.create("ghost", "nope"), (503, {"error": "storage_error"}))
        raw = self.db()
        self.assertEqual(raw.execute("SELECT COUNT(*) FROM records").fetchone()[0], 0)
        self.assertEqual(raw.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 0)
        raw.close()
        # After recovery the chain starts at 1 as if nothing happened.
        raw = self.db()
        with raw:
            raw.execute("DROP TRIGGER block_audit_insert")
        raw.close()
        self.assertEqual(self.create("real", "yep")[0], 201)
        _, body = self.audit()
        self.assertEqual(len(body["events"]), 1)
        self.assertEqual(body["events"][0][:4], [1, "create", "real", 1])
        self.verify_chain("acme", body["events"])

    def test_record_insert_trigger_abort_leaves_no_audit_event(self):
        raw = self.db()
        with raw:
            raw.execute(
                "CREATE TRIGGER block_records_insert BEFORE INSERT ON records "
                "BEGIN SELECT RAISE(ABORT, 'inserts disabled'); END"
            )
        raw.close()
        self.assertEqual(self.create("blocked", "x"), (503, {"error": "storage_error"}))
        raw = self.db()
        self.assertEqual(raw.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 0)
        with raw:
            raw.execute("DROP TRIGGER block_records_insert")
        raw.close()

    def test_storage_failure_during_rotation_rolls_back_events(self):
        self.create("r1", tenant="alpha")
        self.create("r2", tenant="alpha")
        self.create("r3", tenant="beta")
        raw = self.db()
        with raw:
            raw.execute(
                "CREATE TRIGGER block_records_update BEFORE UPDATE ON records "
                "BEGIN SELECT RAISE(ABORT, 'rotations disabled'); END"
            )
        raw.close()
        self.assertEqual(self.rotate(2), (503, {"error": "storage_error"}))
        # No rotate events anywhere; the create chains stay intact.
        _, alpha = self.audit("alpha")
        _, beta = self.audit("beta")
        self.assertEqual([e[1] for e in alpha["events"]], ["create", "create"])
        self.assertEqual([e[1] for e in beta["events"]], ["create"])
        self.verify_chain("alpha", alpha["events"])
        self.verify_chain("beta", beta["events"])

        raw = self.db()
        with raw:
            raw.execute("DROP TRIGGER block_records_update")
        raw.close()
        # Recovery: rotation now succeeds and chains continue per tenant.
        self.assertEqual(
            self.rotate(2), (200, {"active_version": 2, "rewrapped": 3})
        )
        _, alpha = self.audit("alpha")
        _, beta = self.audit("beta")
        self.assertEqual(
            [e[1] for e in alpha["events"]], ["create", "create", "rotate"]
        )
        self.assertEqual(alpha["events"][-1][2:5], [1, 2, 2])
        self.assertEqual(beta["events"][-1][2:5], [1, 2, 1])
        self.verify_chain("alpha", alpha["events"])
        self.verify_chain("beta", beta["events"])

    def test_audit_insert_failure_during_rotation_rolls_back_rewraps(self):
        self.create("r1", tenant="acme")
        # Abort every rotate event while letting create events through: the
        # whole rotation transaction must roll back, including rewraps.
        raw = self.db()
        with raw:
            raw.execute(
                "CREATE TRIGGER block_rotate_audit BEFORE INSERT ON audit_events "
                "WHEN NEW.kind='rotate' "
                "BEGIN SELECT RAISE(ABORT, 'rotate audit disabled'); END"
            )
        raw.close()
        self.assertEqual(self.rotate(2), (503, {"error": "storage_error"}))
        self.assertEqual(self.request("GET", "/v1/keys"), (200, {"active_version": 1}))
        raw = self.db()
        self.assertEqual(raw.execute("SELECT key_version FROM records").fetchone()[0], 1)
        self.assertEqual(
            raw.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 1
        )
        raw.close()
        _, body = self.audit()
        self.assertEqual([e[1] for e in body["events"]], ["create"])

    # -- isolation, ordering & persistence ---------------------------------

    def test_chains_are_independent_per_tenant_and_interleaved(self):
        self.create("x", tenant="alpha")
        self.create("y", tenant="beta")
        self.create("z", tenant="alpha")
        self.rotate(2)
        self.create("w", tenant="beta")
        self.rotate(3)
        _, alpha = self.audit("alpha")
        _, beta = self.audit("beta")
        self.assertEqual(
            [(e[0], e[1]) for e in alpha["events"]],
            [(1, "create"), (2, "create"), (3, "rotate"), (4, "rotate")],
        )
        self.assertEqual(
            [(e[0], e[1]) for e in beta["events"]],
            [(1, "create"), (2, "rotate"), (3, "create"), (4, "rotate")],
        )
        # rotate rewrapped counts are per tenant
        self.assertEqual([e[4] for e in alpha["events"] if e[1] == "rotate"], [2, 2])
        self.assertEqual([e[4] for e in beta["events"] if e[1] == "rotate"], [1, 2])
        self.verify_chain("alpha", alpha["events"])
        self.verify_chain("beta", beta["events"])

    def test_response_contains_only_this_tenant(self):
        self.create("secret-a", tenant="alpha")
        self.create("secret-b", tenant="beta")
        _, alpha = self.audit("alpha")
        encoded = json.dumps(alpha)
        self.assertIn("secret-a", encoded)
        self.assertNotIn("secret-b", encoded)

    def test_events_persist_across_restart_and_chain_continues(self):
        self.create("r1", "persist 内容", tenant="acme")
        self.rotate(2)
        db_path = self.directory / "ledger.sqlite3"
        self.harness.close()

        restarted = ServerHarness(make_config(self.directory, active=1))
        try:
            status, body = self._call(restarted, "GET", "/v1/audit", tenant="acme")
            self.assertEqual(status, 200)
            self.verify_chain("acme", body["events"])
            self.assertEqual(
                [(e[1]) for e in body["events"]], ["create", "rotate"]
            )
            last_digest = body["events"][-1][-1]
            # New create after restart continues numbering and chaining.
            self.assertEqual(
                self._call(restarted, "POST", "/v1/records",
                           {"id": "r2", "plaintext": "new"}, tenant="acme")[1]["key_version"],
                2,
            )
            status, body = self._call(restarted, "GET", "/v1/audit", tenant="acme")
            self.assertEqual(status, 200)
            self.assertEqual([e[0] for e in body["events"]], [1, 2, 3])
            self.assertEqual(body["events"][-1][:5], [3, "create", "r2", 2, last_digest])
            self.verify_chain("acme", body["events"])
        finally:
            restarted.close()

    # -- concurrency -------------------------------------------------------

    def test_concurrent_creates_keep_chain_continuous(self):
        barrier = threading.Barrier(8)
        results = []

        def create(index):
            barrier.wait()
            results.append(self.create(f"rec{index}", f"p{index}"))

        threads = [threading.Thread(target=create, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(1 for status, _ in results if status == 201), 8)
        _, body = self.audit()
        self.assertEqual([e[0] for e in body["events"]], list(range(1, 9)))
        self.verify_chain("acme", body["events"])

    # -- helpers -----------------------------------------------------------

    def _call(self, harness, method, path, body=None, tenant=None):
        headers = {}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
        data = json.dumps(body).encode("utf-8") if body is not None else None
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(harness.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())


if __name__ == "__main__":
    unittest.main()
