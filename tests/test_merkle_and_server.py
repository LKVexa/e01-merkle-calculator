import hashlib
import http.client
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from e01v2 import engine
from e01v2.merkle_ledger import (MerkleLedger, inclusion_proof, leaf_hash,
                                 merkle_root, verify_inclusion, verify_ledger)
from e01v2.server import CalculatorV2Handler, ThreadingHTTPServer


def h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


class MerkleScheme(unittest.TestCase):
    """Cross-checked against the vendored merklecpp donor semantics:
    single-leaf tree root == leaf; internal node = sha256(left||right)."""

    def test_single_leaf_root_is_leaf(self):
        leaf = h(b"\x00" * 32)
        self.assertEqual(merkle_root([leaf]), leaf)

    def test_two_leaf_root(self):
        a, b = h(b"a"), h(b"b")
        self.assertEqual(merkle_root([a, b]), h(a + b))

    def test_sha256_zero_vector(self):
        # merklecpp unit test: sha256(zero||zero) as one compression input.
        zero = b"\x00" * 32
        digest = h(zero + zero)
        self.assertEqual(merkle_root([zero, zero]), digest)

    def test_odd_carry(self):
        a, b, c = h(b"a"), h(b"b"), h(b"c")
        self.assertEqual(merkle_root([a, b, c]), h(h(a + b) + c))

    def test_inclusion_proofs_all_sizes(self):
        leaves = [h(bytes([i])) for i in range(9)]
        for size in range(1, 10):
            sub = leaves[:size]
            root = merkle_root(sub)
            for i in range(size):
                proof = inclusion_proof(sub, i)
                self.assertTrue(verify_inclusion(sub[i], proof, root),
                                f"size={size} leaf={i}")

    def test_tamper_detection(self):
        leaves = [h(bytes([i])) for i in range(5)]
        root = merkle_root(leaves)
        proof = inclusion_proof(leaves, 2)
        self.assertFalse(verify_inclusion(h(b"evil"), proof, root))


class LedgerFile(unittest.TestCase):
    def test_append_verify_and_reload(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "ledger.jsonl")
        led = MerkleLedger(path)
        for i in range(7):
            led.append({"n": i, "outcome": "ok"})
        rep = verify_ledger(path)
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["receipts"], 7)
        led2 = MerkleLedger(path)                 # reload from disk
        self.assertEqual(led2.size, 7)
        self.assertEqual(led2.root_hex(), rep["merkle_root"])
        p = led2.proof(3)
        self.assertTrue(verify_inclusion(bytes.fromhex(p["leaf_sha256"]),
                                         [(s, d) for s, d in p["proof"]],
                                         bytes.fromhex(p["merkle_root"])))

    def test_tampered_file_detected(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "ledger.jsonl")
        led = MerkleLedger(path)
        led.append({"n": 1})
        led.append({"n": 2})
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[0])
        rec["receipt"]["n"] = 999
        lines[0] = json.dumps(rec, sort_keys=True)
        Path(path).write_text("\n".join(lines) + "\n")
        self.assertFalse(verify_ledger(path)["ok"])


class ServerV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.ledger_path = os.path.join(cls.tmp, "merkle_ledger.jsonl")
        CalculatorV2Handler.ledger = MerkleLedger(cls.ledger_path)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), CalculatorV2Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def call(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path,
                     json.dumps(body) if body is not None else None,
                     {"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read().decode())
        conn.close()
        return resp.status, data

    def test_calculate_bigint_and_receipt(self):
        status, data = self.call("POST", "/v2/calculate", {"expression": "2^64"})
        self.assertEqual(status, 200)
        self.assertEqual(data["result"]["value"], str(2**64))
        self.assertEqual(data["result"]["domain"], "bigint")
        self.assertIn("merkle_root", data["receipt"])

    def test_error_execution_still_gets_receipt(self):
        before = CalculatorV2Handler.ledger.size
        status, data = self.call("POST", "/v2/calculate", {"expression": "1/0"})
        self.assertEqual(status, 422)
        self.assertEqual(data["error"]["code"], "E_DOMAIN")
        self.assertEqual(CalculatorV2Handler.ledger.size, before + 1)
        self.assertIn("receipt", data)

    def test_pre_execution_rejection_no_receipt(self):
        before = CalculatorV2Handler.ledger.size
        status, _ = self.call("POST", "/v2/calculate", {"nope": 1})
        self.assertEqual(status, 400)
        self.assertEqual(CalculatorV2Handler.ledger.size, before)

    def test_health_and_proof_roundtrip(self):
        self.call("POST", "/v2/calculate", {"expression": "1+1"})
        status, health = self.call("GET", "/v2/health")
        self.assertEqual(status, 200)
        size = health["ledger"]["size"]
        status, proof = self.call("GET", f"/v2/proof/{size-1}")
        self.assertEqual(status, 200)
        self.assertTrue(verify_inclusion(
            bytes.fromhex(proof["leaf_sha256"]),
            [(s, d) for s, d in proof["proof"]],
            bytes.fromhex(proof["merkle_root"])))

    def test_ledger_file_verifies(self):
        self.call("POST", "/v2/calculate", {"expression": "sqrt(2)"})
        rep = verify_ledger(self.ledger_path)
        self.assertTrue(rep["ok"])

    def test_receipts_carry_no_raw_expression(self):
        with open(self.ledger_path) as fh:
            for line in fh:
                self.assertNotIn("expression\":", line.replace("expression_sha256", ""))

    def test_loopback_binding(self):
        self.assertEqual(self.httpd.server_address[0], "127.0.0.1")

    def test_refuses_non_loopback(self):
        from e01v2.server import serve
        with self.assertRaises(SystemExit):
            serve(0, os.path.join(self.tmp, "x.jsonl"), host="0.0.0.0")


class ZeroSideEffectKernel(unittest.TestCase):
    def test_engine_no_io(self):
        import builtins
        opened = []
        real_open, real_socket = builtins.open, socket.socket
        builtins.open = lambda *a, **k: (opened.append(a), real_open(*a, **k))[1]
        socket.socket = lambda *a, **k: (_ for _ in ()).throw(AssertionError("socket"))
        try:
            engine.evaluate("sqrt(2) + 2^64 + sin(1)", precision=40)
        finally:
            builtins.open, socket.socket = real_open, real_socket
        self.assertEqual(opened, [])


if __name__ == "__main__":
    unittest.main()
