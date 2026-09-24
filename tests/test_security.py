import concurrent.futures
import hashlib
import http.client
import json
import math
import os
import tempfile
import threading
import unittest
from pathlib import Path
from decimal import Decimal, Inexact, ROUND_DOWN, localcontext
from unittest.mock import patch

from e01v2 import engine, server
from e01v2 import merkle_ledger as ledger


class EngineRegressions(unittest.TestCase):
    def test_nested_power_rejected_before_allocation(self):
        for expression in ('(2^4096)^8192', '(3^4096)^8192', '(2^8191)*4'):
            with self.subTest(expression=expression), self.assertRaises(engine.LimitError):
                engine.evaluate(expression)

    def test_deep_parser_rejected(self):
        for expression in ('('*300+'1'+')'*300, '-'*300+'1', '^'.join(['2']*300)):
            with self.subTest(expression=expression), self.assertRaises(engine.LimitError):
                engine.evaluate(expression)

    def test_flat_tree_rejected(self):
        with self.assertRaises(engine.LimitError):
            engine.evaluate('+'.join(['1']*500))

    def test_literal_limits(self):
        for expression in ('9'*1001, '1e10001', '1e-10001', '1e'+'9'*800):
            with self.subTest(expression=expression), self.assertRaises(engine.LimitError):
                engine.evaluate(expression)

    def test_input_types(self):
        for value in (None, 3, True, [], {}):
            with self.subTest(value=value), self.assertRaises(engine.CalcError):
                engine.evaluate(value)

    def test_precision_types_and_bounds(self):
        for value in (True, 1.5, '30', None, 0, 301):
            with self.subTest(value=value), self.assertRaises(engine.LimitError):
                engine.evaluate('1', value)

    def test_timeout_shape(self):
        for value in (True, -1, 61, float('inf'), float('nan'), '2', None, 10**1000):
            with self.subTest(value=value), self.assertRaises(engine.LimitError):
                engine.evaluate('1', timeout_s=value)

    def test_zero_timeout_always_fails(self):
        with patch.object(engine.time, 'monotonic', return_value=100):
            with self.assertRaises(engine.TimeoutExceeded):
                engine.evaluate('1', timeout_s=0)

    def test_watchdog_checks_after_computation(self):
        with patch.object(engine.time, 'monotonic', side_effect=[0, 0, 0, 10]):
            with self.assertRaises(engine.TimeoutExceeded):
                engine.evaluate('1', timeout_s=1)

    def test_decimal_context_isolation(self):
        expression = '-sin(1)+sqrt(2)+pi/7'
        expected = engine.evaluate(expression, 70)
        with localcontext() as context:
            context.prec = 3
            context.rounding = ROUND_DOWN
            context.Emax, context.Emin = 2, -2
            context.traps[Inexact] = True
            context.clear_flags()
            self.assertEqual(engine.evaluate(expression, 70), expected)
            self.assertFalse(any(context.flags.values()))
            self.assertEqual(context.prec, 3)

    def test_unary_sign_preserves_decimal_literal_digits(self):
        self.assertEqual(engine.evaluate('-1.23456789', 3).value, Decimal('-1.23456789'))
        self.assertEqual(engine.evaluate('abs(-1.23456789)', 3).value, Decimal('1.23456789'))

    def test_zero_powers_consistent(self):
        for expression in ('0^0', '0^-1', '0.0^0', '0.0^-1'):
            with self.subTest(expression=expression), self.assertRaises(engine.DomainError):
                engine.evaluate(expression)

    def test_huge_decimal_exponent_not_converted_to_integer(self):
        with self.assertRaises(engine.LimitError):
            engine.evaluate('2^1e10000')

    def test_decimal_exponent_limit_does_not_round(self):
        with self.assertRaises(engine.LimitError):
            engine.evaluate('2^8193.0', 1)

    def test_floor_ceil_integer_conversion_bounded(self):
        for expression in ('floor(1e10000)', 'ceil(-1e10000)'):
            with self.assertRaises(engine.LimitError):
                engine.evaluate(expression)

    def test_decimal_overflow_underflow(self):
        for expression in ('exp(1e100)', 'exp(-1e100)', '1e10000*10', '1e-10000/10'):
            with self.subTest(expression=expression), self.assertRaises(engine.LimitError):
                engine.evaluate(expression)

    def test_trig_magnitude_and_poles(self):
        with self.assertRaises(engine.LimitError):
            engine.evaluate('sin(1e101)')
        with self.assertRaises(engine.DomainError):
            engine.evaluate('tan(pi/2)')

    def test_trig_against_independent_libm(self):
        for value in (-9, -2, -0.1, 0, 0.1, 2, 9):
            for name in ('sin', 'cos', 'tan'):
                with self.subTest(value=value, name=name):
                    result = engine.evaluate(f'{name}({value})', 40)
                    self.assertAlmostEqual(float(result.value), getattr(math, name)(value), places=13)

    def test_large_trig_precision_stability(self):
        # Same-algorithm stability check, not an independent accuracy proof.
        low = engine.evaluate('sin(100000000000000000001)', 40)
        high = engine.evaluate('sin(100000000000000000001)', 80)
        self.assertAlmostEqual(float(low.value), float(high.value), places=14)

    def test_small_trig_input(self):
        self.assertEqual(engine.evaluate('sin(1e-400)').value, Decimal('1e-400'))

    def test_maximum_integer_renders(self):
        result = engine.evaluate('2^8191').as_strings()
        self.assertEqual(int(result['value']), 2**8191)


class LedgerRegressions(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)/'ledger.jsonl'
        self.led = ledger.MerkleLedger(self.path)

    def test_failed_fsync_never_advances_memory(self):
        self.led.append({'n': 1})
        before = list(self.led._state.leaves)
        with patch.object(ledger.os, 'fsync', side_effect=OSError('disk failure')):
            with self.assertRaises(ledger.LedgerError):
                self.led.append({'n': 2})
        self.assertEqual(self.led._state.leaves, before)
        with self.assertRaises(ledger.LedgerError):
            self.led.append({'n': 3})
        with self.assertRaises(ledger.LedgerError):
            self.led.snapshot()

    def test_multiple_instances_serialize_and_share_state(self):
        instances = [self.led]+[ledger.MerkleLedger(self.path) for _ in range(3)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            entries = list(pool.map(lambda i: instances[i % 4].append({'n': i}), range(60)))
        self.assertEqual({e['tree_size'] for e in entries}, set(range(1, 61)))
        self.assertTrue(ledger.verify_ledger(self.path)['ok'])
        self.assertTrue(all(item.size == 60 for item in instances))

    def test_frontier_matches_independent_pairwise_tree(self):
        leaves = []
        for i in range(1, 66):
            entry = self.led.append({'n': i})
            leaves.append(bytes.fromhex(entry['leaf_sha256']))
            self.assertEqual(entry['merkle_root'], ledger.merkle_root(leaves).hex())
            self.assertTrue(ledger.verify_proof(self.led.proof(i-1)))

    def test_all_positional_proofs(self):
        for i in range(17):
            self.led.append({'n': i})
            for index in range(i+1):
                self.assertTrue(ledger.verify_proof(self.led.proof(index)))

    def test_receipt_is_detached(self):
        source = {'nested': {'value': 1}}
        entry = self.led.append(source)
        source['nested']['value'] = 2
        entry['receipt']['nested']['value'] = 3
        self.assertEqual(json.loads(self.path.read_text())['receipt']['nested']['value'], 1)
        self.assertTrue(ledger.verify_ledger(self.path)['ok'])

    def test_invalid_receipts_do_not_change_file(self):
        for value in ([], {'v': float('nan')}, {'v': float('inf')}, {1: 'v'}, {'v': object()}, {'v': '\ud800'}):
            with self.subTest(value=repr(value)), self.assertRaises(ledger.LedgerError):
                self.led.append(value)
            self.assertEqual(self.path.read_bytes(), b'')

    def test_nested_receipt_budget(self):
        value = {}
        for _ in range(40):
            value = {'v': value}
        with self.assertRaises(ledger.LedgerError):
            self.led.append(value)

    def test_record_and_file_budgets(self):
        with self.assertRaises(ledger.LedgerError):
            self.led.append({'v': 'x'*65536})
        with patch.object(ledger, 'MAX_FILE_BYTES', 1):
            with self.assertRaises(ledger.LedgerError):
                self.led.append({'n': 1})

    def test_receipt_count_budget(self):
        self.led.append({'n': 1})
        with patch.object(ledger, 'MAX_RECEIPTS', 1):
            with self.assertRaises(ledger.LedgerError):
                self.led.append({'n': 2})

    def test_external_modification_refused(self):
        self.led.append({'n': 1})
        self.path.write_bytes(self.path.read_bytes()+b'\n')
        with self.assertRaises(ledger.LedgerError):
            self.led.proof(0)
        with self.assertRaises(ledger.LedgerError):
            self.led.append({'n': 2})

    def test_readonly_verifier_never_repairs(self):
        for raw in (b'{', b'{}\n', b'\n', b'null\n', b'{"v":NaN}\n'):
            self.path.write_bytes(raw)
            self.assertFalse(ledger.verify_ledger(self.path)['ok'])
            self.assertEqual(self.path.read_bytes(), raw)

    def test_duplicate_entry_key_rejected(self):
        self.led.append({'n': 1})
        raw = self.path.read_text().replace('"tree_size": 1', '"tree_size": 1, "tree_size": 1')
        self.path.write_text(raw)
        self.assertFalse(ledger.verify_ledger(self.path)['ok'])

    def test_boolean_tree_size_rejected(self):
        self.led.append({'n': 1})
        self.path.write_text(self.path.read_text().replace('"tree_size": 1', '"tree_size": true'))
        self.assertFalse(ledger.verify_ledger(self.path)['ok'])

    def test_missing_verification_file_not_created(self):
        path = self.path.with_name('missing')
        self.assertFalse(ledger.verify_ledger(path)['ok'])
        self.assertFalse(path.exists())

    def test_empty_tree_root_consistent(self):
        self.assertEqual(ledger.verify_ledger(self.path)['merkle_root'], self.led.root_hex())

    def test_invalid_proof_indices(self):
        self.led.append({'n': 1})
        for value in (-1, True, 1, '0', None):
            with self.subTest(value=value), self.assertRaises(IndexError):
                self.led.proof(value)

    def test_malformed_inclusion_proofs_return_false(self):
        leaf = hashlib.sha256(b'x').digest()
        for proof in ([('X', leaf.hex())], [('R', 'GG'*32)], [('R', '00')], [None], [], 'x'):
            self.assertFalse(ledger.verify_inclusion(leaf, proof, b'\x00'*32))
        self.assertFalse(ledger.verify_inclusion(b'x', [], b'x'))

    def test_proof_position_mismatch_rejected(self):
        for i in range(3):
            self.led.append({'n': i})
        proof = self.led.proof(0)
        proof['index'] = 1
        self.assertFalse(ledger.verify_proof(proof))

    def test_nonregular_path_rejected(self):
        with self.assertRaises(ledger.LedgerError):
            ledger.MerkleLedger(self.directory.name)

    @unittest.skipIf(os.name == 'nt', 'Unix file mode assertion')
    def test_new_file_permissions_private(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)


class HTTPRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.path = os.path.join(cls.directory.name, "receipts.jsonl")
        cls.httpd = server.create_server(0, cls.path)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)
        cls.directory.cleanup()

    def request(self, body='{"expression":"1+1"}', headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request("POST", "/v2/calculate", body,
                               {"Content-Type": "application/json", **(headers or {})})
            response = connection.getresponse()
            return response.status, json.loads(response.read()), dict(response.getheaders())
        finally:
            connection.close()

    def test_precision_is_not_coerced(self):
        for value in (True, "20", 12.5, None):
            with self.subTest(value=value):
                status, payload, _ = self.request(json.dumps({"expression": "1", "precision": value}))
                self.assertEqual(status, 400)
                self.assertEqual(payload["error"]["code"], "E_REQUEST")

    def test_precision_range_remains_engine_error(self):
        status, payload, _ = self.request('{"expression":"1","precision":301}')
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "E_LIMIT")

    def test_duplicate_json_rejected(self):
        self.assertEqual(self.request('{"expression":"1","expression":"2"}')[0], 400)

    def test_json_nonfinite_rejected(self):
        self.assertEqual(self.request('{"expression":"1","precision":NaN}')[0], 400)

    def test_json_shapes_rejected(self):
        for body in ("[]", "null", '"text"', '{"expression":"1","extra":2}'):
            with self.subTest(body=body):
                self.assertEqual(self.request(body)[0], 400)

    def test_lone_surrogate_rejected(self):
        self.assertEqual(self.request('{"expression":"\\ud800"}')[0], 400)

    def test_cross_origin_rejected(self):
        self.assertEqual(self.request(headers={"Origin": "https://example.com"})[0], 403)

    def test_unexpected_host_rejected(self):
        self.assertEqual(self.request(headers={"Host": "example.com"})[0], 403)

    def test_same_origin_supported(self):
        self.assertEqual(self.request(headers={"Origin": f"http://127.0.0.1:{self.port}"})[0], 200)

    def test_plain_text_body_rejected(self):
        self.assertEqual(self.request(headers={"Content-Type": "text/plain"})[0], 415)

    def test_transfer_encoding_rejected(self):
        self.assertEqual(self.request(headers={"Transfer-Encoding": "chunked"})[0], 400)

    def test_response_caching_disabled(self):
        status, _, headers = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_receipt_failure_withholds_result(self):
        with patch.object(self.httpd.ledger, "append", side_effect=OSError("unavailable")):
            status, payload, _ = self.request()
        self.assertEqual(status, 500)
        self.assertEqual(payload["error"]["code"], "E_AUDIT")
        self.assertNotIn("result", payload)

    def test_receipt_records_precision_and_response_digest(self):
        _, payload, _ = self.request('{"expression":"sqrt(2)","precision":30}')
        with open(self.path) as stream:
            row = json.loads(stream.readlines()[-1])["receipt"]
        self.assertEqual(row["precision"], 30)
        self.assertEqual(row["engine_version"], "0.1.2a1")
        self.assertEqual(len(row["response_sha256"]), 64)
        payload.pop("receipt")
        self.assertEqual(row["response_sha256"], hashlib.sha256(json.dumps(payload,
            sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()).hexdigest())
        self.assertNotIn("expression", row)

    def test_unexpected_engine_failure_gets_receipt(self):
        before = self.httpd.ledger.size
        with patch.object(engine, 'evaluate', side_effect=RuntimeError('private internal detail')):
            status, payload, _ = self.request()
        self.assertEqual(status, 500)
        self.assertEqual(payload['error']['code'], 'E_INTERNAL')
        self.assertNotIn('private', json.dumps(payload))
        self.assertEqual(self.httpd.ledger.size, before + 1)
        self.assertIn('receipt', payload)

    def test_negative_proof_path_refused(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            connection.request('GET', '/v2/proof/-1')
            response = connection.getresponse()
            self.assertEqual(response.status, 404)
            response.read()
        finally:
            connection.close()

    def test_health_uses_one_ledger_snapshot(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            with patch.object(self.httpd.ledger, 'snapshot', return_value={'size': 7, 'merkle_root': '0'*64}) as snapshot:
                connection.request('GET', '/v2/health')
                response = connection.getresponse()
                self.assertEqual(json.loads(response.read())['ledger']['size'], 7)
                snapshot.assert_called_once()
        finally:
            connection.close()

    def test_engine_resource_error_is_json(self):
        status, payload, _ = self.request('{"expression":"(2^4096)^4096"}')
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "E_LIMIT")

    def test_servers_do_not_share_receipt_sink(self):
        other_path = os.path.join(self.directory.name, "other.jsonl")
        other = server.create_server(0, other_path)
        try:
            self.assertNotEqual(other.ledger.path, self.httpd.ledger.path)
            self.assertIsNot(other.ledger, self.httpd.ledger)
        finally:
            other.server_close()

    def test_non_loopback_factory_rejected(self):
        with self.assertRaises(SystemExit):
            server.create_server(0, self.path, "0.0.0.0")

    def test_invalid_port_rejected(self):
        for port in (-1, 65536, True, "8123"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                server.create_server(port, self.path)

    def test_duplicate_length_header_rejected(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("POST", "/v2/calculate")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", "18")
            connection.putheader("Content-Length", "18")
            connection.endheaders(b'{"expression":"1"}')
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            self.assertEqual(json.loads(response.read())["error"]["code"], "E_REQUEST")
        finally:
            connection.close()

    def test_body_limit_rejected_before_read(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("POST", "/v2/calculate")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(server.MAX_BODY_BYTES + 1))
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 413)
            response.read()
        finally:
            connection.close()

    def test_duplicate_host_rejected(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("GET", "/v2/health")
            connection.putheader("Host", "example.com")
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
        finally:
            connection.close()

