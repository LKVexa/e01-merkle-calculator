"""Focused tests for the 0.1.1-partial hardening fixes (A018-F1..F3)."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from e01v2 import engine
from e01v2.merkle_ledger import LedgerError, MerkleLedger


class CorruptTailRefusal(unittest.TestCase):
    def check_tail(self, tail):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"ledger.jsonl"
            led = MerkleLedger(path)
            led.append({"v": 1})
            with path.open("ab") as stream:
                stream.write(tail)
            before = path.read_bytes()
            with self.assertRaises(LedgerError):
                MerkleLedger(path)
            self.assertEqual(path.read_bytes(), before)
            with self.assertRaises(LedgerError):
                led.append({"v": 2})

    def test_torn_final_line_without_newline_is_preserved(self):
        self.check_tail(b'{"receipt": {"v": 3}, "leaf_sh')

    def test_malformed_final_line_with_newline_is_preserved(self):
        self.check_tail(b'{"garbage": tr\n')

    def test_append_refused_after_corrupt_tail(self):
        self.check_tail(b'half a li')


class TamperDetectionAtLoad(unittest.TestCase):
    def test_tampered_receipt_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "ledger.jsonl")
            led = MerkleLedger(p)
            led.append({"v": 1})
            led.append({"v": 2})
            lines = Path(p).read_text(encoding="utf-8").splitlines()
            rec = json.loads(lines[0])
            rec["receipt"]["v"] = 999
            lines[0] = json.dumps(rec, sort_keys=True, ensure_ascii=False)
            Path(p).write_text("\n".join(lines) + "\n")
            with self.assertRaises(LedgerError):
                MerkleLedger(p)

    def test_tampered_root_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "ledger.jsonl")
            led = MerkleLedger(p)
            led.append({"v": 1})
            led.append({"v": 2})
            lines = Path(p).read_text(encoding="utf-8").splitlines()
            rec = json.loads(lines[0])
            rec["merkle_root"] = "00" * 32
            lines[0] = json.dumps(rec, sort_keys=True, ensure_ascii=False)
            Path(p).write_text("\n".join(lines) + "\n")
            with self.assertRaises(LedgerError):
                MerkleLedger(p)

    def test_corrupt_non_final_line_rejected_not_truncated(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "ledger.jsonl")
            led = MerkleLedger(p)
            led.append({"v": 1})
            led.append({"v": 2})
            lines = Path(p).read_text(encoding="utf-8").splitlines()
            lines[0] = "not json at all"
            Path(p).write_text("\n".join(lines) + "\n")
            with self.assertRaises(LedgerError):
                MerkleLedger(p)

    def test_clean_ledger_still_loads(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "ledger.jsonl")
            led = MerkleLedger(p)
            led.append({"v": 1})
            led2 = MerkleLedger(p)
            self.assertEqual(led2.size, 1)
            self.assertEqual(led2.root_hex(), led.root_hex())


class DecimalErrorContract(unittest.TestCase):
    def test_decimal_overflow_is_typed_limit_error(self):
        with self.assertRaises(engine.LimitError):
            engine.evaluate("1e999999 * 1e999999")

    def test_decimal_overflow_never_leaks_raw_exception(self):
        import decimal
        try:
            engine.evaluate("1e999999 * 1e999999 * 1e999999")
        except engine.CalcError:
            pass
        except decimal.DecimalException:  # pragma: no cover
            self.fail("raw decimal exception leaked from evaluate()")

    def test_normal_results_unchanged(self):
        r = engine.evaluate("2^10 + 1/4")
        self.assertEqual(str(r.value), "1024.25")


class VersionConstant(unittest.TestCase):
    def test_version(self):
        import e01v2
        self.assertEqual(e01v2.__version__, "0.1.2a1")


if __name__ == "__main__":
    unittest.main()
