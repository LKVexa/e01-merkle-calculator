import unittest
from decimal import Decimal

from e01v2 import engine
from e01v2.engine import (CalcError, DomainError, LimitError, TimeoutExceeded,
                          evaluate, parse, canonicalize)


class BigIntDomain(unittest.TestCase):
    def test_stays_bigint(self):
        for expr, val in [("1+2*3", 7), ("2^100", 2**100), ("10/5", 2),
                          ("7%3", 1), ("gcd(12, 18)", 6), ("abs(-5)", 5),
                          ("sqrt(144)", 12), ("min(3, 9)", 3), ("max(3, 9)", 9),
                          ("floor(7/2)", 3), ("-3^2", -9), ("(-3)^2", 9)]:
            r = evaluate(expr)
            self.assertEqual(r.domain, "bigint", expr)
            self.assertEqual(r.value, val, expr)

    def test_huge_bigint(self):
        r = evaluate("2^4096 / 2^4090")
        self.assertEqual(r.value, 64)


class BigDecimalDomain(unittest.TestCase):
    def test_promotion_on_inexact_division(self):
        r = evaluate("1/3", precision=30)
        self.assertEqual(r.domain, "bigdecimal")
        self.assertTrue(str(r.value).startswith("0.3333333333"))

    def test_decimal_literal(self):
        r = evaluate("0.1 + 0.2")
        self.assertEqual(r.domain, "bigdecimal")
        self.assertEqual(r.value, Decimal("0.3"))   # decimal, not binary float

    def test_sqrt2(self):
        r = evaluate("sqrt(2)", precision=40)
        self.assertTrue(str(r.value).startswith("1.414213562373095048801688724209698"))

    def test_constants(self):
        self.assertTrue(str(evaluate("pi", precision=30).value)
                        .startswith("3.1415926535897932384"))
        self.assertTrue(str(evaluate("e", precision=30).value)
                        .startswith("2.7182818284590452353"))

    def test_deterministic(self):
        a = evaluate("sin(2) + ln(7) * sqrt(3)", precision=50)
        b = evaluate("sin(2) + ln(7) * sqrt(3)", precision=50)
        self.assertEqual(str(a.value), str(b.value))


class ErrorsAndLimits(unittest.TestCase):
    def test_domain_errors(self):
        for expr in ("1/0", "7%0", "sqrt(-1)", "ln(0)", "2^(1/3)", "0^-1",
                     "1.5 % 2", "gcd(1.5, 2)"):
            with self.assertRaises(DomainError, msg=expr):
                evaluate(expr)

    def test_parse_errors(self):
        for expr in ("1+", "(1", "foo(1)", "min(1)", "sqrt 2"):
            with self.assertRaises(CalcError, msg=expr):
                evaluate(expr)

    def test_limits(self):
        with self.assertRaises(LimitError):
            evaluate("2^100000")

    def test_watchdog(self):
        # Deep bigint exponentiation chain under a tiny timeout budget.
        with self.assertRaises(TimeoutExceeded):
            evaluate("3^4096 * 5^4096 * 7^4096 * 11^4096 * 13^4096"
                     " * 17^4096 * 19^4096 * 23^4096", timeout_s=0.0)


class PrattParser(unittest.TestCase):
    def test_precedence_and_associativity(self):
        self.assertEqual(evaluate("2+3*4").value, 14)
        self.assertEqual(evaluate("2^3^2").value, 512)      # right assoc
        self.assertEqual(evaluate("100/10/5").value, 2)     # left assoc
        self.assertEqual(evaluate("-2^2").value, -4)        # ^ over unary

    def test_implicit_multiplication(self):
        self.assertEqual(evaluate("2(3+4)").value, 14)

    def test_canonical_deterministic(self):
        self.assertEqual(canonicalize(parse("1 +2* 3")),
                         canonicalize(parse("1+2*3")))

    def test_multiarg_calls(self):
        self.assertEqual(evaluate("min(5, 2, 8)").value, 2)
        self.assertEqual(evaluate("gcd(24, 36, 60)").value, 12)


if __name__ == "__main__":
    unittest.main()
