"""Randomized property tests (P6-02 partial substitute).

The source baseline mandates Hypothesis-based property testing; the
Hypothesis package was not installable in this build environment (package
index unreachable through the egress proxy), so these are seeded stdlib
randomized property tests. Hypothesis proper remains an UNRUN check.
"""

import random
import unittest
from decimal import Decimal

from e01v2 import engine


class AlgebraicProperties(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(0xE01224)

    def rand_int(self):
        return self.rng.randint(-10**6, 10**6)

    def test_addition_commutes_bigint(self):
        for _ in range(300):
            a, b = self.rand_int(), self.rand_int()
            x = engine.evaluate(f"({a}) + ({b})").value
            y = engine.evaluate(f"({b}) + ({a})").value
            self.assertEqual(x, y)
            self.assertEqual(x, a + b)

    def test_mul_distributes(self):
        for _ in range(200):
            a, b, c = self.rand_int(), self.rand_int(), self.rand_int()
            x = engine.evaluate(f"({a}) * (({b}) + ({c}))").value
            y = engine.evaluate(f"({a})*({b}) + ({a})*({c})").value
            self.assertEqual(x, y)

    def test_exact_division_roundtrip(self):
        for _ in range(200):
            a = self.rng.randint(-10**5, 10**5)
            b = self.rng.randint(1, 10**4)
            v = engine.evaluate(f"({a} * {b}) / ({b})").value
            self.assertEqual(v, a)
            self.assertIsInstance(v, int)

    def test_sqrt_square_roundtrip_bigint(self):
        for _ in range(200):
            n = self.rng.randint(0, 10**9)
            v = engine.evaluate(f"sqrt({n} * {n})").value
            self.assertEqual(v, n)

    def test_parser_canonical_idempotent(self):
        for _ in range(100):
            a, b, c = (self.rng.randint(1, 999) for _ in range(3))
            expr = f"{a}+{b}*{c}"
            canon = engine.canonicalize(engine.parse(expr))
            # canonical text must itself parse to the same canonical text
            self.assertEqual(engine.canonicalize(engine.parse(canon)), canon)

    def test_decimal_division_scaled(self):
        for _ in range(100):
            a = self.rng.randint(1, 10**6)
            b = self.rng.randint(1, 10**6)
            r = engine.evaluate(f"{a}/{b}", precision=40)
            if a % b == 0:
                self.assertIsInstance(r.value, int)
            else:
                q = Decimal(a) / Decimal(b)
                self.assertAlmostEqual(float(r.value), float(q), places=12)


if __name__ == "__main__":
    unittest.main()
