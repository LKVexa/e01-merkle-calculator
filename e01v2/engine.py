"""E01 Local Calculator v2 baseline — Pratt-parser engine with BigInt /
BigDecimal numeric semantics (JY-S021-P001, partial candidate).

Provisional decisions (unapproved; see docs/PROVISIONAL_ASSUMPTIONS.md):
- DEC-02: Pratt (precedence-climbing) parsing selected provisionally.
- DEC-05: BigInt backend = Python arbitrary-precision ``int``; BigDecimal
  backend = ``decimal.Decimal`` with explicit context (default 60
  significant digits, ROUND_HALF_EVEN). Promotion rules: int op int stays
  int except ``/`` which promotes to Decimal; any Decimal operand promotes
  the operation to Decimal at the active context.
- P4-04: zero-side-effect evaluation with a wall-clock watchdog
  (``evaluate(..., timeout_s=...)``); the WASM/WASI micro-sandbox itself is
  BLOCKED on DEC-03 runtime selection.
"""

from __future__ import annotations

import decimal
import re
import math
import time
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
from typing import Optional, Union

Number = Union[int, Decimal]

DEFAULT_PRECISION = 60
DEFAULT_ROUNDING = ROUND_HALF_EVEN
MAX_EXPRESSION_LENGTH = 8192
MAX_TOKENS = 2048
MAX_EXPONENT = 8192
MAX_INTEGER_BITS = 8192
MAX_LITERAL_DIGITS = 1000
MAX_DECIMAL_EXPONENT = 10000
MAX_PARSE_DEPTH = 100
MAX_AST_DEPTH = 150
MAX_TRIG_MAGNITUDE = 100
DEFAULT_TIMEOUT_S = 2.0        # provisional wall-clock watchdog bound


class CalcError(Exception):
    code = "E_CALC"


class LexError(CalcError):
    code = "E_LEX"


class ParseError(CalcError):
    code = "E_PARSE"


class DomainError(CalcError):
    code = "E_DOMAIN"


class LimitError(CalcError):
    code = "E_LIMIT"


class TimeoutExceeded(CalcError):
    code = "E_TIMEOUT"


@dataclass(frozen=True)
class Token:
    kind: str   # num | name | op | end
    text: str
    pos: int


_TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<num>[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)
      | (?P<name>[A-Za-z_][A-Za-z_0-9]*)
      | (?P<op>\*\*|[-+*/%^(),])
    )""",
    re.VERBOSE,
)

_FUNCS = {"sqrt", "abs", "floor", "ceil", "min", "max", "gcd",
          "sin", "cos", "tan", "ln", "log10", "exp"}
_CONSTS = {"pi", "e"}


def tokenize(source: str) -> list[Token]:
    if type(source) is not str:
        raise ParseError("expression must be a string")
    if len(source) > MAX_EXPRESSION_LENGTH:
        raise LimitError(f"expression exceeds {MAX_EXPRESSION_LENGTH} characters")
    out: list[Token] = []
    pos = 0
    while pos < len(source):
        m = _TOKEN_RE.match(source, pos)
        if not m or m.end() == m.start():
            rest = source[pos:].lstrip()
            if not rest:
                break
            raise LexError(f"unexpected character {rest[0]!r} at position {pos}")
        kind = m.lastgroup
        text = m.group(kind)
        if kind == "op" and text == "**":
            text = "^"
        if kind == "num":
            if sum(c.isdigit() for c in text) > MAX_LITERAL_DIGITS:
                raise LimitError("numeric literal digit budget exceeded")
            parts = re.split("[eE]", text)
            if len(parts) == 2 and (len(parts[1].lstrip("+-")) > 5 or abs(int(parts[1])) > MAX_DECIMAL_EXPONENT):
                raise LimitError("literal exponent outside supported range")
        out.append(Token(kind, text, m.start(kind)))
        if len(out) > MAX_TOKENS:
            raise LimitError(f"expression exceeds {MAX_TOKENS} tokens")
        pos = m.end()
    out.append(Token("end", "", len(source)))
    return out


# --------------------------- Pratt parser (provisional DEC-02) ----------
# Binding powers: or-like none here; arithmetic only.
_INFIX_BP = {"+": (10, 11), "-": (10, 11), "*": (20, 21), "/": (20, 21),
             "%": (20, 21), "^": (41, 40)}   # ^ right-assoc, above unary (30)
_UNARY_BP = 30


@dataclass(frozen=True)
class Num:
    literal: str


@dataclass(frozen=True)
class Const:
    name: str


@dataclass(frozen=True)
class Unary:
    op: str
    operand: "Node"


@dataclass(frozen=True)
class Binary:
    op: str
    left: "Node"
    right: "Node"


@dataclass(frozen=True)
class Call:
    func: str
    args: tuple


Node = Union[Num, Const, Unary, Binary, Call]


class Parser:
    def __init__(self, tokens: list[Token]):
        self.toks = tokens
        self.i = 0
        self.depth = 0

    def peek(self) -> Token:
        return self.toks[self.i]

    def next(self) -> Token:
        t = self.toks[self.i]
        self.i += 1
        return t

    def parse(self) -> Node:
        node = self.expr(0)
        if self.peek().kind != "end":
            t = self.peek()
            raise ParseError(f"unexpected token {t.text!r} at position {t.pos}")
        return node

    def expr(self, min_bp: int) -> Node:
        self.depth += 1
        try:
            if self.depth > MAX_PARSE_DEPTH:
                raise LimitError("parser nesting budget exceeded")
            return self._expr(min_bp)
        finally:
            self.depth -= 1

    def _expr(self, min_bp: int) -> Node:
        node = self.prefix()
        while True:
            t = self.peek()
            if t.kind == "op" and t.text in _INFIX_BP:
                lbp, rbp = _INFIX_BP[t.text]
                if lbp < min_bp:
                    break
                self.next()
                node = Binary(t.text, node, self.expr(rbp))
                continue
            # implicit multiplication: 2pi, 2(1+1), (a)(b)
            if t.kind in ("num", "name") or (t.kind == "op" and t.text == "("):
                lbp, rbp = _INFIX_BP["*"]
                if lbp < min_bp:
                    break
                node = Binary("*", node, self.expr(rbp))
                continue
            break
        return node

    def prefix(self) -> Node:
        t = self.next()
        if t.kind == "op" and t.text in "+-":
            return Unary(t.text, self.expr(_UNARY_BP))
        if t.kind == "num":
            return Num(t.text)
        if t.kind == "name":
            name = t.text.lower()
            if name in _CONSTS:
                return Const(name)
            if name in _FUNCS:
                if not (self.peek().kind == "op" and self.peek().text == "("):
                    raise ParseError(f"function {name} requires parentheses at position {t.pos}")
                self.next()
                args = [self.expr(0)]
                while self.peek().kind == "op" and self.peek().text == ",":
                    self.next()
                    args.append(self.expr(0))
                closing = self.next()
                if not (closing.kind == "op" and closing.text == ")"):
                    raise ParseError(f"expected ')' at position {closing.pos}")
                return Call(name, tuple(args))
            raise ParseError(f"unknown identifier {t.text!r} at position {t.pos}")
        if t.kind == "op" and t.text == "(":
            node = self.expr(0)
            closing = self.next()
            if not (closing.kind == "op" and closing.text == ")"):
                raise ParseError(f"expected ')' at position {closing.pos}")
            return node
        raise ParseError(f"unexpected token {t.text or 'end of input'!r} at position {t.pos}")


def parse(source: str) -> Node:
    node = Parser(tokenize(source)).parse()
    pending = [(node, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > MAX_AST_DEPTH:
            raise LimitError("expression tree depth budget exceeded")
        if isinstance(current, Unary):
            pending.append((current.operand, depth + 1))
        elif isinstance(current, Binary):
            pending.extend(((current.left, depth + 1), (current.right, depth + 1)))
        elif isinstance(current, Call):
            pending.extend((a, depth + 1) for a in current.args)
    return node


def canonicalize(node: Node) -> str:
    if isinstance(node, Num):
        return node.literal
    if isinstance(node, Const):
        return node.name
    if isinstance(node, Unary):
        return f"({node.op}{canonicalize(node.operand)})"
    if isinstance(node, Binary):
        return f"({canonicalize(node.left)} {node.op} {canonicalize(node.right)})"
    if isinstance(node, Call):
        return f"{node.func}({', '.join(canonicalize(a) for a in node.args)})"
    raise TypeError(node)


# --------------------------- evaluation ---------------------------------
@dataclass(frozen=True)
class Result:
    value: Number
    domain: str          # "bigint" | "bigdecimal"
    precision: Optional[int]

    def as_strings(self) -> dict:
        if self.domain == "bigint":
            return {"domain": "bigint", "value": str(self.value)}
        return {"domain": "bigdecimal", "value": str(self.value),
                "precision": self.precision, "rounding": "ROUND_HALF_EVEN"}


class _Watchdog:
    def __init__(self, timeout_s: float):
        self.deadline = time.monotonic() + timeout_s

    def check(self) -> None:
        if time.monotonic() >= self.deadline:
            raise TimeoutExceeded("wall-clock watchdog exceeded")


def evaluate(source: str, precision: int = DEFAULT_PRECISION,
             timeout_s: float = DEFAULT_TIMEOUT_S) -> Result:
    """Pure evaluation with a wall-clock watchdog. No I/O of any kind."""
    if type(precision) is not int or not (1 <= precision <= 300):
        raise LimitError("precision must be 1..300 significant digits")
    if type(timeout_s) not in (int, float) or not 0 <= timeout_s <= 60 or not math.isfinite(timeout_s):
        raise LimitError("timeout must be finite and in 0..60 seconds")
    if timeout_s == 0:
        raise TimeoutExceeded("wall-clock watchdog exceeded")
    wd = _Watchdog(timeout_s)
    wd.check()
    node = parse(source)
    try:
        context = decimal.Context(prec=precision, rounding=DEFAULT_ROUNDING,
            Emin=-MAX_DECIMAL_EXPONENT, Emax=MAX_DECIMAL_EXPONENT, capitals=1, clamp=0,
            traps=[decimal.InvalidOperation, decimal.DivisionByZero, decimal.Overflow, decimal.Underflow])
        with localcontext(context):
            value = _eval(node, precision, wd)
            wd.check()
    except CalcError:
        raise
    except (decimal.Overflow, decimal.Underflow) as exc:
        # Error-contract hardening: decimal context signals must surface as
        # typed CalcError, never leak the raw decimal exception.
        raise LimitError("decimal overflow: magnitude exceeds the context "
                         "exponent range") from exc
    except (decimal.DecimalException, ArithmeticError) as exc:
        raise DomainError("invalid arithmetic operation") from exc
    if isinstance(value, int):
        return Result(value, "bigint", None)
    return Result(value, "bigdecimal", precision)


def _num_from_literal(text: str) -> Number:
    if re.fullmatch(r"[0-9]+", text):
        return int(text)                       # BigInt domain
    return Decimal(text)                       # BigDecimal domain


def _promote(a: Number, b: Number) -> tuple:
    if isinstance(a, int) and isinstance(b, int):
        return a, b
    return (Decimal(a) if isinstance(a, int) else a,
            Decimal(b) if isinstance(b, int) else b)


def _bounded(value: Number) -> Number:
    if isinstance(value, int):
        if value.bit_length() > MAX_INTEGER_BITS:
            raise LimitError("integer bit budget exceeded")
    elif not value.is_finite() or (value and abs(value.adjusted()) > MAX_DECIMAL_EXPONENT):
        raise LimitError("decimal magnitude outside supported range")
    return value


def _eval(node: Node, prec: int, wd: _Watchdog) -> Number:
    wd.check()
    value = _bounded(_eval_inner(node, prec, wd))
    wd.check()
    return value


def _eval_inner(node: Node, prec: int, wd: _Watchdog) -> Number:
    if isinstance(node, Num):
        return _num_from_literal(node.literal)
    if isinstance(node, Const):
        return _const(node.name, prec)
    if isinstance(node, Unary):
        v = _eval(node.operand, prec, wd)
        return v if node.op == "+" else (v.copy_negate() if isinstance(v, Decimal) else -v)
    if isinstance(node, Binary):
        left = _eval(node.left, prec, wd)
        right = _eval(node.right, prec, wd)
        return _binary(node.op, left, right, prec, wd)
    if isinstance(node, Call):
        args = [_eval(a, prec, wd) for a in node.args]
        return _call(node.func, args, prec)
    raise TypeError(node)


def _binary(op: str, a: Number, b: Number, prec: int, wd: _Watchdog) -> Number:
    if op == "^":
        if isinstance(b, Decimal) and b != b.to_integral_value():
            raise DomainError("non-integer exponents are not supported")
        if (b.copy_abs() if isinstance(b, Decimal) else abs(b)) > MAX_EXPONENT:
            raise LimitError(f"|exponent| exceeds {MAX_EXPONENT}")
        exponent = int(b)
        if a == 0 and exponent <= 0:
            raise DomainError("zero to a nonpositive power is undefined")
        if isinstance(a, int) and isinstance(b, int) and exponent >= 0:
            # Powers of two have an exact bit estimate; other bases use an upper bound.
            magnitude = abs(a)
            bits = (magnitude.bit_length() - 1) * exponent + 1 if magnitude and magnitude & (magnitude - 1) == 0 else magnitude.bit_length() * exponent
            if magnitude > 1 and bits > MAX_INTEGER_BITS:
                raise LimitError("integer power exceeds bit budget")
            return _bounded(pow(a, exponent))
        return Decimal(a) ** exponent
    a, b = _promote(a, b)
    is_int = isinstance(a, int)
    if op == "+":
        return a + b
    if op == "-":
        return a - b
    if op == "*":
        return a * b
    if op == "%":
        if b == 0:
            raise DomainError("modulo by zero")
        if not is_int:
            raise DomainError("% is defined on the bigint domain only (provisional DEC-05)")
        return a % b
    if op == "/":
        if b == 0:
            raise DomainError("division by zero")
        if is_int:
            if a % b == 0:
                return a // b                  # stays bigint when exact
            return Decimal(a) / Decimal(b)     # deterministic promotion rule
        return a / b
    raise ParseError(f"unknown operator {op!r}")


def _const(name: str, prec: int) -> Decimal:
    with localcontext() as ctx:
        ctx.prec = prec + 10
        if name == "e":
            v = Decimal(1).exp()
        elif name == "pi":
            v = _pi()
        else:
            raise DomainError(f"unknown constant {name}")
    with localcontext() as ctx:
        ctx.prec = prec
        return +v


def _pi() -> Decimal:
    from decimal import getcontext
    prec = getcontext().prec

    def arctan_inv(x: int) -> Decimal:
        total = Decimal(0)
        term = Decimal(1) / x
        x2 = x * x
        n = 0
        while term != 0 and n <= prec * 4:
            updated = total + term / (2 * n + 1) * (1 if n % 2 == 0 else -1)
            if updated == total:
                break
            total = updated
            term /= x2
            n += 1
        return total

    return 4 * (4 * arctan_inv(5) - arctan_inv(239))


def _call(func: str, args: list, prec: int) -> Number:
    def one() -> Number:
        if len(args) != 1:
            raise DomainError(f"{func} takes exactly one argument")
        return args[0]

    if func == "abs":
        value = one()
        return value.copy_abs() if isinstance(value, Decimal) else abs(value)
    if func == "floor":
        v = one()
        if isinstance(v, Decimal) and v.adjusted() > 2465:
            raise LimitError("integer conversion exceeds bit budget")
        return v if isinstance(v, int) else int(v.to_integral_value(rounding="ROUND_FLOOR"))
    if func == "ceil":
        v = one()
        if isinstance(v, Decimal) and v.adjusted() > 2465:
            raise LimitError("integer conversion exceeds bit budget")
        return v if isinstance(v, int) else int(v.to_integral_value(rounding="ROUND_CEILING"))
    if func in ("min", "max"):
        if len(args) < 2:
            raise DomainError(f"{func} takes at least two arguments")
        vals = args
        return min(vals) if func == "min" else max(vals)
    if func == "gcd":
        import math
        if len(args) < 2 or not all(isinstance(v, int) for v in args):
            raise DomainError("gcd takes two or more bigint arguments")
        return math.gcd(*args)
    if func == "sqrt":
        v = one()
        if isinstance(v, int):
            if v < 0:
                raise DomainError("sqrt of a negative number")
            import math
            r = math.isqrt(v)
            if r * r == v:
                return r                       # stays bigint
            v = Decimal(v)
        if v < 0:
            raise DomainError("sqrt of a negative number")
        with localcontext() as ctx:
            ctx.prec = prec
            return v.sqrt()

    v = one()
    d = Decimal(v) if isinstance(v, int) else v
    with localcontext() as ctx:
        if func in ("sin", "cos", "tan") and d and d.adjusted() > MAX_TRIG_MAGNITUDE:
            raise LimitError("trigonometric argument magnitude exceeds budget")
        ctx.prec = prec + 10 + (max(0, d.adjusted()) if func in ("sin", "cos", "tan") else 0)
        if func == "exp":
            out = d.exp()
        elif func == "ln":
            if d <= 0:
                raise DomainError("ln requires a positive argument")
            out = d.ln()
        elif func == "log10":
            if d <= 0:
                raise DomainError("log10 requires a positive argument")
            out = d.log10()
        elif func in ("sin", "cos", "tan"):
            out = _trig(func, d, max(1, prec - 4))
        else:
            raise DomainError(f"unknown function {func}")
    with localcontext() as ctx:
        ctx.prec = prec
        return +out


def _trig(func: str, x: Decimal, pole_digits: int) -> Decimal:
    pi = _pi()
    x = x % (2 * pi)
    if func == "tan":
        c = _trig("cos", x, pole_digits)
        if abs(c) < Decimal(10) ** (-pole_digits):
            raise DomainError("tan undefined at odd multiples of pi/2")
        return _trig("sin", x, pole_digits) / c
    total = Decimal(0)
    term = x if func == "sin" else Decimal(1)
    n = 0
    while term != 0 and n < 2000:
        updated = total + (term if n % 2 == 0 else -term)
        if updated == total:
            break
        total = updated
        if func == "sin":
            term = term * x * x / ((2 * n + 2) * (2 * n + 3))
        else:
            term = term * x * x / ((2 * n + 1) * (2 * n + 2))
        n += 1
    return total
