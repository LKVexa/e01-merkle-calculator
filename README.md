# E01 Merkle Calculator

**0.1.2a1 — experimental partial candidate, JY-S021-P001**

A Pratt-parser expression library with bounded BigInt/Decimal arithmetic and
an optional loopback JSON service that records Merkle receipts. This is the
separate E01 v2 baseline, delivered independently from JY-S020-P001.

## Install and use

Python 3.10+; no third-party runtime packages.

~~~sh
python -m pip install .
python -m unittest discover -s tests -t .
python -m e01v2.server --port 8124 --ledger audit/merkle_ledger.jsonl
python -m e01v2.merkle_ledger audit/merkle_ledger.jsonl
~~~

~~~python
from e01v2.engine import evaluate
from e01v2.merkle_ledger import MerkleLedger, verify_proof

assert evaluate("2^4096 / 2^4090").value == 64
print(evaluate("sqrt(2) + 1/3", precision=50).as_strings())
ledger = MerkleLedger("audit/example.jsonl")
ledger.append({"example": "receipt"})
assert verify_proof(ledger.proof(0))
~~~

## Arithmetic contract

Supports +, -, *, /, %, ^ and **, unary signs, implicit multiplication,
abs, floor, ceil, min, max, gcd, sqrt, sin, cos, tan, ln, log10, exp, pi and e.
Powers associate right and bind above unary signs: -2^2 is -4. Exponents must
be integers; zero to a nonpositive power is rejected. Integer arithmetic and
perfect-square roots stay exact within the bit budget. Inexact division and
mixed arithmetic promote to Decimal; min/max preserve the selected value's
domain. Modulo and gcd require integer-domain operands. Decimal literals are
kept as written; unary signs and abs preserve their digits.

precision is a working significant-digit setting (1..300, default 60), not a
rigorous accuracy guarantee for an expression. Intermediate Decimal rounding,
cancellation and rounded trigonometric inputs may lose accuracy. Noninteger
power support and interval/error-bound arithmetic are not supplied. Contexts
use ROUND_HALF_EVEN and explicit exponent/trap settings independent of callers.

Budgets: 8,192 expression characters, 2,048 tokens, 100 parser-call nesting
levels, 150 AST levels, 1,000 digits per literal, scientific/Decimal adjusted
exponents within ±10,000, absolute integer powers at most 8,192, integer results
at most 8,192 bits. Power preflight is conservative for bases other than powers
of two. Trigonometric arguments with adjusted exponent over 100 are rejected;
large arguments receive extra reduction precision and unresolved tangent poles
are rejected. Canonical text describes the AST, not algebraic equivalence.

The cooperative monotonic watchdog defaults to two seconds and accepts 0..60;
zero always fails. It checks between bounded operations and on completion. It
cannot interrupt an individual Python/Decimal operation or provide a hard CPU
deadline. The pure evaluation function performs no file or network I/O, but
runs inside the caller's process. WASM/WASI isolation is not implemented.

## HTTP contract

- GET /v2/health reports one consistent ledger size/root snapshot.
- POST /v2/calculate accepts UTF-8 JSON with a string expression and optional
  integer precision, for example {"expression":"2^64","precision":60}.
- GET /v2/proof/<index> returns a positional inclusion proof for an existing leaf.

The supported create_server/serve factory binds 127.0.0.1 only, limits active
workers to eight, and applies a three-second socket inactivity timeout. Excess
workers are disconnected. Host must exactly match 127.0.0.1:<port>; Origin, if
present, must match http://127.0.0.1:<port>. Requests require one decimal
Content-Length and application/json, with a 64 KiB body cap. Duplicate headers,
transfer encoding, duplicate JSON keys, nonfinite JSON, coercion of precision,
unknown fields and lone Unicode surrogates are rejected. Responses close the
connection and disable caching. There is no CORS or caller authentication.

Any local process/user able to reach loopback can connect. Host/Origin checks
reduce browser-origin and DNS-rebinding exposure; they do not authenticate
clients. Do not forward the port or expose it through a proxy/network bind.
These controls are not a full hostile-client sandbox or rate limiter.

Malformed requests use 400/403/413/415 (408 for an incomplete body timeout),
calculation errors use 422, unexpected engine errors use 500/E_INTERNAL, and
ledger write failures use 500/E_AUDIT with the result withheld. Health/proof
reads use 503 when the ledger is unavailable. Accepted calculation attempts,
including calculation/internal failures, are receipted before responding.
Malformed transport/request shapes and route rejections are not audit receipts.

## Ledger and proof boundaries

Each JSONL entry binds a strict JSON receipt, its SHA-256 leaf, tree size and
root. The preserved merklecpp scheme hashes raw receipt JSON bytes for leaves,
hashes left||right for internal nodes and carries odd nodes upward unchanged.
The empty-tree sentinel is SHA-256 of empty bytes. This unprefixed scheme is
retained for compatibility; it is not RFC 6962. verify_inclusion checks hash
membership only. verify_proof also checks the path shape for the claimed index
and size. Both require a separately trusted root for meaningful verification.

Receipts include timestamp, monotonic duration, precision, engine version,
expression hash, status/outcome and a hash of the response before receipt
metadata is attached. Raw expressions/results are omitted; unsalted hashes are
not anonymization. The response still echoes the expression to its client.

Ledger instances for the same normalized path share state and serialization
within one process. Append publishes memory only after write/flush/fsync succeeds;
an uncertain failed write poisons that state and further use is refused.
Read-only verification never changes files. Incomplete or malformed lines,
duplicate/nonfinite JSON, unexpected fields, blank lines and mismatched roots
fail closed. No automatic tail truncation occurs. Well-formed baseline records
retain their original hash encoding and can still be read.

Limits: 10,000 receipts, 16 MiB per file, 64 KiB per line, 32 receipt nesting
levels and 10,000 JSON values. A frontier avoids recomputing the whole tree on
every append; proofs still traverse the bounded leaf collection. Rotate/export
ledgers manually before reaching limits, preserving a trusted root separately.
No automatic rotation, retention, external root anchoring or signatures exist.

Use a private trusted directory and one owning process per ledger path. New
Unix files request mode 0600; Windows ACLs are inherited. Existing permissions
are unchanged. Direct symlinks/reparse files are refused and file metadata is
checked for unexpected changes. These checks are not race-proof or cross-process
locking and do not secure untrusted parent directories. The file remains
editable: wholesale rewriting/truncation can create a self-consistent different
ledger. Merkle membership is not proof of completeness, authenticity or an
append-only history. After a failed write, stop all users, preserve the file,
verify a copy and investigate before starting a new ledger or reopening a
verified intact one. Never discard a tail merely because it is malformed.

## Verification and compatibility

114 tests: 49 inherited checks and 65 added regressions. Source and installed
wheel suites pass locally (one Unix-mode assertion skipped on Windows).
CI covers Linux Python 3.10/3.12/3.14 and Windows Python 3.12. See
[CHECK_RUNS](docs/CHECK_RUNS.json), [AUDIT](docs/AUDIT.md) and [SECURITY](SECURITY.md).
The retained C++ files are reference material; they are not compiled or executed.

0.1.1-partial -> 0.1.2a1 introduces strict HTTP/numeric limits and refuses corrupt
ledger tails instead of truncating them. Three inherited recovery checks now
assert refusal and byte preservation. The version check was updated. Callers
must send integer precision, the correct Host and JSON content type. Empty-file
verification now reports the same empty-root sentinel as the live ledger.

The original DEC-01..DEC-08 decisions, 680-task program, WASM/WASI isolation,
formal accuracy/performance qualification, Hypothesis coverage, SBOM and signed
provenance remain open. This release does not advance those certifications.

## License

Copyright 2026 **RUSSELL PHILIP SMITHSON**.
Original Python code and modifications: [Apache License 2.0](LICENSE) and
[NOTICE](NOTICE). Microsoft's MIT merklecpp reference files retain their
upstream license; see [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES.md).
