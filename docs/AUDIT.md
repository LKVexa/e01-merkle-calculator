# Audit and hardening — 0.1.2a1

Date: 2026-09-23. Source: JY-S021-P001 / 0.1.1-partial / run-0001 / product.
Reviewed Python engine, ledger, HTTP server, tests and donor attribution.
Original source remains separate from this delivery checkout.

## Repaired findings

- Integer powers and Decimal-to-int conversions could allocate unbounded values;
  literals, magnitude, result bits and power preflight now impose budgets.
- Recursive expressions could leak RecursionError; parser-call and AST-depth
  limits return typed errors. Precision/timeout types and finite bounds are strict.
- The zero-timeout test failed on the baseline because equal monotonic samples
  did not expire. Zero now fails deterministically, with completion checks too.
- Ambient Decimal context influenced results and traps; explicit isolated contexts
  fix that. Quiet sign/absolute-value operations preserve digits. Exponent limit
  comparisons cannot round under low precision. Overflow/underflow use E_LIMIT.
- Trigonometric reduction lacked magnitude guard digits and numerical pole
  rejection. Bounded extra precision and convergence stopping repair those paths
  without claiming a rigorous numerical error bound.
- Ledger append advanced memory before durable write and could diverge after
  failure. Shared path state, prospective frontier calculation, write/flush/fsync
  before publication and failed-state refusal close that path.
- Automatic crash-tail recovery could silently erase corrupt evidence. Loading
  and verification now strictly reject and preserve malformed/incomplete files.
  Strict bounded JSON, exact entry shape and root/size checks cover every line.
- Multiple instances could append conflicting trees. They now share a lock and
  state in one process. Roots/sizes are exposed as one atomic snapshot; proofs
  reject negative/bool indices and validate path shape and digest encoding.
- Recomputing the whole Merkle tree for every entry was quadratic. An incremental
  frontier computes roots in logarithmic work and is checked against the separate
  pairwise tree implementation across 65 sizes; all paths are checked through 17.
- HTTP accepted coerced precision, malformed expression types, duplicate JSON,
  ambiguous framing and arbitrary origins. Strict loopback Host/Origin, bounded
  workers, socket inactivity timeout, request shape/framing and instance-bound
  ledgers now protect the supported factory. Receipts bind response/version/
  precision and use monotonic durations. Unexpected execution errors are receipted.

## Evidence and limits

Baseline: 49 tests, one watchdog failure on Windows. After changes: 114 tests,
zero failures/errors; one Unix-mode assertion is skipped on Windows. 65 new
regressions cover numeric resources/context, libm comparisons, file preservation,
failed fsync, shared-instance concurrency, strict proofs/JSON and HTTP failures.
Three inherited tail-recovery checks now require refusal and unchanged bytes;
the inherited version assertion was updated. Fixture file handles were closed.

Source and installed-wheel suites are recorded in CHECK_RUNS.json; original
evidence is retained in BASELINE_CHECK_RUNS.json. CI covers Python 3.10/3.12/3.14
on Linux and 3.12 on Windows. libm provides an independent ordinary-precision
trigonometric check; higher-precision stability uses the same implementation and
does not establish arbitrary-precision correctness. C++ references are not built.

Version 0.1.1-partial -> 0.1.2a1. README documents numerical limits, strict HTTP
requirements, legacy ledger compatibility, refusal of automatic truncation,
unsigned roots, non-race-proof metadata checks and single-process ownership.
No runtime dependencies require upgrades. Packaging, pinned-action CI, README,
security notes and Apache 2.0 LICENSE/NOTICE name RUSSELL PHILIP SMITHSON.
Microsoft's MIT merklecpp reference license remains intact.

The original DEC decisions/program certifications remain open. The cooperative
watchdog is not WASM/WASI isolation; no certified performance, error bounds,
authenticated storage, complete-history proofs or release signing is claimed.
