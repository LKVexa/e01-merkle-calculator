> Historical source baseline. Current changes and verification are in AUDIT.md and CHECK_RUNS.json; original certification status is not advanced.

# E01 v2 baseline status — canonical accounting (JY-S021-P001 build-0001)

Executor: Claude (model claude-fable-5), Anthropic cloud Linux container,
2026-09-14, Junkyard + Synthetic Batch Product Factory v2.0.0. Controlling
source: audited E01 master TODO v2.1.0 via package 2.1.0-PW1 (680
canonical tasks; carrier v2.2.4).

**Overall state:** IN PROGRESS — partial candidate. Per CTRL.T01 no task
is `DONE` without linked acceptance evidence, and per the decision rules
none of the implemented slices can close while their governing DEC
freezes are open; implemented work is therefore IN PROGRESS with current
test evidence, and decision/gate work is BLOCKED or NOT STARTED.

**Materially advanced groups (evidence = 38/38 passing tests,
`docs/CHECK_RUNS.json`):**
- P2-01 parser (Pratt, provisional DEC-02): precedence, associativity,
  implicit multiplication, error reporting.
- P1-06 grammar semantics slice via canonicalization tests.
- P3 numeric core: BigInt/BigDecimal domains, deterministic promotion,
  transcendental slice (sin, cos, tan, ln, log10, exp, pi, e).
- P4-04 zero-side-effect enforcement + wall-clock watchdog (kernel-level;
  sandbox-level BLOCKED).
- P5-03 Merkle receipts for every execution after the provisional DEC-06
  boundary, with inclusion proofs, file verification, tamper detection.
- P6-02 partial: seeded randomized property tests (Hypothesis proper
  UNRUN — package index unreachable from the build host).
- P6-04 partial: recursion/limit guards tested; fuzzing and sanitizer
  passes UNRUN.

**BLOCKED:** DEC-01..DEC-08 freezes (owner decisions); P4-01 WASM/WASI
micro-sandbox (needs DEC-03); P7-01/P7-03 performance and soak (no frozen
measurement boundary, and this Linux container is not the qualification
host); P8 SBOM/reproducible builds/signing (DEC-07/08); all gate and
release confirmation tasks (CTRL.T05 forbids substituting them with this
report).

**NOT STARTED:** the remaining canonical tasks, including linear algebra,
statistical kernels, and unit conversions (outside the provisional DEC-04
scope), N-AUDIT schema alignment, and certification-assurance groups.

**Highest-priority blockers:** (1) DEC-03 runtime selection — controls
the sandbox architecture; (2) DEC-05 formal freeze — controls numeric
certification; (3) native Windows qualification environment.

**Next executable items:** DEC decision records prepared for owner
sign-off; AST fuzzing harness; `ExecutionReceipt` schema alignment with
N-AUDIT; performance harness skeleton pending the DEC-03/P7 freeze.
