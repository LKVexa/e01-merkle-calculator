# 0.1.2a1 — 2026-09-23

- Bound parser depth, numeric growth and conversions; isolate Decimal contexts.
- Make zero timeout deterministic and improve bounded trigonometric reduction.
- Commit ledger memory after durable writes; serialize shared instances.
- Preserve malformed tails and strictly validate bounded JSONL and proof shapes.
- Compute roots with an incremental frontier and expose atomic snapshots.
- Enforce loopback HTTP origin/framing/JSON, instance sinks and worker limits.
- Add 65 regressions, packaging, CI, README and Apache 2.0 LICENSE/NOTICE.
- Retain MIT reference files; original program decisions remain provisional.

# Changelog — E01 Local Calculator v2 baseline (JY-S021-P001)

## 0.1.1-partial — 2026-09-14

Hardening/repair release produced by the JY Individual Program Audit,
Upgrade & Hardening Factory (existing-program maintenance mode).
Repairs only: patch bump per policy. No donor code introduced.

Baseline fingerprint: build-0001 `product.zip`
sha256 `7da6b37c2ded2bc81e6955d283cb727701f94eb306409c5e3deba6d9f7b0ee47`
(39654 bytes), baseline version `0.1.0-partial`, baseline suite 38/38 PASS.

### Findings fixed (all reproduced on the baseline before patching)

- **A018-F1 — ledger crash-tail reload failure.** Observed: a torn final
  JSONL line (interrupted append) made `MerkleLedger(path)` raise a bare
  `json.JSONDecodeError`, leaving the service unable to start against its
  own ledger. Expected: WAL-style recovery. Fixed: load now validates
  line-by-line, truncates an unreadable *final* line (recording
  `recovered_tail_bytes`), and resumes appending cleanly.
- **A018-F2 — no tamper detection at load.** Observed: `MerkleLedger`
  trusted the stored `leaf_sha256` and never recomputed hashes, so a
  tampered receipt (with a stale leaf hash) loaded silently and the root
  chain went unchecked. Expected: tamper-evidence at load, matching
  `verify_ledger`. Fixed: load recomputes each leaf from the receipt and
  verifies `tree_size` and `merkle_root` per line; any mismatch before the
  final line raises the new typed `LedgerError` (code `E_LEDGER`).
- **A018-F3 — decimal exception leak from `evaluate`.** Observed:
  `evaluate("1e999999 * 1e999999")` raised raw `decimal.Overflow`,
  escaping the documented `CalcError` contract (the server masked it as
  `E_INTERNAL`). Fixed: decimal context signals are mapped to typed
  errors — `decimal.Overflow` → `LimitError`, other arithmetic signals →
  `DomainError`.

### Compatibility

- No public API removed or changed; all 38 baseline tests pass unchanged.
- New: `e01v2.__version__`, `merkle_ledger.LedgerError`,
  `MerkleLedger.recovered_tail_bytes`.
- Behavior change (intended): a corrupted/tampered ledger now fails to
  load with `LedgerError` instead of loading silently; a torn final line
  is truncated on load instead of crashing.

### Rollback

Restore the build-0001 `product.zip` (fingerprint above). Ledgers written
by 0.1.1-partial are format-identical and readable by 0.1.0-partial.
