> Source decisions remain provisional. README documents the 0.1.2a1 engineering limits and stricter service/ledger behavior; no DEC approval is inferred.

# Provisional assumptions (unfrozen DEC decisions) — JY-S021-P001

Every entry is **BLOCKED on owner approval**; per CTRL rules, no task
touched by one of these can be `DONE` until the decision is frozen and
compatibility re-verified.

| Decision | Provisional value used by this build |
|---|---|
| DEC-01 (n=1 vs n=0 boundary) | Protected boundary = the in-process evaluation kernel `engine.evaluate`. Terminology not reconciled. |
| DEC-02 (parser strategy) | Pratt / precedence-climbing selected provisionally; precedence table and depth behavior documented in `e01v2/engine.py`. |
| DEC-03 (WASM/WASI runtime + 127 server) | No runtime selected — the micro-sandbox is NOT implemented; in-process kernel + wall-clock watchdog substituted and recorded. Loopback = IPv4 127.0.0.1 only; IPv6 loopback provisionally out of scope; default-deny capability manifest not implementable without the runtime. |
| DEC-04 (function/kernel scope) | Provisional scope: + - * / % ^, abs, floor, ceil, min, max, gcd, sqrt, sin, cos, tan, ln, log10, exp, pi, e. Linear algebra, statistical kernels, and unit/dimensional analysis NOT included. |
| DEC-05 (numeric semantics) | BigInt = Python int; BigDecimal = decimal.Decimal, default 60 sig. digits, ROUND_HALF_EVEN; promotion: int stays int when exact, `/` promotes on inexactness, any Decimal operand promotes; `%`/`gcd` bigint-only. |
| DEC-06 (execution boundary for receipts) | Execution begins after strict request-shape validation; accepted attempts receive receipts unless the ledger write fails and the result is withheld. Malformed request/route rejections do not receive receipts or a separate audit log. |
| DEC-07 (cryptographic profile) | SHA-256 for Merkle commitments (matching the merklecpp donor default). Artifact signing, key custody, and rotation NOT defined or implemented. |
| DEC-08 (SBOM) | Not frozen; no SBOM produced. Third-party inventory limited to THIRD-PARTY-NOTICES.md. |
| Watchdog budget | Default 2.0 s wall-clock per evaluation — provisional engineering value. |
