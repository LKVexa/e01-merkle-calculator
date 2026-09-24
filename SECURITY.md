# Security boundaries

The calculator runs in-process. Numeric/parser bounds and a cooperative
watchdog reduce resource exposure but are not an OS sandbox or hard deadline.
Decimal working precision does not guarantee final-expression accuracy.

The service has no user authentication. Every process/user able to reach
loopback may calculate and read ledger roots/proofs. Do not proxy or forward
the port. Host/Origin and JSON/framing checks do not identify callers. Worker
limits and socket inactivity timeouts are not total request deadlines.

Use a trusted private ledger directory and one process per path. Shared
in-process state does not coordinate separate processes, alternate path aliases
or hostile file replacement. Direct-link/metadata checks are not race-proof.
Windows ACLs are inherited; Unix mode 0600 applies only to new files.

Failed writes withhold calculation results and poison the active ledger state.
No automatic destructive recovery is performed. Preserve evidence and verify
copies before recovery. Merkle roots are unsigned and unanchored; editable
files can be rewritten into another self-consistent history. Inclusion proofs
do not prove completeness, append-only consistency or caller identity.

Responses echo expressions. Receipt hashes are unsalted and can reveal guessed
inputs; no anonymization or secret redaction is provided. Invalid request shapes
are not logged as calculation receipts. Manage capacity and retention externally.

No runtime third-party packages are required. The MIT C++ donor references are
not executed by the Python package. No build-tool vulnerability scan is claimed.
Report defects privately using synthetic expressions and ledger samples.
