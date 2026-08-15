# Security Boundary

The public repository includes source, tests, placeholder configuration, and
local startup tooling only. It excludes credentials, private paths, memory,
historical data, generated reports, logs, PID files, News, broker access, order
routing, and capital movement.

Services have no built-in authentication and should remain on loopback. The
LLM endpoint, model, external data root, log root, and PID root are operator
configuration. The startup script records process identity and stops only a
process whose PID, executable path, and start time match its own receipt.

The P3 goal guard is a library-only execution boundary, not an authentication or
authorization service. `ApprovalAuthority::ExplicitOwner` is a typed assertion
supplied by the embedding caller; it is not proof of identity, tenancy,
credentials, or session ownership. R3 requests are denied by default. P3 has no
live HTTP, provider, credential, or service wiring.

R2 approval is consumed before the effect closure is called. Ledger consumption
and an external side effect are not one transaction. A failure or panic after
consumption can therefore produce at-most-once/no-retry behavior and may leave no
external effect. Orchestration, execution lifecycle, and approval are separate
logical authorities over two durable media. Execution and approval use separate
entity namespaces in the same SQLite versioned-state database, and current APIs
expose no combined transaction across them. JSONL and SQLite have no cross-medium
transaction, outbox, or reconciliation guarantee.
