# Security Boundary

The public repository includes source, tests, placeholder configuration, and
local startup tooling only. It excludes credentials, private paths, memory,
historical data, generated reports, logs, PID files, News, broker access, order
routing, and capital movement.

Services have no built-in authentication and should remain on loopback. The
LLM endpoint, model, external data root, log root, and PID root are operator
configuration. The startup script records process identity and stops only a
process whose PID, executable path, and start time match its own receipt.
