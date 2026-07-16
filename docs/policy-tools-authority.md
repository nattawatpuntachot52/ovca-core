# Policy Tools Authority

The Python implementation exposes 19 pure functions. Twelve have Rust/Python
parity coverage: `sati_check`, `temporal_gate`, `support_disclose`,
`certainty_zone`, `claim_tag`, `drift_check`, `scamper_fill`, `business_gate`,
`decision_format`, `pre_change_notice`, `plan_before_dispatch`, and
`dispatch_blocker_check`.

The remaining seven cognitive tools are Python-only advisory helpers:
`cognitive_route`, `analytical_frame`, `strategy_review`, `business_story`,
`storyselling_pitch`, `people_execution_plan`, and `leadership_alignment`.
Their presence does not prove runtime wiring or hard-gate enforcement. Any such
claim requires a caller-level test.

The Python `build_server()` surface is dependency-free ASGI compatibility for
embedding and tests; it is not a standalone HTTP server. The Rust
`ovca-policy-tools` binary is the authoritative HTTP service and binds only to
the IPv4 loopback interface.
