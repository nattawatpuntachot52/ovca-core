# Limitations

- This is a development distribution, not a hosted or hardened service.
- No private memory or historical dataset is bundled.
- News ingestion and legacy role servers are excluded.
- Legacy agent enum values remain only for serialized-data compatibility and
  have no public port or routing registration.
- Policy Tools produce structured guidance; most are not runtime hard gates.
- The runtime does not provide authentication, tenancy, or encrypted storage.
- The durable goal runtime is library-only. JSONL orchestration remains a
  single-writer-per-run caller obligation; SQLite provides the P2 execution
  lease and write-ownership authority, and the P3 approval ledger separately
  owns approval state and consumption. Execution and approval use separate
  `execution_run:` and `guard_approval:` entity namespaces in the same SQLite
  versioned-state database.
- Planned-run bootstrap events are synced one JSONL line at a time. A storage
  failure between lines can leave a replayable partial bootstrap that requires
  caller-managed recovery.
- JSONL planning and SQLite execution initialization are two ordered durable
  operations, not one transaction. A missing SQLite run after `create_run` is a
  recoverable bootstrap gap handled by retrying `initialize_execution` with the
  identical definition.
- There is no cross-process integration test for the combined two-store runtime
  yet; the SQLite authority has independent-connection concurrency coverage.
- There is no JSONL projection or outbox for SQLite claim, heartbeat, retry,
  completion, or cancellation lifecycle changes yet. The only P3 projection is
  the closed guard result; it is not an approval-ledger replica.
- `ApprovalAuthority::ExplicitOwner` is a caller assertion, not authentication,
  tenancy, credential, or identity proof.
- R2 approval is consumed before the effect closure. Consumption and an external
  side effect are not one transaction; failure or panic after consumption is
  at-most-once/no-retry and can leave no external effect.
- P3 returns Reviewer and Auditor requirements but does not create their
  decisions. P4 separately enforces structurally valid, replayable decisions
  before completion; it does not assess external evidence bytes, authenticate a
  reviewer or auditor, or validate live human/model judgment quality.
- The APIs expose no combined execution-plus-approval transaction in shared
  SQLite. JSONL and SQLite are the two durable media and have no cross-medium
  transaction, outbox, or reconciliation guarantee. P3 evaluation and its
  redacted JSONL append can therefore be separated by failure.
- R3 is denied by default. P3 has no live HTTP, provider, service, authentication,
  or credential wiring.
- No live worker or provider integration validates the durable execution path.
- Goal runtime traces intentionally omit event metadata, free-form payloads, raw
  IDs, and external evidence references. They cannot be used to recover those
  values.
- Read-only goal runtime evaluation covers JSONL orchestration evidence,
  including recorded redacted P3 outcomes. It does not project SQLite lease,
  retry, cancellation, idempotency, exact guard request, approval identifier, or
  approval-ledger records into the trace.
- P2 and P3 evidence reducers expose typed authority results separately.
  `GuardRequest` has no run ID; `evaluate_run_guard_and_record` accepts one
  explicitly and associates only the closed projection.
- The trace completeness threshold is enforced against a deterministic
  regression fixture. It is not a production telemetry SLO, and no hosted
  ingestion, retention, sampling, alerting, or dashboard exists.
- No trading, broker, order-routing, or capital-movement capability is enabled.
