# Limitations

- This is a development distribution, not a hosted or hardened service.
- No private memory or historical dataset is bundled.
- News ingestion and legacy Aurora, Divina, and Hope servers are excluded.
- Legacy agent enum values remain only for serialized-data compatibility and
  have no public port or routing registration.
- Policy Tools produce structured guidance; most are not runtime hard gates.
- The runtime does not provide authentication, tenancy, or encrypted storage.
- The durable goal runtime is library-only. JSONL orchestration remains a
  single-writer-per-run caller obligation; SQLite provides the P2 execution
  lease and write-ownership authority.
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
  completion, or cancellation lifecycle changes yet.
- No live worker or provider integration validates the durable execution path.
- No trading, broker, order-routing, or capital-movement capability is enabled.
