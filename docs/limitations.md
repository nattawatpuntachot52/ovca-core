# Limitations

- This is a development distribution, not a hosted or hardened service.
- No private memory or historical dataset is bundled.
- News ingestion and legacy Aurora, Divina, and Hope servers are excluded.
- Legacy agent enum values remain only for serialized-data compatibility and
  have no public port or routing registration.
- Policy Tools produce structured guidance; most are not runtime hard gates.
- The runtime does not provide authentication, tenancy, or encrypted storage.
- The durable goal runtime is library-only and single-writer-per-run. It has no
  claim, lease, compare-and-swap, heartbeat, retry, cancellation, or worker
  execution protocol yet.
- Planned-run bootstrap events are synced one JSONL line at a time. A storage
  failure between lines can leave a replayable partial bootstrap that requires
  caller-managed recovery.
- No trading, broker, order-routing, or capital-movement capability is enabled.
