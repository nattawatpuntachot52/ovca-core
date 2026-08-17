# ADR 0004: Disposable workspace tool capability boundary

- Status: Accepted
- Date: 2026-08-17
- Scope: Control Plane A03, contract version 1

## Context

The provider-neutral role execution port intentionally carries write-free invocation authority. Engineer file effects therefore need a separate, narrower admission boundary that does not turn role invocation JSON into a general command, filesystem, environment, or network capability.

Serialized lease, grant, snapshot, request, and receipt records are useful for deterministic interoperation, but their bytes cannot prove that the current runtime issued them or that their workspace still exists. Caller-authored `requested_at` also cannot safely decide whether authority is currently active.

## Decision

V1 is a library-only, local-experimental `WorkspaceCapabilityBroker`. One broker instance owns a private runtime identifier, a clock configured once by the trusted embedding, disposable workspace roots, and process-local canonical lease, grant, and idempotency registries.

The only admitted effects are broker-native `read_file` and `write_file`. Command, shell, Git, child process, environment injection, network, delete, rename, copy, directory creation, and link effects have no backend in V1. Unsupported requests carry only a closed kind and intent digest, never raw commands, environment values, URLs, host paths, or payloads.

`RoleExecutionRequest` and its invocation authority remain unchanged and write-free. Capability issuance uses a distinct active Coordinator `code_review` authority with a different identifier and digest. Its scope, visibility, sensitivity, principal, time window, and sorted permission keys must bind exactly to the invocation, lease, snapshot, grantee role, and granted logical paths. Engineer can receive exact read/write paths; Reviewer and Auditor receive read-only paths; Owner and Coordinator consume no grant.

`open_lease` and `issue_grant` return opaque, non-deserializable `TrustedWorkspaceLease` and `TrustedCapabilityGrant` handles. Tool execution accepts only `ToolRequestV1` plus out-of-band write bytes and resolves every authority value from the same broker registry. A DTO, reconstructed JSON value, foreign handle, closed lease, unknown identifier, substituted snapshot, or changed canonical bytes has no admission authority.

For a fresh request, process-local exact-duplicate and changed-payload idempotency checks run first. The broker then reads its clock once. That evaluation time—not `requested_at`—must be within the invocation authority, grant authority, grant, and lease half-open windows; the resulting receipt time is identical. Exact duplicate replay returns the cached opaque receipt and bounded read bytes without another clock read or backend call.

Logical paths are portable relative ASCII paths only. The broker rejects traversal, drive, UNC, device/verbatim, ADS, reserved-name, trailing-dot, and case-fold aliases. It materializes new ordinary bytes rather than reusing source links, rejects protected-root overlap, and immediately rechecks the owned root, ancestors, final target, hardlink/reparse status, and current snapshot before an effect. Wire records and receipts never contain physical host paths.

A denial has zero effect-backend calls and preserves snapshot digest and generation. A read returns bounded bytes out of band while its digest-only receipt preserves the snapshot. A write must match its declared digest, length, path, and byte cap; fresh same-content writes deny `no_change`. Success must change exactly one manifest entry and increment generation exactly once.

The runtime-only lease lifecycle is `Active -> CleanupRequired(reason) -> Closed`. Cleanup reasons are completed, cancelled, failed, and panicked. Normal close, internal backend failure, and Rust unwind clean broker-owned roots. A cleanup failure remains `CleanupRequired`; it is never reported as closed.

## Consequences

The boundary can make exact, testable claims about process-local API provenance and native file effects. It does not provide authentication, cryptographic or durable provenance, a kernel sandbox, privileged-race protection, crash recovery after hard process termination, cross-process deduplication, persistence, scheduling, event append, orchestration, or provider execution. Those concerns remain outside this issue, with durable recovery deferred to the next orchestration slice.

The Windows implementation reads ordinary-file link count through a minimal read-only file-handle metadata call because the pinned Rust toolchain does not expose that value through stable standard-library metadata. It creates no process and performs no network operation. Immediate rechecks reduce accidental drift under the single-owner threat model but do not claim adversarial no-follow isolation against a privileged concurrent swap.
