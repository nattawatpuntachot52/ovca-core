# ADR 0005: Durable Engineer-to-Verifier loop

- Status: Accepted
- Date: 2026-08-17
- Scope: Control Plane A04, internal contract version 1

## Context

ADR 0004 admits only bounded native file reads and writes in a disposable
workspace. Its trusted lease, grant, and receipt handles are deliberately
process-local. A longer Engineer-to-Verifier flow also crosses SQLite lifecycle
state, append-only JSONL history, local verification commands, and EvidenceBank
publication. None of those surfaces may silently substitute for another's
authority, and a crash between surfaces must not repeat an already-applied
write or admit stale verification evidence.

The existing provider-neutral `RoleExecutor` has no workspace or tool
authority. The existing verifier is an independent, reviewed local command
runner. This issue connects those components without adding a general command
runner, new database table, public wire contract, or cross-medium transaction.

## Decision

The controller persists one optional, deny-unknown-fields
`EngineerVerifierStateV1` inside the existing versioned execution envelope.
The immutable `EngineerLogicalPlanV1` contains zero or more `read_file`
templates followed by at most one final `write_file`. Every plan, attempt,
effect, ledger, diff, state, replay plan, and phase-event identifier uses its
specified ASCII domain, one NUL byte, and compact declared-order JSON. Raw write
payloads remain caller-resupplied and outside durable state.

SQLite is the lifecycle, fencing, retry, cancellation, prepared-effect, and
admission authority. `RunEventLog` is only a projection. Before append, SQLite
stores the exact canonical event bytes, digest, sequence, and predecessor. On
recovery, exactly one missing frozen event may be appended, or an already
identical event may be acknowledged. Any other JSONL advancement or byte drift
fails closed. This relies on the explicit P1 rule that the controller is the
sole writer for the run.

Native workspace effects and cleanup are excluded from concurrent recovery or
Engineer-Verifier CAS by a stable `workspace-effects.lock` sidecar beside the
existing SQLite database. The sidecar is an ordinary canonical file, is never
deleted or replaced, contains no authority or credentials, and is held only
while durable ownership is reloaded and the bounded native action completes.
Acquisition is bounded and fails closed. Windows uses exclusive file sharing;
the supported Unix target allowlist uses advisory `flock`. SQLite CAS remains
the sole fact and ownership authority; the sidecar adds no lifecycle state,
lease decision, database table, or independent service.

The Engineer call boundary is `not_started -> started -> outcome_recorded`.
Only the winner of the started CAS invokes `RoleExecutor`. A recovered started
call without a durable outcome is terminal `executor_outcome_unknown`; it is
never reinvoked and authorizes no planned effect. A valid Completed result is
required before tool execution. RetryRequired closes and removes the current
owned workspace before an attempt-specific binding and fresh lease can be
claimed. Failed, timed-out, and cancelled outcomes execute no tool effect.

Same-content final writes return `no_change` before lifecycle creation, event
append, verifier work, or broker backend invocation. Once lifecycle exists, a
write is first persisted as `PreparedWriteEffectV1`. Its before file must equal
the target entry in the before snapshot, and its after snapshot must be the
exact target-only replacement or insertion; no-op or unrelated deltas fail
validation. Recovery classifies the
physical workspace as exact expected-before, exact intended-after, missing, or
third-state. Expected-before permits one revalidated broker call;
intended-after records a reconciliation and ledger entry without forging a
trusted receipt; every other state fails closed. Durable tool observations are
canonical receipt DTO bytes and snapshots only, never reconstructed opaque
authority.

Workspace recovery requires a private, non-Serde permit minted only by a
successful SQLite fence CAS. The permit binds the new runtime identity and
epoch, invocation and attempt, lease and grant bytes/digests, immutable initial
snapshot, current or prepared snapshot, recovery token, fence, and next receipt
sequence. Re-adoption exposes no host path. Heartbeats strictly increase under
the current fence and remain inside the lease and grant windows. Cleanup closes
the durable disposition only after the owned root is removed. A stale broker
cannot execute, seal, or remove a root after a successor fence; an unadopted
pre-lifecycle root remains removable by the broker that created it.

Before verifier execution, the controller seals the workspace into one
populated disposable source copy and one distinct empty snapshot directory. It
persists a digest-only `VerifierReplayPlanV1`; behavior, capability, selection,
source-manifest, failure-identity, executable-path, environment-value, and temp
path bytes are not copied into that plan. Every initial or recovered execution
requires exact caller resupply and validates all digests and actor/scope
bindings before temp creation or command preparation.

Verifier state is `not_started -> started -> publication_observed -> admitted`.
A fresh run requires an absent EvidenceBank projection. Recovery from started
reruns reviewed local verification against the authoritative absent projection
or, if publication already exists, against a disposable replay-only bank. In
the latter case, the candidate transcript-bound bundle must be byte-identical
to the authoritative record and current binding; authoritative current is not
mutated. Publication-observed recovery performs no rerun. Final promotion to
reviewing happens only inside `EvidenceBank::with_completion_admission_lease`
after the exact current PASS record is reloaded and revalidated. A pending
cancellation wins before admission but cannot reinterpret an ambiguous
in-flight Engineer call as cancellation.

The closed lifecycle is `planned`, `engineering`, `retry_pending`, `verifying`,
`reviewing`, `failed`, and `cancelled`. Reviewing, failed, and cancelled are
terminal. Reviewer and Auditor execution, Git or GitHub mutation, arbitrary
commands, provider calls, environment injection, canonical-memory writes,
network effects, and Issue 7 commit behavior have no path in this controller.

## Consequences

The loop can make deterministic local-experimental claims about its native
workspace writes, durable call boundaries, projection reconciliation, and
exact-current verifier admission. It does not provide a distributed
transaction, multi-writer JSONL compare-and-append, production scheduling,
kernel sandboxing, durable external-provider exactly-once execution, hard-kill
cleanup, production egress enforcement, or product validation. Verifier egress
remains the existing `policy_only` boundary, and crash safety is limited to the
frozen native file-effect model.
