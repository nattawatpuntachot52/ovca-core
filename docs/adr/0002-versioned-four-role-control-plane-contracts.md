# ADR 0002: Versioned four-role control-plane contracts

- Status: Accepted
- Contract version: 1
- Scope: additive public data contracts and pure validation only

## Context

The public control plane needs one provider-independent wire contract for an
Owner to invoke a Coordinator and for a Coordinator to invoke an Engineer,
Reviewer, or Auditor. A valid JSON shape alone must not imply authentication,
authority admission, execution, persistence, or completion.

The shared Foundation contracts already define five principals, hierarchical
scope, authority assertions, and a replayable event envelope. This decision
composes those contracts instead of changing or duplicating them. Existing Goal
Runtime wire shapes remain unchanged.

## Decision

The additive `ovca_types::control_plane` module defines:

- `ExecutionBudget`
- `RoleInvocationV1`
- `RoleResultV1`
- `RoleResultPayloadV1`
- `ControlPlaneState`
- `ControlPlaneEvent`
- `ControlPlaneEventPayload`
- deterministic canonical-digest and replay validators

Every top-level struct carries exact contract version `1` and rejects unknown
fields. The state is a plain snake-case JSON string. Only the result and event
payload unions use the closed discriminator field `type`.

## Closed invocation boundary

Allowed invoker-to-target pairs are exactly:

| Invoker | Target |
|---|---|
| Owner | Coordinator |
| Coordinator | Engineer |
| Coordinator | Reviewer |
| Coordinator | Auditor |

All other pairs, same-principal calls, and Owner as a worker target fail closed.
The four worker roles reuse the existing `Role` values. Owner remains a
Foundation principal and has no implicit legacy worker role.

An invocation binds its ID, invoker, target, task, run, full
project/goal/task/run scope, execution budget, idempotency key, embedded
authority assertion, authority digest, input digest, and invocation time.
Top-level task and run IDs must equal their nested scope values.

## Authority assertion and canonical bytes

`RoleInvocationV1` embeds one exact `FoundationAuthorityV1`. Its namespace must
be `code_review`; principal and scope must equal the invocation; validity must
be active at the invocation time under the Foundation half-open validity
window. The required `authority_digest` is the lowercase SHA-256 of compact
UTF-8 JSON emitted from the typed authority in declared field order, without a
BOM or trailing newline.

The same canonical rule applies to immutable invocation bytes, result bytes,
and tagged event-payload bytes. A mismatched digest fails closed. These checks
bind caller-supplied assertions; they do not authenticate a principal, resolve
the current authority record, or grant durable admission.

## Budget and idempotency

V1 has one budget dimension: unsigned `max_attempts`, including the first
attempt, with exact range `1..=u32::MAX`. Time, token, tool, output, workspace,
network, provider, and persistence budgets are outside this decision.

One logical invocation is immutable across retries. Attempt ordinals are
one-based and carried by events and results. The invocation ID, canonical
invocation digest, and idempotency key do not change between attempts. Reusing
an ID or idempotency key with different bytes is a conflict for a later
admission layer; this contract performs no lookup or storage.

## State, results, and explicit completion

Closed states are `pending`, `running`, `completed`, `failed`, and `cancelled`.
Allowed event-derived transitions are:

| Event payload | Transition |
|---|---|
| `invocation_submitted` | none to pending |
| `attempt_started` | pending to running |
| `retry_scheduled` | running to pending |
| `invocation_completed` | running to completed |
| `invocation_failed` | running to failed |
| `invocation_cancelled` | pending or running to cancelled |

Submission initializes the current attempt to `1`. A retry must name the
running attempt and set `next_attempt` to exactly one greater without overflow
or exceeding the budget. Pending start, every terminal event, and its result
must bind the exact current attempt, including cancellation before a start.

Completed, failed, and cancelled are terminal. Self-transitions, skipped or
reversed transitions, and all mutation after a terminal event fail closed.

A terminal transition requires exactly one matching immutable result whose ID
and canonical digest are present in the event. Result identity, invocation,
producer, task, run, scope, idempotency key, attempt, and time must match. The
payload mapping is exact:

- Coordinator plus completed: `owner_final { response }`
- Engineer, Reviewer, or Auditor plus completed: `specialist { summary }`
- any worker plus failed: `failure { code, message }`
- any worker plus cancelled: `cancellation { reason }`

Result text is trimmed, nonempty, control-free, and at most 4096 Unicode scalar
values. Completed results require a nonempty strict byte-ordinal unique evidence
list. Failed and cancelled results may omit evidence but any supplied list must
remain strictly ordered and unique. A state string, unmatched result, or prose
alone never establishes completion.

## Foundation event-envelope composition

`ControlPlaneEvent` contains exactly `contract_version`, one
`FoundationEventEnvelopeV1`, and one tagged payload. Envelope identity, domain,
scope, producer, event kind, sequence, predecessor, time, and payload digest are
not duplicated at the event top level.

The envelope domain is `control_plane`. Event kind is exactly
`control.<payload type>`. Sequence zero is submission with no predecessor;
later events are contiguous and name the exact previous event. Submission is
produced by the invoker; later events are produced by the target. Envelope scope
equals invocation scope and its payload digest binds canonical tagged payload
bytes.

Submission time is not earlier than invocation time. Each later event is not
earlier than its predecessor. A terminal result time lies within the inclusive
interval from invocation time through terminal-event time. Equal timestamps are
allowed. These are deterministic replay constraints, not trusted-clock claims.

## Schemas and semantic boundary

Five Draft 2020-12 schemas close structural versions, fields, enums, tagged
payload shapes, and simple numeric bounds. They reference the canonical
Foundation authority definitions and event-envelope schema through a finite
local registry. They do not copy Foundation wire definitions or retrieve remote
resources.

Rust validation remains authoritative for role pairs, full-scope equality,
authority/time/digest binding, canonical collection order, exact event mapping,
attempt ownership, replay continuity, result linkage, and explicit completion.
Schema success never upgrades an assertion into runtime authority.

Five synthetic samples share one invocation, result, and terminal event. Their
digests are computed over the exact typed compact JSON bytes. The Python parity
suite uses duplicate-aware JSON loading and a finite local schema registry.

## Compatibility

The module is exposed only as `pub mod control_plane;`; it is not glob-exported.
Foundation and Goal Runtime serialized bytes and behavior are unchanged.

Compatibility is explicit and fallible only:

- `ExecutionBudget` and legacy `RetryBudget`
- completed Coordinator `owner_final` and `CoordinatorFinalResponse`
- completed specialist result and `SpecialistOutput`

There is no implicit conversion to task/run status, run events, Foundation
decisions, durable state, or current-authority admission.

## Non-goals

This decision adds no provider integration, worker process, scheduler, trusted
clock, credential, filesystem or Git mutation, persistence, network service,
runtime admission, or automatic Goal Runtime append. Those behaviors require
separate reviewed contracts and are not implied by these types.
