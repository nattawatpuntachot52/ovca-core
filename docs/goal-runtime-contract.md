# Goal Runtime Contract

## Status and boundary

The goal runtime contract is `contract_available` in `ovca-types`. Versioned
Rust and JSON models plus a pure run-state transition validator are available to
embedding callers.

P1 and P2 consume those contracts through a `runtime_wired`, library-only path. It can
schedule tasks, append strict run events under an external root, validate an
event chain, deterministically replay a `RunRecord`, and maintain an independent
SQLite execution lifecycle with leases and write ownership. This is not a
service: startup does not launch it and no HTTP endpoint exposes it. It does not
invoke workers, request live approvals, perform reviews or audits, call
providers, or authorize external side effects.

## Contract version

Every top-level contract carries `contract_version`. P0 uses integer version `1`,
exposed as `GOAL_RUNTIME_CONTRACT_VERSION` and
`ContractVersion::current()`. The new contracts are additive; existing
`ovca-types` fields and serialized shapes are unchanged.

IDs and timestamps are supplied by the caller. The contract layer does not read a
clock or generate UUIDs, which keeps fixtures and replay inputs deterministic.

## Public identities and roles

The following IDs are transparent JSON string wrappers:

- `ProjectId`
- `GoalId`
- `TaskId`
- `RunId`
- `EvidenceId`
- `EventId`

Goal runtime assignments and event producers use only the public `Role` values:
`coordinator`, `engineer`, `reviewer`, and `auditor`.

## Contracts

| Contract | Purpose |
|---|---|
| `Project` | Groups goal IDs with a stable identity, name, description, and timestamps |
| `GoalContract` | Records objective, constraints, acceptance and verification criteria, permission profile, definition of done, and completion precondition |
| `Task` | Represents one distinct outcome with dependencies, assigned role, resource/write keys, status, and timestamps |
| `RunRecord` | Represents a reconstructable run snapshot and its last applied event position |
| `RunEvent` | Represents one ordered, linked replay input with a typed payload and deterministic metadata ordering |
| `EvidenceRef` | Identifies evidence kind, reference, producer role, optional integrity digest, and production timestamp |
| `PermissionProfile` | Declares risk tier, resource/write keys, and independent approval, review, and audit requirements without granting authority |
| `CompletionEvidence` | Supplies evidence IDs plus satisfied acceptance, verification, and definition-of-done items to the completion validator |

Nested structures such as `PermissionProfile`, `CompletionPrecondition`,
`IntegrityMetadata`, and `CompletionEvidence` also carry an explicit contract
version. Tagged enums are governed by the version of their containing contract.

## Risk and permission representation

`RiskTier` serializes as `r0`, `r1`, `r2`, or `r3`:

| Tier | Policy meaning |
|---|---|
| `r0` | Observation or other no-write work |
| `r1` | Bounded, scoped, reversible work |
| `r2` | Sensitive or externally consequential work that requires an explicit policy decision |
| `r3` | Exceptional, critical, or irreversible work that must never receive implicit authority |

`PermissionProfile` carries the declared resource and write keys plus explicit
`approval_required`, `review_required`, and `audit_required` flags. The flags are
independent: `approval_required` alone never selects a review or audit completion
gate. The contract and P1 kernel neither derive authority from a tier nor approve
or execute an action. A later risk-policy layer must select, validate, and
enforce the profile before effects.

## Run states

`RunStatus` contains:

`draft`, `accepted`, `planned`, `running`, `awaiting_approval`, `reviewing`,
`auditing`, `completed`, `failed`, and `cancelled`.

The closed `RUN_STATUS_TRANSITIONS` table is:

| From | Allowed next states |
|---|---|
| `draft` | `accepted`, `cancelled` |
| `accepted` | `planned`, `cancelled` |
| `planned` | `running`, `cancelled` |
| `running` | `awaiting_approval`, `reviewing`, `completed` (when no review or audit is required), `failed`, `cancelled` |
| `awaiting_approval` | `running`, `failed`, `cancelled` |
| `reviewing` | `running`, `auditing`, `completed` (when review but not audit is required), `failed`, `cancelled` |
| `auditing` | `reviewing`, `completed` (when audit is required), `failed`, `cancelled` |
| `completed` | none; terminal |
| `failed` | none; terminal |
| `cancelled` | none; terminal |

`validate_run_transition` rejects:

- transitions absent from the table, including skipped phases and same-state
  mutation;
- every transition out of a terminal state;
- completion from a state other than the gate selected by the permission profile;
- completion without a version-compatible goal contract, permission profile,
  completion precondition, and completion evidence;
- completion without at least one unique evidence reference; and
- completion that omits definition-of-done items or acceptance and verification
  criteria required by the goal's `CompletionPrecondition`.

The completion gate is selected deterministically. When `audit_required` is
true, only `auditing -> completed` may pass. Otherwise, when `review_required` is
true, only `reviewing -> completed` may pass. With both flags false,
`running -> completed` may pass. A request from another admitted completion edge
returns the structured `wrong_completion_gate` error. All passing paths still
require valid completion evidence.

Failures use the serde-serializable `RunTransitionError` tagged by a stable `code`,
with fields such as `from`, `to`, `required`, `actual`, and `missing` where
applicable.

## Completion validation in P1

P1 can call:

```rust
validate_run_transition(
    current_status,
    requested_status,
    Some(&goal_contract),
    Some(&completion_evidence),
)?;
```

The goal contract defines the minimum evidence count, whether all acceptance and
verification criteria are required, its definition-of-done items, and the
permission flags that select the completion gate. `CompletionEvidence` supplies
the actual evidence IDs and deterministic lists of satisfied acceptance,
verification, and definition-of-done items. A configured minimum of zero is
treated as one, so `completed` can never be evidence-free.

`replay_run` applies this validator before accepting a transition to `completed`.
Every evidence ID used by `CompletionEvidence` must already have appeared in an
`EvidenceAttached` event. Invalid prospective events are rejected before
`DurableGoalRuntime::append_event` writes them.

## Durable replay

`RunEvent` carries a run ID, event ID, zero-based sequence, previous event ID,
timestamp, producer role, typed payload, and sorted metadata. P1 requires the
first event to be one `RunCreated` event in `draft`, one run ID, contiguous
sequences, exact previous-event links, unique event IDs, current nested contract
versions, and a valid execution plan over declared tasks.

`RunEventLog` uses the fixed relative path `run-events/events.jsonl` below a
caller-supplied root. A transparent `RunId` is data only and is never joined into
a filesystem path. Appends flush and sync before returning; reload is strict and
reports malformed non-empty rows rather than skipping them.

`DurableGoalRuntime` builds four caller-stamped Coordinator events through
`planned`, validates a prospective append by replaying it in memory, persists it,
then reloads and replays the durable bytes. `ReplayedRun` contains `RunRecord`,
the execution plan, task statuses, completion evidence, ordered specialist
outputs, and the optional Coordinator final response.

JSONL assumes one writer per run. SQLite is the separate P2 authority for claim,
lease, compare-and-swap revision, heartbeat, retry, cancellation, idempotency,
and write ownership. `DurableGoalRuntime::new` opens neither store.
`create_run` still writes only the validated planned JSONL events.
`initialize_execution` first reloads and replays that run, validates the goal,
exact declared task ID set, task statuses, and reproduced plan, and only then
idempotently initializes SQLite. `load_runtime_view` validates shared run, goal,
and task-set identity and returns both authorities without requiring their task
statuses to remain equal.

The JSONL and SQLite operations are not one transaction. A crash after
`create_run` but before SQLite initialization leaves an explicit, recoverable
bootstrap gap. Retrying `initialize_execution` with the identical task
definition and retry budget either creates revision zero or returns the existing
state. A failure between the four JSONL bootstrap appends can still leave a valid
partial event stream; P1 does not repair it automatically. P2C adds no lifecycle
event projection or outbox.

## Verification surface

`ovca-types` unit tests cover transparent IDs, contract versions, serde round
trips, deterministic event serialization, valid and invalid transitions,
completion gates, and required evidence. `ovca-runtime-core` tests cover golden
scheduling, final-answer ownership, event-chain integrity, replay, and durable
reopen equivalence. `ovca-langgraph` tests cover deterministic bootstrap,
contract-version rejection, validate-before-append behavior, strict reload,
two-store recovery and idempotency, independent status views, path-safe IDs, and
Coordinator-only final responses. See
[durable orchestration runtime](orchestration-runtime.md) for the workflow map.
