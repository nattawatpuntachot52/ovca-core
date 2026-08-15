# Goal Runtime Contract

## Status and boundary

The goal runtime contract is `contract_available` in `ovca-types`. Versioned
Rust and JSON models plus a pure run-state transition validator are available to
embedding callers.

P1 through P4 consume those contracts through a `runtime_wired`, library-only
path. It can schedule tasks, append strict run events under an external root,
validate an event chain, deterministically replay a `RunRecord`, maintain an
independent SQLite execution lifecycle, and guard effect closures through a
durable approval ledger. P4 additionally records and replays role-bound
review/audit decisions before accepting completion. This is not a service:
startup does not launch it and no HTTP endpoint exposes it. It does not invoke
workers, authenticate owner identity, generate live Reviewer or Auditor
judgment, call providers, or wire external side effects.

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
gate. P3 deterministically validates these declarations before an effect closure.

## P3 guard and approval contract

P3 evaluates `GuardRequest` values on `input`, `output`, and `tool` surfaces.
Each request binds a contract version, request ID, operation label, side-effect
class, resource keys, write keys, and exact `PermissionProfile`.

| Tier | P3 execution result | Durable approval state |
|---|---|---|
| `r0` | Execute immediately when the request is valid | None |
| `r1` | Execute immediately and return the Reviewer requirement | None |
| `r2` | Pause before the closure; require exact owner approval | Pending, approved/denied, then consumed on approved resume |
| `r3` | Deny before the closure | None; deny-by-default |

R2 applies to repository writes, network actions, publication, and external side
effects across all three guard surfaces. Network, publication, and external-side-
effect requests also require the Auditor declaration. The durable record includes
the exact request and required gates, so changed request or permission data cannot
resume an existing approval.

`ApprovalAuthority::ExplicitOwner` is a typed assertion supplied by the caller.
It is not authentication, tenancy, credential, session, or identity proof. P3
consumes an approved record with compare-and-swap before calling the effect
closure. It returns Reviewer and Auditor requirements but does not claim their
decisions have occurred. P4 separately records and replays those decisions before
it accepts a completed run.

Approval consumption and an external side effect are not one transaction. If the
effect fails or panics after consumption, the request remains consumed and the
external effect may be absent. This is an explicit at-most-once/no-retry boundary.
R3 remains deny-by-default in P3.

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

## Completion validation and P4 resolution

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

`replay_run` applies this base validator before accepting a transition to
`completed`. Every evidence ID used by `CompletionEvidence` must already have
appeared in an `EvidenceAttached` event. Invalid prospective events are rejected
before `DurableGoalRuntime::append_event` writes them.

P4 adds a durable completion resolution on top of that base transition rule.
`EvidenceReferenceRecorded`, `ReviewAuditRequirementsRecorded`,
`ReviewDecisionRecorded`, and `AuditDecisionRecorded` are role-bound run events.
The replayed requirements select whether Reviewer and Auditor decisions are
required; the evaluator also re-derives the requirement from the goal permission
profile, so a weaker recorded requirement cannot bypass policy. On an attempted
transition to `completed`, replay validates the evidence catalog, completion
evidence, decision identities, roles, criterion coverage, and verdicts. Only
`ReviewAuditResolution::Pass` permits the transition. Missing required review or
audit returns an awaiting resolution, and a Reviewer/Auditor disagreement returns
an owner-escalation resolution; both reject completion before persistence.

The replay contract accepts at most one Reviewer decision and at most one Auditor
decision for a run because it has no durable selector for competing decisions.
Duplicate or distinct second decisions are rejected rather than silently choosing
one. With no selected review or audit requirement, the R0/no-review path keeps
the original `running -> completed` behavior.

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
the execution plan, task statuses, completion evidence, the evidence-reference
catalog, optional review/audit requirements, ordered Reviewer and Auditor
decisions, ordered specialist outputs, and the optional Coordinator final
response. A reload applies the same P4 completion gate as prospective append.

JSONL assumes one writer per run. SQLite is the separate P2 authority for claim,
lease, compare-and-swap revision, heartbeat, retry, cancellation, idempotency,
and write ownership. The P3 approval ledger is a third logical authority for
exact guard requests, caller-supplied decisions, and approval consumption.
Execution records use the `execution_run:` entity namespace and approval records
use `guard_approval:` in the same SQLite versioned-state database. Together with
JSONL orchestration, these are three logical authorities over two durable media.
`DurableGoalRuntime::new` touches neither durable medium.
`create_run` still writes only the validated planned JSONL events.
`initialize_execution` first reloads and replays that run, validates the goal,
exact declared task ID set, task statuses, and reproduced plan, and only then
idempotently initializes SQLite. `load_runtime_view` validates shared run, goal,
and task-set identity and returns both authorities without requiring their task
statuses to remain equal.

`DurableGoalRuntime` also exposes typed wrappers for guard evaluation and record,
guarded execution, decision recording, strict approval loading, and exact
approved resume. `evaluate_run_guard_and_record` accepts an explicit run,
evaluates the existing P3 authority, and appends a `GuardOutcomeRecorded` event
containing only a versioned `RunGuardProjection`. The projection is a closed
allow, pause, or deny result with closed guard requirements or deny reasons. It
contains no raw request, approval identifier, operation label, key, provider
payload, filesystem location, credential, or caller identity. Guard operations
do not project `RunStatus` or `TaskStatus`, and lifecycle operations do not
mutate approval state.

Current APIs expose no combined transaction across execution and approval entity
operations in the shared SQLite database. JSONL and SQLite operations are not one
cross-medium transaction and have no outbox, reconciliation, or atomicity claim.
In particular, P3 authority evaluation and the JSONL projection append are
ordered operations, not one transaction.
A crash after `create_run` but before SQLite initialization leaves an explicit,
recoverable bootstrap gap. Retrying `initialize_execution` with the identical
task definition and retry budget either creates revision zero or returns the
existing state. A failure between the four JSONL bootstrap appends can still
leave a valid partial event stream; P1 does not repair it automatically. P2C adds
no lifecycle event projection or outbox.

## Read-only trace evaluation

`ovca-observability` derives one canonical span per validated durable event.
Spans contain event sequence, trace-local correlation aliases, public producer
role, closed lifecycle and decision kinds, and typed status, plan, requirement,
redacted P3 outcome, closed deny reason, and verdict facts. Raw IDs, event
metadata, and free-form payload fields are not copied or hashed into the trace.

`DurableGoalRuntime::evaluate_run` strictly loads the JSONL stream twice and
requires both replays to validate against the supplied goal contract. The method
does not append JSONL, open SQLite, or mutate execution or approval state.
Completeness counts a fixed required-field schema for the authoritative event
count. Canonical parity compares the candidate with the independently reloaded
trace. Successful evaluation additionally requires a replayed successful
completion. Recorded P3 pauses report `awaiting_approval`, recorded denials
report `policy_denied`, and neither can pass. Failures, missing review/audit,
Reviewer/Auditor disagreement, and R0 compatibility are also preserved.

P2 execution evidence remains separate from canonical spans.
`execution_authority_evidence` reduces an authoritative reloaded execution task
to status, attempts, lease presence, and terminal outcome.
`guard_authority_evidence` reduces an actual guard evaluation to allow, pause,
or deny. `GuardRequest` carries no run ID; the additive runtime method supplies
the explicit run association and persists only its redacted projection.

See [goal runtime observability and evaluations](observability-evals.md). The
documented `0.99` completeness threshold is a regression-fixture rule, not a
production SLO.

## Verification surface

`ovca-types` unit tests cover transparent IDs, contract versions, serde round
trips, deterministic event serialization, valid and invalid transitions,
completion gates, and required evidence. `ovca-runtime-core` tests cover golden
scheduling, final-answer ownership, event-chain integrity, replay, and durable
reopen equivalence, including missing review/audit, conflict escalation,
duplicate-decision rejection, valid `Pass`, and R0 compatibility. `ovca-langgraph`
tests cover deterministic bootstrap,
contract-version rejection, validate-before-append behavior, strict reload,
two-store recovery and idempotency, R0 execution without approval state, all 12
R2 pause paths, all 12 R3 deny paths, durable reopen, request and permission
mismatch, exact concurrent at-most-once resume, logical-authority independence,
path-safe IDs, and Coordinator-only final responses. See
[durable orchestration runtime](orchestration-runtime.md) for the workflow map.
The versioned observability fixture adds 41 persistent deterministic cases for
trace completeness, durable parity, contract outcomes, and redaction.
