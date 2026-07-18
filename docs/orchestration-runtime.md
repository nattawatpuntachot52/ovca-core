# Durable Orchestration Runtime

## Status

| Surface | Status | Meaning |
|---|---|---|
| Goal contracts and transition validator | `contract_available` | Versioned provider-independent data and pure validation |
| Scheduler, event log, replay, and durable kernel | `runtime_wired`, `library-only` | An embedding caller can create and extend a durable run |
| Startup and HTTP | not wired | `scripts/ovca.ps1` does not launch or expose this kernel |
| Worker lifecycle | `runtime_wired`, `library-only` | P2 SQLite authority owns claim, lease, heartbeat, retry, cancellation, idempotency, and write ownership |

P1 turns the P0 contracts into deterministic orchestration and replay. P2 adds a
durable execution authority without adding a provider, network call, or live
worker invocation.

## Bootstrap workflow

`build_planned_run` and `DurableGoalRuntime::create_run` accept a goal, tasks,
run ID, and four caller-supplied event IDs and timestamps.

```mermaid
flowchart TD
    Input["GoalContract, tasks, RunId, and four EventStamps"] --> Versions{"Current contract versions?"}
    Versions -->|"No"| RejectVersion["Reject without writing"]
    Versions -->|"Yes"| Tasks{"Tasks belong to goal and are pending?"}
    Tasks -->|"No"| RejectTask["Reject without writing"]
    Tasks -->|"Yes"| Schedule["Build deterministic execution waves"]
    Schedule --> Stamps{"Unique IDs and nondecreasing timestamps?"}
    Stamps -->|"No"| RejectStamp["Reject without writing"]
    Stamps -->|"Yes"| Events["Create RunCreated, Accepted, PlanRecorded, Planned events"]
    Events --> Replay["Prospective replay and invariant checks"]
    Replay -->|"Invalid"| RejectReplay["Reject without writing"]
    Replay -->|"Valid"| Append["Append, flush, and sync each JSONL event"]
    Append --> Reload["Strict reload and deterministic replay"]
    Reload --> Planned["Return ReplayedRun in planned state"]
```

The scheduler orders ready tasks by task ID. Tasks share a parallel wave only
when dependencies are satisfied before that wave and their declared `write_keys`
are disjoint. A parallel wave is a plan, not evidence that workers ran.

## P2 execution bootstrap workflow

`DurableGoalRuntime::new` constructs both fixed-path store handles without
touching the filesystem. `create_run` remains a JSONL-only operation. The caller
must explicitly bridge the stores with `initialize_execution`.

```mermaid
flowchart TD
    Planned["Existing planned JSONL run"] --> Replay["Strict load and replay"]
    Replay -->|"Missing or invalid"| RejectJsonl["Reject; no SQLite write"]
    Replay --> Validate["Validate run status, goal, exact task IDs, statuses, and plan"]
    Validate -->|"Mismatch"| RejectDefinition["Structured mismatch; no SQLite write"]
    Validate --> Bootstrap["Initialize SQLite execution state"]
    Bootstrap -->|"New definition"| RevisionZero["Create revision zero"]
    Bootstrap -->|"Identical existing definition"| Existing["Return existing revision idempotently"]
    Bootstrap -->|"Different existing definition"| Conflict["Return execution definition conflict"]
    RevisionZero --> View["Validate run, goal, and task-set identity"]
    Existing --> View
    View --> Combined["Return orchestration and execution views"]
```

The order is durable JSONL validation first, SQLite initialization second. There
is no cross-store transaction. If a process stops after `create_run`, the absent
SQLite state is an explicit bootstrap gap. Retrying `initialize_execution` with
identical tasks and retry budget recovers it. Retrying after SQLite already
exists is idempotent; a changed definition fails instead of replacing state.

## Authority matrix

| Concern | Authority |
|---|---|
| Run events, orchestration status, declared task IDs, plan, evidence, and replay | JSONL P1 event log |
| Claims, leases, heartbeats, attempts, terminal idempotency, CAS revision, and write owners | SQLite P2 execution state |
| Shared run, goal, and exact task-set identity | Validated by the combined runtime view |
| Task status after bootstrap | Exposed separately by both stores; equality is not required |

For example, a durable SQLite claim changes its task snapshot to `running` while
JSONL remains `pending` until a caller explicitly appends a valid orchestration
event. P2C does not add that append wrapper, an outbox, or fabricated atomicity.

## Append workflow

An embedding caller supplies a complete next `RunEvent`. The kernel never reads
a clock or generates an ID.

```mermaid
flowchart TD
    Event["Caller-supplied next RunEvent"] --> Load["Strictly load current run events"]
    Load --> Found{"Run exists?"}
    Found -->|"No"| Missing["Return run_not_found; no write"]
    Found -->|"Yes"| Prospective["Append only to an in-memory copy"]
    Prospective --> Replay["Validate chain and replay state"]
    Replay -->|"Invalid"| Reject["Return structured replay error; no write"]
    Replay -->|"Valid"| Persist["Append, flush, and sync event"]
    Persist --> Reload["Strict reload and replay"]
    Reload --> Result["Return updated ReplayedRun"]
```

## Replay invariants

- The stream is non-empty and starts with exactly one `RunCreated` event in
  `draft`.
- Every event uses the current contract version, the same run ID, a contiguous
  zero-based sequence, an exact previous-event link, and a unique event ID.
- A recorded plan covers every declared task exactly once with contiguous wave
  indexes.
- Status transitions start from the replayed status and pass the P0 transition
  validator.
- Completion evidence uses current contracts and references evidence attached
  earlier in the event stream.
- Specialist output belongs to a declared task, uses Engineer, Reviewer, or
  Auditor, and matches the event producer role.
- Only Coordinator may record `CoordinatorFinalResponseRecorded`, and it may
  appear once.

## Storage boundary

`RunEventLog` writes `run-events/events.jsonl` below a caller-supplied external
root. It never treats `RunId` as a path component. Missing logs are empty;
malformed non-empty rows are errors with line context. Every successful append
flushes and calls `sync_all` before returning.

The log is strict across the file. A malformed row for any run prevents a clean
load until the external data is repaired. The repository itself receives no run
data when the caller supplies an external root.

## Role ownership

- Coordinator creates the bootstrap events and owns the final response.
- Engineer, Reviewer, and Auditor may record bounded specialist outputs for
  declared tasks.
- P1 records and replays outputs; it does not invoke or supervise those roles.

## Current API map

| API | Crate | Responsibility |
|---|---|---|
| `schedule_tasks` | `ovca-runtime-core` | Deterministic dependency and write-key planning |
| `RunEventLog` | `ovca-storage` | Strict durable JSONL append and load |
| `validate_event_chain` | `ovca-runtime-core` | Structural event-chain integrity |
| `replay_run` | `ovca-runtime-core` | Deterministic state reconstruction |
| `build_planned_run` | `ovca-langgraph` | Pure four-event bootstrap construction |
| `DurableGoalRuntime` | `ovca-langgraph` | Validate-before-append and strict reload/replay |
| `DurableExecutionAuthority` | `ovca-runtime-core` | Transactional SQLite execution lease and write ownership |
| `initialize_execution` | `ovca-langgraph` | Validate JSONL first, then idempotently bootstrap SQLite |
| `load_runtime_view` | `ovca-langgraph` | Return both authorities after identity/task-set checks |

## Runtime limitations

- One JSONL writer per run remains a caller obligation. SQLite commands serialize
  through their own transactional authority.
- Bootstrap writes four synced JSONL lines sequentially. A storage failure can
  leave a replayable partial bootstrap, and automatic recovery is not present.
- The kernel plans parallel waves but does not execute them.
- There is no cross-store transaction, JSONL lifecycle projection, or outbox.
- Combined two-store behavior has no cross-process integration test yet.
- No live worker or provider path validates execution against external effects.
- No approval interruption, live Reviewer action, live Auditor action, provider
  call, credential, server endpoint, or remote side effect is included.

## Verification map

| Concern | Evidence |
|---|---|
| Contract and state transitions | `rust/ovca-types/src/goal_runtime.rs` tests |
| Deterministic scheduling and Coordinator finalization | `rust/ovca-runtime-core/src/scheduler.rs`, `finalization.rs` tests |
| Event integrity and replay | `rust/ovca-runtime-core/src/replay.rs` tests |
| Strict durable bytes and path safety | `rust/ovca-storage/src/run_events.rs` tests |
| Bootstrap and validate-before-append behavior | `rust/ovca-langgraph/src/goal_runtime.rs` tests |
| Two-store bootstrap, recovery, combined views, and authority divergence | `rust/ovca-langgraph/src/goal_runtime.rs` tests |

All run IDs, event IDs, worker IDs, lease IDs, idempotency keys, and timestamps
are caller supplied. The runtime generates no implicit clock or identity values.
The supported public roles are exactly Coordinator, Engineer, Reviewer, and
Auditor. The core path has no provider dependency.
