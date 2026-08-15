# Architecture

OVCA Core is a Rust workspace with shared types, storage, observability, MCP,
LLM client, brain cache, runtime routing, LangGraph-style orchestration, Policy
Tools, and four MCP server binaries. Coordinator is the front door, Engineer handles
engineering, Reviewer handles review, and Auditor handles cross-audit.

Python contains the reference Policy Tools logic, direct-call adapter, and a
dependency-free ASGI compatibility surface for embedding and tests. It has no
standalone server entrypoint. The Rust `ovca-policy-tools` binary is the
authoritative portable HTTP service for the twelve shared tools. Data roots are
external inputs; the repository contains no operational memory or history.

For the execution sequence, runtime status of each component, inputs, outputs,
failure paths, and Mermaid diagrams, see the
[workflow-by-workflow system guide](system-workflows.md).

## Goal runtime layers

`ovca-types` exposes a provider-independent, version 1 goal runtime contract for
projects, goals, tasks, runs, ordered events, evidence, permissions, risk tiers,
public roles, and validated run-state transitions. This surface is
`contract_available`: an embedding caller can serialize the models and call the
pure transition validator.

Completion is risk-selected by explicit permission-profile flags: a run completes
from `running` when neither review nor audit is required, from `reviewing` when
review alone is required, and from `auditing` when audit is required. Approval
alone does not imply either completion gate.

P1 through P5 add a `runtime_wired`, library-only path across four crates:

- `ovca-storage` appends and strictly reloads typed events from a fixed JSONL
  path below a caller-supplied external root.
- `ovca-runtime-core` creates deterministic execution plans, enforces Coordinator
  final-answer ownership, validates event chains, reconstructs run state, and
  owns the durable SQLite lease/write lifecycle, R0-R3 guard policy, and durable
  approval ledger. It also structurally validates evidence-bound Reviewer and
  Auditor decisions and resolves their required completion outcome.
- `ovca-langgraph` builds the four-event bootstrap through `planned` and wraps
  validate-before-append plus strict reload/replay in `DurableGoalRuntime`. Its
  explicit `initialize_execution` bridge validates JSONL first and then
  idempotently initializes SQLite. The same runtime exposes typed guard
  evaluation, a run-associated redacted guard projection, guarded execution,
  decision, strict-load, and approved-resume methods without opening any store
  during construction. Its prospective replay rejects an invalid `completed`
  event before JSONL persistence and reload uses the same completion gate.
- `ovca-observability` builds a provider-independent canonical trace from
  validated run events and grades required-field completeness, exact
  durable-reload parity, and replayed contract outcome. It omits metadata and
  free-form payloads and uses trace-local opaque correlation aliases. The trace
  includes closed P3 allow/pause/deny projections while separate read-only
  reducers expose identifier-free P2 durable task state and direct typed P3
  evidence.

This path is additive to the existing request-routing graph. It is not launched
by `scripts/ovca.ps1` and has no HTTP endpoint. JSONL remains the orchestration
and replay-evidence authority and retains its single-writer caller obligation.
SQLite is independently authoritative for execution leases, retries,
cancellation, idempotency, revisions, and write ownership. The approval ledger
is independently authoritative for exact R2 requests, caller-supplied owner
decisions, and consumption. These are three logical authorities over two durable
media: JSONL and one shared SQLite versioned-state database. Execution uses the
`execution_run:` entity namespace and approval uses `guard_approval:` in that
database. Current APIs expose no combined execution-plus-approval transaction.
JSONL and SQLite have no cross-medium transaction, outbox, reconciliation, or
automatic P2 lifecycle projection. The P3 projection append is an ordered,
non-atomic operation after guard evaluation; it contains no exact request or
approval-ledger fields. P3 returns review/audit requirements but does not produce
Reviewer or Auditor decisions. P4 consumes separately recorded run events for evidence
references, requirements, and at most one role-bound decision from each required
role; it permits completion only after the structural evaluator returns `Pass`.
The library does not invoke live workers or perform live Reviewer or Auditor
judgment, and it does not claim semantic verification of external evidence bytes.
See the [goal runtime contract](goal-runtime-contract.md) and
[durable orchestration runtime](orchestration-runtime.md) for the exact boundary.
The [observability and evaluations guide](observability-evals.md) documents the
trace schema, read-only API, deterministic graders, fixture, and non-SLO limits.
