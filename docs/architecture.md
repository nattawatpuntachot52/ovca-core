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

P1 adds a `runtime_wired`, library-only path across three crates:

- `ovca-storage` appends and strictly reloads typed events from a fixed JSONL
  path below a caller-supplied external root.
- `ovca-runtime-core` creates deterministic execution plans, enforces Coordinator
  final-answer ownership, validates event chains, and reconstructs run state.
- `ovca-langgraph` builds the four-event bootstrap through `planned` and wraps
  validate-before-append plus strict reload/replay in `DurableGoalRuntime`.

This path is additive to the existing request-routing graph. It is not launched
by `scripts/ovca.ps1` and has no HTTP endpoint. P1 is single-writer-per-run and
does not lease or execute workers, interrupt for approval, or perform Reviewer or
Auditor work. See the [goal runtime contract](goal-runtime-contract.md) and
[durable orchestration runtime](orchestration-runtime.md) for the exact boundary.
