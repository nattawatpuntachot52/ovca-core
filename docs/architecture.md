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

## Goal runtime contract boundary

`ovca-types` exposes a provider-independent, version 1 goal runtime contract for
projects, goals, tasks, runs, ordered events, evidence, permissions, risk tiers,
public roles, and validated run-state transitions. This surface is
`contract_available`: an embedding caller can serialize the models and call the
pure transition validator.

Completion is risk-selected by explicit permission-profile flags: a run completes
from `running` when neither review nor audit is required, from `reviewing` when
review alone is required, and from `auditing` when audit is required. Approval
alone does not imply either completion gate.

It is not `runtime_wired`. No workspace service currently persists these records,
replays events, schedules tasks, leases workers, obtains approvals, performs
reviews or audits, or exposes the contract through HTTP. Those integrations are
separate later-phase work. See the [goal runtime contract](goal-runtime-contract.md)
for the schema, transition table, completion evidence gate, and replay boundary.
