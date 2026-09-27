# ADR 0006: Independent review, audit, and bounded repair

- Status: Accepted
- Date: 2026-09-21
- Scope: Control Plane A05, internal contract version 1

## Context

ADR 0005 ends the Engineer-to-Verifier controller at the immutable terminal
`Reviewing` phase after one bounded workspace change has passed local
verification and its exact EvidenceBank record is current. That state proves a
candidate is ready for independent judgment; it does not authorize a Reviewer
or Auditor, record their outcomes, or permit completion.

Legacy review and audit records are role- and evidence-aware, but by themselves
they do not bind the Issue 6 candidate, independent principals, invocation
state, repair cycle, or exact current evidence anchor. Treating those records
as sufficient would also allow an old completion path to bypass the new
independent checks.

## Decision

A05 is a separate optional `IndependentReviewStateV1` projection inside the
existing execution row. Issue 6 remains terminal and byte-for-byte immutable.
Execution-envelope V1 is valid only without A05. The first A05 CAS atomically
upgrades the envelope to V2; V2 requires A05. New code restores V1/no-A05 and
V2/A05, while all other version/projection combinations fail closed. An older
V1 implementation rejects V2 before it can mutate or erase the projection.

`ReviewPacketV1` binds the exact run, goal, task, candidate cycle, immutable
repair-chain budget, Issue 6 state/plan/ledger/result/diff/verifier digests,
bounded before/after bytes, verifier receipt identities, current verification
bundle, EvidenceBank CAS anchor, principals, invocation, and an actor-bound
evidence manifest. Reviewer differs from Engineer and Verifier. The packet
contains no workspace root or lease, tool request, environment value, Git,
network, persistence, server, or MCP capability.

`AuditPacketV1` embeds the exact ReviewPacket and typed ReviewDecision, binds
their digests, uses a distinct Auditor invocation and evidence-manifest
namespace, and requires Auditor to differ from Engineer, Verifier, and
Reviewer. Each manifest is strictly ordered and rejects evidence produced by
the actor certifying it.

The provider-neutral `IndependentReviewExecutor` receives a typed packet and a
write-free `RoleExecutionRequest`. Reviewer and Auditor return explicit typed
`RoleResultPayloadV1` variants. A05 never interprets `Specialist.summary`.
Legacy Specialist results remain valid outside A05.

Each invocation follows `not_started -> started -> outcome_recorded`. The
controller validates the terminal candidate and holds an EvidenceBank
completion-admission lease while winning each Started CAS. It releases the
lease before invoking the external role and durably records the typed outcome
before advancing. A recovered Started state has an ambiguous external effect,
so it escalates to Owner and never invokes that role again. Two controllers
therefore have one CAS winner and one invocation.

Audit runs after every valid Reviewer verdict. Reviewer Pass plus Auditor Pass
resolves only after a fresh EvidenceBank lease revalidates the candidate and
current anchor around the `ResolvedPass` CAS. The final passing pair is then
projected, idempotently, into the existing singleton review/audit event records
while the same keyed lease serializes the full load/check/append/reload
sequence. Projection accepts only the canonical Issue 6 cursor and an absent,
exact Review, or exact Review-plus-Audit suffix; reserved-ID or envelope drift
fails before mutation.
Fail plus Fail issues one `RepairDirectiveV1` only while
`candidate_cycle < max_repair_cycles`. Verdict disagreement, invalid evidence,
ambiguous invocation state, execution failure, or exhausted budget escalates
to Owner.

`max_repair_cycles` is a positive caller-selected value with no default. The
initial candidate is cycle zero. A repair directive grants no authority,
contains only the failed candidate's changed path and unsatisfied criteria,
routes through Coordinator, and binds one deterministic successor run ID. A
dual-fail outcome is durable before this binding, and the caller must supply
that exact derived successor ID before the terminal directive is persisted.
A missing or alternate ID cannot create a directive. An already-persisted
directive accepts only the same caller binding.
fresh child must load the prior run, use that exact successor ID, preserve the
root and maximum cycle count, bind the prior directive digest, and advance by
exactly one cycle. Exact retry of that child is unchanged; a sibling conflicts.

All completion routes for an Issue 6-managed run require the exact durable A05
`ResolvedPass`, its typed Pass/Pass outcomes, the matching legacy singleton
records, the unchanged Issue 6 candidate, and the current EvidenceBank anchor.
The generic append route, verified-completion route, and ambiguous-append
reconciliation route perform that check while holding a fresh completion
admission lease.

## Consequences

The runtime can make deterministic contract claims about actor independence,
read-only role requests, durable call admission, exact retries, bounded repair
chains, singleton projection, and completion gating. A repair directive is
data for a later Coordinator-authorized run; Reviewer and Auditor cannot invoke
Engineer or mutate the failed run.

The design adds no service, endpoint, MCP dependency, shared mutable folder,
database table, store, or event log. Provider execution can still have an
ambiguous external outcome after Started; the deliberate response is Owner
escalation rather than automatic replay. Tests establish contract and
controller conformance only. Product and owner-workflow validation remains a
later pilot concern.

The in-memory loaded execution envelope and its optional A05 projection are
heap-boxed. Serde keeps the durable JSON shape unchanged. This bounds normal
Windows test-thread stack use while the controller carries and validates the
large Issue 6 and A05 states across recovery steps.
