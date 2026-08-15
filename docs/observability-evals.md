# Goal Runtime Observability and Evaluations

## Status and boundary

Goal runtime trace construction and evaluation are `runtime_wired`,
`library-only` APIs. They have no provider SDK, hosted telemetry backend,
dashboard, HTTP endpoint, or startup wiring.

`build_goal_runtime_trace` consumes only authoritative, structurally valid
`RunEvent` values. `DurableGoalRuntime::evaluate_run` performs two independent
strict JSONL loads, replays both streams against the supplied `GoalContract`, and
returns a `GoalRuntimeEvaluation`. Evaluation does not append JSONL, open SQLite,
or change orchestration, execution, or approval state.

The JSONL stream may include a redacted `guard_outcome_recorded` projection
created by `DurableGoalRuntime::evaluate_run_guard_and_record`. The method
evaluates the existing P3 authority and then appends the closed policy result to
an explicit run. Approval-ledger persistence and JSONL append are ordered but
are not one cross-medium transaction.

Two additional pure evidence reducers cover typed authority state:

- `execution_authority_evidence` accepts an authoritative `LoadedExecutionRun`
  and returns task status, attempt count, active-lease presence, and terminal
  outcome without returning identifiers.
- `guard_authority_evidence` accepts an actual typed
  `DurableApprovalEvaluation` and returns only `allow`, `pause`, or `deny`.

## Canonical trace

One canonical span corresponds to one persisted run event. Every span contains:

- schema version
- trace-local run correlation
- trace-local event identity and previous-event identity
- event sequence and timestamp
- one public producer role: Coordinator, Engineer, Reviewer, or Auditor
- closed event, lifecycle, and decision kinds
- typed facts for run status, task status, execution mode, redacted guard
  outcome and closed deny reasons, guard requirement, and review or audit
  verdict

Correlations are opaque aliases. A trace uses `run:0`, event aliases derived
from validated sequence, and task aliases assigned by declared task order. Raw
run, event, and task IDs are never transformed into hashes or copied into the
trace.

The trace excludes event metadata and every free-form payload field, including
notes, summaries, final responses, evidence references, and provider payloads.
It therefore cannot expose caller-supplied credentials, tokens, passwords,
filesystem locations, or non-public identities through those fields.
`GuardRequirement` is a closed enum containing only owner approval, Reviewer,
and Auditor requirements; it carries no caller-authored text.

## Deterministic graders

`grade_trace_completeness` counts the fixed required-field list once for every
authoritative event expected in the trace. A missing entire span contributes all
of its required fields to the denominator. Nullable required fields count only
when their keys are present. Extra spans, optional fields, omissions, and
self-reported counters cannot increase either the numerator or denominator.

The completeness score is:

```text
present required fields / (authoritative event count * required fields per span)
```

`grade_replay_parity` compares the candidate trace with the exact canonical trace
rebuilt from an independently reloaded event stream. Additional or changed
fields, missing fields, changed ordering, and changed authoritative events fail
parity.

`grade_goal_runtime_invariants` derives outcome only from replayed state and
validated review/audit contracts. A successful evaluation requires:

1. completeness greater than or equal to `0.99`
2. exact canonical parity after durable reload
3. a valid contract
4. a replayed successful completion

Invalid review/audit contracts, draft, in-progress, recorded P3 pause, recorded
P3 policy denial, failed, cancelled, missing review, missing audit, failed
review/audit, and Reviewer/Auditor disagreement outcomes never grade as
successful completion. A denial is reported as `policy_denied`, not generic
`in_progress`. R0 completion with no selected review or audit remains compatible.
An event rejected during prospective replay is absent from the persisted stream
and therefore cannot appear as evaluation evidence.

## Regression fixture

`rust/ovca-observability/tests/fixtures/goal_runtime_p5_golden_cases.json` is a
tracked schema-version-1 dataset with 41 deterministic cases. The persistent
`goal_runtime_evals` integration test enforces the fixture version, a minimum of
36 unique cases, required coverage labels, exact span counts, outcomes,
completeness, parity, redaction, and success results.

The cases cover P0-P4 contracts and transitions, sequential and parallel plans,
routing waves, task cancellation, P4 missing/pass/fail and disagreement paths,
durable reload parity, malformed traces, and redaction.

P2/P3 fixture cases carry a required `semantic_assertion`; coverage labels alone
cannot satisfy the test. P2 assertions initialize the actual SQLite execution
authority and invoke claim/lease, failure/retry, duplicate completion
idempotency, and cancellation commands before extracting the reloaded durable
state. P3 cases invoke the actual guard authority, derive the closed
`RunGuardProjection`, append it to a real JSONL log, and reload the bytes before
evaluation. They verify R0 allow, durable R2 pause, and R3 policy denial as
run-associated outcomes.

`GuardRequest` itself still has no run identifier. The additive runtime method
accepts the run explicitly and persists only the redacted projection. It never
copies or infers a guard request ID, approval ID, operation label, resource or
write key, provider payload, filesystem location, credential, or caller identity
into the run event.

The `0.99` threshold is a fixture-level regression rule for this canonical
library trace. It is not a production telemetry SLO, availability target, or
claim about deployed trace collection.

## Known limits

- The trace describes JSONL orchestration evidence, including redacted P3
  outcomes. It does not project SQLite execution leases, retries, idempotency
  records, exact guard requests, approval identifiers, or approval ledger rows.
- P2 evidence remains separate. The P3 reducer remains useful for direct typed
  results, while the run projection is the durable reporting association.
- P3 authority evaluation and JSONL projection append are not atomic. There is
  no outbox or reconciliation mechanism if the second operation fails.
- Evaluation checks deterministic structure, replay parity, and contract
  outcomes. It does not inspect external evidence bytes or prove semantic
  quality.
- The API accepts a caller-supplied `GoalContract`; it does not authenticate a
  person, provider, tenant, or session.
- No production trace ingestion, retention, sampling, alerting, or operational
  SLO has been implemented or validated.
