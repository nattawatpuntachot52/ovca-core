# ADR 0003: Provider-neutral role execution ports

- Status: Accepted
- Enforcement status: `contract_available`, `library_only`
- Scope: additive pure synchronous execution boundary and deterministic fake

## Context

The public control plane has immutable invocation and result contracts, but it
needs one provider-neutral boundary for handing a validated role invocation to
an execution implementation. The boundary must be usable in deterministic
tests without granting write authority or implying scheduling, persistence,
provider access, or process control.

## Decision

The additive `ovca_runtime_core::role_executor` module defines a synchronous
`RoleExecutor` port:

```text
invoke(RoleExecutionRequest) -> Result<RoleExecutionOutcome, RoleExecutorError>
```

`RoleExecutionRequest` carries one complete `RoleInvocationV1` plus the exact
one-based attempt being executed. The invocation remains immutable across
attempts. Implementations receive no provider, credential, filesystem,
network, shell, Git, persistence, clock, or cancellation capability from this
contract.

This decision also provides `DeterministicFakeRoleExecutor`. It is an immutable
map of prevalidated scripts keyed by the exact `(idempotency_key, attempt)`.
Each script binds the invocation ID and canonical invocation digest. Repeating
an identical request returns an equal clone without consuming or mutating the
script. Reusing an ID or key with different invocation bytes fails closed.
Missing, duplicate, and conflicting scripts are distinct closed errors.

## Caller assertions and authority

The port reuses `RoleInvocationV1::validate` before every outcome. The embedded
Foundation authority remains a caller-supplied assertion: validation does not
authenticate a principal or establish current authority. Role execution is
allowed only when `authority.permission_profile.write_keys` is empty. A caller
that needs write authority must use a separately reviewed admission boundary;
this port never widens authority.

The request attempt must be in `1..=budget.max_attempts`. Every terminal result
is validated against the exact invocation and request attempt, including role,
state, payload, task, run, scope, idempotency key, canonical invocation digest,
and timestamp constraints inherited from the control-plane contract.

## Outcomes and retry contract

Terminal outcomes are closed:

| Port outcome | Required control-plane result |
|---|---|
| `Completed` | state `completed` and the role-appropriate completed payload |
| `Failed` | state `failed` and a failure code other than `execution_timeout` |
| `TimedOut` | state `failed` and exact failure code `execution_timeout` |
| `Cancelled` | state `cancelled` and a cancellation payload |

Timeout and cancellation are normalized reported outcomes. They do not claim
that this library controls a clock, thread, process, token, or provider.

`RetryRequired` is nonterminal and carries no `RoleResultV1`. Its
`completed_attempt` must equal the request attempt; `next_attempt` must be the
checked successor and remain within `max_attempts`. Only `failed` and
`timed_out` are closed retry causes. This port reports a retry requirement but
does not schedule, append, or execute the retry.

Usage is either `Unavailable` or caller-reported input and output unit counts.
The total is derived with checked addition and is never stored as an
independent value. Overflow fails closed.

## Replay and idempotency

The deterministic fake is observational and stateless. An exact repeat is
idempotent because lookup uses immutable bindings and returns an equal value.
It does not append control-plane events, mutate durable state, advance an
attempt, or claim completion. Event replay and durable idempotency admission
remain responsibilities of their existing reviewed layers.

## Compatibility

This change adds one module and explicit exports to `ovca-runtime-core`.
Existing Foundation, control-plane, Goal Runtime, storage, wire schemas, and
serialized bytes are unchanged. No implicit provider or runtime conversion is
introduced.

## Non-goals

This decision adds no provider adapter, model selection, credential handling,
network or filesystem access, shell or process execution, scheduler, timeout
mechanism, cancellation mechanism, trusted usage meter, event append,
persistence, memory, durable retry orchestration, or automatic completion.
Those behaviors require separate reviewed contracts and implementations.
