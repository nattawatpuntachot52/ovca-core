# ADR 0001: Shared authority, evidence, decision, and event compatibility

- Status: Accepted
- Contract version: 1
- Scope: additive public foundation contracts only

## Context

The public control plane and governed brain need a common vocabulary for authority, evidence references, decisions, and payload-free event envelopes. Existing Goal Runtime contracts and legacy agent identities already have stable wire representations and must remain unchanged.

JSON Schema can close object shapes, versions, enums, identifiers, digests, and locator syntax. It cannot establish authority, compare principal identities, validate lifecycle transitions, or admit an event or evidence record. Those checks remain mandatory Rust semantic validation.

## Decision

Four exact-version V1 contracts are added:

- `FoundationAuthorityV1` declares one principal's scoped permission profile, visibility, sensitivity, and validity state. Permission resource and write keys may be empty; populated collections must be valid stable IDs in strict ordinal order without duplicates.
- `FoundationEvidenceRefV1` identifies content by a lowercase SHA-256 digest and a bounded stable-ID or logical-path locator. It never contains raw evidence bytes. Its kind reuses the existing closed `EvidenceKind` values: artifact, document, test result, log, review, audit, external reference, and other.
- `FoundationDecisionV1` records approval, review, or audit outcomes. Owner, Reviewer, and Auditor respectively own those decision kinds, and an actor cannot decide for the same `principal_id`. Evidence IDs are nonempty valid stable IDs in strict ordinal order without duplicates. `supersedes_decision_id` is required exactly for a superseded decision, forbidden for every other status, and cannot refer to the decision itself.
- `FoundationEventEnvelopeV1` carries ordering and a payload digest, but never payload bytes. Control-plane kinds use `control.` and governed-brain kinds use `memory.`.

Authority is declarative in this slice. Deserialization and schema success do not grant permission or perform admission. Every top-level value must pass its Rust `validate` method before a later system may consider it.

## Schema and semantic boundary

Draft 2020-12 schemas provide structural wire validation and reject unknown properties. Rust provides the authoritative semantic checks for parent-complete scope, exact lowercase digests, canonical collection order, decision actor and transition rules, self-decision, validity windows and transitions, visibility widening approval, and event sequence/domain binding.

An equal or narrower visibility transition needs no approval. A widening transition must receive a caller-supplied lowercase SHA-256 digest of the current authority bytes and a valid Owner approval. The approval namespace, scope, subject identity, and subject digest must exactly match the target authority and supplied current digest. Because visibility is part of the authority bytes, any later widening requires a decision bound to the newly current digest; approval from another authority or an earlier byte representation cannot be reused.

Duplicate JSON object keys are rejected by the contract test loader before schema validation. Implementations in other languages must provide an equivalent duplicate-aware boundary.

## Version policy

V1 accepts exactly `contract_version: 1`. Missing or unknown versions fail closed. A future version must be a new additive contract with an explicit conversion path; it must not reinterpret V1 bytes.

## Compatibility

`PrincipalV1` adds Owner without changing `Role` or `AgentId`. Owner has no legacy `Role`, so that conversion is fallible. `FoundationPermissionProfileV1` is distinct from the Goal Runtime permission profile; conversion in either direction is explicit, fallible, and version checked.

The existing Goal Runtime module, schemas, samples, and serialized role and agent values remain separate. The crate exposes the new module without a glob re-export, preventing accidental namespace or upgrade coupling.

## Hygiene

Samples use synthetic public-role identities and logical paths. Machine paths, environment values, provider data, network locations, raw task bodies, payload bytes, and private roster identities are excluded. The only production contract URLs are the exact JSON Schema metaschema declarations. Tests use only generic bounded invalid literals to prove rejection and do not encode private-persona names.

## Non-goals

This decision does not add persistence, runtime execution, event publication, admission, current pointers, network or provider calls, Brain mutation, evidence storage, automatic migration, or completion claims. It does not change any existing Goal Runtime contract.

## Consequences

Callers gain a deterministic, closed compatibility surface and must explicitly run semantic validation. Later storage and runtime work can depend on these types without redefining authority or evidence semantics, while remaining responsible for its own admission and durability guarantees.
