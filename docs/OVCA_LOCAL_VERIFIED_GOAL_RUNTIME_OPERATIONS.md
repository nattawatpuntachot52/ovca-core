# OVCA Local Verified Goal Runtime Operations

This runbook covers the standalone local-verification operator surface and its
observational shadow CLI. It does not infer authority from host state or permit
network access. Every durable root, projection selection, archive identity,
digest, generation, and retry decision is caller supplied and validated exactly.

## Safety boundary

- Use a caller-owned absolute local durable root outside the source tree and
  outside any verifier snapshot.
- Keep `CARGO_NET_OFFLINE=true`; all verification uses Cargo `--offline --locked`.
- Never use the reviewed `cap.core@1` sample as execution, current-pointer,
  admission, shadow, handoff, or completion authority.
- Never infer a latest archive, current row, generation, CAS token, state digest,
  or rollback target.
- Archive and health values contain logical identifiers and digests only. Do not
  add paths, environment values, task bodies, secrets, or process streams.

### Protected workspace configuration

Every standalone `goal_runtime_shadow` invocation must set
`OVCA_PROTECTED_WORKSPACE` to the existing absolute local workspace directory.
The binary has no default and never infers this value. Missing or blank
configuration returns `protected_workspace_required`; a relative value returns
`protected_workspace_not_absolute`; a UNC or device-namespace value returns
`protected_workspace_unsupported`; and a nonexistent, non-directory, or
unresolvable value returns `protected_workspace_invalid`. These failures occur
before durable persistence.

`--durable-root` must resolve outside the configured workspace. An equal path, a
descendant, a case or extended-path form, or a filesystem alias that resolves
into the workspace returns `protected_root`. Schema-v1 invocation returns the
closed error envelope with exit code 2. Schema-v2 invocation retains its closed
`configuration_error` observation. Neither the configured workspace nor the
durable path is emitted or persisted.

## 1. Deterministic legacy migration

Call `migrate_goal_free_text_contract(&goal)` from `ovca_types`.

The function consumes only `acceptance_criteria`, `verification_criteria`, and
`definition_of_done`. It emits one `BehavioralAcceptanceContract` with
`BehaviorBinding::Unbound`, preserving group order, declaration order, and
duplicates through kind-and-ordinal content identities. Repeating the call with
the same three arrays yields identical canonical bytes. Empty, blank, NUL-bearing,
oversized, or unsupported-version input returns an error and writes nothing.

An operator must explicitly bind and review a migrated contract before use.
Existing completion admission rejects `Unbound`; migration itself never admits
or stores completion evidence.

## 2. Reviewed capability seed

Parse `contracts/samples/capability_definition.v1.sample.json` as a
`CapabilityDefinition`, verify its canonical byte length is `953`, and verify its
canonical SHA-256 is
`ca6f6c8a04c745feccc5dec1b18abf9a2e59891cd8be968244f5cae13143b524`.

Construct `LocalVerificationStore::try_new(durable_root)`, obtain
`capability_registry()`, then call:

```rust
registry.seed_capability(
    &definition,
    expected_record_digest,
    CapabilitySeedPolicy::PublishOnlyNoCurrent,
)?;
```

The first exact call returns `Inserted`; an exact repeat returns
`ExistingIdentical`. Both leave current and generation rows absent. A dependency,
alternate revision, conflicting immutable record, pre-existing current row, or
pre-existing generation row fails closed. The operation never executes the
sample command.

## 3. Real verification and completion admission

Execution authority must come from a separately reviewed capability and bound
behavior contract. Build a `TargetedRerunSelection` from an exact caller-owned
registry snapshot and call `ovca_verifier::verify_and_publish` with an
`EvidenceBank` and caller-provided `ProjectionExpectation`.

After a `Pass` bundle is current, construct an exact
`LocalVerificationCompletionContract` and an
`EnforcedLocalVerificationGoal`. `DurableGoalRuntime` re-reads current capability
and evidence records, rechecks source and environment fingerprints, and applies
completion admission before appending the final completed transition.

Mixed revisions, stale evidence, incomplete criteria, missing dependencies,
unbound behavior, and fingerprint drift must remain errors. Do not synthesize
`EvidenceRef`, `CompletionEvidence`, or `RunEvent` outside the existing admitted
runtime flow.

## 4. Content-addressed archive and readback

Create an exact sorted `AuthoritativeProjectionSelection`, then call:

```rust
let record = store.persist_projection_archive("archive.operator-stable-id", &selection)?;
let archive = store.read_projection_archive(
    &record.manifest.archive_id,
    &record.record_digest,
)?;
```

The bounded caller-stable `archive_id` is part of the canonical manifest with
the closed archive version and exact selection. The manifest contains no self or
payload digest field. `ArchiveRecord` owns the SHA-256 `record_digest` computed
over those canonical bytes and the exact logical reference
`local-verification-archives/sha256/<record_digest>`. Persistence uses immutable
rows in the local-verification SQLite store. The caller identity, content address,
and exact canonical manifest bytes are claimed by one `BEGIN IMMEDIATE`
transaction with unique constraints on both identity and digest. Repeating the
exact ID and bytes returns the same record; the same ID with different bytes, or
the same content address owned by another ID, fails closed. A failure before
commit publishes no identity, digest, or canonical bytes and does not mutate
current projections or generation allocators.

`LocalVerificationStore::try_new` remains path-only and side-effect-free. The
first archive persist or read performs the only archive-related compatible
initialization side effect: it creates the internal archive tables under storage
schema version 1 and, once per durable store, transactionally imports the bounded
legacy `archives/` layout before committing a migration marker. This preserves
reopen of old local stores without changing the public storage schema version.
Legacy import requires an exact bijection between every canonical digest-named
record and its canonical identity mapping. A record-only, mapping-only,
mismatched, duplicate, ambiguous, or unknown entry rejects the whole import and
rolls back the internal tables, rows, and marker.

The internal migration state has only two valid forms: pristine means neither
archive table exists; complete means both tables exist with exactly the singleton
completion marker and the frozen ownership shape: `archive_id` is the text
primary key, `record_digest` has one non-partial unique owner index, and
`canonical_json` is a non-null blob. The marker table also retains its exact
two-column singleton shape. A one-table state, both tables without the marker,
malformed table shape, or any malformed or extra marker fails closed before
scanning legacy files. Deleting or corrupting a committed marker never causes
legacy data to regain authority.
After that marker commits, legacy files are non-authoritative and are never
consulted by persistence or readback. Later archive calls check the completed
marker through a read-only connection and perform no migration write. Health
does not call the archive initializer; it remains strictly read-only and never
creates or migrates tables.

Readback requires the exact caller identity and record digest, strict UTF-8,
canonical bytes, valid immutable ownership, and every referenced immutable
record. The bundle must bind the exact selected capability IDs, revisions, and
record digests, plus the recomputed capability-set, command-set, and policy
fingerprints. Missing, oversized, corrupt, noncanonical, mismatched, ambiguous,
or unowned data fails closed. The one-time legacy directory and identity scan is
bounded. Normal readback is an exact read-only SQLite query and never mutates
current projections or completion state.

## 5. Read-only health

Call `store.local_verification_health()`.

The returned value has exactly five closed sections:

1. `immutable_record_integrity`
2. `current_projection_integrity`
3. `capability_dependency_health`
4. `evidence_binding_health`
5. `recovery_required`

The implementation opens SQLite read-only, sorts all inspected identities, and
bounds the combined row count. Overflow reports `limit_exceeded` and can never be
healthy. Any unhealthy section makes `recovery_required` explicit. Health does
not change current rows, generation allocators, completion, or admission.

## 6. Explicit recovery and rollback

Recovery requires all three exact caller values:

```rust
store.recover_projections_from_archive(
    archive_id,
    expected_record_digest,
    &exact_selection,
)?;
```

The caller selection must equal the archived selection byte-for-byte. `Reset` is
never recovery authority. Empty `Genesis` is only an idempotent no-op when both
projection and allocator tables are pristine. All other recovery requires an
explicit nonempty `Replace` that includes every durable allocator/current key;
omitting a capability or bundle is an error and cannot delete it. A selected new
key must use generation `1`; every selected existing key must be strictly greater
than its durable allocator. Therefore, a historical archive is always stale and
cannot be replayed directly. A legitimate rollback requires a newly constructed
complete selection that references the intended older immutable records but
carries fresh, strictly-increasing caller generations and newly computed state
and selection digests. Persist it under a new caller-stable archive ID before
recovery.

Recovery validates the complete archive, selection, generations, immutable
records, and bindings before deleting any current row. The rebuild and allocator
updates share one immediate SQLite transaction; any validation or write failure
rolls back and preserves the prior projection.

## 7. Ambiguous completion append

If `append_verified_completion` returns after an uncertain durable-write boundary,
do not append or retry first. Call:

```rust
runtime.reconcile_verified_completion_append(&exact_event, &goal)?
```

The method reloads the JSONL stream, resolves the exact persisted authoritative
goal and task set from an enabled local-verification completion policy, then
strictly replays without opening SQLite or writing bytes. Disabled or missing
policy, a same-ID altered goal, and a different authoritative task set fail
closed. It returns only:

- `AlreadyCommitted` when the exact event identity and all bytes are present.
- `RetryRequired` when the exact event is absent and would replay validly.

A reused or alternate event ID, different event bytes, alternate sequence or
previous-event link, non-completion event, malformed stream, or conflicting
completion fails closed. The raw log is unchanged on every return. The method
never appends and never retries.

## 8. Standalone verification and cleanup

Run from the repository root with `CARGO_NET_OFFLINE=true` and caller-owned
external `CARGO_TARGET_DIR`, `TEMP`, and `TMP` directories. The public verification
set is self-contained:

```text
python -m pytest -p no:cacheprovider scripts/tests/test_local_verification_contracts.py
python -m pytest -p no:cacheprovider scripts/tests/test_revision_loop.py
python -m pytest -p no:cacheprovider scripts/tests/test_diagnostic_normalizer.py
cargo metadata --offline --locked --manifest-path rust/Cargo.toml --format-version 1 --no-deps
cargo check --offline --locked --manifest-path rust/Cargo.toml --workspace --all-targets
cargo test --offline --locked --manifest-path rust/Cargo.toml -p ovca-types --lib
cargo test --offline --locked --manifest-path rust/Cargo.toml -p ovca-storage --lib
cargo test --offline --locked --manifest-path rust/Cargo.toml -p ovca-verifier --test integration_test
cargo test --offline --locked --manifest-path rust/Cargo.toml -p ovca-runtime-core --lib
cargo test --offline --locked --manifest-path rust/Cargo.toml -p ovca-langgraph --lib
cargo test --offline --locked --manifest-path rust/Cargo.toml -p ovca-langgraph --test goal_runtime_shadow_cli
cargo test --offline --locked --manifest-path rust/Cargo.toml -p ovca-langgraph --test goal_runtime_v5_e2e
cargo test --offline --locked --manifest-path rust/Cargo.toml -p ovca-observability --test goal_runtime_evals
cargo --offline --locked fmt --manifest-path rust/Cargo.toml -p ovca-types -p ovca-storage -p ovca-verifier -p ovca-runtime-core -p ovca-observability -p ovca-langgraph --check
git diff --check
```

Before closeout, confirm
`rust/ovca-observability/tests/fixtures/goal_runtime_p5_golden_cases.json` remains
byte-identical, no source or snapshot temporary data remains, the Git index is
unchanged, and no network or fetch operation occurred.
