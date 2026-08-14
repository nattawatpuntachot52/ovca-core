use chrono::{TimeZone, Utc};
use ovca_langgraph::{
    DurableGoalRuntime, EnforcedLocalVerificationGoal, EventStamp,
    LocalVerificationCompletionPolicy, PlannedRunStamps,
};
use ovca_runtime_core::{
    validate_local_verification_completion_contract, LocalVerificationCompletionContract,
    LocalVerificationCompletionTask,
};
use ovca_storage::{
    AuthoritativeProjectionSelection, CapabilityCurrent, CapabilitySeedPolicy, CasOutcome,
    EvidenceCurrent, LocalVerificationHealthState, LocalVerificationStore,
    LocalVerificationStoreError, ProjectionExpectation, ProjectionRebuildIntent, PublishOutcome,
};
use ovca_types::{
    migrate_goal_free_text_contract, select_targeted_rerun, verification_policy_digest,
    verification_sha256_hex, BehaviorBinding, BehaviorCriterion, BehaviorKind,
    BehavioralAcceptanceContract, CapabilityDefinition, CapabilityRegistryRow,
    CapabilityRegistrySnapshot, ChangedPathEntry, ChangedPathKind, ChangedPathManifest,
    ChangedPathSelector, CompletionAppendReconciliation, CompletionPrecondition, ContractVersion,
    DeniedAccess, DigestAlgorithm, EventId, GoalContract, GoalId, LocalMachinePolicy,
    PathSelectorKind, PermissionProfile, ProjectId, RiskTier, Role, RunEvent, RunEventPayload,
    RunId, RunStatus, ShellPolicy, TargetedRerunOutcome, TargetedRerunRequest, Task, TaskId,
    TaskStatus, UnknownPathPolicy, VerificationCommand, VerificationVerdict, WorkerId,
    WorkingDirectory, LOCAL_VERIFICATION_CONTRACT_VERSION,
};
use ovca_verifier::bundle::{expected_failure_identity_keys, FailureIdentityMap};
use ovca_verifier::execution::{
    EnvironmentBindings, ExecutableProfile, ExecutableRegistry, ExecutionLimits,
};
use ovca_verifier::snapshot::{SourceFile, SourceManifest};
use ovca_verifier::{verify_and_publish, VerifierOutcome, VerifierRequest};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const CHILD_MODE: &str = "OVCA_V5_E2E_CHILD";
const SAMPLE_DIGEST: &str = "ca6f6c8a04c745feccc5dec1b18abf9a2e59891cd8be968244f5cae13143b524";

#[test]
fn verification_child_probe() {
    if std::env::var(CHILD_MODE).as_deref() == Ok("pass") {
        assert_eq!(2 + 2, 4);
    }
}

#[test]
fn v5_full_local_lifecycle_is_deterministic_reopen_safe_and_fail_closed() {
    let durable = TempDir::new().unwrap();
    let source = TempDir::new().unwrap();
    fs::write(source.path().join("input.txt"), b"frozen V5 source\n").unwrap();
    let manifest = SourceManifest {
        files: vec![SourceFile {
            logical_path: "input.txt".to_owned(),
            sha256: verification_sha256_hex(b"frozen V5 source\n"),
        }],
    };

    let goal = goal();
    let migrated = migrate_goal_free_text_contract(&goal).unwrap();
    assert_eq!(migrated.binding, BehaviorBinding::Unbound);
    assert_eq!(
        migrated.canonical_json_bytes().unwrap(),
        migrate_goal_free_text_contract(&goal)
            .unwrap()
            .canonical_json_bytes()
            .unwrap()
    );

    seed_reviewed_sample_without_current();

    // This capability is deliberately test-only and V4a-derived. The reviewed
    // cap.core sample is seed provenance only and is never execution authority.
    let capability = verifier_capability();
    assert_ne!(capability.capability_id, "cap.core");
    let behavior = verifier_behavior();
    let selection = targeted_selection(&capability, &manifest);
    let invalid_unbound = LocalVerificationCompletionContract {
        goal: goal.clone(),
        task_ids: vec![TaskId::from("task.v5")],
        tasks: vec![LocalVerificationCompletionTask {
            behavior: migrated,
            selection: selection.clone(),
            capabilities: vec![capability.clone()],
        }],
    };
    assert_eq!(
        validate_local_verification_completion_contract(&invalid_unbound)
            .unwrap_err()
            .code,
        "completion_behavior_binding_mismatch"
    );

    let store = LocalVerificationStore::try_new(durable.path()).unwrap();
    let registry = store.capability_registry();
    let capability_record = inserted(registry.publish(&capability).unwrap());
    let capability_current = applied(
        registry
            .compare_and_swap_current(
                &capability.capability_id,
                capability.revision,
                &capability_record.digest,
                &ProjectionExpectation::Absent,
            )
            .unwrap(),
    );
    let published = run_real_verifier(
        durable.path(),
        source.path(),
        &manifest,
        &behavior,
        &capability,
        &selection,
    );
    assert_eq!(published.bundle.verdict, VerificationVerdict::Pass);
    let bundle_current = applied(published.storage.projection.clone());

    let completion = LocalVerificationCompletionContract {
        goal: goal.clone(),
        task_ids: vec![TaskId::from("task.v5")],
        tasks: vec![LocalVerificationCompletionTask {
            behavior: behavior.clone(),
            selection: selection.clone(),
            capabilities: vec![capability.clone()],
        }],
    };
    validate_local_verification_completion_contract(&completion).unwrap();
    let environment_bindings = child_environment();
    let runtime = DurableGoalRuntime::try_new_with_completion_policy(
        durable.path(),
        LocalVerificationCompletionPolicy::Enforced {
            goals: BTreeMap::from([(
                goal.id.clone(),
                EnforcedLocalVerificationGoal {
                    completion,
                    source_manifest: manifest.clone(),
                    source_root: source.path().to_path_buf(),
                    environment_bindings,
                },
            )]),
        },
    )
    .unwrap();
    runtime
        .create_run(RunId::from("run.v5"), &goal, &[task()], planned_stamps())
        .unwrap();
    append(
        &runtime,
        &goal,
        event(
            4,
            RunEventPayload::StatusTransition {
                from: RunStatus::Planned,
                to: RunStatus::Running,
            },
        ),
    );
    let material = runtime
        .prepare_local_verification_completion(&RunId::from("run.v5"), &goal)
        .unwrap();
    append(
        &runtime,
        &goal,
        event(
            5,
            RunEventPayload::EvidenceReferenceRecorded {
                evidence: material.evidence_references[0].clone(),
            },
        ),
    );
    append(
        &runtime,
        &goal,
        event(
            6,
            RunEventPayload::CompletionEvidenceRecorded {
                evidence: material.completion_evidence,
            },
        ),
    );
    let final_event = event(
        7,
        RunEventPayload::StatusTransition {
            from: RunStatus::Running,
            to: RunStatus::Completed,
        },
    );
    let before_completion = fs::read(runtime.log_path()).unwrap();
    assert_eq!(
        runtime
            .reconcile_verified_completion_append(&final_event, &goal)
            .unwrap(),
        CompletionAppendReconciliation::RetryRequired
    );
    assert_eq!(fs::read(runtime.log_path()).unwrap(), before_completion);
    let mut altered_goal = goal.clone();
    altered_goal.objective = "same identifier, altered goal authority".to_owned();
    assert!(runtime
        .reconcile_verified_completion_append(&final_event, &altered_goal)
        .is_err());
    assert_eq!(fs::read(runtime.log_path()).unwrap(), before_completion);

    let completed = runtime
        .append_verified_completion(final_event.clone(), &goal)
        .unwrap();
    assert_eq!(completed.run_record.status, RunStatus::Completed);
    let committed_bytes = fs::read(runtime.log_path()).unwrap();
    assert_eq!(
        runtime
            .reconcile_verified_completion_append(&final_event, &goal)
            .unwrap(),
        CompletionAppendReconciliation::AlreadyCommitted
    );
    assert_eq!(fs::read(runtime.log_path()).unwrap(), committed_bytes);
    let mut conflicting_event = final_event.clone();
    conflicting_event.occurred_at = fixed_time(8);
    assert!(runtime
        .reconcile_verified_completion_append(&conflicting_event, &goal)
        .is_err());
    assert_eq!(fs::read(runtime.log_path()).unwrap(), committed_bytes);
    let mut alternate_id = final_event.clone();
    alternate_id.id = EventId::from("event.v5.alternate");
    let mut alternate_sequence = final_event.clone();
    alternate_sequence.sequence += 1;
    let mut alternate_link = final_event.clone();
    alternate_link.previous_event_id = Some(EventId::from("event.v5.alternate-link"));
    let mut alternate_completion = final_event.clone();
    alternate_completion.payload = RunEventPayload::StatusTransition {
        from: RunStatus::Running,
        to: RunStatus::Failed,
    };
    for rejected in [
        alternate_id,
        alternate_sequence,
        alternate_link,
        alternate_completion,
    ] {
        assert!(runtime
            .reconcile_verified_completion_append(&rejected, &goal)
            .is_err());
        assert_eq!(fs::read(runtime.log_path()).unwrap(), committed_bytes);
    }

    let disabled_runtime = DurableGoalRuntime::new(durable.path());
    assert!(disabled_runtime
        .reconcile_verified_completion_append(&final_event, &goal)
        .is_err());
    assert_eq!(fs::read(runtime.log_path()).unwrap(), committed_bytes);

    let historical_selection = AuthoritativeProjectionSelection::new(
        ProjectionRebuildIntent::Replace,
        vec![capability_current.clone()],
        vec![bundle_current.clone()],
    )
    .unwrap();
    let historical_receipt = store
        .persist_projection_archive("archive.v5.historical", &historical_selection)
        .unwrap();
    assert_eq!(
        historical_receipt,
        store
            .persist_projection_archive("archive.v5.historical", &historical_selection)
            .unwrap()
    );
    let reopened = LocalVerificationStore::try_new(durable.path()).unwrap();
    assert_eq!(
        reopened
            .read_projection_archive(
                &historical_receipt.manifest.archive_id,
                &historical_receipt.record_digest,
            )
            .unwrap()
            .manifest
            .selection,
        historical_selection
    );
    let health = reopened.local_verification_health().unwrap();
    assert_eq!(
        health.recovery_required.state,
        LocalVerificationHealthState::Healthy
    );

    let archive_directory = durable.path().join("local-verification").join("archives");
    assert!(!archive_directory.exists());
    fs::create_dir_all(&archive_directory).unwrap();
    let archive_path = archive_directory.join(format!("{}.json", historical_receipt.record_digest));
    fs::write(&archive_path, b"{\"corrupt\":true}").unwrap();
    assert_eq!(
        reopened
            .read_projection_archive(
                &historical_receipt.manifest.archive_id,
                &historical_receipt.record_digest,
            )
            .unwrap(),
        historical_receipt
    );
    assert!(matches!(
        reopened.recover_projections_from_archive(
            &historical_receipt.manifest.archive_id,
            &historical_receipt.record_digest,
            &historical_selection,
        ),
        Err(LocalVerificationStoreError::RecoveryRequiresFreshGeneration { .. })
    ));

    let mut newer_capability = capability.clone();
    newer_capability.revision = 2;
    newer_capability.commands[0].command_id = "command.v5.revision2".to_owned();
    let newer_record = inserted(registry.publish(&newer_capability).unwrap());
    let newer_current = applied(
        registry
            .compare_and_swap_current(
                &newer_capability.capability_id,
                newer_capability.revision,
                &newer_record.digest,
                &ProjectionExpectation::Token(capability_current.token.clone()),
            )
            .unwrap(),
    );
    assert_eq!(newer_current.token.generation, 2);
    let unhealthy = reopened.local_verification_health().unwrap();
    assert_eq!(
        unhealthy.evidence_binding_health.state,
        LocalVerificationHealthState::Unhealthy
    );
    assert_eq!(
        unhealthy.evidence_binding_health.issue_codes,
        vec!["bundle_capability_set_mismatch".to_owned()]
    );

    let mixed_revision = AuthoritativeProjectionSelection::new(
        ProjectionRebuildIntent::Replace,
        vec![newer_current.clone()],
        vec![bundle_current.clone()],
    )
    .unwrap();
    assert!(reopened
        .persist_projection_archive("archive.v5.mixed-revision", &mixed_revision)
        .is_err());

    let rollback_capability = CapabilityCurrent::new(
        capability_current.capability_id.clone(),
        capability_current.revision,
        capability_current.record_digest.clone(),
        newer_current.token.generation + 1,
    )
    .unwrap();
    let rollback_bundle = EvidenceCurrent::new(
        bundle_current.key.clone(),
        bundle_current.bundle_id.clone(),
        bundle_current.record_digest.clone(),
        bundle_current.freshness.clone(),
        bundle_current.token.generation + 1,
    )
    .unwrap();
    let rollback_selection = AuthoritativeProjectionSelection::new(
        ProjectionRebuildIntent::Replace,
        vec![rollback_capability.clone()],
        vec![rollback_bundle],
    )
    .unwrap();

    let omitted_bundle_selection = AuthoritativeProjectionSelection::new(
        ProjectionRebuildIntent::Replace,
        vec![rollback_capability.clone()],
        vec![],
    )
    .unwrap();
    let omitted_bundle_archive = reopened
        .persist_projection_archive("archive.v5.omitted-bundle", &omitted_bundle_selection)
        .unwrap();
    assert!(reopened
        .recover_projections_from_archive(
            &omitted_bundle_archive.manifest.archive_id,
            &omitted_bundle_archive.record_digest,
            &omitted_bundle_selection,
        )
        .is_err());
    assert_eq!(
        registry
            .load_current(&capability.capability_id)
            .unwrap()
            .unwrap(),
        newer_current
    );

    for (archive_id, intent) in [
        ("archive.v5.empty-reset", ProjectionRebuildIntent::Reset),
        ("archive.v5.empty-genesis", ProjectionRebuildIntent::Genesis),
    ] {
        let empty = AuthoritativeProjectionSelection::new(intent, vec![], vec![]).unwrap();
        let empty_record = reopened
            .persist_projection_archive(archive_id, &empty)
            .unwrap();
        assert!(reopened
            .recover_projections_from_archive(
                &empty_record.manifest.archive_id,
                &empty_record.record_digest,
                &empty,
            )
            .is_err());
        assert_eq!(
            registry
                .load_current(&capability.capability_id)
                .unwrap()
                .unwrap(),
            newer_current
        );
    }

    let rollback_receipt = reopened
        .persist_projection_archive("archive.v5.rollback", &rollback_selection)
        .unwrap();
    assert_ne!(
        rollback_receipt.record_digest,
        historical_receipt.record_digest
    );
    assert!(reopened
        .persist_projection_archive("archive.v5.historical", &rollback_selection)
        .is_err());
    reopened
        .recover_projections_from_archive(
            &rollback_receipt.manifest.archive_id,
            &rollback_receipt.record_digest,
            &rollback_selection,
        )
        .unwrap();
    assert_eq!(
        registry
            .load_current(&capability.capability_id)
            .unwrap()
            .unwrap(),
        rollback_capability
    );
    assert_eq!(
        reopened
            .local_verification_health()
            .unwrap()
            .recovery_required
            .state,
        LocalVerificationHealthState::Healthy
    );

    let mut corrupt_stream = fs::read(runtime.log_path()).unwrap();
    corrupt_stream.extend_from_slice(b"{not-canonical-json}\n");
    fs::write(runtime.log_path(), &corrupt_stream).unwrap();
    assert!(runtime
        .reconcile_verified_completion_append(&final_event, &goal)
        .is_err());
    assert_eq!(fs::read(runtime.log_path()).unwrap(), corrupt_stream);
}

fn seed_reviewed_sample_without_current() {
    let root = TempDir::new().unwrap();
    let sample_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("contracts/samples/capability_definition.v1.sample.json");
    let definition: CapabilityDefinition =
        serde_json::from_slice(&fs::read(sample_path).unwrap()).unwrap();
    assert_eq!(definition.capability_id, "cap.core");
    let canonical = definition.canonical_json_bytes().unwrap();
    assert_eq!(canonical.len(), 953);
    assert_eq!(verification_sha256_hex(&canonical), SAMPLE_DIGEST);
    let store = LocalVerificationStore::try_new(root.path()).unwrap();
    assert!(matches!(
        store
            .capability_registry()
            .seed_capability(
                &definition,
                SAMPLE_DIGEST,
                CapabilitySeedPolicy::PublishOnlyNoCurrent,
            )
            .unwrap(),
        PublishOutcome::Inserted(_)
    ));
    assert!(store
        .capability_registry()
        .load_current("cap.core")
        .unwrap()
        .is_none());
}

fn run_real_verifier(
    durable_root: &Path,
    source_root: &Path,
    manifest: &SourceManifest,
    behavior: &BehavioralAcceptanceContract,
    capability: &CapabilityDefinition,
    selection: &ovca_types::TargetedRerunSelection,
) -> Box<ovca_verifier::PublishedVerification> {
    let snapshot = TempDir::new().unwrap();
    let executable = std::env::current_exe().unwrap();
    let executable_digest = verification_sha256_hex(&fs::read(&executable).unwrap());
    let environment_names = BTreeSet::from([CHILD_MODE.to_owned()]);
    let executable_registry = ExecutableRegistry {
        profiles: BTreeMap::from([(
            "test-runner".to_owned(),
            ExecutableProfile {
                executable_id: "test-runner".to_owned(),
                executable_path: executable,
                sha256: executable_digest,
                enabled: true,
                approved: true,
                reviewed_offline: true,
                allowed_environment_names: environment_names.clone(),
            },
        )]),
    };
    let environment_bindings = child_environment();
    let environment_digest = environment_bindings.digest_for(&environment_names).unwrap();
    let failure_identities: FailureIdentityMap = expected_failure_identity_keys(1)
        .unwrap()
        .into_iter()
        .enumerate()
        .map(|(index, key)| (key, format!("failure.v5.{index:03}")))
        .collect();
    let evidence_bank = ovca_storage::EvidenceBank::try_new(durable_root).unwrap();
    match verify_and_publish(
        VerifierRequest {
            behavior,
            capabilities: std::slice::from_ref(capability),
            selection,
            source_manifest: manifest,
            source_root,
            snapshot_root: snapshot.path(),
            executable_registry: &executable_registry,
            environment_bindings: &environment_bindings,
            environment_digest: &environment_digest,
            limits: ExecutionLimits {
                timeout_millis: 10_000,
                stdout_cap_bytes: 16_384,
                stderr_cap_bytes: 16_384,
            },
            implementation_actor: WorkerId::from("engineer.v5.implementation"),
            verifier_actor: WorkerId::from("auditor.v5.independent"),
            created_at: fixed_time(12),
            failure_identities: &failure_identities,
        },
        &evidence_bank,
        &ProjectionExpectation::Absent,
    )
    .unwrap()
    {
        VerifierOutcome::Published(value) => value,
        VerifierOutcome::Rejected(rejected) => {
            panic!("real verifier rejected: {:?}", rejected.code)
        }
    }
}

fn verifier_capability() -> CapabilityDefinition {
    let environment_names = BTreeSet::from([CHILD_MODE.to_owned()]);
    CapabilityDefinition {
        contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
        capability_id: "capability.v5.e2e".to_owned(),
        revision: 1,
        criterion_ids: vec!["criterion.v5.verify".to_owned()],
        dependencies: vec![],
        changed_path_selectors: vec![ChangedPathSelector {
            kind: PathSelectorKind::Exact,
            path: "input.txt".to_owned(),
        }],
        policy: LocalMachinePolicy {
            local_only: true,
            network: DeniedAccess::Denied,
            provider: DeniedAccess::Denied,
            telemetry: DeniedAccess::Denied,
            egress: DeniedAccess::Denied,
            external_evidence: DeniedAccess::Denied,
            external_storage: DeniedAccess::Denied,
            raw_shell: ShellPolicy::Forbidden,
            inherit_environment: false,
            fingerprint_algorithm: DigestAlgorithm::Sha256,
            allowed_executable_ids: BTreeSet::from(["test-runner".to_owned()]),
            allowed_environment_names: environment_names.clone(),
        },
        commands: vec![VerificationCommand {
            command_id: "command.v5.e2e".to_owned(),
            executable_id: "test-runner".to_owned(),
            argv: vec![
                "verification_child_probe".to_owned(),
                "--exact".to_owned(),
                "--nocapture".to_owned(),
            ],
            cwd: WorkingDirectory::SnapshotRoot,
            environment_names,
        }],
    }
}

fn verifier_behavior() -> BehavioralAcceptanceContract {
    BehavioralAcceptanceContract {
        contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
        contract_id: "behavior.v5.e2e".to_owned(),
        binding: BehaviorBinding::Bound {
            goal_id: GoalId::from("goal.v5"),
            task_id: TaskId::from("task.v5"),
        },
        criteria: vec![BehaviorCriterion {
            criterion_id: "criterion.v5.verify".to_owned(),
            order: 0,
            kind: BehaviorKind::Verification,
            text: "verified by real local verifier".to_owned(),
            required: true,
            capability_ids: vec!["capability.v5.e2e".to_owned()],
        }],
    }
}

fn targeted_selection(
    capability: &CapabilityDefinition,
    manifest: &SourceManifest,
) -> ovca_types::TargetedRerunSelection {
    let record_digest = verification_sha256_hex(&capability.canonical_json_bytes().unwrap());
    #[derive(Serialize)]
    struct State<'a> {
        capability_id: &'a str,
        revision: u64,
        record_digest: &'a str,
        generation: u64,
    }
    let state_digest = verification_sha256_hex(
        &serde_json::to_vec(&State {
            capability_id: &capability.capability_id,
            revision: capability.revision,
            record_digest: &record_digest,
            generation: 1,
        })
        .unwrap(),
    );
    let snapshot = CapabilityRegistrySnapshot::new(vec![CapabilityRegistryRow {
        definition: capability.clone(),
        record_digest,
        generation: 1,
        state_digest,
    }])
    .unwrap();
    let request = TargetedRerunRequest {
        contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
        run_id: RunId::from("run.v5"),
        goal_id: GoalId::from("goal.v5"),
        task_id: TaskId::from("task.v5"),
        source_fingerprint: manifest.fingerprint().unwrap(),
        policy_digest: verification_policy_digest(std::slice::from_ref(capability)).unwrap(),
        changed_paths: ChangedPathManifest {
            entries: vec![ChangedPathEntry {
                kind: ChangedPathKind::Modified,
                path: "input.txt".to_owned(),
                previous_path: None,
            }],
        },
        unknown_path_policy: UnknownPathPolicy::Blocked,
    };
    match select_targeted_rerun(&request, &snapshot) {
        TargetedRerunOutcome::Selected { selection } => *selection,
        other => panic!("selection failed: {other:?}"),
    }
}

fn goal() -> GoalContract {
    GoalContract {
        contract_version: ContractVersion::current(),
        id: GoalId::from("goal.v5"),
        project_id: ProjectId::from("project.oracle"),
        objective: "exercise the local verified goal lifecycle".to_owned(),
        constraints: vec![],
        acceptance_criteria: vec![],
        verification_criteria: vec!["verified by real local verifier".to_owned()],
        permission_profile: PermissionProfile {
            contract_version: ContractVersion::current(),
            risk_tier: RiskTier::R1,
            resource_keys: vec![],
            write_keys: vec![],
            approval_required: false,
            review_required: false,
            audit_required: false,
        },
        definition_of_done: vec![],
        completion_precondition: CompletionPrecondition {
            contract_version: ContractVersion::current(),
            minimum_evidence_refs: 1,
            require_all_acceptance_criteria: true,
            require_all_verification_criteria: true,
        },
        created_at: fixed_time(0),
        updated_at: fixed_time(0),
    }
}

fn task() -> Task {
    Task {
        contract_version: ContractVersion::current(),
        id: TaskId::from("task.v5"),
        goal_id: GoalId::from("goal.v5"),
        outcome: "verified completion".to_owned(),
        dependencies: vec![],
        assigned_role: Role::Engineer,
        resource_keys: vec![],
        write_keys: vec!["local-v5".to_owned()],
        status: TaskStatus::Pending,
        created_at: fixed_time(0),
        updated_at: fixed_time(0),
    }
}

fn planned_stamps() -> PlannedRunStamps {
    PlannedRunStamps {
        run_created: EventStamp {
            id: EventId::from("event-0"),
            occurred_at: fixed_time(0),
        },
        accepted: EventStamp {
            id: EventId::from("event-1"),
            occurred_at: fixed_time(1),
        },
        plan_recorded: EventStamp {
            id: EventId::from("event-2"),
            occurred_at: fixed_time(2),
        },
        planned: EventStamp {
            id: EventId::from("event-3"),
            occurred_at: fixed_time(3),
        },
    }
}

fn event(sequence: u64, payload: RunEventPayload) -> RunEvent {
    RunEvent {
        contract_version: ContractVersion::current(),
        id: EventId::from(format!("event-{sequence}")),
        run_id: RunId::from("run.v5"),
        sequence,
        previous_event_id: Some(EventId::from(format!("event-{}", sequence - 1))),
        occurred_at: fixed_time(sequence as u32),
        producer_role: Role::Coordinator,
        payload,
        metadata: BTreeMap::new(),
    }
}

fn append(runtime: &DurableGoalRuntime, goal: &GoalContract, event: RunEvent) {
    runtime.append_event(event, goal).unwrap();
}

fn child_environment() -> EnvironmentBindings {
    EnvironmentBindings {
        values: BTreeMap::from([(CHILD_MODE.to_owned(), OsString::from("pass"))]),
    }
}

fn inserted<T>(outcome: PublishOutcome<T>) -> T {
    match outcome {
        PublishOutcome::Inserted(value) | PublishOutcome::ExistingIdentical(value) => value,
    }
}

fn applied<T>(outcome: CasOutcome<T>) -> T {
    match outcome {
        CasOutcome::Applied(value) => value,
        CasOutcome::Conflict(_) | CasOutcome::Unchanged(_) => panic!("expected applied CAS"),
    }
}

fn fixed_time(second: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 12, 0, 0, second)
        .single()
        .unwrap()
}
