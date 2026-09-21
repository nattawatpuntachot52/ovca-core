use chrono::{DateTime, TimeZone, Utc};
use ovca_runtime_core::{
    derive_phase_event_id, derive_tool_identity, CancellationRecordV1, DurableExecutionAuthority,
    DurableWorkspaceAuthorityV1, EngineerLogicalPlanV1, EngineerVerifierCasOutcome,
    EngineerVerifierPhaseProjectionV1, EngineerVerifierPhaseV1, EngineerVerifierStateV1,
    EngineerVerifierTriggerV1, ExecutorCallStateV1, PendingPhaseProjectionV1,
    PlannedToolEffectTemplateV1, PreparedWriteEffectV1, RoleExecutionRequest,
    WorkspaceCapabilityBroker, WorkspaceSeedFile, EMPTY_PAYLOAD_SHA256,
    ENGINEER_VERIFIER_CONTRACT_VERSION,
};
use ovca_types::control_plane::{
    canonical_authority_digest as invocation_authority_digest, ExecutionBudget, RoleInvocationV1,
};
use ovca_types::foundation::{
    FoundationAuthorityV1, FoundationNamespaceV1, FoundationPermissionProfileV1, FoundationScopeV1,
    FoundationSensitivityV1, FoundationValidityStatusV1, FoundationValidityV1,
    FoundationVisibilityV1, PrincipalIdentityV1, PrincipalV1,
};
use ovca_types::tool_boundary::{
    canonical_authority_digest, expected_read_permission_keys, expected_write_permission_keys,
    CapabilityGrantV1, CapabilityPolicyV1, ToolOperationV1, ToolRequestV1, WorkspaceFileV1,
    WorkspaceSnapshotV1,
};
use ovca_types::{
    verification_sha256_hex, ContractVersion, EventId, GoalId, IdempotencyKey, RetryBudget,
    RiskTier, Role, RunEvent, RunEventPayload, RunId, Task, TaskId, TaskStatus,
};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

fn at(minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 17, 12, minute, 0)
        .single()
        .unwrap()
}

#[test]
fn cross_process_effect_lock_child() {
    let Ok(sidecar) = std::env::var("OVCA_EFFECT_LOCK_SIDECAR") else {
        return;
    };
    let ready = std::env::var("OVCA_EFFECT_LOCK_READY").unwrap();
    let release = std::env::var("OVCA_EFFECT_LOCK_RELEASE").unwrap();
    let lock = lock_test_sidecar(Path::new(&sidecar)).unwrap();
    fs::write(&ready, std::process::id().to_string()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !Path::new(&release).exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        Path::new(&release).exists(),
        "parent did not release child lock"
    );
    drop(lock);
}

#[cfg(windows)]
fn lock_test_sidecar(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
}

#[cfg(unix)]
fn lock_test_sidecar(path: &Path) -> std::io::Result<File> {
    use std::os::fd::AsRawFd;

    unsafe extern "C" {
        fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    if unsafe { flock(file.as_raw_fd(), 2) } == 0 {
        Ok(file)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn attach_claim_projection(state: &mut EngineerVerifierStateV1) {
    state.phase = EngineerVerifierPhaseV1::Engineering;
    state.phase_revision = 1;
    state.refresh_digest().unwrap();
    let projection = EngineerVerifierPhaseProjectionV1 {
        contract_version: ENGINEER_VERIFIER_CONTRACT_VERSION,
        run_id: state.run_id.clone(),
        goal_id: state.goal_id.clone(),
        task_id: state.task_id.clone(),
        from: EngineerVerifierPhaseV1::Planned,
        to: EngineerVerifierPhaseV1::Engineering,
        trigger: EngineerVerifierTriggerV1::ClaimAccepted,
        phase_revision: state.phase_revision,
        attempt: state.attempt,
        execution_binding_digest: state.execution_binding.execution_binding_digest.clone(),
        logical_plan_digest: state.plan.logical_plan_digest.clone(),
        state_digest: state.state_digest.clone(),
        resolved_effect_ledger_digest: state.ledger.resolved_effect_ledger_digest.clone(),
        engineer_result_digest: None,
        verifier_transcript_digest: None,
        controller_time: state.controller_time,
    };
    let event_id = derive_phase_event_id(&projection).unwrap();
    let event = RunEvent {
        contract_version: ContractVersion::current(),
        id: EventId::from(event_id.clone()),
        run_id: state.run_id.clone(),
        sequence: 0,
        previous_event_id: None,
        occurred_at: state.controller_time,
        producer_role: Role::Coordinator,
        payload: RunEventPayload::NoteRecorded {
            message: "engineer_verifier_phase_v1".to_owned(),
        },
        metadata: BTreeMap::from([(
            "engineer_verifier_phase_v1".to_owned(),
            serde_json::Value::String(
                String::from_utf8(projection.canonical_json_bytes().unwrap()).unwrap(),
            ),
        )]),
    };
    let event_bytes = serde_json::to_vec(&event).unwrap();
    state.pending_projection = Some(PendingPhaseProjectionV1 {
        event_id,
        sequence: 0,
        previous_event_id: None,
        event_digest: verification_sha256_hex(&event_bytes),
        event_bytes,
    });
    state.validate().unwrap();
}

fn identity(id: &str, role: PrincipalV1) -> PrincipalIdentityV1 {
    PrincipalIdentityV1 {
        principal_id: id.to_owned(),
        role,
    }
}

fn invocation(suffix: &str) -> RoleInvocationV1 {
    let scope = FoundationScopeV1 {
        project_id: format!("project.{suffix}"),
        goal_id: Some(format!("goal.{suffix}")),
        task_id: Some(format!("task.{suffix}")),
        run_id: Some(format!("run.{suffix}")),
    };
    let invoker = identity(
        &format!("principal.{suffix}.coordinator"),
        PrincipalV1::Coordinator,
    );
    let authority = FoundationAuthorityV1 {
        contract_version: 1,
        authority_id: format!("authority.{suffix}.invocation"),
        principal: invoker.clone(),
        scope: scope.clone(),
        namespace: FoundationNamespaceV1::CodeReview,
        permission_profile: FoundationPermissionProfileV1 {
            contract_version: 1,
            risk_tier: RiskTier::R1,
            resource_keys: vec![format!("resource.{suffix}")],
            write_keys: Vec::new(),
            approval_required: true,
            review_required: true,
            audit_required: true,
        },
        visibility: FoundationVisibilityV1::RoleScoped,
        sensitivity: FoundationSensitivityV1::Internal,
        validity: FoundationValidityV1 {
            status: FoundationValidityStatusV1::Active,
            valid_from: at(0),
            valid_until: Some(at(59)),
        },
    };
    RoleInvocationV1 {
        contract_version: 1,
        invocation_id: format!("invocation.{suffix}"),
        invoker,
        target: identity(
            &format!("principal.{suffix}.engineer"),
            PrincipalV1::Engineer,
        ),
        task_id: TaskId::from(format!("task.{suffix}")),
        run_id: RunId::from(format!("run.{suffix}")),
        scope,
        budget: ExecutionBudget {
            contract_version: 1,
            max_attempts: 2,
        },
        idempotency_key: IdempotencyKey::from(format!("invocation-key.{suffix}")),
        authority_digest: invocation_authority_digest(&authority).unwrap(),
        authority,
        input_digest: "a".repeat(64),
        invoked_at: at(1),
    }
}

fn plan(suffix: &str) -> EngineerLogicalPlanV1 {
    EngineerLogicalPlanV1::try_new(
        RunId::from(format!("run.{suffix}")),
        GoalId::from(format!("goal.{suffix}")),
        TaskId::from(format!("task.{suffix}")),
        invocation(suffix),
        vec![
            PlannedToolEffectTemplateV1 {
                contract_version: 1,
                ordinal: 0,
                effect_id: format!("effect.{suffix}.read"),
                operation: ToolOperationV1::ReadFile {
                    logical_path: "README.md".to_owned(),
                },
                payload_sha256: EMPTY_PAYLOAD_SHA256.to_owned(),
            },
            PlannedToolEffectTemplateV1 {
                contract_version: 1,
                ordinal: 1,
                effect_id: format!("effect.{suffix}.write"),
                operation: ToolOperationV1::WriteFile {
                    logical_path: "src/lib.rs".to_owned(),
                    content_sha256: ovca_types::verification_sha256_hex(b"new\n"),
                    byte_length: 4,
                },
                payload_sha256: ovca_types::verification_sha256_hex(b"new\n"),
            },
        ],
    )
    .unwrap()
}

fn task(suffix: &str) -> Task {
    Task {
        contract_version: ContractVersion::current(),
        id: TaskId::from(format!("task.{suffix}")),
        goal_id: GoalId::from(format!("goal.{suffix}")),
        outcome: "implement the bounded change".to_owned(),
        dependencies: Vec::new(),
        assigned_role: Role::Engineer,
        resource_keys: Vec::new(),
        write_keys: vec!["src/lib.rs".to_owned()],
        status: TaskStatus::Ready,
        created_at: at(0),
        updated_at: at(0),
    }
}

fn grant(
    execution: &RoleExecutionRequest,
    lease: &ovca_runtime_core::TrustedWorkspaceLease,
) -> CapabilityGrantV1 {
    let read_paths = vec!["README.md".to_owned(), "src/lib.rs".to_owned()];
    let write_paths = vec!["src/lib.rs".to_owned()];
    let grant_authority = FoundationAuthorityV1 {
        contract_version: 1,
        authority_id: "authority.recovery.grant".to_owned(),
        principal: execution.invocation.invoker.clone(),
        scope: execution.invocation.scope.clone(),
        namespace: FoundationNamespaceV1::CodeReview,
        permission_profile: FoundationPermissionProfileV1 {
            contract_version: 1,
            risk_tier: RiskTier::R2,
            resource_keys: expected_read_permission_keys(&read_paths).unwrap(),
            write_keys: expected_write_permission_keys(&write_paths).unwrap(),
            approval_required: true,
            review_required: true,
            audit_required: true,
        },
        visibility: execution.invocation.authority.visibility,
        sensitivity: execution.invocation.authority.sensitivity,
        validity: FoundationValidityV1 {
            status: FoundationValidityStatusV1::Active,
            valid_from: at(0),
            valid_until: Some(at(50)),
        },
    };
    CapabilityGrantV1 {
        contract_version: 1,
        grant_id: "grant.recovery".to_owned(),
        invocation_id: execution.invocation.invocation_id.clone(),
        invocation_digest: execution.invocation.canonical_digest().unwrap(),
        attempt: execution.attempt,
        issuer: execution.invocation.invoker.clone(),
        grantee: execution.invocation.target.clone(),
        scope: execution.invocation.scope.clone(),
        grant_authority_digest: canonical_authority_digest(&grant_authority).unwrap(),
        grant_authority,
        lease_id: lease.observation().lease_id.clone(),
        lease_digest: lease.digest().to_owned(),
        workspace_id: lease.observation().workspace_id.clone(),
        snapshot_digest: lease.initial_snapshot().snapshot_digest.clone(),
        read_paths,
        write_paths,
        max_read_bytes: 1024,
        max_write_bytes: 1024,
        command_policy: CapabilityPolicyV1::Denied,
        environment_policy: CapabilityPolicyV1::Denied,
        network_policy: CapabilityPolicyV1::Denied,
        valid_from: at(5),
        valid_until: at(40),
    }
}

#[test]
fn logical_plan_is_closed_canonical_and_attempt_ids_are_domain_bound() {
    let first = plan("canonical-a");
    first.validate().unwrap();
    let bytes = first.canonical_json_bytes().unwrap();
    assert!(!bytes.ends_with(b"\n"));

    let mut with_unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    with_unknown
        .as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<EngineerLogicalPlanV1>(with_unknown).is_err());

    let same_attempt = derive_tool_identity(&first, "effect.canonical-a.read", 1).unwrap();
    let retry = derive_tool_identity(&first, "effect.canonical-a.read", 2).unwrap();
    assert_ne!(same_attempt.request_id, retry.request_id);
    assert_ne!(same_attempt.idempotency_key, retry.idempotency_key);

    let second = plan("canonical-b");
    let other_invocation = derive_tool_identity(&second, "effect.canonical-b.read", 1).unwrap();
    assert_ne!(same_attempt.request_id, other_invocation.request_id);
    assert_ne!(
        same_attempt.idempotency_key,
        other_invocation.idempotency_key
    );
}

#[test]
fn invalid_effect_order_and_payload_fail_before_runtime_authority() {
    let mut invalid = plan("invalid-order");
    invalid.ordered_effects.swap(0, 1);
    assert!(invalid.validate().is_err());

    let write = &plan("payload").ordered_effects[1];
    assert!(write.validate_payload(Some(b"changed")).is_err());
    assert!(write.validate_payload(None).is_err());
}

#[test]
fn prepared_write_requires_the_exact_target_only_snapshot_delta() {
    let invocation = invocation("prepared-delta");
    let before_target = WorkspaceFileV1 {
        logical_path: "src/lib.rs".to_owned(),
        sha256: verification_sha256_hex(b"old\n"),
        byte_length: 4,
    };
    let unchanged = WorkspaceFileV1 {
        logical_path: "README.md".to_owned(),
        sha256: verification_sha256_hex(b"readme\n"),
        byte_length: 7,
    };
    let intended_target = WorkspaceFileV1 {
        logical_path: "src/lib.rs".to_owned(),
        sha256: verification_sha256_hex(b"new\n"),
        byte_length: 4,
    };
    let before = WorkspaceSnapshotV1::try_new(
        "workspace.prepared-delta".to_owned(),
        "lease.prepared-delta".to_owned(),
        0,
        vec![unchanged.clone(), before_target.clone()],
    )
    .unwrap();
    let after = WorkspaceSnapshotV1::try_new(
        before.workspace_id.clone(),
        before.lease_id.clone(),
        1,
        vec![unchanged.clone(), intended_target.clone()],
    )
    .unwrap();
    let request = ToolRequestV1 {
        contract_version: 1,
        request_id: "request.prepared-delta".to_owned(),
        idempotency_key: "idempotency.prepared-delta".to_owned(),
        invocation_id: invocation.invocation_id.clone(),
        invocation_digest: invocation.canonical_digest().unwrap(),
        attempt: 1,
        grant_id: "grant.prepared-delta".to_owned(),
        grant_digest: "b".repeat(64),
        lease_id: before.lease_id.clone(),
        lease_digest: "c".repeat(64),
        workspace_id: before.workspace_id.clone(),
        expected_snapshot_digest: before.snapshot_digest.clone(),
        requester: invocation.target.clone(),
        scope: invocation.scope.clone(),
        operation: ToolOperationV1::WriteFile {
            logical_path: intended_target.logical_path.clone(),
            content_sha256: intended_target.sha256.clone(),
            byte_length: intended_target.byte_length,
        },
        requested_at: at(10),
    };
    let prepared = PreparedWriteEffectV1 {
        contract_version: ENGINEER_VERIFIER_CONTRACT_VERSION,
        ordinal: 1,
        effect_id: "effect.prepared-delta.write".to_owned(),
        request_digest: request.canonical_digest().unwrap(),
        payload_sha256: intended_target.sha256.clone(),
        lease_digest: request.lease_digest.clone(),
        grant_digest: request.grant_digest.clone(),
        expected_before_snapshot: before.clone(),
        expected_before_file: Some(before_target.clone()),
        intended_after_snapshot: after.clone(),
        intended_after_file: intended_target.clone(),
        request,
        reserved_sequence: 1,
        prepared_at: at(10),
    };
    prepared.validate().unwrap();

    let mut wrong_before = prepared.clone();
    wrong_before.expected_before_file = None;
    assert!(wrong_before.validate().is_err());

    let mut omitted_target = prepared.clone();
    omitted_target.intended_after_snapshot = WorkspaceSnapshotV1::try_new(
        before.workspace_id.clone(),
        before.lease_id.clone(),
        1,
        vec![unchanged.clone()],
    )
    .unwrap();
    assert!(omitted_target.validate().is_err());

    let mut no_op = prepared.clone();
    no_op.intended_after_file = before_target.clone();
    no_op.intended_after_snapshot = WorkspaceSnapshotV1::try_new(
        before.workspace_id.clone(),
        before.lease_id.clone(),
        1,
        before.files.clone(),
    )
    .unwrap();
    assert!(no_op.validate().is_err());

    let mut unrelated_delta = prepared;
    let changed_unrelated = WorkspaceFileV1 {
        logical_path: unchanged.logical_path,
        sha256: verification_sha256_hex(b"forged\n"),
        byte_length: 7,
    };
    unrelated_delta.intended_after_snapshot = WorkspaceSnapshotV1::try_new(
        before.workspace_id,
        before.lease_id,
        1,
        vec![changed_unrelated, intended_target],
    )
    .unwrap();
    assert!(unrelated_delta.validate().is_err());
}

#[test]
fn optional_projection_preserves_legacy_bytes_and_cas_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let authority = DurableExecutionAuthority::new(temp.path());
    let initialized = authority
        .initialize_run(
            RunId::from("run.sqlite"),
            vec![task("sqlite")],
            RetryBudget {
                contract_version: ContractVersion::current(),
                max_attempts: 2,
            },
        )
        .unwrap();
    let legacy_bytes = serde_json::to_vec(&initialized.state.envelope).unwrap();
    assert!(!String::from_utf8(legacy_bytes)
        .unwrap()
        .contains("engineer_verifier"));

    let state = EngineerVerifierStateV1::planned(plan("sqlite"), at(2)).unwrap();
    let applied = authority
        .compare_and_swap_engineer_verifier(
            &RunId::from("run.sqlite"),
            initialized.state.revision,
            None,
            state.clone(),
        )
        .unwrap();
    let EngineerVerifierCasOutcome::Applied(applied) = applied else {
        panic!("first projection must apply")
    };
    assert_eq!(applied.envelope.engineer_verifier, Some(state.clone()));

    let conflict = authority
        .compare_and_swap_engineer_verifier(
            &RunId::from("run.sqlite"),
            initialized.state.revision,
            None,
            state,
        )
        .unwrap();
    assert!(matches!(conflict, EngineerVerifierCasOutcome::Conflict(_)));
}

#[test]
fn pre_admission_root_is_cleaned_when_revision_advances_without_adoption() {
    let workspace_parent = tempfile::tempdir().unwrap();
    let protected = tempfile::tempdir().unwrap();
    let durable_root = tempfile::tempdir().unwrap();
    let logical_plan = plan("unadopted-root");
    let authority = DurableExecutionAuthority::new(durable_root.path());
    let initialized = authority
        .initialize_run(
            logical_plan.run_id.clone(),
            vec![task("unadopted-root")],
            RetryBudget {
                contract_version: ContractVersion::current(),
                max_attempts: 2,
            },
        )
        .unwrap();
    let execution = RoleExecutionRequest {
        invocation: logical_plan.invocation.clone(),
        attempt: 1,
    };
    let mut broker = WorkspaceCapabilityBroker::try_new(
        "runtime.unadopted",
        workspace_parent.path(),
        vec![protected.path().to_path_buf()],
        Box::new(TestClock(at(10))),
    )
    .unwrap();
    let lease = broker
        .open_recoverable_lease(
            &authority,
            &logical_plan.run_id,
            initialized.state.revision,
            None,
            &execution,
            "lease.unadopted",
            "workspace.unadopted",
            "recovery-token.unadopted",
            vec![WorkspaceSeedFile::try_new("src/lib.rs", b"old\n".to_vec()).unwrap()],
            at(5),
            at(40),
        )
        .unwrap();
    assert_eq!(broker.active_root_count(), 1);

    let planned = EngineerVerifierStateV1::planned(logical_plan.clone(), at(6)).unwrap();
    let applied = authority
        .compare_and_swap_engineer_verifier(
            &logical_plan.run_id,
            initialized.state.revision,
            None,
            planned.clone(),
        )
        .unwrap();
    assert!(matches!(applied, EngineerVerifierCasOutcome::Applied(_)));

    broker
        .close_lease(&lease, ovca_runtime_core::CleanupReason::Failed)
        .unwrap();
    assert_eq!(broker.active_root_count(), 0);
    let durable = authority.load(&logical_plan.run_id).unwrap();
    assert_eq!(durable.envelope.engineer_verifier, Some(planned));
}

#[test]
fn cancellation_after_request_preparation_blocks_native_effect_and_allows_owned_cleanup() {
    let workspace_parent = tempfile::tempdir().unwrap();
    let protected = tempfile::tempdir().unwrap();
    let durable_root = tempfile::tempdir().unwrap();
    let logical_plan = plan("cancel-before-effect");
    let authority = DurableExecutionAuthority::new(durable_root.path());
    let initialized = authority
        .initialize_run(
            logical_plan.run_id.clone(),
            vec![task("cancel-before-effect")],
            RetryBudget {
                contract_version: ContractVersion::current(),
                max_attempts: 2,
            },
        )
        .unwrap();
    let execution = RoleExecutionRequest {
        invocation: logical_plan.invocation.clone(),
        attempt: 1,
    };
    let mut broker = WorkspaceCapabilityBroker::try_new(
        "runtime.cancel-before-effect",
        workspace_parent.path(),
        vec![protected.path().to_path_buf()],
        Box::new(TestClock(at(10))),
    )
    .unwrap();
    let lease = broker
        .open_recoverable_lease(
            &authority,
            &logical_plan.run_id,
            initialized.state.revision,
            None,
            &execution,
            "lease.cancel-before-effect",
            "workspace.cancel-before-effect",
            "recovery-token.cancel-before-effect",
            vec![
                WorkspaceSeedFile::try_new("README.md", b"readme\n".to_vec()).unwrap(),
                WorkspaceSeedFile::try_new("src/lib.rs", b"old\n".to_vec()).unwrap(),
            ],
            at(5),
            at(40),
        )
        .unwrap();
    let grant_dto = grant(&execution, &lease);
    let trusted_grant = broker
        .issue_grant(&execution, &lease, grant_dto.clone())
        .unwrap();

    let mut state = EngineerVerifierStateV1::planned(logical_plan.clone(), at(6)).unwrap();
    state.executor = ExecutorCallStateV1::NotStarted;
    state.workspace = Some(DurableWorkspaceAuthorityV1 {
        lease: lease.observation().clone(),
        lease_digest: lease.digest().to_owned(),
        initial_snapshot: lease.initial_snapshot().clone(),
        grant: grant_dto,
        grant_digest: trusted_grant.digest().to_owned(),
        current_snapshot: lease.initial_snapshot().clone(),
        recovery_token: "recovery-token.cancel-before-effect".to_owned(),
        runtime_instance_id: "runtime.cancel-before-effect".to_owned(),
        fence: 1,
        runtime_epoch: 1,
        heartbeat_at: at(6),
        next_receipt_sequence: 1,
        cleanup_required: false,
        closed: false,
    });
    attach_claim_projection(&mut state);
    let applied = authority
        .compare_and_swap_engineer_verifier(
            &logical_plan.run_id,
            initialized.state.revision,
            None,
            state,
        )
        .unwrap();
    let EngineerVerifierCasOutcome::Applied(applied) = applied else {
        panic!("engineering state must apply")
    };
    let pending = applied
        .envelope
        .engineer_verifier
        .as_ref()
        .unwrap()
        .pending_projection
        .clone()
        .unwrap();
    let mut projected_state = applied.envelope.engineer_verifier.clone().unwrap();
    let applied_digest = projected_state.state_digest.clone();
    projected_state.pending_projection = None;
    projected_state.projected_sequence = Some(pending.sequence);
    projected_state.projected_event_id = Some(pending.event_id);
    projected_state.refresh_digest().unwrap();
    let projected = authority
        .compare_and_swap_engineer_verifier(
            &logical_plan.run_id,
            applied.revision,
            Some(&applied_digest),
            projected_state,
        )
        .unwrap();
    let EngineerVerifierCasOutcome::Applied(projected) = projected else {
        panic!("phase projection must apply")
    };

    let identity =
        derive_tool_identity(&logical_plan, "effect.cancel-before-effect.read", 1).unwrap();
    let request = ToolRequestV1 {
        contract_version: 1,
        request_id: identity.request_id,
        idempotency_key: identity.idempotency_key,
        invocation_id: logical_plan.invocation.invocation_id.clone(),
        invocation_digest: logical_plan.invocation_digest.clone(),
        attempt: 1,
        grant_id: trusted_grant.observation().grant_id.clone(),
        grant_digest: trusted_grant.digest().to_owned(),
        lease_id: lease.observation().lease_id.clone(),
        lease_digest: lease.digest().to_owned(),
        workspace_id: lease.observation().workspace_id.clone(),
        expected_snapshot_digest: lease.initial_snapshot().snapshot_digest.clone(),
        requester: logical_plan.invocation.target.clone(),
        scope: logical_plan.invocation.scope.clone(),
        operation: ToolOperationV1::ReadFile {
            logical_path: "README.md".to_owned(),
        },
        requested_at: at(9),
    };

    let mut cancelled = projected.envelope.engineer_verifier.clone().unwrap();
    cancelled.cancellation =
        Some(CancellationRecordV1::try_new("cancel-before-native-effect", at(11)).unwrap());
    cancelled.controller_time = at(11);
    cancelled.refresh_digest().unwrap();
    let cancelled = authority
        .compare_and_swap_engineer_verifier(
            &logical_plan.run_id,
            projected.revision,
            projected
                .envelope
                .engineer_verifier
                .as_ref()
                .map(|state| state.state_digest.as_str()),
            cancelled,
        )
        .unwrap();
    assert!(matches!(cancelled, EngineerVerifierCasOutcome::Applied(_)));

    assert!(broker.execute(request, None).is_err());
    assert_eq!(broker.backend_calls(), 0);
    let durable = authority.load(&logical_plan.run_id).unwrap();
    let state = durable.envelope.engineer_verifier.unwrap();
    assert!(state.cancellation.is_some());
    assert!(state.ledger.entries.is_empty());
    broker
        .close_lease(&lease, ovca_runtime_core::CleanupReason::Cancelled)
        .unwrap();
    assert_eq!(broker.active_root_count(), 0);
}

#[test]
fn separate_process_effect_lock_excludes_cas_and_releases_on_exit() {
    let temp = tempfile::tempdir().unwrap();
    let authority = DurableExecutionAuthority::new(temp.path());
    let logical_plan = plan("cross-process-lock");
    let initialized = authority
        .initialize_run(
            logical_plan.run_id.clone(),
            vec![task("cross-process-lock")],
            RetryBudget {
                contract_version: ContractVersion::current(),
                max_attempts: 2,
            },
        )
        .unwrap();
    let sidecar = temp.path().join("state").join("workspace-effects.lock");
    let ready = temp.path().join("child-ready");
    let release = temp.path().join("child-release");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("cross_process_effect_lock_child")
        .arg("--nocapture")
        .env("OVCA_EFFECT_LOCK_SIDECAR", &sidecar)
        .env("OVCA_EFFECT_LOCK_READY", &ready)
        .env("OVCA_EFFECT_LOCK_RELEASE", &release)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let ready_deadline = Instant::now() + Duration::from_secs(2);
    while !ready.exists() && Instant::now() < ready_deadline {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("effect-lock child exited before readiness: {status}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if !ready.exists() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("effect-lock child readiness timed out");
    }
    let child_pid = fs::read_to_string(&ready).unwrap();
    let release_path = release.clone();
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        fs::write(release_path, b"release").unwrap();
    });
    let started = Instant::now();
    let run_id = logical_plan.run_id.clone();
    let outcome = authority
        .compare_and_swap_engineer_verifier(
            &run_id,
            initialized.state.revision,
            None,
            EngineerVerifierStateV1::planned(logical_plan, at(2)).unwrap(),
        )
        .unwrap();
    let elapsed = started.elapsed();
    releaser.join().unwrap();
    assert!(matches!(outcome, EngineerVerifierCasOutcome::Applied(_)));
    assert!(elapsed >= Duration::from_millis(50));
    assert!(elapsed < Duration::from_secs(5));

    let exit_deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= exit_deadline {
            let _ = child.kill();
            let status = child.wait().unwrap();
            panic!("effect-lock child {child_pid} timed out and was terminated: {status}");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    println!("effect-lock-child pid={child_pid} status={status}");
    assert!(status.success());
}

#[test]
fn recovery_permit_is_cas_minted_and_re_adopts_exact_physical_workspace() {
    let workspace_parent = tempfile::tempdir().unwrap();
    let protected = tempfile::tempdir().unwrap();
    let effect_entered = Arc::new((Mutex::new(false), Condvar::new()));
    let effect_release = Arc::new((Mutex::new(false), Condvar::new()));
    let mut original = WorkspaceCapabilityBroker::try_new(
        "runtime.original",
        workspace_parent.path(),
        vec![protected.path().to_path_buf()],
        Box::new(BlockingClock {
            now: at(10),
            effect_entered: effect_entered.clone(),
            effect_release: effect_release.clone(),
            blocked: AtomicBool::new(false),
        }),
    )
    .unwrap();
    let logical_plan = plan("recovery");
    let execution = RoleExecutionRequest {
        invocation: logical_plan.invocation.clone(),
        attempt: 1,
    };
    let durable_root = tempfile::tempdir().unwrap();
    let authority = DurableExecutionAuthority::new(durable_root.path());
    let initialized = authority
        .initialize_run(
            logical_plan.run_id.clone(),
            vec![task("recovery")],
            RetryBudget {
                contract_version: ContractVersion::current(),
                max_attempts: 2,
            },
        )
        .unwrap();
    let lease = original
        .open_recoverable_lease(
            &authority,
            &logical_plan.run_id,
            initialized.state.revision,
            None,
            &execution,
            "lease.recovery",
            "workspace.recovery",
            "recovery-token.recovery",
            vec![
                WorkspaceSeedFile::try_new("README.md", b"readme\n".to_vec()).unwrap(),
                WorkspaceSeedFile::try_new("src/lib.rs", b"old\n".to_vec()).unwrap(),
            ],
            at(5),
            at(40),
        )
        .unwrap();
    let mut grant_dto = grant(&execution, &lease);
    grant_dto.valid_until = at(20);
    let trusted_grant = original
        .issue_grant(&execution, &lease, grant_dto.clone())
        .unwrap();
    assert!(!original
        .target_matches_current(
            &lease,
            "src/lib.rs",
            &ovca_types::verification_sha256_hex(b"new\n"),
            4,
        )
        .unwrap());
    assert_eq!(original.backend_calls(), 0);

    let mut state = EngineerVerifierStateV1::planned(logical_plan.clone(), at(6)).unwrap();
    state.executor = ExecutorCallStateV1::NotStarted;
    state.workspace = Some(DurableWorkspaceAuthorityV1 {
        lease: lease.observation().clone(),
        lease_digest: lease.digest().to_owned(),
        initial_snapshot: lease.initial_snapshot().clone(),
        grant: grant_dto,
        grant_digest: trusted_grant.digest().to_owned(),
        current_snapshot: lease.initial_snapshot().clone(),
        recovery_token: "recovery-token.recovery".to_owned(),
        runtime_instance_id: "runtime.original".to_owned(),
        fence: 1,
        runtime_epoch: 1,
        heartbeat_at: at(6),
        next_receipt_sequence: 1,
        cleanup_required: false,
        closed: false,
    });
    attach_claim_projection(&mut state);
    let applied = authority
        .compare_and_swap_engineer_verifier(
            &logical_plan.run_id,
            initialized.state.revision,
            None,
            state.clone(),
        )
        .unwrap();
    let EngineerVerifierCasOutcome::Applied(applied) = applied else {
        panic!("state must apply")
    };
    let pending = state.pending_projection.clone().unwrap();
    let mut projected = state.clone();
    projected.pending_projection = None;
    projected.projected_sequence = Some(pending.sequence);
    projected.projected_event_id = Some(pending.event_id);
    let projected = authority
        .compare_and_swap_engineer_verifier(
            &logical_plan.run_id,
            applied.revision,
            Some(&state.state_digest),
            projected,
        )
        .unwrap();
    let EngineerVerifierCasOutcome::Applied(projected) = projected else {
        panic!("projected state must apply")
    };
    let mut forged = projected.envelope.engineer_verifier.clone().unwrap();
    forged.workspace.as_mut().unwrap().fence += 1;
    forged.refresh_digest().unwrap();
    assert!(matches!(
        authority.compare_and_swap_engineer_verifier(
            &logical_plan.run_id,
            projected.revision,
            Some(&state.state_digest),
            forged,
        ),
        Err(ovca_runtime_core::DurableExecutionError::EngineerVerifier(
            ovca_runtime_core::EngineerVerifierError::InvalidTransition
        ))
    ));
    assert!(matches!(
        authority.claim_workspace_recovery(
            &logical_plan.run_id,
            projected.revision,
            &state.state_digest,
            "runtime.expired-grant",
            at(20),
        ),
        Err(ovca_runtime_core::DurableExecutionError::EngineerVerifier(
            ovca_runtime_core::EngineerVerifierError::InvalidBinding
        ))
    ));
    let read_identity = derive_tool_identity(&logical_plan, "effect.recovery.read", 1).unwrap();
    let read_request = ToolRequestV1 {
        contract_version: 1,
        request_id: read_identity.request_id,
        idempotency_key: read_identity.idempotency_key,
        invocation_id: logical_plan.invocation.invocation_id.clone(),
        invocation_digest: logical_plan.invocation_digest.clone(),
        attempt: 1,
        grant_id: trusted_grant.observation().grant_id.clone(),
        grant_digest: trusted_grant.digest().to_owned(),
        lease_id: lease.observation().lease_id.clone(),
        lease_digest: lease.digest().to_owned(),
        workspace_id: lease.observation().workspace_id.clone(),
        expected_snapshot_digest: lease.initial_snapshot().snapshot_digest.clone(),
        requester: logical_plan.invocation.target.clone(),
        scope: logical_plan.invocation.scope.clone(),
        operation: ToolOperationV1::ReadFile {
            logical_path: "README.md".to_owned(),
        },
        requested_at: at(9),
    };
    let effect_thread = std::thread::spawn(move || {
        let result = original.execute(read_request, None);
        (original, lease, trusted_grant, result)
    });
    let (entered_lock, entered_signal) = &*effect_entered;
    let entered = entered_lock.lock().unwrap();
    let (entered, wait) = entered_signal
        .wait_timeout_while(entered, Duration::from_secs(2), |entered| !*entered)
        .unwrap();
    assert!(*entered && !wait.timed_out(), "broker effect did not enter");
    let claim_authority = authority.clone();
    let claim_run_id = logical_plan.run_id.clone();
    let claim_state_digest = state.state_digest.clone();
    let (claim_sender, claim_receiver) = mpsc::channel();
    let claim_thread = std::thread::spawn(move || {
        claim_sender
            .send(claim_authority.claim_workspace_recovery(
                &claim_run_id,
                projected.revision,
                &claim_state_digest,
                "runtime.recovered-a",
                at(11),
            ))
            .unwrap();
    });
    assert!(matches!(
        claim_receiver.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    let (release_lock, release_signal) = &*effect_release;
    *release_lock.lock().unwrap() = true;
    release_signal.notify_all();
    let claim_a = claim_receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap()
        .unwrap();
    claim_thread.join().unwrap();
    let (mut original, lease, trusted_grant, read_result) = effect_thread.join().unwrap();
    assert_eq!(
        read_result.unwrap().read_bytes(),
        Some(b"readme\n".as_slice())
    );

    let recovered_authority = claim_a
        .state
        .envelope
        .engineer_verifier
        .as_ref()
        .unwrap()
        .workspace
        .as_ref()
        .unwrap();
    assert_eq!(recovered_authority.fence, 2);
    assert_eq!(recovered_authority.runtime_epoch, 2);

    let claim_a_state = claim_a.state.envelope.engineer_verifier.as_ref().unwrap();
    let claim_b = authority
        .claim_workspace_recovery(
            &logical_plan.run_id,
            claim_a.state.revision,
            &claim_a_state.state_digest,
            "runtime.recovered-b",
            at(12),
        )
        .unwrap()
        .unwrap();
    let newest_authority = claim_b
        .state
        .envelope
        .engineer_verifier
        .as_ref()
        .unwrap()
        .workspace
        .as_ref()
        .unwrap();
    assert_eq!(newest_authority.fence, 3);
    assert_eq!(newest_authority.runtime_epoch, 3);

    let mut stale_recovery = WorkspaceCapabilityBroker::try_new(
        "runtime.recovered-a",
        workspace_parent.path(),
        vec![protected.path().to_path_buf()],
        Box::new(TestClock(at(13))),
    )
    .unwrap();
    assert!(stale_recovery.recover_lease(claim_a.permit).is_err());
    assert!(!original.grant_is_live(&trusted_grant));
    assert!(original
        .target_matches_current(
            &lease,
            "src/lib.rs",
            &ovca_types::verification_sha256_hex(b"new\n"),
            4,
        )
        .is_err());
    assert!(original
        .close_lease(&lease, ovca_runtime_core::CleanupReason::Failed)
        .is_err());
    assert_eq!(original.active_root_count(), 1);
    drop(original);

    let mut recovered = WorkspaceCapabilityBroker::try_new(
        "runtime.recovered-b",
        workspace_parent.path(),
        vec![protected.path().to_path_buf()],
        Box::new(TestClock(at(13))),
    )
    .unwrap();
    let (recovered_lease, recovered_grant) = recovered.recover_lease(claim_b.permit).unwrap();
    assert_eq!(
        recovered.snapshot(&recovered_lease).unwrap(),
        *lease.initial_snapshot()
    );
    assert!(recovered.grant_is_live(&recovered_grant));
    assert_eq!(recovered.backend_calls(), 0);
}

#[derive(Debug)]
struct TestClock(DateTime<Utc>);

impl ovca_runtime_core::BrokerClock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

#[derive(Debug)]
struct BlockingClock {
    now: DateTime<Utc>,
    effect_entered: Arc<(Mutex<bool>, Condvar)>,
    effect_release: Arc<(Mutex<bool>, Condvar)>,
    blocked: AtomicBool,
}

impl ovca_runtime_core::BrokerClock for BlockingClock {
    fn now(&self) -> DateTime<Utc> {
        if !self.blocked.swap(true, Ordering::SeqCst) {
            let (entered_lock, entered_signal) = &*self.effect_entered;
            *entered_lock.lock().unwrap() = true;
            entered_signal.notify_all();
            let (release_lock, release_signal) = &*self.effect_release;
            let release = release_lock.lock().unwrap();
            let (release, wait) = release_signal
                .wait_timeout_while(release, Duration::from_secs(2), |release| !*release)
                .unwrap();
            assert!(*release && !wait.timed_out(), "effect release timed out");
        }
        self.now
    }
}

#[test]
fn exact_phase_enum_rejects_unknown_and_terminal_outgoing_edges() {
    assert!(serde_json::from_str::<EngineerVerifierPhaseV1>("\"unknown\"").is_err());
    for terminal in [
        EngineerVerifierPhaseV1::Reviewing,
        EngineerVerifierPhaseV1::Failed,
        EngineerVerifierPhaseV1::Cancelled,
    ] {
        assert!(terminal.is_terminal());
        assert!(!ovca_runtime_core::transition_allowed(
            terminal,
            ovca_runtime_core::EngineerVerifierTriggerV1::FailureRecorded,
            EngineerVerifierPhaseV1::Failed,
        ));
    }
}

#[test]
fn compact_plan_json_has_declared_top_level_field_order() {
    let value = plan("field-order");
    let parsed: BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&value.canonical_json_bytes().unwrap()).unwrap();
    assert_eq!(parsed.len(), 8);
    let text = String::from_utf8(value.canonical_json_bytes().unwrap()).unwrap();
    let positions = [
        "contract_version",
        "run_id",
        "goal_id",
        "task_id",
        "invocation",
        "invocation_digest",
        "ordered_effects",
        "logical_plan_digest",
    ]
    .map(|field| text.find(&format!("\"{field}\"")).unwrap());
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
}
