use chrono::{DateTime, TimeZone, Utc};
use ovca_runtime_core::{
    BrokerClock, CleanupReason, RoleExecutionRequest, ToolExecutionResult, TrustedCapabilityGrant,
    TrustedWorkspaceLease, WorkspaceCapabilityBroker, WorkspaceCapabilityError,
    WorkspaceLeaseState, WorkspaceSeedFile,
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
    CapabilityGrantV1, CapabilityPolicyV1, ToolDeniedCodeV1, ToolOperationV1, ToolReceiptOutcomeV1,
    ToolRequestV1, UnsupportedToolKindV1,
};
use ovca_types::{IdempotencyKey, RiskTier, RunId, TaskId};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

fn timestamp(minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 17, 10, minute, 0)
        .single()
        .unwrap()
}

fn identity(id: &str, role: PrincipalV1) -> PrincipalIdentityV1 {
    PrincipalIdentityV1 {
        principal_id: id.to_owned(),
        role,
    }
}

fn scope(suffix: &str) -> FoundationScopeV1 {
    FoundationScopeV1 {
        project_id: format!("project.{suffix}"),
        goal_id: Some(format!("goal.{suffix}")),
        task_id: Some(format!("task.{suffix}")),
        run_id: Some(format!("run.{suffix}")),
    }
}

fn invocation(suffix: &str, target_role: PrincipalV1) -> RoleInvocationV1 {
    let invocation_scope = scope(suffix);
    let invoker = if target_role == PrincipalV1::Coordinator {
        identity(&format!("principal.{suffix}.owner"), PrincipalV1::Owner)
    } else {
        identity(
            &format!("principal.{suffix}.coordinator"),
            PrincipalV1::Coordinator,
        )
    };
    let authority = FoundationAuthorityV1 {
        contract_version: 1,
        authority_id: format!("authority.{suffix}.invocation"),
        principal: invoker.clone(),
        scope: invocation_scope.clone(),
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
            valid_from: timestamp(0),
            valid_until: Some(timestamp(59)),
        },
    };
    RoleInvocationV1 {
        contract_version: 1,
        invocation_id: format!("invocation.{suffix}"),
        invoker,
        target: identity(&format!("principal.{suffix}.target"), target_role),
        task_id: TaskId::from(format!("task.{suffix}")),
        run_id: RunId::from(format!("run.{suffix}")),
        scope: invocation_scope,
        budget: ExecutionBudget {
            contract_version: 1,
            max_attempts: 2,
        },
        idempotency_key: IdempotencyKey::from(format!("invocation-key.{suffix}")),
        authority_digest: invocation_authority_digest(&authority).unwrap(),
        authority,
        input_digest: "a".repeat(64),
        invoked_at: timestamp(1),
    }
}

#[derive(Clone)]
struct ControlledClock {
    now: Arc<Mutex<DateTime<Utc>>>,
    calls: Arc<AtomicUsize>,
}

impl ControlledClock {
    fn new(now: DateTime<Utc>) -> Self {
        Self {
            now: Arc::new(Mutex::new(now)),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn set(&self, now: DateTime<Utc>) {
        *self.now.lock().unwrap() = now;
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl BrokerClock for ControlledClock {
    fn now(&self) -> DateTime<Utc> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.now.lock().unwrap()
    }
}

struct Harness {
    _workspace_parent: TempDir,
    _protected_root: TempDir,
    broker: WorkspaceCapabilityBroker,
    execution: RoleExecutionRequest,
    lease: TrustedWorkspaceLease,
    grant: TrustedCapabilityGrant,
    clock: ControlledClock,
}

fn grant_dto(
    execution: &RoleExecutionRequest,
    lease: &TrustedWorkspaceLease,
    role: PrincipalV1,
) -> CapabilityGrantV1 {
    let read_paths = vec!["README.md".to_owned(), "src/lib.rs".to_owned()];
    let write_paths = if role == PrincipalV1::Engineer {
        vec!["src/lib.rs".to_owned()]
    } else {
        Vec::new()
    };
    let grant_authority = FoundationAuthorityV1 {
        contract_version: 1,
        authority_id: format!("authority.{}.grant", execution.invocation.invocation_id),
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
            valid_from: timestamp(0),
            valid_until: Some(timestamp(55)),
        },
    };
    CapabilityGrantV1 {
        contract_version: 1,
        grant_id: format!("grant.{}", execution.invocation.invocation_id),
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
        valid_from: timestamp(5),
        valid_until: timestamp(40),
    }
}

fn harness(suffix: &str, role: PrincipalV1) -> Harness {
    let workspace_parent = tempfile::tempdir().unwrap();
    let protected_root = tempfile::tempdir().unwrap();
    let clock = ControlledClock::new(timestamp(10));
    let mut broker = WorkspaceCapabilityBroker::try_new(
        format!("runtime.{suffix}"),
        workspace_parent.path().to_path_buf(),
        vec![protected_root.path().to_path_buf()],
        Box::new(clock.clone()),
    )
    .unwrap();
    let execution = RoleExecutionRequest {
        invocation: invocation(suffix, role),
        attempt: 1,
    };
    let lease = broker
        .open_lease(
            &execution,
            format!("lease.{suffix}"),
            format!("workspace.{suffix}"),
            [
                WorkspaceSeedFile::try_new("README.md", b"review".to_vec()).unwrap(),
                WorkspaceSeedFile::try_new("src/lib.rs", b"hello".to_vec()).unwrap(),
            ],
            timestamp(2),
            timestamp(50),
        )
        .unwrap();
    let grant = broker
        .issue_grant(&execution, &lease, grant_dto(&execution, &lease, role))
        .unwrap();
    Harness {
        _workspace_parent: workspace_parent,
        _protected_root: protected_root,
        broker,
        execution,
        lease,
        grant,
        clock,
    }
}

fn request(harness: &Harness, suffix: &str, operation: ToolOperationV1) -> ToolRequestV1 {
    ToolRequestV1 {
        contract_version: 1,
        request_id: format!("request.{suffix}"),
        idempotency_key: format!("idempotency.{suffix}"),
        invocation_id: harness.execution.invocation.invocation_id.clone(),
        invocation_digest: harness.execution.invocation.canonical_digest().unwrap(),
        attempt: harness.execution.attempt,
        grant_id: harness.grant.observation().grant_id.clone(),
        grant_digest: harness.grant.digest().to_owned(),
        lease_id: harness.lease.observation().lease_id.clone(),
        lease_digest: harness.lease.digest().to_owned(),
        workspace_id: harness.lease.observation().workspace_id.clone(),
        expected_snapshot_digest: harness.grant.observation().snapshot_digest.clone(),
        requester: harness.execution.invocation.target.clone(),
        scope: harness.execution.invocation.scope.clone(),
        operation,
        requested_at: timestamp(9),
    }
}

fn denial(result: &ToolExecutionResult) -> ToolDeniedCodeV1 {
    match result.receipt().observation().outcome {
        ToolReceiptOutcomeV1::Denied { code } => code,
        ref outcome => panic!("expected denial, got {outcome:?}"),
    }
}

fn assert_no_delta(result: &ToolExecutionResult) {
    let receipt = result.receipt().observation();
    assert_eq!(
        receipt.before_snapshot_digest,
        receipt.after_snapshot_digest
    );
    assert_eq!(receipt.before_generation, receipt.after_generation);
    assert!(result.read_bytes().is_none());
}

#[test]
fn engineer_native_read_and_write_have_exact_bounded_effects() {
    let mut read_harness = harness("read", PrincipalV1::Engineer);
    let before = read_harness.lease.initial_snapshot().clone();
    let read = read_harness
        .broker
        .execute(
            request(
                &read_harness,
                "read",
                ToolOperationV1::ReadFile {
                    logical_path: "src/lib.rs".into(),
                },
            ),
            None,
        )
        .unwrap();
    assert_eq!(read.read_bytes(), Some(b"hello".as_slice()));
    assert!(matches!(
        read.receipt().observation().outcome,
        ToolReceiptOutcomeV1::Read { byte_length: 5, .. }
    ));
    assert_eq!(read_harness.broker.backend_calls(), 1);
    assert_eq!(
        read_harness.broker.snapshot(&read_harness.lease).unwrap(),
        before
    );

    let mut write_harness = harness("write", PrincipalV1::Engineer);
    let before = write_harness.lease.initial_snapshot().clone();
    let payload = b"changed";
    let write_request = request(
        &write_harness,
        "write",
        ToolOperationV1::WriteFile {
            logical_path: "src/lib.rs".into(),
            content_sha256: ovca_types::verification_sha256_hex(payload),
            byte_length: payload.len() as u64,
        },
    );
    let written = write_harness
        .broker
        .execute(write_request, Some(payload))
        .unwrap();
    let after = write_harness.broker.snapshot(&write_harness.lease).unwrap();
    assert!(matches!(
        written.receipt().observation().outcome,
        ToolReceiptOutcomeV1::Written { byte_length: 7, .. }
    ));
    assert_eq!(after.generation, before.generation + 1);
    assert_ne!(after.snapshot_digest, before.snapshot_digest);
    let changed: Vec<_> = after
        .files
        .iter()
        .zip(&before.files)
        .filter(|(left, right)| left != right)
        .collect();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].0.logical_path, "src/lib.rs");
    assert_eq!(write_harness.broker.backend_calls(), 1);
}

#[test]
fn exact_duplicate_and_conflict_resolve_before_clock_or_backend() {
    let mut harness = harness("idempotency", PrincipalV1::Engineer);
    let initial_clock_calls = harness.clock.calls();
    let payload = b"changed";
    let original = request(
        &harness,
        "same-key",
        ToolOperationV1::WriteFile {
            logical_path: "src/lib.rs".into(),
            content_sha256: ovca_types::verification_sha256_hex(payload),
            byte_length: payload.len() as u64,
        },
    );
    let first = harness
        .broker
        .execute(original.clone(), Some(payload))
        .unwrap();
    assert_eq!(harness.clock.calls(), initial_clock_calls + 1);
    assert_eq!(harness.broker.backend_calls(), 1);
    harness.clock.set(timestamp(45));
    let duplicate = harness
        .broker
        .execute(original.clone(), Some(b"wrong replay bytes"))
        .unwrap();
    assert_eq!(duplicate, first);
    assert_eq!(harness.clock.calls(), initial_clock_calls + 1);
    assert_eq!(harness.broker.backend_calls(), 1);

    let mut conflict_request = original;
    conflict_request.request_id = "request.changed-payload".into();
    let conflict = harness
        .broker
        .execute(conflict_request.clone(), Some(payload))
        .unwrap();
    assert_eq!(denial(&conflict), ToolDeniedCodeV1::IdempotencyConflict);
    assert_no_delta(&conflict);
    assert_eq!(harness.clock.calls(), initial_clock_calls + 1);
    assert_eq!(harness.broker.backend_calls(), 1);
    let repeated_conflict = harness
        .broker
        .execute(conflict_request, Some(payload))
        .unwrap();
    assert_eq!(repeated_conflict, conflict);
    assert_eq!(harness.clock.calls(), initial_clock_calls + 1);
}

#[test]
fn fresh_same_content_payload_and_limit_fail_before_backend() {
    let mut harness = harness("payload", PrincipalV1::Engineer);
    let before = harness.lease.initial_snapshot().clone();
    let same = request(
        &harness,
        "same-content",
        ToolOperationV1::WriteFile {
            logical_path: "src/lib.rs".into(),
            content_sha256: ovca_types::verification_sha256_hex(b"hello"),
            byte_length: 5,
        },
    );
    let result = harness.broker.execute(same, Some(b"hello")).unwrap();
    assert_eq!(denial(&result), ToolDeniedCodeV1::NoChange);
    assert_no_delta(&result);
    assert_eq!(harness.broker.backend_calls(), 0);
    assert_eq!(harness.broker.snapshot(&harness.lease).unwrap(), before);

    let mismatch = request(
        &harness,
        "mismatch",
        ToolOperationV1::WriteFile {
            logical_path: "src/lib.rs".into(),
            content_sha256: ovca_types::verification_sha256_hex(b"declared"),
            byte_length: 8,
        },
    );
    let result = harness.broker.execute(mismatch, Some(b"actual!!")).unwrap();
    assert_eq!(denial(&result), ToolDeniedCodeV1::PayloadMismatch);
    assert_eq!(harness.broker.backend_calls(), 0);

    let over_limit = vec![b'x'; 1025];
    let request = request(
        &harness,
        "limit",
        ToolOperationV1::WriteFile {
            logical_path: "src/lib.rs".into(),
            content_sha256: ovca_types::verification_sha256_hex(&over_limit),
            byte_length: over_limit.len() as u64,
        },
    );
    let result = harness.broker.execute(request, Some(&over_limit)).unwrap();
    assert_eq!(denial(&result), ToolDeniedCodeV1::LimitExceeded);
    assert_eq!(harness.broker.backend_calls(), 0);
}

#[test]
fn unsupported_operations_and_path_alias_matrix_are_effect_free() {
    let mut harness = harness("paths", PrincipalV1::Engineer);
    let before = harness.lease.initial_snapshot().clone();
    let paths = [
        ("../escape", ToolDeniedCodeV1::AliasForbidden),
        ("C:/escape", ToolDeniedCodeV1::PathForbidden),
        ("//server/share", ToolDeniedCodeV1::PathForbidden),
        ("\\\\?\\C:\\escape", ToolDeniedCodeV1::PathForbidden),
        ("file:stream", ToolDeniedCodeV1::PathForbidden),
        ("CON.txt", ToolDeniedCodeV1::AliasForbidden),
        ("SRC/LIB.RS", ToolDeniedCodeV1::AliasForbidden),
        ("src/other.rs", ToolDeniedCodeV1::PathForbidden),
    ];
    for (index, (path, code)) in paths.into_iter().enumerate() {
        let result = harness
            .broker
            .execute(
                request(
                    &harness,
                    &format!("path-{index}"),
                    ToolOperationV1::ReadFile {
                        logical_path: path.into(),
                    },
                ),
                None,
            )
            .unwrap();
        assert_eq!(denial(&result), code, "{path}");
        assert_no_delta(&result);
    }
    for (index, kind) in [
        UnsupportedToolKindV1::Command,
        UnsupportedToolKindV1::Environment,
        UnsupportedToolKindV1::Network,
        UnsupportedToolKindV1::Delete,
        UnsupportedToolKindV1::Rename,
        UnsupportedToolKindV1::Copy,
        UnsupportedToolKindV1::CreateDirectory,
        UnsupportedToolKindV1::Link,
    ]
    .into_iter()
    .enumerate()
    {
        let result = harness
            .broker
            .execute(
                request(
                    &harness,
                    &format!("unsupported-{index}"),
                    ToolOperationV1::Unsupported {
                        kind,
                        intent_digest: "f".repeat(64),
                    },
                ),
                None,
            )
            .unwrap();
        assert_eq!(denial(&result), ToolDeniedCodeV1::UnsupportedOperation);
    }
    assert_eq!(harness.broker.backend_calls(), 0);
    assert_eq!(harness.broker.snapshot(&harness.lease).unwrap(), before);
}

#[test]
fn broker_time_not_requested_at_controls_all_half_open_windows() {
    let mut harness = harness("time", PrincipalV1::Engineer);
    harness.clock.set(timestamp(40));
    let expired = harness
        .broker
        .execute(
            request(
                &harness,
                "expired",
                ToolOperationV1::ReadFile {
                    logical_path: "src/lib.rs".into(),
                },
            ),
            None,
        )
        .unwrap();
    assert_eq!(denial(&expired), ToolDeniedCodeV1::Expired);
    assert_eq!(expired.receipt().observation().occurred_at, timestamp(40));

    harness.clock.set(timestamp(10));
    let mut future = request(
        &harness,
        "future",
        ToolOperationV1::ReadFile {
            logical_path: "src/lib.rs".into(),
        },
    );
    future.requested_at = timestamp(11);
    let result = harness.broker.execute(future, None).unwrap();
    assert_eq!(denial(&result), ToolDeniedCodeV1::InvalidBinding);
    assert_eq!(result.receipt().observation().occurred_at, timestamp(10));
    assert_eq!(harness.broker.backend_calls(), 0);
}

#[test]
fn authority_substitution_digest_and_permission_extras_fail_closed() {
    let workspace_parent = tempfile::tempdir().unwrap();
    let protected = tempfile::tempdir().unwrap();
    let clock = ControlledClock::new(timestamp(10));
    let mut broker = WorkspaceCapabilityBroker::try_new(
        "runtime.authority",
        workspace_parent.path().to_path_buf(),
        vec![protected.path().to_path_buf()],
        Box::new(clock),
    )
    .unwrap();
    let execution = RoleExecutionRequest {
        invocation: invocation("authority", PrincipalV1::Engineer),
        attempt: 1,
    };
    let lease = broker
        .open_lease(
            &execution,
            "lease.authority",
            "workspace.authority",
            [WorkspaceSeedFile::try_new("src/lib.rs", b"hello".to_vec()).unwrap()],
            timestamp(2),
            timestamp(50),
        )
        .unwrap();

    let mut substituted = grant_dto(&execution, &lease, PrincipalV1::Engineer);
    substituted.grant_authority = execution.invocation.authority.clone();
    substituted.grant_authority_digest =
        canonical_authority_digest(&substituted.grant_authority).unwrap();
    assert_eq!(
        broker.issue_grant(&execution, &lease, substituted),
        Err(WorkspaceCapabilityError::InvalidGrant)
    );

    let mut reused_digest = grant_dto(&execution, &lease, PrincipalV1::Engineer);
    reused_digest.grant_id = "grant.reused-digest".into();
    reused_digest.grant_authority_digest = execution.invocation.authority_digest.clone();
    assert_eq!(
        broker.issue_grant(&execution, &lease, reused_digest),
        Err(WorkspaceCapabilityError::InvalidGrant)
    );

    let mut extra_permission = grant_dto(&execution, &lease, PrincipalV1::Engineer);
    extra_permission.grant_id = "grant.extra-permission".into();
    extra_permission
        .grant_authority
        .permission_profile
        .resource_keys
        .push("zz.extra".into());
    extra_permission.grant_authority_digest =
        canonical_authority_digest(&extra_permission.grant_authority).unwrap();
    assert_eq!(
        broker.issue_grant(&execution, &lease, extra_permission),
        Err(WorkspaceCapabilityError::InvalidGrant)
    );
    assert_eq!(broker.backend_calls(), 0);
}

#[test]
fn grant_attempt_must_match_lease_attempt_before_registry_insert() {
    let workspace_parent = tempfile::tempdir().unwrap();
    let protected = tempfile::tempdir().unwrap();
    let clock = ControlledClock::new(timestamp(10));
    let mut broker = WorkspaceCapabilityBroker::try_new(
        "runtime.attempt-binding",
        workspace_parent.path().to_path_buf(),
        vec![protected.path().to_path_buf()],
        Box::new(clock),
    )
    .unwrap();
    let attempt_one = RoleExecutionRequest {
        invocation: invocation("attempt-binding", PrincipalV1::Engineer),
        attempt: 1,
    };
    let lease = broker
        .open_lease(
            &attempt_one,
            "lease.attempt-binding",
            "workspace.attempt-binding",
            [WorkspaceSeedFile::try_new("src/lib.rs", b"hello".to_vec()).unwrap()],
            timestamp(2),
            timestamp(50),
        )
        .unwrap();
    let attempt_two = RoleExecutionRequest {
        invocation: attempt_one.invocation.clone(),
        attempt: 2,
    };
    let mismatched = grant_dto(&attempt_two, &lease, PrincipalV1::Engineer);
    let grant_id = mismatched.grant_id.clone();

    assert_eq!(
        broker.issue_grant(&attempt_two, &lease, mismatched),
        Err(WorkspaceCapabilityError::InvalidGrant)
    );
    assert_eq!(broker.backend_calls(), 0);

    let corrected = grant_dto(&attempt_one, &lease, PrincipalV1::Engineer);
    assert_eq!(corrected.grant_id, grant_id);
    let trusted = broker.issue_grant(&attempt_one, &lease, corrected).unwrap();
    assert!(broker.grant_is_live(&trusted));
    assert_eq!(broker.backend_calls(), 0);
}

#[test]
fn role_matrix_and_broker_issuance_provenance_are_closed() {
    for role in [PrincipalV1::Reviewer, PrincipalV1::Auditor] {
        let mut harness = harness(&format!("role-{role:?}").to_ascii_lowercase(), role);
        let write = request(
            &harness,
            &format!("write-{role:?}").to_ascii_lowercase(),
            ToolOperationV1::WriteFile {
                logical_path: "src/lib.rs".into(),
                content_sha256: ovca_types::verification_sha256_hex(b"changed"),
                byte_length: 7,
            },
        );
        let result = harness.broker.execute(write, Some(b"changed")).unwrap();
        assert_eq!(denial(&result), ToolDeniedCodeV1::RoleForbidden);
        assert_eq!(harness.broker.backend_calls(), 0);
    }

    let workspace_parent = tempfile::tempdir().unwrap();
    let protected = tempfile::tempdir().unwrap();
    let owner_clock = ControlledClock::new(timestamp(10));
    let mut owner_broker = WorkspaceCapabilityBroker::try_new(
        "runtime.owner",
        workspace_parent.path().to_path_buf(),
        vec![protected.path().to_path_buf()],
        Box::new(owner_clock),
    )
    .unwrap();
    let owner_execution = RoleExecutionRequest {
        invocation: invocation("owner", PrincipalV1::Coordinator),
        attempt: 1,
    };
    let owner_lease = owner_broker
        .open_lease(
            &owner_execution,
            "lease.owner",
            "workspace.owner",
            [WorkspaceSeedFile::try_new("src/lib.rs", b"hello".to_vec()).unwrap()],
            timestamp(2),
            timestamp(50),
        )
        .unwrap();
    assert_eq!(
        owner_broker.issue_grant(
            &owner_execution,
            &owner_lease,
            grant_dto(&owner_execution, &owner_lease, PrincipalV1::Coordinator),
        ),
        Err(WorkspaceCapabilityError::InvalidGrant)
    );

    let harness = harness("foreign", PrincipalV1::Engineer);
    let other_parent = tempfile::tempdir().unwrap();
    let other_protected = tempfile::tempdir().unwrap();
    let mut other = WorkspaceCapabilityBroker::try_new(
        "runtime.other",
        other_parent.path().to_path_buf(),
        vec![other_protected.path().to_path_buf()],
        Box::new(ControlledClock::new(timestamp(10))),
    )
    .unwrap();
    assert_eq!(
        other.issue_grant(
            &harness.execution,
            &harness.lease,
            grant_dto(&harness.execution, &harness.lease, PrincipalV1::Engineer),
        ),
        Err(WorkspaceCapabilityError::ForeignHandle)
    );
    assert!(!other.grant_is_live(&harness.grant));
    assert!(harness.broker.grant_is_live(&harness.grant));
}

#[test]
fn never_issued_closed_foreign_and_snapshot_substitution_deny_without_effect() {
    let mut harness = harness("bindings", PrincipalV1::Engineer);
    let mut never_issued = request(
        &harness,
        "never-issued",
        ToolOperationV1::ReadFile {
            logical_path: "src/lib.rs".into(),
        },
    );
    never_issued.grant_id = "grant.never-issued".into();
    never_issued.grant_digest = "9".repeat(64);
    let result = harness.broker.execute(never_issued, None).unwrap();
    assert_eq!(denial(&result), ToolDeniedCodeV1::InvalidBinding);
    assert_eq!(harness.broker.backend_calls(), 0);

    let payload = b"changed";
    let write = request(
        &harness,
        "advance",
        ToolOperationV1::WriteFile {
            logical_path: "src/lib.rs".into(),
            content_sha256: ovca_types::verification_sha256_hex(payload),
            byte_length: payload.len() as u64,
        },
    );
    harness.broker.execute(write, Some(payload)).unwrap();
    let stale = harness
        .broker
        .execute(
            request(
                &harness,
                "stale",
                ToolOperationV1::ReadFile {
                    logical_path: "src/lib.rs".into(),
                },
            ),
            None,
        )
        .unwrap();
    assert_eq!(denial(&stale), ToolDeniedCodeV1::StaleSnapshot);
    assert_eq!(harness.broker.backend_calls(), 1);

    harness
        .broker
        .close_lease(&harness.lease, CleanupReason::Completed)
        .unwrap();
    assert_eq!(
        harness
            .broker
            .lease_state(&harness.lease.observation().lease_id)
            .unwrap(),
        WorkspaceLeaseState::Closed
    );
    let closed = harness
        .broker
        .execute(
            request(
                &harness,
                "closed",
                ToolOperationV1::ReadFile {
                    logical_path: "src/lib.rs".into(),
                },
            ),
            None,
        )
        .unwrap();
    assert_eq!(denial(&closed), ToolDeniedCodeV1::InvalidBinding);
    assert_eq!(harness.broker.backend_calls(), 1);
    assert_eq!(harness.broker.active_root_count(), 0);
}

#[test]
fn malformed_unknown_version_and_forged_observations_have_no_trust() {
    let mut harness = harness("decode", PrincipalV1::Engineer);
    let valid = request(
        &harness,
        "decode",
        ToolOperationV1::ReadFile {
            logical_path: "src/lib.rs".into(),
        },
    );
    let mut value = serde_json::to_value(&valid).unwrap();
    value["contract_version"] = serde_json::json!(2);
    assert_eq!(
        harness
            .broker
            .execute_json(&serde_json::to_vec(&value).unwrap(), None),
        Err(WorkspaceCapabilityError::InvalidRequest)
    );
    value["unexpected"] = serde_json::json!(true);
    assert_eq!(
        harness
            .broker
            .execute_json(&serde_json::to_vec(&value).unwrap(), None),
        Err(WorkspaceCapabilityError::InvalidRequest)
    );
    assert_eq!(
        harness.broker.execute_json(b"{", None),
        Err(WorkspaceCapabilityError::InvalidRequest)
    );
    assert_eq!(harness.clock.calls(), 0);
    assert_eq!(harness.broker.backend_calls(), 0);

    let source = include_str!("../src/workspace_capability.rs");
    for trusted in [
        "TrustedWorkspaceLease",
        "TrustedCapabilityGrant",
        "TrustedToolReceipt",
    ] {
        assert!(source.contains(&format!("pub struct {trusted}")));
    }
    assert!(!source.contains("impl<'de> Deserialize<'de> for Trusted"));
    assert!(!source.contains("Command::new"));
    assert!(!source.contains("std::process"));
    assert!(!source.contains("std::net"));
}

#[test]
fn normal_return_and_unwind_cleanup_leave_no_owned_roots() {
    let harness = harness("cleanup", PrincipalV1::Engineer);
    let parent = harness._workspace_parent.path().to_path_buf();
    assert_eq!(harness.broker.active_root_count(), 1);
    drop(harness);
    assert!(!parent.exists() || std::fs::read_dir(parent).unwrap().count() == 0);

    let unwind_parent = tempfile::tempdir().unwrap();
    let protected = tempfile::tempdir().unwrap();
    let parent_path = unwind_parent.path().to_path_buf();
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut broker = WorkspaceCapabilityBroker::try_new(
            "runtime.unwind",
            parent_path.clone(),
            vec![protected.path().to_path_buf()],
            Box::new(ControlledClock::new(timestamp(10))),
        )
        .unwrap();
        let execution = RoleExecutionRequest {
            invocation: invocation("unwind", PrincipalV1::Engineer),
            attempt: 1,
        };
        let _lease = broker
            .open_lease(
                &execution,
                "lease.unwind",
                "workspace.unwind",
                [WorkspaceSeedFile::try_new("src/lib.rs", b"hello".to_vec()).unwrap()],
                timestamp(2),
                timestamp(50),
            )
            .unwrap();
        panic!("test unwind");
    }));
    assert!(observed.is_err());
    assert_eq!(std::fs::read_dir(parent_path).unwrap().count(), 0);
}
