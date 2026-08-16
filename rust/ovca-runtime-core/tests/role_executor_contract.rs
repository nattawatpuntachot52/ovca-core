use chrono::{DateTime, TimeZone, Utc};
use ovca_runtime_core::{
    DeterministicFakeRoleExecutor, RoleExecutionOutcome, RoleExecutionRequest, RoleExecutionScript,
    RoleExecutionUsage, RoleExecutor, RoleExecutorError, RoleRetryCause, EXECUTION_TIMEOUT_CODE,
};
use ovca_types::control_plane::{
    canonical_authority_digest, ControlPlaneState, ExecutionBudget, RoleInvocationV1,
    RoleResultPayloadV1, RoleResultV1,
};
use ovca_types::foundation::{
    FoundationAuthorityV1, FoundationNamespaceV1, FoundationPermissionProfileV1, FoundationScopeV1,
    FoundationSensitivityV1, FoundationValidityStatusV1, FoundationValidityV1,
    FoundationVisibilityV1, PrincipalIdentityV1, PrincipalV1,
};
use ovca_types::{EvidenceId, IdempotencyKey, RiskTier, RunId, TaskId};

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

fn authority(
    suffix: &str,
    invoker: PrincipalIdentityV1,
    scope: FoundationScopeV1,
) -> FoundationAuthorityV1 {
    FoundationAuthorityV1 {
        contract_version: 1,
        authority_id: format!("authority.{suffix}"),
        principal: invoker,
        scope,
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
        visibility: FoundationVisibilityV1::Private,
        sensitivity: FoundationSensitivityV1::Internal,
        validity: FoundationValidityV1 {
            status: FoundationValidityStatusV1::Active,
            valid_from: timestamp(0),
            valid_until: Some(timestamp(59)),
        },
    }
}

fn invocation(
    suffix: &str,
    invoker_role: PrincipalV1,
    target_role: PrincipalV1,
    max_attempts: u32,
) -> RoleInvocationV1 {
    let invocation_scope = scope(suffix);
    let invoker = identity(&format!("principal.{suffix}.invoker"), invoker_role);
    let authority = authority(suffix, invoker.clone(), invocation_scope.clone());
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
            max_attempts,
        },
        idempotency_key: IdempotencyKey::from(format!("idempotency.{suffix}")),
        authority_digest: canonical_authority_digest(&authority).unwrap(),
        authority,
        input_digest: "a".repeat(64),
        invoked_at: timestamp(1),
    }
}

fn execution_request(invocation: RoleInvocationV1, attempt: u32) -> RoleExecutionRequest {
    RoleExecutionRequest {
        invocation,
        attempt,
    }
}

fn terminal_result(
    request: &RoleExecutionRequest,
    state: ControlPlaneState,
    payload: RoleResultPayloadV1,
) -> RoleResultV1 {
    RoleResultV1 {
        contract_version: 1,
        result_id: format!(
            "result.{}.{}",
            request.invocation.invocation_id, request.attempt
        ),
        invocation_id: request.invocation.invocation_id.clone(),
        invocation_digest: request.invocation.canonical_digest().unwrap(),
        producer: request.invocation.target.clone(),
        task_id: request.invocation.task_id.clone(),
        run_id: request.invocation.run_id.clone(),
        scope: request.invocation.scope.clone(),
        idempotency_key: request.invocation.idempotency_key.clone(),
        attempt: request.attempt,
        state,
        payload,
        evidence_ids: if state == ControlPlaneState::Completed {
            vec![EvidenceId::from("evidence.public.001")]
        } else {
            Vec::new()
        },
        occurred_at: timestamp(2 + request.attempt),
    }
}

fn completed_outcome(request: &RoleExecutionRequest) -> RoleExecutionOutcome {
    let payload = if request.invocation.target.role == PrincipalV1::Coordinator {
        RoleResultPayloadV1::OwnerFinal {
            response: "Owner-ready response".into(),
        }
    } else {
        RoleResultPayloadV1::Specialist {
            summary: "Bounded specialist response".into(),
        }
    };
    RoleExecutionOutcome::Completed {
        result: terminal_result(request, ControlPlaneState::Completed, payload),
        usage: RoleExecutionUsage::Reported {
            input_units: 8,
            output_units: 5,
        },
    }
}

fn script(request: RoleExecutionRequest, outcome: RoleExecutionOutcome) -> RoleExecutionScript {
    RoleExecutionScript { request, outcome }
}

#[test]
fn role_executor_accepts_exact_four_role_routes_and_repeats_deterministically() {
    let routes = [
        (PrincipalV1::Owner, PrincipalV1::Coordinator),
        (PrincipalV1::Coordinator, PrincipalV1::Engineer),
        (PrincipalV1::Coordinator, PrincipalV1::Reviewer),
        (PrincipalV1::Coordinator, PrincipalV1::Auditor),
    ];
    for (index, (invoker, target)) in routes.into_iter().enumerate() {
        let request =
            execution_request(invocation(&format!("route{index}"), invoker, target, 2), 1);
        let expected = completed_outcome(&request);
        let executor =
            DeterministicFakeRoleExecutor::try_new([script(request.clone(), expected.clone())])
                .unwrap();
        let first = executor.invoke(request.clone()).unwrap();
        let second = executor.invoke(request).unwrap();
        assert_eq!(first, expected);
        assert_eq!(second, first);
        assert_eq!(first.usage().total_units().unwrap(), Some(13));
    }
}

#[test]
fn role_executor_normalizes_all_terminal_outcomes() {
    let request = execution_request(
        invocation(
            "terminal",
            PrincipalV1::Coordinator,
            PrincipalV1::Engineer,
            2,
        ),
        1,
    );
    let failed = RoleExecutionOutcome::Failed {
        result: terminal_result(
            &request,
            ControlPlaneState::Failed,
            RoleResultPayloadV1::Failure {
                code: "execution_failed".into(),
                message: "Execution failed safely".into(),
            },
        ),
        usage: RoleExecutionUsage::Unavailable,
    };
    let timed_out = RoleExecutionOutcome::TimedOut {
        result: terminal_result(
            &request,
            ControlPlaneState::Failed,
            RoleResultPayloadV1::Failure {
                code: EXECUTION_TIMEOUT_CODE.into(),
                message: "Execution timed out safely".into(),
            },
        ),
        usage: RoleExecutionUsage::Reported {
            input_units: 3,
            output_units: 0,
        },
    };
    let cancelled = RoleExecutionOutcome::Cancelled {
        result: terminal_result(
            &request,
            ControlPlaneState::Cancelled,
            RoleResultPayloadV1::Cancellation {
                reason: "Execution cancelled safely".into(),
            },
        ),
        usage: RoleExecutionUsage::Unavailable,
    };

    for outcome in [failed, timed_out, cancelled] {
        assert_eq!(outcome.validate_against(&request), Ok(()));
    }
}

#[test]
fn role_executor_rejects_invalid_invocation_attempt_and_write_authority() {
    let invalid_route = invocation(
        "invalid_route",
        PrincipalV1::Owner,
        PrincipalV1::Engineer,
        2,
    );
    assert_eq!(
        execution_request(invalid_route, 1).validate(),
        Err(RoleExecutorError::InvalidInvocation)
    );

    let mut invalid = invocation(
        "invalid",
        PrincipalV1::Coordinator,
        PrincipalV1::Engineer,
        2,
    );
    invalid.authority_digest = "b".repeat(64);
    assert_eq!(
        execution_request(invalid, 1).validate(),
        Err(RoleExecutorError::InvalidInvocation)
    );

    let mut invalid_authority = invocation(
        "invalid_authority",
        PrincipalV1::Coordinator,
        PrincipalV1::Engineer,
        2,
    );
    invalid_authority.authority.namespace = FoundationNamespaceV1::KnowledgeReview;
    invalid_authority.authority_digest =
        canonical_authority_digest(&invalid_authority.authority).unwrap();
    assert_eq!(
        execution_request(invalid_authority, 1).validate(),
        Err(RoleExecutorError::InvalidInvocation)
    );

    let mut invalid_scope = invocation(
        "invalid_scope",
        PrincipalV1::Coordinator,
        PrincipalV1::Engineer,
        2,
    );
    invalid_scope.scope.project_id = "project.other".into();
    assert_eq!(
        execution_request(invalid_scope, 1).validate(),
        Err(RoleExecutorError::InvalidInvocation)
    );

    let valid = invocation(
        "attempt",
        PrincipalV1::Coordinator,
        PrincipalV1::Engineer,
        2,
    );
    assert_eq!(
        execution_request(valid.clone(), 0).validate(),
        Err(RoleExecutorError::InvalidAttempt)
    );
    assert_eq!(
        execution_request(valid, 3).validate(),
        Err(RoleExecutorError::InvalidAttempt)
    );

    let mut write = invocation("write", PrincipalV1::Coordinator, PrincipalV1::Engineer, 2);
    write
        .authority
        .permission_profile
        .write_keys
        .push("resource.write".into());
    write.authority_digest = canonical_authority_digest(&write.authority).unwrap();
    assert_eq!(
        execution_request(write, 1).validate(),
        Err(RoleExecutorError::ForbiddenWriteAuthority)
    );
}

#[test]
fn role_executor_rejects_every_terminal_result_binding_drift() {
    let request = execution_request(
        invocation("binding", PrincipalV1::Owner, PrincipalV1::Coordinator, 2),
        1,
    );
    let baseline = match completed_outcome(&request) {
        RoleExecutionOutcome::Completed { result, .. } => result,
        _ => unreachable!(),
    };
    let mut invalid_results = Vec::new();

    let mut value = baseline.clone();
    value.producer = request.invocation.invoker.clone();
    invalid_results.push(value);
    let mut value = baseline.clone();
    value.state = ControlPlaneState::Failed;
    invalid_results.push(value);
    let mut value = baseline.clone();
    value.payload = RoleResultPayloadV1::Specialist {
        summary: "Wrong role payload".into(),
    };
    invalid_results.push(value);
    let mut value = baseline.clone();
    value.idempotency_key = IdempotencyKey::from("idempotency.other");
    invalid_results.push(value);
    let mut value = baseline.clone();
    value.invocation_digest = "b".repeat(64);
    invalid_results.push(value);
    let mut value = baseline.clone();
    value.invocation_id = "invocation.other".into();
    invalid_results.push(value);
    let mut value = baseline.clone();
    value.task_id = TaskId::from("task.other");
    invalid_results.push(value);
    let mut value = baseline.clone();
    value.run_id = RunId::from("run.other");
    invalid_results.push(value);
    let mut value = baseline.clone();
    value.scope.project_id = "project.other".into();
    invalid_results.push(value);
    let mut value = baseline.clone();
    value.attempt = 2;
    invalid_results.push(value);
    let mut value = baseline;
    value.occurred_at = timestamp(0);
    invalid_results.push(value);

    for result in invalid_results {
        let outcome = RoleExecutionOutcome::Completed {
            result,
            usage: RoleExecutionUsage::Unavailable,
        };
        assert_eq!(
            outcome.validate_against(&request),
            Err(RoleExecutorError::InvalidOutcome)
        );
    }
}

#[test]
fn role_executor_separates_failure_and_timeout_codes() {
    let request = execution_request(
        invocation("codes", PrincipalV1::Coordinator, PrincipalV1::Reviewer, 2),
        1,
    );
    let timeout_result = terminal_result(
        &request,
        ControlPlaneState::Failed,
        RoleResultPayloadV1::Failure {
            code: EXECUTION_TIMEOUT_CODE.into(),
            message: "Timed out".into(),
        },
    );
    let failure_result = terminal_result(
        &request,
        ControlPlaneState::Failed,
        RoleResultPayloadV1::Failure {
            code: "execution_failed".into(),
            message: "Failed".into(),
        },
    );
    assert_eq!(
        RoleExecutionOutcome::Failed {
            result: timeout_result,
            usage: RoleExecutionUsage::Unavailable,
        }
        .validate_against(&request),
        Err(RoleExecutorError::InvalidOutcome)
    );
    assert_eq!(
        RoleExecutionOutcome::TimedOut {
            result: failure_result,
            usage: RoleExecutionUsage::Unavailable,
        }
        .validate_against(&request),
        Err(RoleExecutorError::InvalidOutcome)
    );
}

#[test]
fn role_executor_retry_is_nonterminal_exact_and_budget_bound() {
    let request = execution_request(
        invocation("retry", PrincipalV1::Coordinator, PrincipalV1::Auditor, 3),
        1,
    );
    for cause in [RoleRetryCause::Failed, RoleRetryCause::TimedOut] {
        let retry = RoleExecutionOutcome::RetryRequired {
            completed_attempt: 1,
            next_attempt: 2,
            cause,
            usage: RoleExecutionUsage::Unavailable,
        };
        assert_eq!(retry.validate_against(&request), Ok(()));
    }

    for (completed_attempt, next_attempt) in [(0, 2), (1, 1), (1, 3)] {
        let invalid = RoleExecutionOutcome::RetryRequired {
            completed_attempt,
            next_attempt,
            cause: RoleRetryCause::Failed,
            usage: RoleExecutionUsage::Unavailable,
        };
        assert_eq!(
            invalid.validate_against(&request),
            Err(RoleExecutorError::InvalidOutcome)
        );
    }

    let final_attempt = execution_request(
        invocation("final", PrincipalV1::Coordinator, PrincipalV1::Auditor, 2),
        2,
    );
    let retry = RoleExecutionOutcome::RetryRequired {
        completed_attempt: 2,
        next_attempt: 3,
        cause: RoleRetryCause::TimedOut,
        usage: RoleExecutionUsage::Unavailable,
    };
    assert_eq!(
        retry.validate_against(&final_attempt),
        Err(RoleExecutorError::InvalidOutcome)
    );

    let overflow = execution_request(
        invocation(
            "overflow",
            PrincipalV1::Coordinator,
            PrincipalV1::Auditor,
            u32::MAX,
        ),
        u32::MAX,
    );
    let retry = RoleExecutionOutcome::RetryRequired {
        completed_attempt: u32::MAX,
        next_attempt: 0,
        cause: RoleRetryCause::Failed,
        usage: RoleExecutionUsage::Unavailable,
    };
    assert_eq!(
        retry.validate_against(&overflow),
        Err(RoleExecutorError::InvalidOutcome)
    );
}

#[test]
fn role_executor_fake_rejects_missing_duplicate_and_conflicting_scripts() {
    let request = execution_request(
        invocation(
            "scripts",
            PrincipalV1::Coordinator,
            PrincipalV1::Engineer,
            2,
        ),
        1,
    );
    let outcome = completed_outcome(&request);
    let executor =
        DeterministicFakeRoleExecutor::try_new([script(request.clone(), outcome.clone())]).unwrap();
    let missing = RoleExecutionRequest {
        attempt: 2,
        ..request.clone()
    };
    assert_eq!(
        executor.invoke(missing),
        Err(RoleExecutorError::MissingScript)
    );
    assert!(matches!(
        DeterministicFakeRoleExecutor::try_new([
            script(request.clone(), outcome.clone()),
            script(request.clone(), outcome.clone()),
        ]),
        Err(RoleExecutorError::DuplicateScript)
    ));

    let conflicting = RoleExecutionOutcome::Failed {
        result: terminal_result(
            &request,
            ControlPlaneState::Failed,
            RoleResultPayloadV1::Failure {
                code: "execution_failed".into(),
                message: "Different scripted outcome".into(),
            },
        ),
        usage: RoleExecutionUsage::Unavailable,
    };
    assert!(matches!(
        DeterministicFakeRoleExecutor::try_new([
            script(request.clone(), outcome),
            script(request, conflicting),
        ]),
        Err(RoleExecutorError::ConflictingScript)
    ));

    let first = execution_request(
        invocation(
            "same_key_first",
            PrincipalV1::Coordinator,
            PrincipalV1::Engineer,
            2,
        ),
        1,
    );
    let mut second = execution_request(
        invocation(
            "same_key_second",
            PrincipalV1::Coordinator,
            PrincipalV1::Engineer,
            2,
        ),
        2,
    );
    second.invocation.idempotency_key = first.invocation.idempotency_key.clone();
    assert!(matches!(
        DeterministicFakeRoleExecutor::try_new([
            script(first.clone(), completed_outcome(&first)),
            script(second.clone(), completed_outcome(&second)),
        ]),
        Err(RoleExecutorError::ConflictingScript)
    ));
}

#[test]
fn role_executor_fake_rejects_changed_bytes_key_and_id() {
    let request = execution_request(
        invocation(
            "identity",
            PrincipalV1::Coordinator,
            PrincipalV1::Reviewer,
            2,
        ),
        1,
    );
    let executor = DeterministicFakeRoleExecutor::try_new([script(
        request.clone(),
        completed_outcome(&request),
    )])
    .unwrap();

    let mut changed_bytes = request.clone();
    changed_bytes.invocation.input_digest = "b".repeat(64);
    assert_eq!(
        executor.invoke(changed_bytes),
        Err(RoleExecutorError::IdempotencyConflict)
    );
    let mut changed_key = request.clone();
    changed_key.invocation.idempotency_key = IdempotencyKey::from("idempotency.changed");
    assert_eq!(
        executor.invoke(changed_key),
        Err(RoleExecutorError::IdempotencyConflict)
    );
    let mut changed_id = request;
    changed_id.invocation.invocation_id = "invocation.changed".into();
    assert_eq!(
        executor.invoke(changed_id),
        Err(RoleExecutorError::IdempotencyConflict)
    );
}

#[test]
fn role_executor_usage_total_is_checked_and_never_stored() {
    assert_eq!(RoleExecutionUsage::Unavailable.total_units().unwrap(), None);
    assert_eq!(
        RoleExecutionUsage::Reported {
            input_units: 4,
            output_units: 7,
        }
        .total_units()
        .unwrap(),
        Some(11)
    );
    assert_eq!(
        RoleExecutionUsage::Reported {
            input_units: u64::MAX,
            output_units: 1,
        }
        .total_units(),
        Err(RoleExecutorError::UsageOverflow)
    );
}

#[test]
fn role_executor_invalid_inputs_return_closed_errors_without_panicking() {
    let request = execution_request(
        invocation(
            "no_panic",
            PrincipalV1::Coordinator,
            PrincipalV1::Engineer,
            1,
        ),
        1,
    );
    let invalid = RoleExecutionOutcome::RetryRequired {
        completed_attempt: 1,
        next_attempt: 2,
        cause: RoleRetryCause::Failed,
        usage: RoleExecutionUsage::Reported {
            input_units: u64::MAX,
            output_units: 1,
        },
    };
    let observed = std::panic::catch_unwind(|| invalid.validate_against(&request));
    assert_eq!(observed.unwrap(), Err(RoleExecutorError::UsageOverflow));
}

#[test]
fn role_executor_errors_are_fieldless_closed_and_fixed() {
    let cases = [
        (
            RoleExecutorError::InvalidInvocation,
            "invalid role invocation",
        ),
        (
            RoleExecutorError::ForbiddenWriteAuthority,
            "role execution forbids write authority",
        ),
        (
            RoleExecutorError::InvalidAttempt,
            "invalid role execution attempt",
        ),
        (
            RoleExecutorError::MissingScript,
            "role execution script is missing",
        ),
        (
            RoleExecutorError::DuplicateScript,
            "role execution script is duplicated",
        ),
        (
            RoleExecutorError::ConflictingScript,
            "role execution scripts conflict",
        ),
        (
            RoleExecutorError::IdempotencyConflict,
            "role execution idempotency binding conflicts",
        ),
        (
            RoleExecutorError::InvalidOutcome,
            "invalid role execution outcome",
        ),
        (
            RoleExecutorError::UsageOverflow,
            "role execution usage overflows",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn role_executor_source_has_no_external_authority_or_nondeterministic_runtime() {
    let source = include_str!("../src/role_executor.rs");
    for forbidden in [
        "std::fs",
        "std::process",
        "std::thread",
        "std::time",
        "std::env",
        "tokio::",
        "reqwest::",
        "TcpStream",
        "UdpSocket",
        "Command::new",
        "ovca_storage",
        "unsafe {",
        "provider:",
        "model:",
        "cost:",
        "raw_response",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden source token: {forbidden}"
        );
    }
}
