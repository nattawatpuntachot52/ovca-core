use chrono::{TimeZone, Utc};
use ovca_runtime_core::{
    audit_execution_request, review_execution_request, DurableExecutionAuthority,
    DurableExecutionError, IndependentCallStateV1, IndependentReviewError,
    IndependentReviewPhaseV1, IndependentReviewResolutionV1, IndependentReviewStateV1,
    PersistedRoleExecutionOutcomeV1, RoleExecutionOutcome, RoleExecutionUsage,
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
use ovca_types::independent_review::{
    derive_repair_successor_run_id, AuditPacketV1, EvidenceCurrentAnchorV1,
    EvidenceManifestEntryV1, EvidenceManifestV1, FrozenPathDiffV1, IndependentEvidenceActorRoleV1,
    IndependentEvidenceActorV1, RepairDirectiveV1, ReviewPacketV1, UnsatisfiedCriterionV1,
    INDEPENDENT_REVIEW_CONTRACT_VERSION,
};
use ovca_types::tool_boundary::WorkspaceFileV1;
use ovca_types::{
    verification_sha256_hex, AuditDecision, AuditDecisionId, BehaviorKind, CompletionEvidence,
    CompletionPrecondition, ContractVersion, CriterionAssessment, CriterionAssessmentVerdict,
    CriterionKind, CriterionResult, CriterionResultVerdict, EvidenceId, EvidenceKind, EvidenceRef,
    GoalContract, GoalId, IdempotencyKey, IntegrityMetadata, PermissionProfile, ProjectId,
    ReviewDecision, ReviewDecisionId, ReviewVerdict, RiskTier, Role, RunId, Task, TaskId,
    TaskStatus, VerificationBundle, VerificationFingerprints, VerificationTermination,
    VerificationTranscriptCommandIdentity, VerificationVerdict, WorkerId,
};
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

fn at(hour: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 21, hour, 0, 0)
        .single()
        .unwrap()
}

fn identity(id: &str, role: PrincipalV1) -> PrincipalIdentityV1 {
    PrincipalIdentityV1 {
        principal_id: id.to_owned(),
        role,
    }
}

fn scope(run_id: &RunId) -> FoundationScopeV1 {
    FoundationScopeV1 {
        project_id: "project.a05".to_owned(),
        goal_id: Some("goal.a05".to_owned()),
        task_id: Some("task.a05".to_owned()),
        run_id: Some(run_id.as_str().to_owned()),
    }
}

fn invocation(run_id: &RunId, role: PrincipalV1, suffix: &str) -> RoleInvocationV1 {
    let invoker = identity("principal.a05.coordinator", PrincipalV1::Coordinator);
    let authority = FoundationAuthorityV1 {
        contract_version: 1,
        authority_id: format!("authority.a05.{suffix}"),
        principal: invoker.clone(),
        scope: scope(run_id),
        namespace: FoundationNamespaceV1::CodeReview,
        permission_profile: FoundationPermissionProfileV1 {
            contract_version: 1,
            risk_tier: RiskTier::R3,
            resource_keys: Vec::new(),
            write_keys: Vec::new(),
            approval_required: true,
            review_required: true,
            audit_required: true,
        },
        visibility: FoundationVisibilityV1::RoleScoped,
        sensitivity: FoundationSensitivityV1::Internal,
        validity: FoundationValidityV1 {
            status: FoundationValidityStatusV1::Active,
            valid_from: at(8),
            valid_until: Some(at(20)),
        },
    };
    RoleInvocationV1 {
        contract_version: 1,
        invocation_id: format!("invocation.a05.{suffix}"),
        invoker,
        target: identity(&format!("principal.a05.{suffix}"), role),
        task_id: TaskId::from("task.a05"),
        run_id: run_id.clone(),
        scope: scope(run_id),
        budget: ExecutionBudget {
            contract_version: 1,
            max_attempts: 1,
        },
        idempotency_key: IdempotencyKey::from(format!("idempotency.a05.{suffix}")),
        authority_digest: canonical_authority_digest(&authority).unwrap(),
        authority,
        input_digest: verification_sha256_hex(format!("input.{suffix}").as_bytes()),
        invoked_at: at(9),
    }
}

fn goal() -> GoalContract {
    GoalContract {
        contract_version: ContractVersion::current(),
        id: GoalId::from("goal.a05"),
        project_id: ProjectId::from("project.a05"),
        objective: "independently review the frozen verified candidate".to_owned(),
        constraints: vec!["read only".to_owned()],
        acceptance_criteria: vec!["candidate is correct".to_owned()],
        verification_criteria: vec!["verification evidence is current".to_owned()],
        permission_profile: PermissionProfile {
            contract_version: ContractVersion::current(),
            risk_tier: RiskTier::R3,
            resource_keys: Vec::new(),
            write_keys: vec!["input.txt".to_owned()],
            approval_required: true,
            review_required: true,
            audit_required: true,
        },
        definition_of_done: vec!["independent pass pair is durable".to_owned()],
        completion_precondition: CompletionPrecondition {
            contract_version: ContractVersion::current(),
            minimum_evidence_refs: 1,
            require_all_acceptance_criteria: true,
            require_all_verification_criteria: true,
        },
        created_at: at(8),
        updated_at: at(9),
    }
}

fn task() -> Task {
    Task {
        contract_version: ContractVersion::current(),
        id: TaskId::from("task.a05"),
        goal_id: GoalId::from("goal.a05"),
        outcome: "produce one bounded verified change".to_owned(),
        dependencies: Vec::new(),
        assigned_role: Role::Engineer,
        resource_keys: vec!["input.txt".to_owned()],
        write_keys: vec!["input.txt".to_owned()],
        status: TaskStatus::Ready,
        created_at: at(8),
        updated_at: at(9),
    }
}

fn completion(goal: &GoalContract) -> CompletionEvidence {
    CompletionEvidence {
        contract_version: ContractVersion::current(),
        evidence_refs: vec![EvidenceId::from("evidence.a05.verification")],
        satisfied_acceptance_criteria: goal.acceptance_criteria.clone(),
        satisfied_verification_criteria: goal.verification_criteria.clone(),
        satisfied_definition_of_done: goal.definition_of_done.clone(),
    }
}

fn evidence_catalog() -> Vec<EvidenceRef> {
    vec![EvidenceRef {
        contract_version: ContractVersion::current(),
        id: EvidenceId::from("evidence.a05.verification"),
        kind: EvidenceKind::TestResult,
        reference: "evidence-bank://bundle.a05".to_owned(),
        producer_role: Role::Engineer,
        integrity: Some(IntegrityMetadata {
            contract_version: ContractVersion::current(),
            algorithm: "sha256".to_owned(),
            digest: "1".repeat(64),
        }),
        produced_at: at(10),
    }]
}

fn assessments(
    goal: &GoalContract,
    verdict: CriterionAssessmentVerdict,
) -> Vec<CriterionAssessment> {
    [
        (CriterionKind::Acceptance, &goal.acceptance_criteria[0]),
        (CriterionKind::Verification, &goal.verification_criteria[0]),
        (CriterionKind::DefinitionOfDone, &goal.definition_of_done[0]),
    ]
    .into_iter()
    .map(|(kind, criterion)| CriterionAssessment {
        contract_version: ContractVersion::current(),
        kind,
        criterion: criterion.clone(),
        verdict,
        evidence_refs: vec![EvidenceId::from("evidence.a05.verification")],
        rationale: "the bound evidence supports this exact criterion".to_owned(),
    })
    .collect()
}

fn review_decision(goal: &GoalContract, verdict: ReviewVerdict) -> ReviewDecision {
    let assessment_verdict = match verdict {
        ReviewVerdict::Pass => CriterionAssessmentVerdict::Satisfied,
        ReviewVerdict::Fail => CriterionAssessmentVerdict::Unsatisfied,
    };
    ReviewDecision {
        contract_version: ContractVersion::current(),
        id: ReviewDecisionId::from("review.a05"),
        run_id: RunId::from("run.a05"),
        goal_id: goal.id.clone(),
        producer_role: Role::Reviewer,
        verdict,
        assessments: assessments(goal, assessment_verdict),
        summary: "reviewed the exact frozen candidate".to_owned(),
        decided_at: at(11),
    }
}

fn audit_decision(
    goal: &GoalContract,
    review: &ReviewDecision,
    verdict: ReviewVerdict,
) -> AuditDecision {
    let assessment_verdict = match verdict {
        ReviewVerdict::Pass => CriterionAssessmentVerdict::Satisfied,
        ReviewVerdict::Fail => CriterionAssessmentVerdict::Unsatisfied,
    };
    AuditDecision {
        contract_version: ContractVersion::current(),
        id: AuditDecisionId::from("audit.a05"),
        run_id: RunId::from("run.a05"),
        goal_id: goal.id.clone(),
        review_decision_id: review.id.clone(),
        producer_role: Role::Auditor,
        verdict,
        assessments: assessments(goal, assessment_verdict),
        summary: "audited the exact review and evidence bindings".to_owned(),
        decided_at: at(12),
    }
}

fn manifest(
    actor: PrincipalIdentityV1,
    namespace: &str,
    producer: IndependentEvidenceActorV1,
    evidence_id: &str,
    evidence_kind: EvidenceKind,
) -> EvidenceManifestV1 {
    let mut manifest = EvidenceManifestV1 {
        contract_version: INDEPENDENT_REVIEW_CONTRACT_VERSION,
        actor,
        criteria_namespace: namespace.to_owned(),
        entries: [
            (CriterionKind::Acceptance, "candidate is correct"),
            (
                CriterionKind::Verification,
                "verification evidence is current",
            ),
            (
                CriterionKind::DefinitionOfDone,
                "independent pass pair is durable",
            ),
        ]
        .into_iter()
        .map(|(criterion_kind, criterion)| EvidenceManifestEntryV1 {
            criterion_kind,
            criterion: criterion.to_owned(),
            evidence_id: EvidenceId::from(evidence_id),
            evidence_kind,
            producer: producer.clone(),
            content_digest: "1".repeat(64),
        })
        .collect(),
        manifest_digest: String::new(),
    };
    manifest.refresh_digest().unwrap();
    manifest
}

fn verification_bundle() -> VerificationBundle {
    VerificationBundle {
        contract_version: ContractVersion::current(),
        bundle_id: "bundle.a05".to_owned(),
        run_id: RunId::from("run.a05"),
        goal_id: GoalId::from("goal.a05"),
        task_id: TaskId::from("task.a05"),
        behavior_contract_id: "behavior.a05".to_owned(),
        capability_ids: vec!["capability.a05".to_owned()],
        implementation_actor: WorkerId::from("principal.a05.engineer"),
        verifier_actor: WorkerId::from("principal.a05.verifier"),
        fingerprints: VerificationFingerprints {
            source_pre: "3".repeat(64),
            source_post: "4".repeat(64),
            behavior_contract: "5".repeat(64),
            capability_set: "6".repeat(64),
            command: "7".repeat(64),
            policy: "8".repeat(64),
            environment: "9".repeat(64),
        },
        criterion_results: vec![CriterionResult {
            criterion_id: "criterion.a05".to_owned(),
            order: 0,
            kind: BehaviorKind::Verification,
            text: "verification evidence is current".to_owned(),
            verdict: CriterionResultVerdict::Pass,
        }],
        failures: Vec::new(),
        verdict: VerificationVerdict::Pass,
        created_at: at(10),
    }
}

fn review_packet() -> ReviewPacketV1 {
    let run_id = RunId::from("run.a05");
    let reviewer_invocation = invocation(&run_id, PrincipalV1::Reviewer, "reviewer");
    let before_bytes = b"old\n".to_vec();
    let after_bytes = b"new\n".to_vec();
    let mut frozen_diff = FrozenPathDiffV1 {
        contract_version: INDEPENDENT_REVIEW_CONTRACT_VERSION,
        logical_path: "input.txt".to_owned(),
        before_bytes: Some(before_bytes.clone()),
        after_bytes: after_bytes.clone(),
        before_file: Some(WorkspaceFileV1 {
            logical_path: "input.txt".to_owned(),
            sha256: verification_sha256_hex(&before_bytes),
            byte_length: before_bytes.len() as u64,
        }),
        after_file: WorkspaceFileV1 {
            logical_path: "input.txt".to_owned(),
            sha256: verification_sha256_hex(&after_bytes),
            byte_length: after_bytes.len() as u64,
        },
        issue6_diff_digest: "a".repeat(64),
        frozen_diff_digest: String::new(),
    };
    frozen_diff.refresh_digest().unwrap();
    let goal = goal();
    let bundle = verification_bundle();
    let reviewer = reviewer_invocation.target.clone();
    let mut packet = ReviewPacketV1 {
        contract_version: INDEPENDENT_REVIEW_CONTRACT_VERSION,
        packet_id: "packet.a05.review".to_owned(),
        root_run_id: run_id.clone(),
        run_id,
        goal_id: GoalId::from("goal.a05"),
        task_id: TaskId::from("task.a05"),
        candidate_cycle: 0,
        max_repair_cycles: 2,
        prior_run_id: None,
        prior_repair_directive_digest: None,
        task: task(),
        goal_contract: goal.clone(),
        completion_evidence: completion(&goal),
        evidence_catalog: evidence_catalog(),
        engineer: identity("principal.a05.engineer", PrincipalV1::Engineer),
        verifier: WorkerId::from("principal.a05.verifier"),
        reviewer: reviewer.clone(),
        reviewer_invocation_digest: reviewer_invocation.canonical_digest().unwrap(),
        reviewer_invocation,
        issue6_state_digest: "b".repeat(64),
        logical_plan_digest: "c".repeat(64),
        resolved_effect_ledger_digest: "d".repeat(64),
        engineer_result_digest: "e".repeat(64),
        verifier_replay_plan_digest: "f".repeat(64),
        verifier_transcript_digest: "0".repeat(64),
        frozen_diff,
        verification_bundle: bundle,
        verification_bundle_record_digest: "1".repeat(64),
        evidence_current: EvidenceCurrentAnchorV1 {
            bundle_id: "bundle.a05".to_owned(),
            record_digest: "1".repeat(64),
            generation: 1,
            state_digest: "2".repeat(64),
        },
        verifier_receipts: vec![VerificationTranscriptCommandIdentity {
            sequence: 0,
            command_digest: "3".repeat(64),
            executable_digest: "4".repeat(64),
            termination: VerificationTermination::Completed,
            exit_code: Some(0),
            stdout_sha256: "5".repeat(64),
            stderr_sha256: "6".repeat(64),
            stdout_bytes: 7,
            stderr_bytes: 0,
        }],
        evidence_manifest: manifest(
            reviewer,
            "criteria.a05.review",
            IndependentEvidenceActorV1 {
                actor_id: "principal.a05.engineer".to_owned(),
                role: IndependentEvidenceActorRoleV1::Engineer,
            },
            "evidence.a05.verification",
            EvidenceKind::TestResult,
        ),
        packet_digest: String::new(),
    };
    packet.refresh_digest().unwrap();
    packet.validate().unwrap();
    packet
}

fn result(
    invocation: &RoleInvocationV1,
    payload: RoleResultPayloadV1,
    id: &str,
    occurred_at: chrono::DateTime<Utc>,
) -> RoleResultV1 {
    RoleResultV1 {
        contract_version: 1,
        result_id: id.to_owned(),
        invocation_id: invocation.invocation_id.clone(),
        invocation_digest: invocation.canonical_digest().unwrap(),
        producer: invocation.target.clone(),
        task_id: invocation.task_id.clone(),
        run_id: invocation.run_id.clone(),
        scope: invocation.scope.clone(),
        idempotency_key: invocation.idempotency_key.clone(),
        attempt: 1,
        state: ControlPlaneState::Completed,
        payload,
        evidence_ids: vec![EvidenceId::from(format!("evidence.{id}"))],
        occurred_at,
    }
}

fn audit_packet_for(
    review_packet: &ReviewPacketV1,
    review_verdict: ReviewVerdict,
) -> AuditPacketV1 {
    let review = review_decision(&review_packet.goal_contract, review_verdict);
    let review_result = result(
        &review_packet.reviewer_invocation,
        RoleResultPayloadV1::Reviewer {
            packet_digest: review_packet.packet_digest.clone(),
            decision: review.clone(),
        },
        "result.a05.review",
        at(11),
    );
    let auditor_invocation = invocation(&review_packet.run_id, PrincipalV1::Auditor, "auditor");
    let auditor = auditor_invocation.target.clone();
    let mut packet = AuditPacketV1 {
        contract_version: INDEPENDENT_REVIEW_CONTRACT_VERSION,
        packet_id: "packet.a05.audit".to_owned(),
        review_packet: review_packet.clone(),
        review_packet_digest: review_packet.packet_digest.clone(),
        review_result_digest: review_result.canonical_digest().unwrap(),
        review_decision: review,
        auditor: auditor.clone(),
        auditor_invocation_digest: auditor_invocation.canonical_digest().unwrap(),
        auditor_invocation,
        evidence_manifest: manifest(
            auditor,
            "criteria.a05.audit",
            IndependentEvidenceActorV1 {
                actor_id: "principal.a05.engineer".to_owned(),
                role: IndependentEvidenceActorRoleV1::Engineer,
            },
            "evidence.a05.verification",
            EvidenceKind::TestResult,
        ),
        packet_digest: String::new(),
    };
    packet.refresh_digest().unwrap();
    packet.validate().unwrap();
    packet
}

fn audit_packet(review_packet: &ReviewPacketV1) -> AuditPacketV1 {
    audit_packet_for(review_packet, ReviewVerdict::Pass)
}

fn completed_call(
    request: &ovca_runtime_core::IndependentRoleExecutionRequest,
    result: RoleResultV1,
    started_at: chrono::DateTime<Utc>,
    recorded_at: chrono::DateTime<Utc>,
) -> IndependentCallStateV1 {
    let request_digest = request.canonical_digest().unwrap();
    let outcome = RoleExecutionOutcome::Completed {
        result,
        usage: RoleExecutionUsage::Unavailable,
    };
    let persisted =
        PersistedRoleExecutionOutcomeV1::try_from_live(&outcome, &request.role_request).unwrap();
    let outcome_digest = persisted.outcome_digest().unwrap();
    IndependentCallStateV1::OutcomeRecorded {
        request_digest,
        started_at,
        outcome: Box::new(persisted),
        outcome_digest,
        recorded_at,
    }
}

fn auditing_state(
    review_verdict: ReviewVerdict,
    audit_verdict: ReviewVerdict,
) -> IndependentReviewStateV1 {
    let mut review_packet = review_packet();
    if review_verdict == ReviewVerdict::Fail {
        review_packet
            .completion_evidence
            .satisfied_acceptance_criteria
            .clear();
        review_packet
            .completion_evidence
            .satisfied_verification_criteria
            .clear();
        review_packet
            .completion_evidence
            .satisfied_definition_of_done
            .clear();
        review_packet.refresh_digest().unwrap();
    }
    let review = review_decision(&review_packet.goal_contract, review_verdict);
    let review_result = result(
        &review_packet.reviewer_invocation,
        RoleResultPayloadV1::Reviewer {
            packet_digest: review_packet.packet_digest.clone(),
            decision: review,
        },
        "result.a05.review",
        at(11),
    );
    let mut state = IndependentReviewStateV1::initial(review_packet.clone(), at(10)).unwrap();
    state.review_call = completed_call(
        &review_execution_request(&review_packet),
        review_result,
        at(10),
        at(11),
    );
    state.controller_time = at(11);
    state.refresh_digest().unwrap();

    let audit_packet = audit_packet_for(&review_packet, review_verdict);
    let audit = audit_decision(
        &review_packet.goal_contract,
        &audit_packet.review_decision,
        audit_verdict,
    );
    let audit_result = result(
        &audit_packet.auditor_invocation,
        RoleResultPayloadV1::Auditor {
            packet_digest: audit_packet.packet_digest.clone(),
            decision: audit,
        },
        "result.a05.audit",
        at(12),
    );
    state.phase = IndependentReviewPhaseV1::Auditing;
    state.audit_call = Some(completed_call(
        &audit_execution_request(&audit_packet),
        audit_result,
        at(11),
        at(12),
    ));
    state.audit_packet = Some(audit_packet);
    state.controller_time = at(12);
    let durable_review = ovca_runtime_core::completed_result(&state.review_call).unwrap();
    let bound_audit_packet = state.audit_packet.as_ref().unwrap();
    assert_eq!(
        bound_audit_packet.review_result_digest,
        durable_review.canonical_digest().unwrap()
    );
    let RoleResultPayloadV1::Reviewer {
        decision: durable_review_decision,
        ..
    } = &durable_review.payload
    else {
        unreachable!()
    };
    assert_eq!(&bound_audit_packet.review_decision, durable_review_decision);
    let validated_review = ovca_runtime_core::validate_review_decision(
        &ovca_runtime_core::ReviewDecisionValidationContext {
            expected_run_id: &state.review_packet.run_id,
            goal_contract: &state.review_packet.goal_contract,
            completion_evidence: &state.review_packet.completion_evidence,
            evidence_catalog: &state.review_packet.evidence_catalog,
        },
        durable_review_decision,
    )
    .unwrap();
    let durable_audit =
        ovca_runtime_core::completed_result(state.audit_call.as_ref().unwrap()).unwrap();
    let RoleResultPayloadV1::Auditor {
        decision: durable_audit_decision,
        ..
    } = &durable_audit.payload
    else {
        unreachable!()
    };
    ovca_runtime_core::validate_audit_decision(
        &ovca_runtime_core::AuditDecisionValidationContext {
            expected_run_id: &state.review_packet.run_id,
            goal_contract: &state.review_packet.goal_contract,
            completion_evidence: &state.review_packet.completion_evidence,
            evidence_catalog: &state.review_packet.evidence_catalog,
            validated_review_decision: &validated_review,
        },
        durable_audit_decision,
    )
    .unwrap();
    state.refresh_digest().unwrap();
    state
}

fn repair_directive(audit_packet: &AuditPacketV1) -> RepairDirectiveV1 {
    let audit = audit_decision(
        &audit_packet.review_packet.goal_contract,
        &audit_packet.review_decision,
        ReviewVerdict::Fail,
    );
    let audit_result = result(
        &audit_packet.auditor_invocation,
        RoleResultPayloadV1::Auditor {
            packet_digest: audit_packet.packet_digest.clone(),
            decision: audit,
        },
        "result.a05.audit",
        at(12),
    );
    let audit_result_digest = audit_result.canonical_digest().unwrap();
    let successor_run_id = derive_repair_successor_run_id(
        &audit_packet.review_packet.root_run_id,
        1,
        &audit_packet.review_result_digest,
        &audit_result_digest,
    )
    .unwrap();
    let mut directive = RepairDirectiveV1 {
        contract_version: INDEPENDENT_REVIEW_CONTRACT_VERSION,
        directive_id: "directive.a05.repair".to_owned(),
        root_run_id: audit_packet.review_packet.root_run_id.clone(),
        failed_run_id: audit_packet.review_packet.run_id.clone(),
        successor_run_id,
        goal_id: audit_packet.review_packet.goal_id.clone(),
        task_id: audit_packet.review_packet.task_id.clone(),
        failed_candidate_cycle: 0,
        successor_candidate_cycle: 1,
        max_repair_cycles: audit_packet.review_packet.max_repair_cycles,
        prior_repair_directive_digest: None,
        review_packet_digest: audit_packet.review_packet.packet_digest.clone(),
        review_result_digest: audit_packet.review_result_digest.clone(),
        audit_packet_digest: audit_packet.packet_digest.clone(),
        audit_result_digest,
        repair_paths: vec!["input.txt".to_owned()],
        unsatisfied_criteria: vec![UnsatisfiedCriterionV1 {
            kind: CriterionKind::Acceptance,
            criterion: "candidate is correct".to_owned(),
        }],
        routed_by: identity("principal.a05.coordinator", PrincipalV1::Coordinator),
        grants_authority: false,
        directive_digest: String::new(),
    };
    directive.refresh_digest().unwrap();
    directive.validate().unwrap();
    directive
}

fn repair_directive_for_state(state: &IndependentReviewStateV1) -> RepairDirectiveV1 {
    let review_result = ovca_runtime_core::completed_result(&state.review_call).unwrap();
    let audit_result =
        ovca_runtime_core::completed_result(state.audit_call.as_ref().unwrap()).unwrap();
    let review_result_digest = review_result.canonical_digest().unwrap();
    let audit_result_digest = audit_result.canonical_digest().unwrap();
    let successor_cycle = state.review_packet.candidate_cycle + 1;
    let successor_run_id = derive_repair_successor_run_id(
        &state.review_packet.root_run_id,
        successor_cycle,
        &review_result_digest,
        &audit_result_digest,
    )
    .unwrap();
    let RoleResultPayloadV1::Reviewer {
        decision: review, ..
    } = &review_result.payload
    else {
        unreachable!()
    };
    let RoleResultPayloadV1::Auditor {
        decision: audit, ..
    } = &audit_result.payload
    else {
        unreachable!()
    };
    let mut criteria = review
        .assessments
        .iter()
        .chain(&audit.assessments)
        .filter(|assessment| assessment.verdict == CriterionAssessmentVerdict::Unsatisfied)
        .map(|assessment| UnsatisfiedCriterionV1 {
            kind: assessment.kind,
            criterion: assessment.criterion.clone(),
        })
        .collect::<Vec<_>>();
    criteria.sort();
    criteria.dedup();
    let mut directive = RepairDirectiveV1 {
        contract_version: INDEPENDENT_REVIEW_CONTRACT_VERSION,
        directive_id: "directive.a05.state".to_owned(),
        root_run_id: state.review_packet.root_run_id.clone(),
        failed_run_id: state.review_packet.run_id.clone(),
        successor_run_id,
        goal_id: state.review_packet.goal_id.clone(),
        task_id: state.review_packet.task_id.clone(),
        failed_candidate_cycle: state.review_packet.candidate_cycle,
        successor_candidate_cycle: successor_cycle,
        max_repair_cycles: state.review_packet.max_repair_cycles,
        prior_repair_directive_digest: state.review_packet.prior_repair_directive_digest.clone(),
        review_packet_digest: state.review_packet.packet_digest.clone(),
        review_result_digest,
        audit_packet_digest: state.audit_packet.as_ref().unwrap().packet_digest.clone(),
        audit_result_digest,
        repair_paths: vec![state.review_packet.frozen_diff.logical_path.clone()],
        unsatisfied_criteria: criteria,
        routed_by: identity("principal.a05.coordinator", PrincipalV1::Coordinator),
        grants_authority: false,
        directive_digest: String::new(),
    };
    directive.refresh_digest().unwrap();
    directive
}

fn assert_direct_cas_rejects_invalid_state(mut state: IndependentReviewStateV1) {
    state.state_digest = state.computed_state_digest().unwrap();
    let directory = tempdir().unwrap();
    let authority = DurableExecutionAuthority::new(directory.path());
    let run_id = state.review_packet.run_id.clone();
    assert!(matches!(
        authority.compare_and_swap_independent_review(&run_id, 0, None, state,),
        Err(DurableExecutionError::IndependentReview(
            IndependentReviewError::InvalidState
        ))
    ));
}

fn sample_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/samples")
        .join(name)
}

#[test]
fn packet_directive_and_sample_round_trips_are_canonical() {
    let review = review_packet();
    let audit = audit_packet(&review);
    let directive = repair_directive(&audit);

    if std::env::var_os("OVCA_UPDATE_A05_SAMPLES").is_some() {
        for (name, bytes) in [
            (
                "review_packet.v1.sample.json",
                serde_json::to_vec_pretty(&review).unwrap(),
            ),
            (
                "audit_packet.v1.sample.json",
                serde_json::to_vec_pretty(&audit).unwrap(),
            ),
            (
                "repair_directive.v1.sample.json",
                serde_json::to_vec_pretty(&directive).unwrap(),
            ),
        ] {
            let mut bytes = bytes;
            bytes.push(b'\n');
            fs::write(sample_path(name), bytes).unwrap();
        }
    }

    let loaded_review: ReviewPacketV1 =
        serde_json::from_slice(&fs::read(sample_path("review_packet.v1.sample.json")).unwrap())
            .unwrap();
    let loaded_audit: AuditPacketV1 =
        serde_json::from_slice(&fs::read(sample_path("audit_packet.v1.sample.json")).unwrap())
            .unwrap();
    let loaded_directive: RepairDirectiveV1 =
        serde_json::from_slice(&fs::read(sample_path("repair_directive.v1.sample.json")).unwrap())
            .unwrap();
    loaded_review.validate().unwrap();
    loaded_audit.validate().unwrap();
    loaded_directive.validate().unwrap();
    assert_eq!(loaded_review, review);
    assert_eq!(loaded_audit, audit);
    assert_eq!(loaded_directive, directive);

    for schema in [
        "review_packet.v1.schema.json",
        "audit_packet.v1.schema.json",
        "repair_directive.v1.schema.json",
    ] {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts")
            .join(schema);
        let _: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    }
}

#[test]
fn nested_decisions_reject_unknown_fields_without_breaking_legacy_valid_bytes() {
    let goal = goal();
    let review = review_decision(&goal, ReviewVerdict::Pass);
    let audit = audit_decision(&goal, &review, ReviewVerdict::Pass);
    let legacy_review = serde_json::to_vec(&review).unwrap();
    let legacy_audit = serde_json::to_vec(&audit).unwrap();
    assert_eq!(
        serde_json::from_slice::<ReviewDecision>(&legacy_review).unwrap(),
        review
    );
    assert_eq!(
        serde_json::from_slice::<AuditDecision>(&legacy_audit).unwrap(),
        audit
    );

    let mut unknown_review = serde_json::to_value(&review).unwrap();
    unknown_review["assessments"][0]["unknown_nested"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ReviewDecision>(unknown_review).is_err());
    let mut unknown_audit = serde_json::to_value(&audit).unwrap();
    unknown_audit["assessments"][0]["unknown_nested"] = serde_json::json!(true);
    assert!(serde_json::from_value::<AuditDecision>(unknown_audit).is_err());
}

#[test]
fn typed_requests_are_packet_visible_and_write_free_while_legacy_results_remain_valid() {
    let review_packet = review_packet();
    let review_request = review_execution_request(&review_packet);
    review_request.validate().unwrap();
    assert_eq!(review_request.packet.digest(), review_packet.packet_digest);
    assert!(review_request
        .role_request
        .invocation
        .authority
        .permission_profile
        .resource_keys
        .is_empty());
    assert!(review_request
        .role_request
        .invocation
        .authority
        .permission_profile
        .write_keys
        .is_empty());

    let audit_packet = audit_packet(&review_packet);
    audit_execution_request(&audit_packet).validate().unwrap();

    let typed = result(
        &review_packet.reviewer_invocation,
        RoleResultPayloadV1::Reviewer {
            packet_digest: review_packet.packet_digest.clone(),
            decision: review_decision(&review_packet.goal_contract, ReviewVerdict::Pass),
        },
        "result.a05.typed",
        at(11),
    );
    typed
        .validate_against(&review_packet.reviewer_invocation)
        .unwrap();

    let legacy = result(
        &review_packet.reviewer_invocation,
        RoleResultPayloadV1::Specialist {
            summary: "legacy reviewer result remains valid outside A05".to_owned(),
        },
        "result.a05.legacy",
        at(11),
    );
    legacy
        .validate_against(&review_packet.reviewer_invocation)
        .unwrap();
    let mut state = IndependentReviewStateV1::initial(review_packet, at(10)).unwrap();
    state.review_call = ovca_runtime_core::IndependentCallStateV1::NotStarted;
    state.refresh_digest().unwrap();
}

#[test]
fn self_approval_write_attempt_and_alternate_successor_fail_closed() {
    let baseline = review_packet();
    for forbidden_id in [
        baseline.engineer.principal_id.clone(),
        baseline.verifier.0.clone(),
    ] {
        let mut packet = baseline.clone();
        packet.reviewer.principal_id = forbidden_id;
        packet.reviewer_invocation.target = packet.reviewer.clone();
        packet.reviewer_invocation_digest = packet.reviewer_invocation.canonical_digest().unwrap();
        packet.refresh_digest().unwrap();
        assert!(packet.validate().is_err());
    }

    let mut packet = review_packet();
    packet
        .reviewer_invocation
        .authority
        .permission_profile
        .write_keys
        .push("input.txt".to_owned());
    packet.reviewer_invocation.authority_digest =
        canonical_authority_digest(&packet.reviewer_invocation.authority).unwrap();
    packet.reviewer_invocation_digest = packet.reviewer_invocation.canonical_digest().unwrap();
    packet.refresh_digest().unwrap();
    assert!(packet.validate().is_err());

    let review = review_packet();
    for forbidden_id in [
        review.engineer.principal_id.clone(),
        review.verifier.0.clone(),
        review.reviewer.principal_id.clone(),
    ] {
        let mut audit = audit_packet(&review);
        audit.auditor.principal_id = forbidden_id;
        audit.auditor_invocation.target = audit.auditor.clone();
        audit.auditor_invocation_digest = audit.auditor_invocation.canonical_digest().unwrap();
        audit.refresh_digest().unwrap();
        assert!(audit.validate().is_err());
    }

    let mut audit = audit_packet(&review);
    audit
        .auditor_invocation
        .authority
        .permission_profile
        .write_keys
        .push("input.txt".to_owned());
    audit.auditor_invocation.authority_digest =
        canonical_authority_digest(&audit.auditor_invocation.authority).unwrap();
    audit.auditor_invocation_digest = audit.auditor_invocation.canonical_digest().unwrap();
    audit.refresh_digest().unwrap();
    assert!(audit.validate().is_err());

    let audit = audit_packet(&review);
    let mut directive = repair_directive(&audit);
    directive.successor_run_id = RunId::from("run.a05.alternate-sibling");
    directive.refresh_digest().unwrap();
    assert!(directive.validate().is_err());
}

#[test]
fn root_cycle_directive_chain_and_manifest_coverage_fail_closed() {
    let mut packet = review_packet();
    packet.root_run_id = RunId::from("run.a05.unrelated-root");
    packet.refresh_digest().unwrap();
    assert!(packet.validate().is_err());

    let audit = audit_packet(&review_packet());
    let mut directive = repair_directive(&audit);
    directive.prior_repair_directive_digest = Some("9".repeat(64));
    directive.refresh_digest().unwrap();
    assert!(directive.validate().is_err());

    let mut packet = review_packet();
    packet
        .completion_evidence
        .evidence_refs
        .push(EvidenceId::from("evidence.a05.uncovered"));
    packet.evidence_catalog.push(EvidenceRef {
        contract_version: ContractVersion::current(),
        id: EvidenceId::from("evidence.a05.uncovered"),
        kind: EvidenceKind::TestResult,
        reference: "evidence-bank://bundle.a05.uncovered".to_owned(),
        producer_role: Role::Engineer,
        integrity: Some(IntegrityMetadata {
            contract_version: ContractVersion::current(),
            algorithm: "sha256".to_owned(),
            digest: "7".repeat(64),
        }),
        produced_at: at(10),
    });
    packet.refresh_digest().unwrap();
    assert!(packet.validate().is_err());
}

#[test]
fn durable_state_rejects_forged_audit_and_terminal_semantics_before_lookup() {
    let mut mismatched_audit = auditing_state(ReviewVerdict::Pass, ReviewVerdict::Pass);
    let packet = mismatched_audit.audit_packet.as_mut().unwrap();
    packet.review_decision.summary = "different review bytes".to_owned();
    packet.refresh_digest().unwrap();
    mismatched_audit.audit_call = Some(IndependentCallStateV1::NotStarted);
    assert_direct_cas_rejects_invalid_state(mismatched_audit);

    let mut fail_as_pass = auditing_state(ReviewVerdict::Fail, ReviewVerdict::Fail);
    let review_digest = ovca_runtime_core::completed_result(&fail_as_pass.review_call)
        .unwrap()
        .canonical_digest()
        .unwrap();
    let audit_digest =
        ovca_runtime_core::completed_result(fail_as_pass.audit_call.as_ref().unwrap())
            .unwrap()
            .canonical_digest()
            .unwrap();
    fail_as_pass.phase = IndependentReviewPhaseV1::ResolvedPass;
    fail_as_pass.resolution = Some(IndependentReviewResolutionV1::Pass {
        review_result_digest: review_digest,
        audit_result_digest: audit_digest,
    });
    assert_direct_cas_rejects_invalid_state(fail_as_pass);

    let mut wrong_digest = auditing_state(ReviewVerdict::Pass, ReviewVerdict::Pass);
    wrong_digest.phase = IndependentReviewPhaseV1::ResolvedPass;
    wrong_digest.resolution = Some(IndependentReviewResolutionV1::Pass {
        review_result_digest: "7".repeat(64),
        audit_result_digest: "8".repeat(64),
    });
    assert_direct_cas_rejects_invalid_state(wrong_digest);

    let mut forged_repair = auditing_state(ReviewVerdict::Fail, ReviewVerdict::Fail);
    let mut directive = repair_directive_for_state(&forged_repair);
    directive.repair_paths = vec!["other.txt".to_owned()];
    directive.refresh_digest().unwrap();
    forged_repair.phase = IndependentReviewPhaseV1::RepairDirected;
    forged_repair.resolution = Some(IndependentReviewResolutionV1::Repair {
        directive_digest: directive.directive_digest.clone(),
        successor_run_id: directive.successor_run_id.clone(),
    });
    forged_repair.repair_directive = Some(directive);
    assert_direct_cas_rejects_invalid_state(forged_repair);
}

#[test]
fn recorded_decision_must_bind_each_assessment_to_its_manifest_pair() {
    let packet = review_packet();
    let mut state = IndependentReviewStateV1::initial(packet.clone(), at(10)).unwrap();
    let mut decision = review_decision(&packet.goal_contract, ReviewVerdict::Pass);
    decision.assessments[1].criterion = packet.goal_contract.acceptance_criteria[0].clone();
    let result = result(
        &packet.reviewer_invocation,
        RoleResultPayloadV1::Reviewer {
            packet_digest: packet.packet_digest.clone(),
            decision,
        },
        "result.a05.wrong-manifest-pair",
        at(11),
    );
    state.review_call = completed_call(&review_execution_request(&packet), result, at(10), at(11));
    state.controller_time = at(11);
    assert!(matches!(
        state.refresh_digest(),
        Err(IndependentReviewError::InvalidExecutorOutcome)
    ));
}
