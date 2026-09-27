use chrono::{DateTime, TimeZone, Utc};
use ovca_langgraph::engineer_verifier_loop::{
    EngineerVerifierClock, EngineerVerifierLoop, EngineerVerifierLoopInput,
    EngineerVerifierLoopOutcome, EngineerWorkspaceInput, VerifierReplayInputs,
};
use ovca_langgraph::review_audit_loop::{
    ReviewAuditClock, ReviewAuditLoop, ReviewAuditLoopInput, ReviewAuditLoopOutcome,
};
use ovca_langgraph::{
    DurableGoalRuntime, EnforcedLocalVerificationGoal, EventStamp,
    LocalVerificationCompletionPolicy, PlannedRunStamps,
};
use ovca_runtime_core::{
    BrokerClock, DeterministicFakeRoleExecutor, DurableExecutionError, EngineerLogicalPlanV1,
    IndependentReviewError, IndependentReviewExecutor, IndependentReviewPhaseV1,
    IndependentReviewStateV1, IndependentRoleExecutionRequest, LocalVerificationCompletionContract,
    LocalVerificationCompletionTask, OwnerEscalationReasonV1, PlannedToolEffectTemplateV1,
    RoleExecutionOutcome, RoleExecutionRequest, RoleExecutionScript, RoleExecutionUsage,
    RoleExecutorError, VerifierExecutionStateV1, WorkspaceCapabilityBroker, WorkspaceSeedFile,
};
use ovca_types::control_plane::{
    canonical_authority_digest as invocation_authority_digest, ControlPlaneState, ExecutionBudget,
    RoleInvocationV1, RoleResultPayloadV1, RoleResultV1,
};
use ovca_types::foundation::{
    FoundationAuthorityV1, FoundationNamespaceV1, FoundationPermissionProfileV1, FoundationScopeV1,
    FoundationSensitivityV1, FoundationValidityStatusV1, FoundationValidityV1,
    FoundationVisibilityV1, PrincipalIdentityV1, PrincipalV1,
};
use ovca_types::independent_review::{
    derive_repair_successor_run_id, EvidenceCurrentAnchorV1, EvidenceManifestEntryV1,
    EvidenceManifestV1, FrozenPathDiffV1, IndependentEvidenceActorRoleV1,
    IndependentEvidenceActorV1, ReviewPacketV1, INDEPENDENT_REVIEW_CONTRACT_VERSION,
};
use ovca_types::tool_boundary::{
    expected_read_permission_keys, expected_write_permission_keys, ToolOperationV1,
};
use ovca_types::{
    select_targeted_rerun, verification_policy_digest, verification_sha256_hex, AuditDecision,
    AuditDecisionId, BehaviorBinding, BehaviorCriterion, BehaviorKind,
    BehavioralAcceptanceContract, CapabilityDefinition, CapabilityRegistryRow,
    CapabilityRegistrySnapshot, ChangedPathEntry, ChangedPathKind, ChangedPathManifest,
    ChangedPathSelector, CompletionEvidence, CompletionPrecondition, ContractVersion,
    CriterionAssessment, CriterionAssessmentVerdict, CriterionKind, DeniedAccess, DigestAlgorithm,
    EventId, EvidenceId, EvidenceKind, EvidenceRef, GoalContract, GoalId, GuardRequirement,
    IdempotencyKey, IntegrityMetadata, LocalMachinePolicy, PathSelectorKind, PermissionProfile,
    ProjectId, RetryBudget, ReviewAuditRequirements, ReviewDecision, ReviewDecisionId,
    ReviewVerdict, RiskTier, Role, RunEvent, RunEventPayload, RunId, RunStatus, ShellPolicy,
    TargetedRerunOutcome, TargetedRerunRequest, TargetedRerunSelection, Task, TaskId, TaskStatus,
    UnknownPathPolicy, VerificationCommand, WorkerId, WorkingDirectory,
    LOCAL_VERIFICATION_CONTRACT_VERSION,
};
use ovca_verifier::bundle::{expected_failure_identity_keys, FailureIdentityMap};
use ovca_verifier::execution::{
    EnvironmentBindings, ExecutableProfile, ExecutableRegistry, ExecutionLimits,
};
use ovca_verifier::snapshot::{SourceFile, SourceManifest};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use tempfile::{tempdir, TempDir};
fn at(minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 17, 12, minute, 0)
        .single()
        .unwrap()
}

#[test]
fn child_probe() {
    if std::env::var("OVCA_CHILD_MODE").as_deref() == Ok("pass") {
        if let Ok(path) = std::env::var("OVCA_CHILD_COUNTER") {
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap()
                .write_all(b"invoked\n")
                .unwrap();
        }
        writeln!(io::stdout(), "bounded verifier output").unwrap();
        io::stdout().flush().unwrap();
    }
}

#[derive(Clone)]
struct MutableClock(Arc<AtomicI64>);

impl MutableClock {
    fn new(value: DateTime<Utc>) -> Self {
        Self(Arc::new(AtomicI64::new(value.timestamp_millis())))
    }

    fn read(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.0.load(Ordering::SeqCst)).unwrap()
    }
}

impl EngineerVerifierClock for MutableClock {
    fn now(&self) -> DateTime<Utc> {
        self.read()
    }
}

impl ReviewAuditClock for MutableClock {
    fn now(&self) -> DateTime<Utc> {
        self.read()
    }
}

impl BrokerClock for MutableClock {
    fn now(&self) -> DateTime<Utc> {
        self.read()
    }
}

struct PanicAfterReviewOutcomeClock(AtomicUsize);

impl ReviewAuditClock for PanicAfterReviewOutcomeClock {
    fn now(&self) -> DateTime<Utc> {
        let call = self.0.fetch_add(1, Ordering::SeqCst);
        if call == 3 {
            panic!("simulated crash after durable Reviewer outcome")
        }
        at(10 + u32::try_from(call).unwrap())
    }
}

struct Fixture {
    durable: TempDir,
    workspaces: TempDir,
    protected: TempDir,
    verifier_temp: TempDir,
    _probe: TempDir,
    plan: EngineerLogicalPlanV1,
    behavior: BehavioralAcceptanceContract,
    capability: CapabilityDefinition,
    selection: TargetedRerunSelection,
    manifest: SourceManifest,
    registry: ExecutableRegistry,
    bindings: EnvironmentBindings,
    environment_digest: String,
    failures: FailureIdentityMap,
}

impl Fixture {
    fn new() -> Self {
        let durable = tempdir().unwrap();
        let workspaces = tempdir().unwrap();
        let protected = tempdir().unwrap();
        let verifier_temp = tempdir().unwrap();
        let probe = tempdir().unwrap();
        let counter_path = probe.path().join("verifier-invocations.log");
        let plan = plan(&RunId::from("run.loop"));
        let manifest = SourceManifest {
            files: vec![SourceFile {
                logical_path: "input.txt".to_owned(),
                sha256: verification_sha256_hex(b"new\n"),
            }],
        };
        let environment_names = BTreeSet::from([
            "OVCA_CHILD_COUNTER".to_owned(),
            "OVCA_CHILD_MODE".to_owned(),
        ]);
        let capability = CapabilityDefinition {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            capability_id: "capability.loop".to_owned(),
            revision: 1,
            criterion_ids: vec!["criterion.loop".to_owned()],
            dependencies: Vec::new(),
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
                command_id: "command.loop".to_owned(),
                executable_id: "test-runner".to_owned(),
                argv: vec![
                    "child_probe".to_owned(),
                    "--exact".to_owned(),
                    "--nocapture".to_owned(),
                ],
                cwd: WorkingDirectory::SnapshotRoot,
                environment_names: environment_names.clone(),
            }],
        };
        let behavior = BehavioralAcceptanceContract {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            contract_id: "behavior.loop".to_owned(),
            binding: BehaviorBinding::Bound {
                goal_id: GoalId::from("goal.loop"),
                task_id: TaskId::from("task.loop"),
            },
            criteria: vec![BehaviorCriterion {
                criterion_id: "criterion.loop".to_owned(),
                order: 0,
                kind: BehaviorKind::Verification,
                text: "the bounded workspace change passes local verification".to_owned(),
                required: true,
                capability_ids: vec!["capability.loop".to_owned()],
            }],
        };
        let policy_digest = verification_policy_digest(std::slice::from_ref(&capability)).unwrap();
        let selection = selection(
            &capability,
            manifest.fingerprint().unwrap(),
            policy_digest,
            &plan.run_id,
        );
        let executable = std::env::current_exe().unwrap();
        let registry = ExecutableRegistry {
            profiles: BTreeMap::from([(
                "test-runner".to_owned(),
                ExecutableProfile {
                    executable_id: "test-runner".to_owned(),
                    sha256: verification_sha256_hex(&fs::read(&executable).unwrap()),
                    executable_path: executable,
                    enabled: true,
                    approved: true,
                    reviewed_offline: true,
                    allowed_environment_names: environment_names.clone(),
                },
            )]),
        };
        let bindings = EnvironmentBindings {
            values: BTreeMap::from([
                (
                    "OVCA_CHILD_COUNTER".to_owned(),
                    counter_path.as_os_str().to_os_string(),
                ),
                ("OVCA_CHILD_MODE".to_owned(), "pass".into()),
            ]),
        };
        let environment_digest = bindings.digest_for(&environment_names).unwrap();
        let failures = expected_failure_identity_keys(1)
            .unwrap()
            .into_iter()
            .enumerate()
            .map(|(index, key)| (key, format!("failure.loop.{index}")))
            .collect();
        Self {
            durable,
            workspaces,
            protected,
            verifier_temp,
            _probe: probe,
            plan,
            behavior,
            capability,
            selection,
            manifest,
            registry,
            bindings,
            environment_digest,
            failures,
        }
    }

    fn loop_with_clock(&self, clock: MutableClock) -> EngineerVerifierLoop {
        EngineerVerifierLoop::try_new(self.durable.path(), Box::new(clock)).unwrap()
    }

    fn broker(&self, runtime_id: &str, clock: MutableClock) -> WorkspaceCapabilityBroker {
        WorkspaceCapabilityBroker::try_new(
            runtime_id,
            self.workspaces.path(),
            vec![self.protected.path().to_path_buf()],
            Box::new(clock),
        )
        .unwrap()
    }

    fn initialize(&self, controller: &EngineerVerifierLoop) {
        controller
            .execution()
            .initialize_run(
                self.plan.run_id.clone(),
                vec![task()],
                RetryBudget {
                    contract_version: ContractVersion::current(),
                    max_attempts: 2,
                },
            )
            .unwrap();
    }

    fn publish_capability(&self) {
        let registry = ovca_storage::CapabilityRegistry::try_new(self.durable.path()).unwrap();
        let published = registry.publish(&self.capability).unwrap();
        let record = match published {
            ovca_storage::PublishOutcome::Inserted(record)
            | ovca_storage::PublishOutcome::ExistingIdentical(record) => record,
        };
        assert!(matches!(
            registry
                .compare_and_swap_current(
                    &self.capability.capability_id,
                    self.capability.revision,
                    &record.digest,
                    &ovca_storage::ProjectionExpectation::Absent,
                )
                .unwrap(),
            ovca_storage::CasOutcome::Applied(_)
        ));
    }

    fn input<'a>(
        &'a self,
        seed: &'a [u8],
        lease_id: &str,
        workspace_id: &str,
        recovery_token: &str,
        grant_id: &str,
        environment_digest: &'a str,
    ) -> EngineerVerifierLoopInput<'a> {
        EngineerVerifierLoopInput {
            plan: self.plan.clone(),
            workspace: EngineerWorkspaceInput {
                lease_id: lease_id.to_owned(),
                workspace_id: workspace_id.to_owned(),
                recovery_token: recovery_token.to_owned(),
                seeds: vec![WorkspaceSeedFile::try_new("input.txt", seed.to_vec()).unwrap()],
                lease_issued_at: at(5),
                lease_expires_at: at(40),
                grant_id: grant_id.to_owned(),
                grant_authority: grant_authority(&self.plan.run_id),
                read_paths: vec!["input.txt".to_owned()],
                write_paths: vec!["input.txt".to_owned()],
                max_read_bytes: 1024,
                max_write_bytes: 1024,
                grant_valid_from: at(5),
                grant_valid_until: at(40),
            },
            write_payloads: BTreeMap::from([("effect.loop.write".to_owned(), b"new\n".as_slice())]),
            verifier: VerifierReplayInputs {
                behavior: &self.behavior,
                capabilities: std::slice::from_ref(&self.capability),
                selection: &self.selection,
                source_manifest: &self.manifest,
                failure_identities: &self.failures,
                executable_registry: &self.registry,
                environment_bindings: &self.bindings,
                environment_digest,
                limits: ExecutionLimits {
                    timeout_millis: 5_000,
                    stdout_cap_bytes: 16_384,
                    stderr_cap_bytes: 16_384,
                },
                implementation_actor: WorkerId::from("principal.loop.engineer"),
                verifier_actor: WorkerId::from("principal.loop.verifier"),
                created_at: at(10),
                verifier_temp_parent: self.verifier_temp.path(),
            },
        }
    }
}

fn identity(id: &str, role: PrincipalV1) -> PrincipalIdentityV1 {
    PrincipalIdentityV1 {
        principal_id: id.to_owned(),
        role,
    }
}

fn scope(run_id: &RunId) -> FoundationScopeV1 {
    FoundationScopeV1 {
        project_id: "project.loop".to_owned(),
        goal_id: Some("goal.loop".to_owned()),
        task_id: Some("task.loop".to_owned()),
        run_id: Some(run_id.as_str().to_owned()),
    }
}

fn invocation(run_id: &RunId) -> RoleInvocationV1 {
    let invoker = identity("principal.loop.coordinator", PrincipalV1::Coordinator);
    let authority = FoundationAuthorityV1 {
        contract_version: 1,
        authority_id: "authority.loop.invocation".to_owned(),
        principal: invoker.clone(),
        scope: scope(run_id),
        namespace: FoundationNamespaceV1::CodeReview,
        permission_profile: FoundationPermissionProfileV1 {
            contract_version: 1,
            risk_tier: RiskTier::R1,
            resource_keys: vec!["resource.loop".to_owned()],
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
        invocation_id: "invocation.loop".to_owned(),
        invoker,
        target: identity("principal.loop.engineer", PrincipalV1::Engineer),
        task_id: TaskId::from("task.loop"),
        run_id: run_id.clone(),
        scope: scope(run_id),
        budget: ExecutionBudget {
            contract_version: 1,
            max_attempts: 2,
        },
        idempotency_key: IdempotencyKey::from("invocation-key.loop"),
        authority_digest: invocation_authority_digest(&authority).unwrap(),
        authority,
        input_digest: "a".repeat(64),
        invoked_at: at(1),
    }
}

fn plan(run_id: &RunId) -> EngineerLogicalPlanV1 {
    EngineerLogicalPlanV1::try_new(
        run_id.clone(),
        GoalId::from("goal.loop"),
        TaskId::from("task.loop"),
        invocation(run_id),
        vec![PlannedToolEffectTemplateV1 {
            contract_version: 1,
            ordinal: 0,
            effect_id: "effect.loop.write".to_owned(),
            operation: ToolOperationV1::WriteFile {
                logical_path: "input.txt".to_owned(),
                content_sha256: verification_sha256_hex(b"new\n"),
                byte_length: 4,
            },
            payload_sha256: verification_sha256_hex(b"new\n"),
        }],
    )
    .unwrap()
}

fn task() -> Task {
    Task {
        contract_version: ContractVersion::current(),
        id: TaskId::from("task.loop"),
        goal_id: GoalId::from("goal.loop"),
        outcome: "produce a verified bounded workspace change".to_owned(),
        dependencies: Vec::new(),
        assigned_role: Role::Engineer,
        resource_keys: vec!["input.txt".to_owned()],
        write_keys: vec!["input.txt".to_owned()],
        status: TaskStatus::Ready,
        created_at: at(0),
        updated_at: at(0),
    }
}

fn grant_authority(run_id: &RunId) -> FoundationAuthorityV1 {
    let read_paths = vec!["input.txt".to_owned()];
    let write_paths = vec!["input.txt".to_owned()];
    FoundationAuthorityV1 {
        contract_version: 1,
        authority_id: "authority.loop.grant".to_owned(),
        principal: identity("principal.loop.coordinator", PrincipalV1::Coordinator),
        scope: scope(run_id),
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
        visibility: FoundationVisibilityV1::RoleScoped,
        sensitivity: FoundationSensitivityV1::Internal,
        validity: FoundationValidityV1 {
            status: FoundationValidityStatusV1::Active,
            valid_from: at(0),
            valid_until: Some(at(50)),
        },
    }
}

fn completed_outcome(run_id: &RunId, attempt: u32) -> RoleExecutionOutcome {
    let invocation = invocation(run_id);
    RoleExecutionOutcome::Completed {
        result: RoleResultV1 {
            contract_version: 1,
            result_id: format!("result.loop.{attempt}"),
            invocation_id: invocation.invocation_id.clone(),
            invocation_digest: invocation.canonical_digest().unwrap(),
            producer: invocation.target.clone(),
            task_id: invocation.task_id.clone(),
            run_id: invocation.run_id.clone(),
            scope: invocation.scope.clone(),
            idempotency_key: invocation.idempotency_key.clone(),
            attempt,
            state: ControlPlaneState::Completed,
            payload: RoleResultPayloadV1::Specialist {
                summary: "bounded implementation complete".to_owned(),
            },
            evidence_ids: vec![EvidenceId::from(format!("evidence.loop.{attempt}"))],
            occurred_at: at(3 + attempt),
        },
        usage: RoleExecutionUsage::Unavailable,
    }
}

fn completed_executor(run_id: &RunId, attempts: &[u32]) -> DeterministicFakeRoleExecutor {
    DeterministicFakeRoleExecutor::try_new(attempts.iter().map(|attempt| RoleExecutionScript {
        request: RoleExecutionRequest {
            invocation: invocation(run_id),
            attempt: *attempt,
        },
        outcome: completed_outcome(run_id, *attempt),
    }))
    .unwrap()
}

fn selection(
    capability: &CapabilityDefinition,
    source_fingerprint: String,
    policy_digest: String,
    run_id: &RunId,
) -> TargetedRerunSelection {
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
        run_id: run_id.clone(),
        goal_id: GoalId::from("goal.loop"),
        task_id: TaskId::from("task.loop"),
        source_fingerprint,
        policy_digest,
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

fn a05_goal() -> GoalContract {
    GoalContract {
        contract_version: ContractVersion::current(),
        id: GoalId::from("goal.loop"),
        project_id: ProjectId::from("project.loop"),
        objective: "independently assess the frozen Issue 6 candidate".to_owned(),
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
        definition_of_done: vec!["independent decision pair is durable".to_owned()],
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

fn a05_completion(goal: &GoalContract, verdict: ReviewVerdict) -> CompletionEvidence {
    CompletionEvidence {
        contract_version: ContractVersion::current(),
        evidence_refs: vec![EvidenceId::from("evidence.loop.a05")],
        satisfied_acceptance_criteria: if verdict == ReviewVerdict::Pass {
            goal.acceptance_criteria.clone()
        } else {
            Vec::new()
        },
        satisfied_verification_criteria: goal.verification_criteria.clone(),
        satisfied_definition_of_done: goal.definition_of_done.clone(),
    }
}

fn a05_catalog() -> Vec<EvidenceRef> {
    vec![EvidenceRef {
        contract_version: ContractVersion::current(),
        id: EvidenceId::from("evidence.loop.a05"),
        kind: EvidenceKind::TestResult,
        reference: "evidence-bank://bundle.loop".to_owned(),
        producer_role: Role::Engineer,
        integrity: Some(IntegrityMetadata {
            contract_version: ContractVersion::current(),
            algorithm: "sha256".to_owned(),
            digest: "a".repeat(64),
        }),
        produced_at: at(10),
    }]
}

fn a05_assessments(goal: &GoalContract, verdict: ReviewVerdict) -> Vec<CriterionAssessment> {
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
        verdict: if verdict == ReviewVerdict::Fail && kind == CriterionKind::Acceptance {
            CriterionAssessmentVerdict::Unsatisfied
        } else {
            CriterionAssessmentVerdict::Satisfied
        },
        evidence_refs: vec![EvidenceId::from("evidence.loop.a05")],
        rationale: "checked against the exact bound evidence".to_owned(),
    })
    .collect()
}

fn a05_invocation(role: PrincipalV1, run_id: &RunId) -> RoleInvocationV1 {
    let suffix = match role {
        PrincipalV1::Reviewer => "reviewer",
        PrincipalV1::Auditor => "auditor",
        _ => panic!("A05 test invocation is review-only"),
    };
    let invoker = identity("principal.loop.coordinator", PrincipalV1::Coordinator);
    let authority = FoundationAuthorityV1 {
        contract_version: 1,
        authority_id: format!("authority.loop.{suffix}"),
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
            valid_from: at(0),
            valid_until: Some(at(59)),
        },
    };
    RoleInvocationV1 {
        contract_version: 1,
        invocation_id: format!("invocation.loop.{suffix}"),
        invoker,
        target: identity(&format!("principal.loop.{suffix}"), role),
        task_id: TaskId::from("task.loop"),
        run_id: run_id.clone(),
        scope: scope(run_id),
        budget: ExecutionBudget {
            contract_version: 1,
            max_attempts: 1,
        },
        idempotency_key: IdempotencyKey::from(format!("idempotency.loop.{suffix}")),
        authority_digest: invocation_authority_digest(&authority).unwrap(),
        authority,
        input_digest: verification_sha256_hex(format!("input.loop.{suffix}").as_bytes()),
        invoked_at: at(9),
    }
}

fn a05_manifest(
    actor: PrincipalIdentityV1,
    namespace: &str,
    producer: IndependentEvidenceActorV1,
    evidence_id: &str,
    evidence_kind: EvidenceKind,
) -> EvidenceManifestV1 {
    let mut value = EvidenceManifestV1 {
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
                "independent decision pair is durable",
            ),
        ]
        .into_iter()
        .map(|(criterion_kind, criterion)| EvidenceManifestEntryV1 {
            criterion_kind,
            criterion: criterion.to_owned(),
            evidence_id: EvidenceId::from(evidence_id),
            evidence_kind,
            producer: producer.clone(),
            content_digest: "a".repeat(64),
        })
        .collect(),
        manifest_digest: String::new(),
    };
    value.refresh_digest().unwrap();
    value
}

fn with_a05_ready<T>(check: impl FnOnce(&Fixture, &EngineerVerifierLoop, MutableClock) -> T) -> T {
    let fixture = Fixture::new();
    let clock = MutableClock::new(at(10));
    let issue6 = fixture.loop_with_clock(clock.clone());
    fixture.initialize(&issue6);
    fixture.publish_capability();
    let mut broker = fixture.broker("runtime.loop.a05", clock.clone());
    assert!(matches!(
        issue6
            .drive(
                &mut broker,
                &completed_executor(&fixture.plan.run_id, &[1]),
                fixture.input(
                    b"old\n",
                    "lease.loop.a05",
                    "workspace.loop.a05",
                    "recovery.loop.a05",
                    "grant.loop.a05",
                    &fixture.environment_digest,
                ),
            )
            .unwrap(),
        EngineerVerifierLoopOutcome::Reviewing { .. }
    ));
    assert_eq!(broker.active_root_count(), 0);
    drop(broker);
    check(&fixture, &issue6, clock)
}

fn a05_review_packet(
    controller: &EngineerVerifierLoop,
    run_id: &RunId,
    review_verdict: ReviewVerdict,
    max_repair_cycles: u32,
) -> ReviewPacketV1 {
    let loaded = controller.execution().load(run_id).unwrap();
    let state = loaded.envelope.engineer_verifier.as_ref().unwrap();
    let bridge = state.workspace_bridge.as_ref().unwrap();
    let replay = state.verifier_replay_plan.as_ref().unwrap();
    let VerifierExecutionStateV1::Admitted {
        transcript,
        transcript_digest,
        bundle,
        bundle_record_digest,
        evidence_current,
        ..
    } = state.verifier.as_ref().unwrap()
    else {
        panic!("Issue 6 must be admitted")
    };
    let reviewer_invocation = a05_invocation(PrincipalV1::Reviewer, run_id);
    let reviewer = reviewer_invocation.target.clone();
    let before_bytes = b"old\n".to_vec();
    let after_bytes = b"new\n".to_vec();
    let mut frozen_diff = FrozenPathDiffV1 {
        contract_version: INDEPENDENT_REVIEW_CONTRACT_VERSION,
        logical_path: "input.txt".to_owned(),
        before_bytes: Some(before_bytes),
        after_bytes,
        before_file: bridge.before_file_identities[0].file.clone(),
        after_file: bridge.after_file_identities[0].file.clone().unwrap(),
        issue6_diff_digest: bridge.canonical_diff_digest.clone(),
        frozen_diff_digest: String::new(),
    };
    frozen_diff.refresh_digest().unwrap();
    let goal = a05_goal();
    let mut packet = ReviewPacketV1 {
        contract_version: INDEPENDENT_REVIEW_CONTRACT_VERSION,
        packet_id: "packet.loop.review".to_owned(),
        root_run_id: run_id.clone(),
        run_id: run_id.clone(),
        goal_id: GoalId::from("goal.loop"),
        task_id: TaskId::from("task.loop"),
        candidate_cycle: 0,
        max_repair_cycles,
        prior_run_id: None,
        prior_repair_directive_digest: None,
        task: loaded
            .envelope
            .tasks
            .get(&TaskId::from("task.loop"))
            .unwrap()
            .clone(),
        goal_contract: goal.clone(),
        completion_evidence: a05_completion(&goal, review_verdict),
        evidence_catalog: a05_catalog(),
        engineer: state.plan.invocation.target.clone(),
        verifier: bundle.verifier_actor.clone(),
        reviewer: reviewer.clone(),
        reviewer_invocation_digest: reviewer_invocation.canonical_digest().unwrap(),
        reviewer_invocation,
        issue6_state_digest: state.state_digest.clone(),
        logical_plan_digest: state.plan.logical_plan_digest.clone(),
        resolved_effect_ledger_digest: state.ledger.resolved_effect_ledger_digest.clone(),
        engineer_result_digest: state.engineer_result_digest.clone().unwrap(),
        verifier_replay_plan_digest: replay.replay_plan_digest.clone(),
        verifier_transcript_digest: transcript_digest.clone(),
        frozen_diff,
        verification_bundle: bundle.clone(),
        verification_bundle_record_digest: bundle_record_digest.clone(),
        evidence_current: EvidenceCurrentAnchorV1 {
            bundle_id: evidence_current.bundle_id.clone(),
            record_digest: evidence_current.record_digest.clone(),
            generation: evidence_current.token.generation,
            state_digest: evidence_current.token.state_digest.clone(),
        },
        verifier_receipts: transcript.commands.clone(),
        evidence_manifest: a05_manifest(
            reviewer,
            "criteria.loop.review",
            IndependentEvidenceActorV1 {
                actor_id: "principal.loop.engineer".to_owned(),
                role: IndependentEvidenceActorRoleV1::Engineer,
            },
            "evidence.loop.a05",
            EvidenceKind::TestResult,
        ),
        packet_digest: String::new(),
    };
    packet.refresh_digest().unwrap();
    packet.validate().unwrap();
    packet
}

fn a05_input(packet: ReviewPacketV1) -> ReviewAuditLoopInput {
    let run_id = packet.run_id.clone();
    let auditor_invocation = a05_invocation(PrincipalV1::Auditor, &run_id);
    let auditor = auditor_invocation.target.clone();
    ReviewAuditLoopInput {
        review_packet: packet,
        auditor_invocation,
        audit_manifest: a05_manifest(
            auditor,
            "criteria.loop.audit",
            IndependentEvidenceActorV1 {
                actor_id: "principal.loop.engineer".to_owned(),
                role: IndependentEvidenceActorRoleV1::Engineer,
            },
            "evidence.loop.a05",
            EvidenceKind::TestResult,
        ),
        coordinator: identity("principal.loop.coordinator", PrincipalV1::Coordinator),
        repair_successor_run_id: None,
    }
}

fn boxed_a05_input(packet: ReviewPacketV1) -> Box<ReviewAuditLoopInput> {
    Box::new(a05_input(packet))
}

fn append_goal_runtime_event(
    runtime: &DurableGoalRuntime,
    goal: &GoalContract,
    producer_role: Role,
    occurred_at: DateTime<Utc>,
    payload: RunEventPayload,
) -> RunEvent {
    let current = runtime.load_run(&RunId::from("run.loop"), goal).unwrap();
    let event = RunEvent {
        contract_version: ContractVersion::current(),
        id: EventId::from(format!("event.legacy.{}", current.run_record.event_count)),
        run_id: RunId::from("run.loop"),
        sequence: current.run_record.event_count,
        previous_event_id: current.run_record.last_event_id,
        occurred_at,
        producer_role,
        payload,
        metadata: BTreeMap::new(),
    };
    runtime.append_event(event.clone(), goal).unwrap();
    event
}

fn canonical_event_bytes(events: &[ovca_types::RunEvent]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for event in events {
        bytes.extend(serde_json::to_vec(event).unwrap());
        bytes.push(b'\n');
    }
    bytes
}

fn append_test_event(
    events: &[ovca_types::RunEvent],
    id: EventId,
    producer_role: Role,
    occurred_at: DateTime<Utc>,
    payload: ovca_types::RunEventPayload,
) -> ovca_types::RunEvent {
    ovca_types::RunEvent {
        contract_version: ContractVersion::current(),
        id,
        run_id: RunId::from("run.loop"),
        sequence: events.len() as u64,
        previous_event_id: events.last().map(|event| event.id.clone()),
        occurred_at,
        producer_role,
        payload,
        metadata: BTreeMap::new(),
    }
}

fn assert_projection_retry_conflicts_without_log_mutation(
    controller: &ReviewAuditLoop,
    executor: &A05Executor,
    input: &ReviewAuditLoopInput,
) {
    let before = fs::read(controller.log().path()).unwrap_or_default();
    assert!(matches!(
        controller.drive(executor, input),
        Err(ovca_langgraph::review_audit_loop::ReviewAuditLoopError::ProjectionConflict)
    ));
    assert_eq!(
        fs::read(controller.log().path()).unwrap_or_default(),
        before
    );
    assert!(executor.calls().is_empty());
}

fn bind_expected_repair_successor(
    controller: &ReviewAuditLoop,
    input: &mut ReviewAuditLoopInput,
) -> RunId {
    let loaded = controller
        .execution()
        .load(&input.review_packet.run_id)
        .unwrap();
    let state = loaded.envelope.independent_review.as_ref().unwrap();
    let review_result = ovca_runtime_core::completed_result(&state.review_call).unwrap();
    let audit_result =
        ovca_runtime_core::completed_result(state.audit_call.as_ref().unwrap()).unwrap();
    let successor = derive_repair_successor_run_id(
        &state.review_packet.root_run_id,
        state.review_packet.candidate_cycle + 1,
        &review_result.canonical_digest().unwrap(),
        &audit_result.canonical_digest().unwrap(),
    )
    .unwrap();
    input.repair_successor_run_id = Some(successor.clone());
    successor
}

fn issue6_projection_digest(controller: &EngineerVerifierLoop) -> String {
    let loaded = controller
        .execution()
        .load(&RunId::from("run.loop"))
        .unwrap();
    verification_sha256_hex(
        &serde_json::to_vec(loaded.envelope.engineer_verifier.as_ref().unwrap()).unwrap(),
    )
}

fn assert_issue6_projection_digest(controller: &ReviewAuditLoop, expected: &str) {
    let loaded = controller
        .execution()
        .load(&RunId::from("run.loop"))
        .unwrap();
    assert_eq!(
        verification_sha256_hex(
            &serde_json::to_vec(loaded.envelope.engineer_verifier.as_ref().unwrap()).unwrap(),
        ),
        expected
    );
    assert_eq!(
        loaded.envelope.contract_version,
        ovca_runtime_core::EXECUTION_ENVELOPE_V2
    );
    assert_eq!(
        loaded.envelope.independent_review.as_ref().unwrap().phase,
        IndependentReviewPhaseV1::ResolvedPass
    );
}

struct A05Executor {
    review_verdict: ReviewVerdict,
    audit_verdict: ReviewVerdict,
    calls: Mutex<Vec<PrincipalV1>>,
    fail_review_call: AtomicBool,
}

impl A05Executor {
    fn new(review_verdict: ReviewVerdict, audit_verdict: ReviewVerdict) -> Self {
        Self {
            review_verdict,
            audit_verdict,
            calls: Mutex::new(Vec::new()),
            fail_review_call: AtomicBool::new(false),
        }
    }

    fn failing_review(review_verdict: ReviewVerdict, audit_verdict: ReviewVerdict) -> Self {
        Self {
            review_verdict,
            audit_verdict,
            calls: Mutex::new(Vec::new()),
            fail_review_call: AtomicBool::new(true),
        }
    }

    fn calls(&self) -> Vec<PrincipalV1> {
        self.calls.lock().unwrap().clone()
    }
}

impl IndependentReviewExecutor for A05Executor {
    fn invoke(
        &self,
        request: IndependentRoleExecutionRequest,
    ) -> Result<RoleExecutionOutcome, RoleExecutorError> {
        request.validate().unwrap();
        let role = request.role_request.invocation.target.role;
        self.calls.lock().unwrap().push(role);
        if role == PrincipalV1::Reviewer && self.fail_review_call.swap(false, Ordering::SeqCst) {
            return Err(RoleExecutorError::MissingScript);
        }
        let (payload, result_id, occurred_at) = match request.packet {
            ovca_runtime_core::IndependentRolePacketV1::Review(packet) => {
                let decision = ReviewDecision {
                    contract_version: ContractVersion::current(),
                    id: ReviewDecisionId::from("review.loop.a05"),
                    run_id: packet.run_id,
                    goal_id: packet.goal_id,
                    producer_role: Role::Reviewer,
                    verdict: self.review_verdict,
                    assessments: a05_assessments(&packet.goal_contract, self.review_verdict),
                    summary: "reviewed the exact frozen candidate".to_owned(),
                    decided_at: at(11),
                };
                (
                    RoleResultPayloadV1::Reviewer {
                        packet_digest: packet.packet_digest,
                        decision,
                    },
                    "result.loop.a05.review",
                    at(11),
                )
            }
            ovca_runtime_core::IndependentRolePacketV1::Audit(packet) => {
                let decision = AuditDecision {
                    contract_version: ContractVersion::current(),
                    id: AuditDecisionId::from("audit.loop.a05"),
                    run_id: packet.review_packet.run_id.clone(),
                    goal_id: packet.review_packet.goal_id.clone(),
                    review_decision_id: packet.review_decision.id.clone(),
                    producer_role: Role::Auditor,
                    verdict: self.audit_verdict,
                    assessments: a05_assessments(
                        &packet.review_packet.goal_contract,
                        self.audit_verdict,
                    ),
                    summary: "audited the exact review and evidence".to_owned(),
                    decided_at: at(12),
                };
                (
                    RoleResultPayloadV1::Auditor {
                        packet_digest: packet.packet_digest,
                        decision,
                    },
                    "result.loop.a05.audit",
                    at(12),
                )
            }
        };
        let invocation = request.role_request.invocation;
        Ok(RoleExecutionOutcome::Completed {
            result: RoleResultV1 {
                contract_version: 1,
                result_id: result_id.to_owned(),
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
                evidence_ids: vec![EvidenceId::from(format!("evidence.{result_id}"))],
                occurred_at,
            },
            usage: RoleExecutionUsage::Unavailable,
        })
    }
}

#[test]
fn independent_pass_projects_once_and_preserves_issue6_and_caller_state() {
    with_a05_ready(|fixture, issue6, clock| {
        let issue6_before = issue6_projection_digest(issue6);
        let evidence_before = issue6
            .evidence()
            .load_current(&ovca_storage::EvidenceKey {
                run_id: RunId::from("run.loop"),
                goal_id: GoalId::from("goal.loop"),
                task_id: TaskId::from("task.loop"),
            })
            .unwrap()
            .unwrap();
        let events_before = issue6.log().load_run(&fixture.plan.run_id).unwrap().len();
        let input = boxed_a05_input(a05_review_packet(
            issue6,
            &fixture.plan.run_id,
            ReviewVerdict::Pass,
            2,
        ));
        let controller = ReviewAuditLoop::try_new(fixture.durable.path(), Box::new(clock)).unwrap();
        let executor = A05Executor::new(ReviewVerdict::Pass, ReviewVerdict::Pass);

        assert!(matches!(
            controller.drive(&executor, &input).unwrap(),
            ReviewAuditLoopOutcome::ResolvedPass { .. }
        ));
        assert_eq!(
            executor.calls(),
            vec![PrincipalV1::Reviewer, PrincipalV1::Auditor]
        );
        assert_issue6_projection_digest(&controller, &issue6_before);
        assert_eq!(
            controller
                .evidence()
                .load_current(&ovca_storage::EvidenceKey {
                    run_id: RunId::from("run.loop"),
                    goal_id: GoalId::from("goal.loop"),
                    task_id: TaskId::from("task.loop"),
                })
                .unwrap()
                .unwrap(),
            evidence_before
        );
        assert_eq!(
            controller
                .log()
                .load_run(&fixture.plan.run_id)
                .unwrap()
                .len(),
            events_before + 2
        );
        assert!(fs::read_dir(fixture.workspaces.path())
            .unwrap()
            .next()
            .is_none());

        assert!(matches!(
            controller.drive(&executor, &input).unwrap(),
            ReviewAuditLoopOutcome::ResolvedPass { .. }
        ));
        assert_eq!(executor.calls().len(), 2);
        assert_eq!(
            controller
                .log()
                .load_run(&fixture.plan.run_id)
                .unwrap()
                .len(),
            events_before + 2
        );
    });
}

#[test]
fn missing_issue6_execution_authority_blocks_every_completion_route_without_mutation() {
    let fixture = Fixture::new();
    let goal = a05_goal();
    let mut completion_behavior = fixture.behavior.clone();
    completion_behavior.contract_id = "behavior.loop.completion".to_owned();
    completion_behavior.binding = BehaviorBinding::Bound {
        goal_id: goal.id.clone(),
        task_id: TaskId::from("task.loop"),
    };
    completion_behavior.criteria[0].text = goal.verification_criteria[0].clone();
    let completion = LocalVerificationCompletionContract {
        goal: goal.clone(),
        task_ids: vec![TaskId::from("task.loop")],
        tasks: vec![LocalVerificationCompletionTask {
            behavior: completion_behavior,
            selection: fixture.selection.clone(),
            capabilities: vec![fixture.capability.clone()],
        }],
    };
    let runtime = DurableGoalRuntime::try_new_with_completion_policy(
        fixture.durable.path(),
        LocalVerificationCompletionPolicy::Enforced {
            goals: BTreeMap::from([(
                goal.id.clone(),
                EnforcedLocalVerificationGoal {
                    completion,
                    source_manifest: fixture.manifest.clone(),
                    source_root: fixture.protected.path().to_path_buf(),
                    environment_bindings: fixture.bindings.clone(),
                },
            )]),
        },
    )
    .unwrap();
    let mut planned_task = task();
    planned_task.status = TaskStatus::Pending;
    runtime
        .create_run(
            RunId::from("run.loop"),
            &goal,
            &[planned_task],
            PlannedRunStamps {
                run_created: EventStamp {
                    id: EventId::from("event.legacy.created"),
                    occurred_at: at(0),
                },
                accepted: EventStamp {
                    id: EventId::from("event.legacy.accepted"),
                    occurred_at: at(1),
                },
                plan_recorded: EventStamp {
                    id: EventId::from("event.legacy.plan"),
                    occurred_at: at(2),
                },
                planned: EventStamp {
                    id: EventId::from("event.legacy.planned"),
                    occurred_at: at(3),
                },
            },
        )
        .unwrap();

    let clock = MutableClock::new(at(10));
    let issue6 = fixture.loop_with_clock(clock.clone());
    fixture.initialize(&issue6);
    fixture.publish_capability();
    let mut broker = fixture.broker("runtime.loop.a05.legacy", clock);
    assert!(matches!(
        issue6
            .drive(
                &mut broker,
                &completed_executor(&fixture.plan.run_id, &[1]),
                fixture.input(
                    b"old\n",
                    "lease.loop.a05.legacy",
                    "workspace.loop.a05.legacy",
                    "recovery.loop.a05.legacy",
                    "grant.loop.a05.legacy",
                    &fixture.environment_digest,
                ),
            )
            .unwrap(),
        EngineerVerifierLoopOutcome::Reviewing { .. }
    ));
    drop(broker);

    append_goal_runtime_event(
        &runtime,
        &goal,
        Role::Coordinator,
        at(13),
        RunEventPayload::StatusTransition {
            from: RunStatus::Planned,
            to: RunStatus::Running,
        },
    );
    let evidence = a05_catalog().remove(0);
    append_goal_runtime_event(
        &runtime,
        &goal,
        Role::Engineer,
        at(14),
        RunEventPayload::EvidenceReferenceRecorded {
            evidence: evidence.clone(),
        },
    );
    append_goal_runtime_event(
        &runtime,
        &goal,
        Role::Engineer,
        at(15),
        RunEventPayload::CompletionEvidenceRecorded {
            evidence: a05_completion(&goal, ReviewVerdict::Pass),
        },
    );
    append_goal_runtime_event(
        &runtime,
        &goal,
        Role::Coordinator,
        at(16),
        RunEventPayload::ReviewAuditRequirementsRecorded {
            requirements: ReviewAuditRequirements {
                contract_version: ContractVersion::current(),
                guard_requirements: BTreeSet::from([
                    GuardRequirement::Reviewer,
                    GuardRequirement::Auditor,
                ]),
            },
        },
    );
    append_goal_runtime_event(
        &runtime,
        &goal,
        Role::Coordinator,
        at(17),
        RunEventPayload::StatusTransition {
            from: RunStatus::Running,
            to: RunStatus::Reviewing,
        },
    );
    let review = ReviewDecision {
        contract_version: ContractVersion::current(),
        id: ReviewDecisionId::from("review.legacy"),
        run_id: RunId::from("run.loop"),
        goal_id: goal.id.clone(),
        producer_role: Role::Reviewer,
        verdict: ReviewVerdict::Pass,
        assessments: a05_assessments(&goal, ReviewVerdict::Pass),
        summary: "legacy role-only review".to_owned(),
        decided_at: at(18),
    };
    append_goal_runtime_event(
        &runtime,
        &goal,
        Role::Reviewer,
        at(18),
        RunEventPayload::ReviewDecisionRecorded {
            decision: review.clone(),
        },
    );
    append_goal_runtime_event(
        &runtime,
        &goal,
        Role::Coordinator,
        at(19),
        RunEventPayload::StatusTransition {
            from: RunStatus::Reviewing,
            to: RunStatus::Auditing,
        },
    );
    append_goal_runtime_event(
        &runtime,
        &goal,
        Role::Auditor,
        at(20),
        RunEventPayload::AuditDecisionRecorded {
            decision: AuditDecision {
                contract_version: ContractVersion::current(),
                id: AuditDecisionId::from("audit.legacy"),
                run_id: RunId::from("run.loop"),
                goal_id: goal.id.clone(),
                review_decision_id: review.id,
                producer_role: Role::Auditor,
                verdict: ReviewVerdict::Pass,
                assessments: a05_assessments(&goal, ReviewVerdict::Pass),
                summary: "legacy role-only audit".to_owned(),
                decided_at: at(20),
            },
        },
    );
    let current = runtime.load_run(&RunId::from("run.loop"), &goal).unwrap();
    let legacy_completion = RunEvent {
        contract_version: ContractVersion::current(),
        id: EventId::from("event.legacy.completed"),
        run_id: RunId::from("run.loop"),
        sequence: current.run_record.event_count,
        previous_event_id: current.run_record.last_event_id,
        occurred_at: at(21),
        producer_role: Role::Coordinator,
        payload: RunEventPayload::StatusTransition {
            from: RunStatus::Auditing,
            to: RunStatus::Completed,
        },
        metadata: BTreeMap::new(),
    };
    assert!(runtime
        .execution_authority()
        .load(&RunId::from("run.loop"))
        .unwrap()
        .envelope
        .independent_review
        .is_none());
    let execution_database = runtime.execution_database_path();
    fs::remove_file(&execution_database).unwrap();
    assert!(!execution_database.exists());

    let generic_runtime = DurableGoalRuntime::new(fixture.durable.path());
    let assert_completion_routes_reject = || {
        let before = fs::read(runtime.log_path()).unwrap();
        assert!(matches!(
            generic_runtime.append_event(legacy_completion.clone(), &goal),
            Err(ovca_langgraph::DurableGoalRuntimeError::IndependentReviewCompletionInvalid { .. })
        ));
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);

        assert!(matches!(
            runtime.append_verified_completion(legacy_completion.clone(), &goal),
            Err(ovca_langgraph::DurableGoalRuntimeError::IndependentReviewCompletionInvalid { .. })
        ));
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);

        assert!(matches!(
            runtime.reconcile_verified_completion_append(&legacy_completion, &goal),
            Err(ovca_langgraph::DurableGoalRuntimeError::IndependentReviewCompletionInvalid { .. })
        ));
        assert_eq!(fs::read(runtime.log_path()).unwrap(), before);
    };
    assert_completion_routes_reject();
    assert!(!execution_database.exists());

    let unrelated_run_id = RunId::from("run.unrelated");
    let unrelated = runtime
        .execution_authority()
        .initialize_run(
            unrelated_run_id.clone(),
            vec![task()],
            RetryBudget {
                contract_version: ContractVersion::current(),
                max_attempts: 1,
            },
        )
        .unwrap()
        .state;
    assert!(execution_database.exists());
    assert_completion_routes_reject();
    assert_eq!(
        runtime
            .execution_authority()
            .load(&unrelated_run_id)
            .unwrap(),
        unrelated
    );

    issue6.log().append(&legacy_completion).unwrap();
    assert_eq!(
        runtime
            .load_run(&RunId::from("run.loop"), &goal)
            .unwrap()
            .run_record
            .status,
        RunStatus::Completed
    );
    let committed = fs::read(runtime.log_path()).unwrap();
    assert!(matches!(
        runtime.reconcile_verified_completion_append(&legacy_completion, &goal),
        Err(ovca_langgraph::DurableGoalRuntimeError::IndependentReviewCompletionInvalid { .. })
    ));
    assert_eq!(fs::read(runtime.log_path()).unwrap(), committed);
    assert!(execution_database.exists());
    assert_eq!(
        runtime
            .execution_authority()
            .load(&unrelated_run_id)
            .unwrap(),
        unrelated
    );
}

fn run_a05_resolution_case(
    review: ReviewVerdict,
    audit: ReviewVerdict,
    expected_reason: Option<OwnerEscalationReasonV1>,
) {
    with_a05_ready(|fixture, issue6, clock| {
        let controller = ReviewAuditLoop::try_new(fixture.durable.path(), Box::new(clock)).unwrap();
        let executor = A05Executor::new(review, audit);
        let mut input = boxed_a05_input(a05_review_packet(issue6, &fixture.plan.run_id, review, 2));
        let outcome = if review == ReviewVerdict::Fail && audit == ReviewVerdict::Fail {
            assert!(matches!(
                controller.drive(&executor, &input),
                Err(ovca_langgraph::review_audit_loop::ReviewAuditLoopError::InvalidInput)
            ));
            bind_expected_repair_successor(&controller, &mut input);
            controller.drive(&executor, &input).unwrap()
        } else {
            controller.drive(&executor, &input).unwrap()
        };
        match expected_reason {
            None => {
                let ReviewAuditLoopOutcome::RepairDirected { directive, .. } = outcome else {
                    panic!("dual fail must emit one repair directive")
                };
                assert_eq!(directive.failed_candidate_cycle, 0);
                assert_eq!(directive.successor_candidate_cycle, 1);
                assert!(!directive.grants_authority);
                assert_eq!(directive.repair_paths, vec!["input.txt"]);
                assert_eq!(
                    input.repair_successor_run_id.as_ref(),
                    Some(&directive.successor_run_id)
                );
                assert!(matches!(
                    controller.drive(&executor, &input).unwrap(),
                    ReviewAuditLoopOutcome::RepairDirected { .. }
                ));
                let mut alternate = (*input).clone();
                alternate.repair_successor_run_id = Some(RunId::from("run.alternate"));
                assert!(matches!(
                    controller.drive(&executor, &alternate),
                    Err(
                        ovca_langgraph::review_audit_loop::ReviewAuditLoopError::ProjectionConflict
                    )
                ));
            }
            Some(reason) => assert!(matches!(
                outcome,
                ReviewAuditLoopOutcome::OwnerEscalated { reason: actual, .. } if actual == reason
            )),
        }
        assert_eq!(
            executor.calls(),
            vec![PrincipalV1::Reviewer, PrincipalV1::Auditor]
        );
        assert_eq!(
            controller
                .log()
                .load_run(&fixture.plan.run_id)
                .unwrap()
                .len(),
            3
        );
    });
}

#[test]
fn independent_dual_fail_and_both_disagreement_directions_resolve_exactly() {
    for (review, audit, expected_reason) in [
        (ReviewVerdict::Fail, ReviewVerdict::Fail, None),
        (
            ReviewVerdict::Pass,
            ReviewVerdict::Fail,
            Some(OwnerEscalationReasonV1::VerdictDisagreement),
        ),
        (
            ReviewVerdict::Fail,
            ReviewVerdict::Pass,
            Some(OwnerEscalationReasonV1::VerdictDisagreement),
        ),
    ] {
        run_a05_resolution_case(review, audit, expected_reason);
    }
}

#[test]
fn crashed_started_review_is_not_reinvoked_and_escalates() {
    with_a05_ready(|fixture, issue6, clock| {
        let controller = ReviewAuditLoop::try_new(fixture.durable.path(), Box::new(clock)).unwrap();
        let input = boxed_a05_input(a05_review_packet(
            issue6,
            &fixture.plan.run_id,
            ReviewVerdict::Pass,
            2,
        ));
        let crashing = A05Executor::failing_review(ReviewVerdict::Pass, ReviewVerdict::Pass);
        assert!(controller.drive(&crashing, &input).is_err());
        assert_eq!(crashing.calls(), vec![PrincipalV1::Reviewer]);

        let recovered = A05Executor::new(ReviewVerdict::Pass, ReviewVerdict::Pass);
        let mut conflicting = (*input).clone();
        conflicting
            .review_packet
            .goal_contract
            .objective
            .push_str(" changed bytes");
        conflicting.review_packet.refresh_digest().unwrap();
        assert!(matches!(
            controller.drive(&recovered, &conflicting),
            Err(ovca_langgraph::review_audit_loop::ReviewAuditLoopError::ProjectionConflict)
        ));
        assert!(recovered.calls().is_empty());
        assert!(matches!(
            controller.drive(&recovered, &input).unwrap(),
            ReviewAuditLoopOutcome::OwnerEscalated {
                reason: OwnerEscalationReasonV1::ReviewerOutcomeUnknown,
                ..
            }
        ));
        assert!(recovered.calls().is_empty());
    });
}

#[test]
fn crash_after_review_outcome_resumes_with_auditor_only() {
    with_a05_ready(|fixture, issue6, _clock| {
        let input = boxed_a05_input(a05_review_packet(
            issue6,
            &fixture.plan.run_id,
            ReviewVerdict::Pass,
            2,
        ));
        let crashing = ReviewAuditLoop::try_new(
            fixture.durable.path(),
            Box::new(PanicAfterReviewOutcomeClock(AtomicUsize::new(0))),
        )
        .unwrap();
        let first_executor = A05Executor::new(ReviewVerdict::Pass, ReviewVerdict::Pass);
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _ = crashing.drive(&first_executor, &input);
        }))
        .is_err());
        assert_eq!(first_executor.calls(), vec![PrincipalV1::Reviewer]);
        let loaded = crashing.execution().load(&fixture.plan.run_id).unwrap();
        let state = loaded.envelope.independent_review.as_ref().unwrap();
        assert_eq!(state.phase, IndependentReviewPhaseV1::Reviewing);
        assert!(matches!(
            state.review_call,
            ovca_runtime_core::IndependentCallStateV1::OutcomeRecorded { .. }
        ));
        drop(loaded);

        let recovered =
            ReviewAuditLoop::try_new(fixture.durable.path(), Box::new(MutableClock::new(at(14))))
                .unwrap();
        let recovered_executor = A05Executor::new(ReviewVerdict::Pass, ReviewVerdict::Pass);
        assert!(matches!(
            recovered.drive(&recovered_executor, &input).unwrap(),
            ReviewAuditLoopOutcome::ResolvedPass { .. }
        ));
        assert_eq!(recovered_executor.calls(), vec![PrincipalV1::Auditor]);
    });
}

#[test]
fn malformed_goal_and_unused_catalog_are_rejected_before_reviewer_invocation() {
    with_a05_ready(|fixture, issue6, clock| {
        let controller = ReviewAuditLoop::try_new(fixture.durable.path(), Box::new(clock)).unwrap();

        let mut malformed_goal =
            a05_review_packet(issue6, &fixture.plan.run_id, ReviewVerdict::Pass, 2);
        malformed_goal
            .goal_contract
            .permission_profile
            .resource_keys
            .push(" ".to_owned());
        malformed_goal.refresh_digest().unwrap();
        malformed_goal.validate().unwrap();
        let goal_executor = A05Executor::new(ReviewVerdict::Pass, ReviewVerdict::Pass);
        assert!(matches!(
            controller.drive(&goal_executor, &a05_input(malformed_goal)),
            Err(ovca_langgraph::review_audit_loop::ReviewAuditLoopError::InvalidInput)
        ));
        assert!(goal_executor.calls().is_empty());

        let mut malformed_catalog =
            a05_review_packet(issue6, &fixture.plan.run_id, ReviewVerdict::Pass, 2);
        malformed_catalog.evidence_catalog.push(EvidenceRef {
            contract_version: ContractVersion::current(),
            id: EvidenceId::from("evidence.z.unused"),
            kind: EvidenceKind::TestResult,
            reference: "evidence-bank://unused".to_owned(),
            producer_role: Role::Engineer,
            integrity: Some(IntegrityMetadata {
                contract_version: ContractVersion::current(),
                algorithm: " ".to_owned(),
                digest: " ".to_owned(),
            }),
            produced_at: at(10),
        });
        malformed_catalog.refresh_digest().unwrap();
        malformed_catalog.validate().unwrap();
        let catalog_executor = A05Executor::new(ReviewVerdict::Pass, ReviewVerdict::Pass);
        assert!(matches!(
            controller.drive(&catalog_executor, &a05_input(malformed_catalog)),
            Err(ovca_langgraph::review_audit_loop::ReviewAuditLoopError::InvalidInput)
        ));
        assert!(catalog_executor.calls().is_empty());
        assert!(controller
            .execution()
            .load(&fixture.plan.run_id)
            .unwrap()
            .envelope
            .independent_review
            .is_none());
    });
}

#[test]
fn stale_current_evidence_escalates_before_reviewer_invocation() {
    with_a05_ready(|fixture, issue6, clock| {
        let controller = ReviewAuditLoop::try_new(fixture.durable.path(), Box::new(clock)).unwrap();
        let input = a05_input(a05_review_packet(
            issue6,
            &fixture.plan.run_id,
            ReviewVerdict::Pass,
            2,
        ));
        let key = ovca_storage::EvidenceKey {
            run_id: fixture.plan.run_id.clone(),
            goal_id: GoalId::from("goal.loop"),
            task_id: TaskId::from("task.loop"),
        };
        let current = controller.evidence().load_current(&key).unwrap().unwrap();
        assert!(matches!(
            controller
                .evidence()
                .mark_stale(
                    &key,
                    &current.token,
                    BTreeSet::from([ovca_storage::StaleCause::Source]),
                )
                .unwrap(),
            ovca_storage::CasOutcome::Applied(_)
        ));
        let executor = A05Executor::new(ReviewVerdict::Pass, ReviewVerdict::Pass);
        assert!(matches!(
            controller.drive(&executor, &input).unwrap(),
            ReviewAuditLoopOutcome::OwnerEscalated {
                reason: OwnerEscalationReasonV1::EvidenceInvalid,
                ..
            }
        ));
        assert!(executor.calls().is_empty());
    });
}

#[test]
fn public_a05_install_rejects_forged_issue6_candidate_anchors() {
    with_a05_ready(|fixture, issue6, clock| {
        let controller = ReviewAuditLoop::try_new(fixture.durable.path(), Box::new(clock)).unwrap();
        let loaded = controller.execution().load(&fixture.plan.run_id).unwrap();

        let mut forged_identity =
            a05_review_packet(issue6, &fixture.plan.run_id, ReviewVerdict::Pass, 2);
        forged_identity.frozen_diff.before_bytes = Some(b"forged\n".to_vec());
        forged_identity.frozen_diff.before_file =
            Some(ovca_types::tool_boundary::WorkspaceFileV1 {
                logical_path: "input.txt".to_owned(),
                sha256: verification_sha256_hex(b"forged\n"),
                byte_length: 7,
            });
        forged_identity.frozen_diff.refresh_digest().unwrap();
        forged_identity.refresh_digest().unwrap();
        forged_identity.validate().unwrap();
        let forged_state = IndependentReviewStateV1::initial(forged_identity, at(10)).unwrap();
        assert!(matches!(
            controller.execution().compare_and_swap_independent_review(
                &fixture.plan.run_id,
                loaded.revision,
                None,
                forged_state,
            ),
            Err(DurableExecutionError::IndependentReview(
                IndependentReviewError::InvalidState
            ))
        ));

        let mut forged_receipt =
            a05_review_packet(issue6, &fixture.plan.run_id, ReviewVerdict::Pass, 2);
        forged_receipt.verifier_receipts[0].stdout_sha256 = "7".repeat(64);
        forged_receipt.refresh_digest().unwrap();
        forged_receipt.validate().unwrap();
        let forged_state = IndependentReviewStateV1::initial(forged_receipt, at(10)).unwrap();
        assert!(matches!(
            controller.execution().compare_and_swap_independent_review(
                &fixture.plan.run_id,
                loaded.revision,
                None,
                forged_state,
            ),
            Err(DurableExecutionError::IndependentReview(
                IndependentReviewError::InvalidState
            ))
        ));
        assert!(controller
            .execution()
            .load(&fixture.plan.run_id)
            .unwrap()
            .envelope
            .independent_review
            .is_none());
    });
}

#[test]
fn terminal_projection_rejects_corrupt_or_hijacked_suffixes_and_serializes_retries() {
    with_a05_ready(|fixture, issue6, clock| {
        let controller =
            ReviewAuditLoop::try_new(fixture.durable.path(), Box::new(clock.clone())).unwrap();
        let input = a05_input(a05_review_packet(
            issue6,
            &fixture.plan.run_id,
            ReviewVerdict::Pass,
            2,
        ));
        let base_events = controller.log().load_run(&fixture.plan.run_id).unwrap();
        let base_bytes = canonical_event_bytes(&base_events);

        let blocker = append_test_event(
            &base_events,
            EventId::from("event.a05.blocker"),
            Role::Coordinator,
            at(10),
            ovca_types::RunEventPayload::NoteRecorded {
                message: "block projection without changing the Issue 6 prefix".to_owned(),
            },
        );
        controller.log().append(&blocker).unwrap();
        let first_executor = A05Executor::new(ReviewVerdict::Pass, ReviewVerdict::Pass);
        assert!(matches!(
            controller.drive(&first_executor, &input),
            Err(ovca_langgraph::review_audit_loop::ReviewAuditLoopError::ProjectionConflict)
        ));
        assert_eq!(
            first_executor.calls(),
            vec![PrincipalV1::Reviewer, PrincipalV1::Auditor]
        );
        let loaded = controller.execution().load(&fixture.plan.run_id).unwrap();
        let state = loaded.envelope.independent_review.as_ref().unwrap();
        assert_eq!(state.phase, IndependentReviewPhaseV1::ResolvedPass);
        let ovca_runtime_core::IndependentReviewResolutionV1::Pass {
            review_result_digest,
            audit_result_digest,
        } = state.resolution.as_ref().unwrap()
        else {
            unreachable!()
        };
        let review_event_id = EventId::from(format!("a05.review.{review_result_digest}"));
        let audit_event_id = EventId::from(format!("a05.audit.{audit_result_digest}"));
        let review_result = ovca_runtime_core::completed_result(&state.review_call).unwrap();
        let audit_result =
            ovca_runtime_core::completed_result(state.audit_call.as_ref().unwrap()).unwrap();
        let RoleResultPayloadV1::Reviewer {
            decision: review_decision,
            ..
        } = &review_result.payload
        else {
            unreachable!()
        };
        let RoleResultPayloadV1::Auditor {
            decision: audit_decision,
            ..
        } = &audit_result.payload
        else {
            unreachable!()
        };
        let review_decision = review_decision.clone();
        let audit_decision = audit_decision.clone();
        drop(loaded);

        let retry_executor = A05Executor::new(ReviewVerdict::Pass, ReviewVerdict::Pass);

        fs::write(controller.log().path(), []).unwrap();
        assert_projection_retry_conflicts_without_log_mutation(
            &controller,
            &retry_executor,
            &input,
        );

        let unanchored = append_test_event(
            &[],
            EventId::from("event.a05.unanchored"),
            Role::Coordinator,
            at(10),
            ovca_types::RunEventPayload::NoteRecorded {
                message: "not an Issue 6 origin".to_owned(),
            },
        );
        fs::write(
            controller.log().path(),
            canonical_event_bytes(&[unanchored]),
        )
        .unwrap();
        assert_projection_retry_conflicts_without_log_mutation(
            &controller,
            &retry_executor,
            &input,
        );

        fs::write(
            controller.log().path(),
            canonical_event_bytes(&base_events[..base_events.len() - 1]),
        )
        .unwrap();
        assert_projection_retry_conflicts_without_log_mutation(
            &controller,
            &retry_executor,
            &input,
        );

        let mut noncanonical = base_bytes.clone();
        let newline = noncanonical.iter().position(|byte| *byte == b'\n').unwrap();
        noncanonical.insert(newline, b' ');
        fs::write(controller.log().path(), noncanonical).unwrap();
        assert_projection_retry_conflicts_without_log_mutation(
            &controller,
            &retry_executor,
            &input,
        );

        let hijacked_review = append_test_event(
            &base_events,
            review_event_id.clone(),
            Role::Coordinator,
            at(11),
            ovca_types::RunEventPayload::NoteRecorded {
                message: "reserved review id hijack".to_owned(),
            },
        );
        let mut hijacked = base_events.clone();
        hijacked.push(hijacked_review);
        fs::write(controller.log().path(), canonical_event_bytes(&hijacked)).unwrap();
        assert_projection_retry_conflicts_without_log_mutation(
            &controller,
            &retry_executor,
            &input,
        );

        let hijacked_audit = append_test_event(
            &hijacked,
            audit_event_id.clone(),
            Role::Coordinator,
            at(12),
            ovca_types::RunEventPayload::NoteRecorded {
                message: "reserved audit id hijack".to_owned(),
            },
        );
        hijacked.push(hijacked_audit);
        fs::write(controller.log().path(), canonical_event_bytes(&hijacked)).unwrap();
        assert_projection_retry_conflicts_without_log_mutation(
            &controller,
            &retry_executor,
            &input,
        );

        let altered_envelope = append_test_event(
            &base_events,
            review_event_id.clone(),
            Role::Coordinator,
            review_decision.decided_at,
            ovca_types::RunEventPayload::ReviewDecisionRecorded {
                decision: review_decision.clone(),
            },
        );
        let mut altered = base_events.clone();
        altered.push(altered_envelope);
        fs::write(controller.log().path(), canonical_event_bytes(&altered)).unwrap();
        assert_projection_retry_conflicts_without_log_mutation(
            &controller,
            &retry_executor,
            &input,
        );

        fs::write(controller.log().path(), &base_bytes).unwrap();
        let root = fixture.durable.path().to_path_buf();
        let input = Arc::new(input);
        let executor = Arc::new(A05Executor::new(ReviewVerdict::Pass, ReviewVerdict::Pass));
        let barrier = Arc::new(Barrier::new(2));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let root = root.clone();
            let input = Arc::clone(&input);
            let executor = Arc::clone(&executor);
            let barrier = Arc::clone(&barrier);
            let clock = clock.clone();
            threads.push(std::thread::spawn(move || {
                let controller = ReviewAuditLoop::try_new(root, Box::new(clock)).unwrap();
                barrier.wait();
                controller.drive(executor.as_ref(), input.as_ref()).unwrap()
            }));
        }
        for thread in threads {
            assert!(matches!(
                thread.join().unwrap(),
                ReviewAuditLoopOutcome::ResolvedPass { .. }
            ));
        }
        assert!(executor.calls().is_empty());
        let projected = controller.log().load_run(&fixture.plan.run_id).unwrap();
        assert_eq!(projected.len(), base_events.len() + 2);
        assert_eq!(projected[base_events.len()].id, review_event_id);
        assert_eq!(projected[base_events.len() + 1].id, audit_event_id);
        assert_eq!(
            projected[base_events.len()].payload,
            ovca_types::RunEventPayload::ReviewDecisionRecorded {
                decision: review_decision
            }
        );
        assert_eq!(
            projected[base_events.len() + 1].payload,
            ovca_types::RunEventPayload::AuditDecisionRecorded {
                decision: audit_decision
            }
        );
        assert!(matches!(
            controller.drive(executor.as_ref(), input.as_ref()).unwrap(),
            ReviewAuditLoopOutcome::ResolvedPass { .. }
        ));
        assert!(executor.calls().is_empty());
        assert_eq!(
            controller
                .log()
                .load_run(&fixture.plan.run_id)
                .unwrap()
                .len(),
            base_events.len() + 2
        );
    });
}

#[test]
fn repair_successor_is_one_fresh_chained_candidate_and_max_cycle_escalates() {
    with_a05_ready(|fixture, issue6, clock| {
        let controller =
            ReviewAuditLoop::try_new(fixture.durable.path(), Box::new(clock.clone())).unwrap();
        let mut root_input = a05_input(a05_review_packet(
            issue6,
            &fixture.plan.run_id,
            ReviewVerdict::Fail,
            1,
        ));
        let root_executor = A05Executor::new(ReviewVerdict::Fail, ReviewVerdict::Fail);
        assert!(matches!(
            controller.drive(&root_executor, &root_input),
            Err(ovca_langgraph::review_audit_loop::ReviewAuditLoopError::InvalidInput)
        ));
        let successor_run_id = bind_expected_repair_successor(&controller, &mut root_input);
        let ReviewAuditLoopOutcome::RepairDirected { directive, .. } =
            controller.drive(&root_executor, &root_input).unwrap()
        else {
            panic!("dual fail below budget must issue the bound directive")
        };
        assert_eq!(directive.successor_run_id, successor_run_id);

        let child_plan = plan(&successor_run_id);
        issue6
            .execution()
            .initialize_run(
                successor_run_id.clone(),
                vec![task()],
                RetryBudget {
                    contract_version: ContractVersion::current(),
                    max_attempts: 2,
                },
            )
            .unwrap();
        let child_selection = selection(
            &fixture.capability,
            fixture.manifest.fingerprint().unwrap(),
            verification_policy_digest(std::slice::from_ref(&fixture.capability)).unwrap(),
            &successor_run_id,
        );
        let mut child_input = fixture.input(
            b"old\n",
            "lease.loop.a05.child",
            "workspace.loop.a05.child",
            "recovery.loop.a05.child",
            "grant.loop.a05.child",
            &fixture.environment_digest,
        );
        child_input.plan = child_plan;
        child_input.workspace.grant_authority = grant_authority(&successor_run_id);
        child_input.verifier.selection = &child_selection;
        let mut broker = fixture.broker("runtime.loop.a05.child", clock.clone());
        assert!(matches!(
            issue6
                .drive(
                    &mut broker,
                    &completed_executor(&successor_run_id, &[1]),
                    child_input,
                )
                .unwrap(),
            EngineerVerifierLoopOutcome::Reviewing { .. }
        ));
        assert_eq!(broker.active_root_count(), 0);
        drop(broker);

        let mut child_packet = a05_review_packet(
            issue6,
            &successor_run_id,
            ReviewVerdict::Fail,
            directive.max_repair_cycles,
        );
        child_packet.packet_id = "packet.loop.review.child".to_owned();
        child_packet.root_run_id = directive.root_run_id.clone();
        child_packet.candidate_cycle = directive.successor_candidate_cycle;
        child_packet.prior_run_id = Some(directive.failed_run_id.clone());
        child_packet.prior_repair_directive_digest = Some(directive.directive_digest.clone());
        child_packet.refresh_digest().unwrap();
        child_packet.validate().unwrap();
        let child_input = a05_input(child_packet);
        let child_executor = A05Executor::new(ReviewVerdict::Fail, ReviewVerdict::Fail);
        assert!(matches!(
            controller.drive(&child_executor, &child_input).unwrap(),
            ReviewAuditLoopOutcome::OwnerEscalated {
                reason: OwnerEscalationReasonV1::RepairBudgetExhausted,
                ..
            }
        ));
        assert_eq!(
            child_executor.calls(),
            vec![PrincipalV1::Reviewer, PrincipalV1::Auditor]
        );
        let child = controller.execution().load(&successor_run_id).unwrap();
        let child_state = child.envelope.independent_review.as_ref().unwrap();
        assert_eq!(child_state.review_packet.candidate_cycle, 1);
        assert_eq!(child_state.review_packet.max_repair_cycles, 1);
        assert!(child_state.repair_directive.is_none());

        let mut wrong_child = child_input.clone();
        wrong_child.review_packet.run_id = RunId::from("run.wrong-child");
        wrong_child.review_packet.refresh_digest().unwrap();
        assert!(controller.drive(&child_executor, &wrong_child).is_err());
    });
}
