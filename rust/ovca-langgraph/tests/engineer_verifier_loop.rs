use chrono::{DateTime, TimeZone, Utc};
use ovca_langgraph::engineer_verifier_loop::{
    EngineerVerifierClock, EngineerVerifierFailureReason, EngineerVerifierLoop,
    EngineerVerifierLoopInput, EngineerVerifierLoopOutcome, EngineerWorkspaceInput,
    VerifierReplayInputs,
};
use ovca_runtime_core::{
    BrokerClock, CleanupReason, DeterministicFakeRoleExecutor, EngineerLogicalPlanV1,
    EngineerVerifierCasOutcome, EngineerVerifierPhaseProjectionV1, EngineerVerifierPhaseV1,
    EngineerVerifierTriggerV1, ExecutorCallStateV1, PendingPhaseProjectionV1,
    PlannedToolEffectTemplateV1, PreparedWorkspaceState, RoleExecutionOutcome,
    RoleExecutionRequest, RoleExecutionScript, RoleExecutionUsage, RoleExecutor, RoleExecutorError,
    VerifierExecutionStateV1, WorkspaceCapabilityBroker, WorkspaceSeedFile,
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
use ovca_types::tool_boundary::{
    expected_read_permission_keys, expected_write_permission_keys, ToolOperationV1,
};
use ovca_types::{
    select_targeted_rerun, verification_policy_digest, verification_sha256_hex, BehaviorBinding,
    BehaviorCriterion, BehaviorKind, BehavioralAcceptanceContract, CapabilityDefinition,
    CapabilityRegistryRow, CapabilityRegistrySnapshot, ChangedPathEntry, ChangedPathKind,
    ChangedPathManifest, ChangedPathSelector, ContractVersion, DeniedAccess, DigestAlgorithm,
    EvidenceId, GoalId, IdempotencyKey, LocalMachinePolicy, PathSelectorKind, RetryBudget,
    RiskTier, Role, RunId, ShellPolicy, TargetedRerunOutcome, TargetedRerunRequest,
    TargetedRerunSelection, Task, TaskId, TaskStatus, UnknownPathPolicy, VerificationCommand,
    VerificationVerdict, WorkerId, WorkingDirectory, LOCAL_VERIFICATION_CONTRACT_VERSION,
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
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};

const SUCCESSOR_HANDOFF_TIMEOUT: Duration = Duration::from_secs(30);

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

    fn set(&self, value: DateTime<Utc>) {
        self.0.store(value.timestamp_millis(), Ordering::SeqCst);
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

impl BrokerClock for MutableClock {
    fn now(&self) -> DateTime<Utc> {
        self.read()
    }
}

struct PostEffectClock {
    now: DateTime<Utc>,
    workspaces: PathBuf,
    effect_visible: mpsc::SyncSender<()>,
    claim_complete: Mutex<Option<mpsc::Receiver<()>>>,
    triggered: Arc<AtomicBool>,
}

impl EngineerVerifierClock for PostEffectClock {
    fn now(&self) -> DateTime<Utc> {
        let physical_write_is_visible = fs::read_dir(&self.workspaces)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .any(|entry| {
                fs::read(entry.path().join("input.txt")).is_ok_and(|bytes| bytes == b"new\n")
            });
        if physical_write_is_visible && !self.triggered.swap(true, Ordering::SeqCst) {
            self.effect_visible
                .try_send(())
                .expect("successor thread stopped before observing the physical write");
            let claim_complete = self
                .claim_complete
                .lock()
                .unwrap()
                .take()
                .expect("post-effect clock may wait for only one successor claim");
            claim_complete
                .recv_timeout(SUCCESSOR_HANDOFF_TIMEOUT)
                .expect("successor claim stopped before releasing the clock");
        }
        self.now
    }
}

#[derive(Clone)]
struct CapabilityDriftClock {
    now: DateTime<Utc>,
    durable_root: PathBuf,
    capability: CapabilityDefinition,
    triggered: Arc<AtomicBool>,
}

impl CapabilityDriftClock {
    fn drift_if_published(&self) {
        if self.triggered.load(Ordering::SeqCst) {
            return;
        }
        let evidence = ovca_storage::EvidenceBank::try_new(&self.durable_root).unwrap();
        let key = ovca_storage::EvidenceKey {
            run_id: RunId::from("run.loop"),
            goal_id: GoalId::from("goal.loop"),
            task_id: TaskId::from("task.loop"),
        };
        if evidence.load_current(&key).unwrap().is_none()
            || self.triggered.swap(true, Ordering::SeqCst)
        {
            return;
        }
        let registry = ovca_storage::CapabilityRegistry::try_new(&self.durable_root).unwrap();
        let current = registry
            .load_current(&self.capability.capability_id)
            .unwrap()
            .unwrap();
        let mut changed = self.capability.clone();
        changed.revision = current.revision + 1;
        changed.commands[0]
            .argv
            .push("--capability-drift".to_owned());
        let record = match registry.publish(&changed).unwrap() {
            ovca_storage::PublishOutcome::Inserted(record)
            | ovca_storage::PublishOutcome::ExistingIdentical(record) => record,
        };
        assert!(matches!(
            registry
                .compare_and_swap_current(
                    &changed.capability_id,
                    changed.revision,
                    &record.digest,
                    &ovca_storage::ProjectionExpectation::Token(current.token),
                )
                .unwrap(),
            ovca_storage::CasOutcome::Applied(_)
        ));
    }
}

impl EngineerVerifierClock for CapabilityDriftClock {
    fn now(&self) -> DateTime<Utc> {
        self.drift_if_published();
        self.now
    }
}

impl BrokerClock for CapabilityDriftClock {
    fn now(&self) -> DateTime<Utc> {
        self.drift_if_published();
        self.now
    }
}

struct Fixture {
    durable: TempDir,
    workspaces: TempDir,
    protected: TempDir,
    verifier_temp: TempDir,
    _probe: TempDir,
    counter_path: PathBuf,
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
        let plan = plan();
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
        let selection = selection(&capability, manifest.fingerprint().unwrap(), policy_digest);
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
            counter_path,
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

    fn verifier_calls(&self) -> usize {
        fs::read(&self.counter_path)
            .map(|bytes| {
                bytes
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.is_empty())
                    .count()
            })
            .unwrap_or(0)
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
                grant_authority: grant_authority(),
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

fn scope() -> FoundationScopeV1 {
    FoundationScopeV1 {
        project_id: "project.loop".to_owned(),
        goal_id: Some("goal.loop".to_owned()),
        task_id: Some("task.loop".to_owned()),
        run_id: Some("run.loop".to_owned()),
    }
}

fn invocation() -> RoleInvocationV1 {
    let invoker = identity("principal.loop.coordinator", PrincipalV1::Coordinator);
    let authority = FoundationAuthorityV1 {
        contract_version: 1,
        authority_id: "authority.loop.invocation".to_owned(),
        principal: invoker.clone(),
        scope: scope(),
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
        run_id: RunId::from("run.loop"),
        scope: scope(),
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

fn plan() -> EngineerLogicalPlanV1 {
    EngineerLogicalPlanV1::try_new(
        RunId::from("run.loop"),
        GoalId::from("goal.loop"),
        TaskId::from("task.loop"),
        invocation(),
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

fn grant_authority() -> FoundationAuthorityV1 {
    let read_paths = vec!["input.txt".to_owned()];
    let write_paths = vec!["input.txt".to_owned()];
    FoundationAuthorityV1 {
        contract_version: 1,
        authority_id: "authority.loop.grant".to_owned(),
        principal: identity("principal.loop.coordinator", PrincipalV1::Coordinator),
        scope: scope(),
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

fn completed_outcome(attempt: u32) -> RoleExecutionOutcome {
    let invocation = invocation();
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

fn completed_executor(attempts: &[u32]) -> DeterministicFakeRoleExecutor {
    DeterministicFakeRoleExecutor::try_new(attempts.iter().map(|attempt| RoleExecutionScript {
        request: RoleExecutionRequest {
            invocation: invocation(),
            attempt: *attempt,
        },
        outcome: completed_outcome(*attempt),
    }))
    .unwrap()
}

fn selection(
    capability: &CapabilityDefinition,
    source_fingerprint: String,
    policy_digest: String,
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
        run_id: RunId::from("run.loop"),
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

#[test]
fn full_loop_writes_verifies_and_admits_exact_current_evidence() {
    let fixture = Fixture::new();
    let clock = MutableClock::new(at(10));
    let controller = fixture.loop_with_clock(clock.clone());
    fixture.initialize(&controller);
    fixture.publish_capability();
    let mut broker = fixture.broker("runtime.loop.initial", clock);
    let outcome = controller
        .drive(
            &mut broker,
            &completed_executor(&[1]),
            fixture.input(
                b"old\n",
                "lease.loop.1",
                "workspace.loop.1",
                "recovery.loop.1",
                "grant.loop.1",
                &fixture.environment_digest,
            ),
        )
        .unwrap();
    let EngineerVerifierLoopOutcome::Reviewing { bundle_id, .. } = outcome else {
        panic!("expected reviewing")
    };
    assert_eq!(broker.backend_calls(), 1);
    assert_eq!(broker.active_root_count(), 0);
    assert!(fs::read_dir(fixture.verifier_temp.path())
        .unwrap()
        .next()
        .is_none());

    let state = controller.execution().load(&fixture.plan.run_id).unwrap();
    let projection = state.envelope.engineer_verifier.unwrap();
    assert_eq!(projection.phase, EngineerVerifierPhaseV1::Reviewing);
    assert_eq!(projection.ledger.entries.len(), 1);
    assert!(projection.workspace.unwrap().closed);
    assert!(matches!(
        projection.verifier,
        Some(ovca_runtime_core::VerifierExecutionStateV1::Admitted { .. })
    ));
    let current = controller
        .evidence()
        .load_current(&ovca_storage::EvidenceKey {
            run_id: RunId::from("run.loop"),
            goal_id: GoalId::from("goal.loop"),
            task_id: TaskId::from("task.loop"),
        })
        .unwrap()
        .unwrap();
    assert_eq!(current.bundle_id, bundle_id);
    assert_eq!(
        controller
            .log()
            .load_run(&fixture.plan.run_id)
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn capability_current_drift_blocks_admission_and_closes_workspace() {
    let fixture = Fixture::new();
    let triggered = Arc::new(AtomicBool::new(false));
    let clock = CapabilityDriftClock {
        now: at(10),
        durable_root: fixture.durable.path().to_path_buf(),
        capability: fixture.capability.clone(),
        triggered: Arc::clone(&triggered),
    };
    let controller =
        EngineerVerifierLoop::try_new(fixture.durable.path(), Box::new(clock.clone())).unwrap();
    fixture.initialize(&controller);
    fixture.publish_capability();
    let mut broker = WorkspaceCapabilityBroker::try_new(
        "runtime.loop.capability-drift",
        fixture.workspaces.path(),
        vec![fixture.protected.path().to_path_buf()],
        Box::new(clock),
    )
    .unwrap();
    let outcome = controller
        .drive(
            &mut broker,
            &completed_executor(&[1]),
            fixture.input(
                b"old\n",
                "lease.loop.capability-drift",
                "workspace.loop.capability-drift",
                "recovery.loop.capability-drift",
                "grant.loop.capability-drift",
                &fixture.environment_digest,
            ),
        )
        .unwrap();
    assert!(triggered.load(Ordering::SeqCst));
    assert!(matches!(
        outcome,
        EngineerVerifierLoopOutcome::Failed {
            reason: EngineerVerifierFailureReason::RecoveryConflict,
            ..
        }
    ));
    assert_eq!(broker.backend_calls(), 1);
    assert_eq!(broker.active_root_count(), 0);
    let state = controller
        .execution()
        .load(&fixture.plan.run_id)
        .unwrap()
        .envelope
        .engineer_verifier
        .unwrap();
    assert_eq!(state.phase, EngineerVerifierPhaseV1::Failed);
    assert!(state.workspace.unwrap().closed);
}

#[test]
fn same_content_is_no_change_before_lifecycle_verifier_or_backend() {
    let fixture = Fixture::new();
    let clock = MutableClock::new(at(10));
    let controller = fixture.loop_with_clock(clock.clone());
    fixture.initialize(&controller);
    let mut broker = fixture.broker("runtime.loop.no-change", clock);
    let panic_executor = PanicExecutor::default();
    let outcome = controller
        .drive(
            &mut broker,
            &panic_executor,
            fixture.input(
                b"new\n",
                "lease.loop.no-change",
                "workspace.loop.no-change",
                "recovery.loop.no-change",
                "grant.loop.no-change",
                "invalid-environment-digest",
            ),
        )
        .unwrap();
    assert_eq!(outcome, EngineerVerifierLoopOutcome::NoChange);
    assert_eq!(panic_executor.calls.load(Ordering::SeqCst), 0);
    assert_eq!(broker.backend_calls(), 0);
    assert_eq!(broker.active_root_count(), 0);
    assert!(controller
        .execution()
        .load(&fixture.plan.run_id)
        .unwrap()
        .envelope
        .engineer_verifier
        .is_none());
    assert!(controller
        .log()
        .load_run(&fixture.plan.run_id)
        .unwrap()
        .is_empty());
    assert!(!controller.evidence().database_path().exists());
}

#[test]
fn fresh_pre_admission_errors_remove_only_the_owned_workspace() {
    let fixture = Fixture::new();
    let clock = MutableClock::new(at(10));
    let controller = fixture.loop_with_clock(clock.clone());
    fixture.initialize(&controller);
    let mut broker = fixture.broker("runtime.loop.invalid-grant", clock.clone());
    let never = NeverExecutor::default();
    let invalid_grant = controller.drive(
        &mut broker,
        &never,
        fixture.input(
            b"old\n",
            "lease.loop.invalid-grant",
            "workspace.loop.invalid-grant",
            "recovery.loop.invalid-grant",
            "",
            &fixture.environment_digest,
        ),
    );
    assert!(matches!(
        invalid_grant,
        Err(ovca_langgraph::engineer_verifier_loop::EngineerVerifierLoopError::InvalidInput)
    ));
    assert_eq!(never.calls.load(Ordering::SeqCst), 0);
    assert_eq!(broker.active_root_count(), 0);
    assert!(controller
        .execution()
        .load(&fixture.plan.run_id)
        .unwrap()
        .envelope
        .engineer_verifier
        .is_none());

    let mut broker = fixture.broker("runtime.loop.invalid-verifier", clock);
    let invalid_verifier = controller.drive(
        &mut broker,
        &never,
        fixture.input(
            b"old\n",
            "lease.loop.invalid-verifier",
            "workspace.loop.invalid-verifier",
            "recovery.loop.invalid-verifier",
            "grant.loop.invalid-verifier",
            "invalid-environment-digest",
        ),
    );
    assert!(invalid_verifier.is_err());
    assert_eq!(never.calls.load(Ordering::SeqCst), 0);
    assert_eq!(broker.active_root_count(), 0);
    assert!(controller
        .execution()
        .load(&fixture.plan.run_id)
        .unwrap()
        .envelope
        .engineer_verifier
        .is_none());
}

#[derive(Default)]
struct PanicExecutor {
    calls: AtomicUsize,
}

impl RoleExecutor for PanicExecutor {
    fn invoke(
        &self,
        _request: RoleExecutionRequest,
    ) -> Result<RoleExecutionOutcome, RoleExecutorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("simulated crash after executor started CAS")
    }
}

#[derive(Default)]
struct NeverExecutor {
    calls: AtomicUsize,
}

impl RoleExecutor for NeverExecutor {
    fn invoke(
        &self,
        _request: RoleExecutionRequest,
    ) -> Result<RoleExecutionOutcome, RoleExecutorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(RoleExecutorError::MissingScript)
    }
}

struct PanicOnceBrokerClock {
    now: DateTime<Utc>,
    panicked: AtomicBool,
}

impl BrokerClock for PanicOnceBrokerClock {
    fn now(&self) -> DateTime<Utc> {
        if !self.panicked.swap(true, Ordering::SeqCst) {
            panic!("simulated crash after durable write preparation")
        }
        self.now
    }
}

#[derive(Default)]
struct CountingCompletedExecutor {
    calls: AtomicUsize,
}

impl RoleExecutor for CountingCompletedExecutor {
    fn invoke(
        &self,
        request: RoleExecutionRequest,
    ) -> Result<RoleExecutionOutcome, RoleExecutorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(completed_outcome(request.attempt))
    }
}

fn durable_loop_state(
    durable_root: &std::path::Path,
) -> Option<ovca_runtime_core::EngineerVerifierStateV1> {
    ovca_runtime_core::DurableExecutionAuthority::new(durable_root)
        .load(&RunId::from("run.loop"))
        .ok()?
        .envelope
        .engineer_verifier
}

fn loop_evidence_key() -> ovca_storage::EvidenceKey {
    ovca_storage::EvidenceKey {
        run_id: RunId::from("run.loop"),
        goal_id: GoalId::from("goal.loop"),
        task_id: TaskId::from("task.loop"),
    }
}

struct PanicBeforePreparedClock {
    now: DateTime<Utc>,
    durable_root: PathBuf,
    triggered: AtomicBool,
}

impl EngineerVerifierClock for PanicBeforePreparedClock {
    fn now(&self) -> DateTime<Utc> {
        let should_crash = durable_loop_state(&self.durable_root).is_some_and(|state| {
            state.engineer_result.is_some()
                && state.prepared_write.is_none()
                && state.ledger.entries.is_empty()
                && matches!(state.executor, ExecutorCallStateV1::OutcomeRecorded { .. })
        });
        if should_crash && !self.triggered.swap(true, Ordering::SeqCst) {
            panic!("simulated crash before durable write preparation")
        }
        self.now
    }
}

struct PanicAtVerifierNotStartedClock {
    now: DateTime<Utc>,
    durable_root: PathBuf,
    triggered: AtomicBool,
}

impl EngineerVerifierClock for PanicAtVerifierNotStartedClock {
    fn now(&self) -> DateTime<Utc> {
        let should_crash = durable_loop_state(&self.durable_root).is_some_and(|state| {
            state.phase == EngineerVerifierPhaseV1::Verifying
                && matches!(
                    state.verifier,
                    Some(VerifierExecutionStateV1::NotStarted { .. })
                )
        });
        if should_crash && !self.triggered.swap(true, Ordering::SeqCst) {
            panic!("simulated stop immediately before verifier-started CAS")
        }
        self.now
    }
}

struct PanicAfterEvidencePublicationClock {
    now: DateTime<Utc>,
    durable_root: PathBuf,
    triggered: AtomicBool,
}

impl EngineerVerifierClock for PanicAfterEvidencePublicationClock {
    fn now(&self) -> DateTime<Utc> {
        let started = durable_loop_state(&self.durable_root).is_some_and(|state| {
            matches!(
                state.verifier,
                Some(VerifierExecutionStateV1::Started { .. })
            )
        });
        let published = ovca_storage::EvidenceBank::try_new(&self.durable_root)
            .ok()
            .and_then(|bank| bank.load_current(&loop_evidence_key()).ok().flatten())
            .is_some();
        if started && published && !self.triggered.swap(true, Ordering::SeqCst) {
            panic!("simulated crash after evidence publication")
        }
        self.now
    }
}

struct PanicBeforeAdmissionClock {
    now: DateTime<Utc>,
    durable_root: PathBuf,
    triggered: AtomicBool,
}

impl EngineerVerifierClock for PanicBeforeAdmissionClock {
    fn now(&self) -> DateTime<Utc> {
        let observed = durable_loop_state(&self.durable_root).is_some_and(|state| {
            matches!(
                state.verifier,
                Some(VerifierExecutionStateV1::PublicationObserved { .. })
            )
        });
        if observed && !self.triggered.swap(true, Ordering::SeqCst) {
            panic!("simulated crash after publication-observed CAS")
        }
        self.now
    }
}

struct ReadOnlyFileGuard {
    path: PathBuf,
    original_permissions: fs::Permissions,
    restored: bool,
}

impl ReadOnlyFileGuard {
    fn install(path: PathBuf) -> Self {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"").unwrap();
        let original_permissions = fs::metadata(&path).unwrap().permissions();
        let mut permissions = original_permissions.clone();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();
        Self {
            path,
            original_permissions,
            restored: false,
        }
    }

    fn restore(&mut self) {
        if !self.restored {
            fs::set_permissions(&self.path, self.original_permissions.clone()).unwrap();
            self.restored = true;
        }
    }
}

impl Drop for ReadOnlyFileGuard {
    fn drop(&mut self) {
        if !self.restored {
            let _ = fs::set_permissions(&self.path, self.original_permissions.clone());
        }
    }
}

fn frozen_event_occurrences(raw: &[u8], pending: &PendingPhaseProjectionV1) -> usize {
    raw.split(|byte| *byte == b'\n')
        .filter(|line| *line == pending.event_bytes.as_slice())
        .count()
}

#[test]
fn crash_before_durable_prepare_resumes_without_precrash_backend_call() {
    let fixture = Fixture::new();
    let controller = EngineerVerifierLoop::try_new(
        fixture.durable.path(),
        Box::new(PanicBeforePreparedClock {
            now: at(10),
            durable_root: fixture.durable.path().to_path_buf(),
            triggered: AtomicBool::new(false),
        }),
    )
    .unwrap();
    fixture.initialize(&controller);
    fixture.publish_capability();
    let mut original = fixture.broker("runtime.loop.before-prepare", MutableClock::new(at(10)));
    let executor = CountingCompletedExecutor::default();
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = controller.drive(
            &mut original,
            &executor,
            fixture.input(
                b"old\n",
                "lease.loop.before-prepare",
                "workspace.loop.before-prepare",
                "recovery.loop.before-prepare",
                "grant.loop.before-prepare",
                &fixture.environment_digest,
            ),
        );
    }))
    .is_err());
    assert_eq!(original.backend_calls(), 0);
    let crashed = controller.execution().load(&fixture.plan.run_id).unwrap();
    let crashed = crashed.envelope.engineer_verifier.unwrap();
    assert!(crashed.prepared_write.is_none());
    assert!(matches!(
        crashed.executor,
        ExecutorCallStateV1::OutcomeRecorded { .. }
    ));

    let recovered = fixture.loop_with_clock(MutableClock::new(at(12)));
    let mut broker = fixture.broker(
        "runtime.loop.before-prepare-recovered",
        MutableClock::new(at(12)),
    );
    let never = NeverExecutor::default();
    assert!(matches!(
        recovered
            .drive(
                &mut broker,
                &never,
                fixture.input(
                    b"old\n",
                    "lease.loop.before-prepare",
                    "workspace.loop.before-prepare",
                    "recovery.loop.before-prepare",
                    "grant.loop.before-prepare",
                    &fixture.environment_digest,
                ),
            )
            .unwrap(),
        EngineerVerifierLoopOutcome::Reviewing { .. }
    ));
    assert_eq!(never.calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    assert_eq!(broker.backend_calls(), 1);
}

#[test]
fn prepared_exact_before_recovery_revalidates_and_writes_once() {
    let fixture = Fixture::new();
    let controller_clock = MutableClock::new(at(10));
    let controller = fixture.loop_with_clock(controller_clock.clone());
    fixture.initialize(&controller);
    fixture.publish_capability();
    let mut original = WorkspaceCapabilityBroker::try_new(
        "runtime.loop.prepared-before",
        fixture.workspaces.path(),
        vec![fixture.protected.path().to_path_buf()],
        Box::new(PanicOnceBrokerClock {
            now: at(10),
            panicked: AtomicBool::new(false),
        }),
    )
    .unwrap();
    let executor = CountingCompletedExecutor::default();
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = controller.drive(
            &mut original,
            &executor,
            fixture.input(
                b"old\n",
                "lease.loop.prepared-before",
                "workspace.loop.prepared-before",
                "recovery.loop.prepared-before",
                "grant.loop.prepared-before",
                &fixture.environment_digest,
            ),
        );
    }))
    .is_err());
    assert_eq!(original.backend_calls(), 0);
    assert!(controller
        .execution()
        .load(&fixture.plan.run_id)
        .unwrap()
        .envelope
        .engineer_verifier
        .unwrap()
        .prepared_write
        .is_some());

    controller_clock.set(at(12));
    let recovered = fixture.loop_with_clock(controller_clock.clone());
    let mut broker = fixture.broker("runtime.loop.prepared-before-recovered", controller_clock);
    let never = NeverExecutor::default();
    assert!(matches!(
        recovered
            .drive(
                &mut broker,
                &never,
                fixture.input(
                    b"old\n",
                    "lease.loop.prepared-before",
                    "workspace.loop.prepared-before",
                    "recovery.loop.prepared-before",
                    "grant.loop.prepared-before",
                    &fixture.environment_digest,
                ),
            )
            .unwrap(),
        EngineerVerifierLoopOutcome::Reviewing { .. }
    ));
    assert_eq!(never.calls.load(Ordering::SeqCst), 0);
    assert_eq!(broker.backend_calls(), 1);
}

#[test]
fn lifecycle_cas_before_jsonl_append_recovers_one_frozen_event() {
    let fixture = Fixture::new();
    let clock = MutableClock::new(at(10));
    let controller = fixture.loop_with_clock(clock.clone());
    fixture.initialize(&controller);
    fixture.publish_capability();
    let mut projection_file = ReadOnlyFileGuard::install(controller.log().path().to_path_buf());
    let mut original = fixture.broker("runtime.loop.pre-append", clock.clone());
    assert!(controller
        .drive(
            &mut original,
            &CountingCompletedExecutor::default(),
            fixture.input(
                b"old\n",
                "lease.loop.pre-append",
                "workspace.loop.pre-append",
                "recovery.loop.pre-append",
                "grant.loop.pre-append",
                &fixture.environment_digest,
            ),
        )
        .is_err());
    assert_eq!(original.backend_calls(), 0);
    let pending = controller
        .execution()
        .load(&fixture.plan.run_id)
        .unwrap()
        .envelope
        .engineer_verifier
        .unwrap()
        .pending_projection
        .unwrap();
    assert!(fs::read(controller.log().path()).unwrap().is_empty());
    projection_file.restore();

    let recovered = fixture.loop_with_clock(MutableClock::new(at(12)));
    let mut broker = fixture.broker(
        "runtime.loop.pre-append-recovered",
        MutableClock::new(at(12)),
    );
    assert!(matches!(
        recovered
            .drive(
                &mut broker,
                &CountingCompletedExecutor::default(),
                fixture.input(
                    b"old\n",
                    "lease.loop.pre-append",
                    "workspace.loop.pre-append",
                    "recovery.loop.pre-append",
                    "grant.loop.pre-append",
                    &fixture.environment_digest,
                ),
            )
            .unwrap(),
        EngineerVerifierLoopOutcome::Reviewing { .. }
    ));
    let raw = fs::read(recovered.log().path()).unwrap();
    assert_eq!(frozen_event_occurrences(&raw, &pending), 1);
}

#[test]
fn jsonl_append_before_pending_clear_preserves_exact_bytes_without_duplicate() {
    let fixture = Fixture::new();
    let clock = MutableClock::new(at(10));
    let controller = fixture.loop_with_clock(clock.clone());
    fixture.initialize(&controller);
    fixture.publish_capability();
    let mut projection_file = ReadOnlyFileGuard::install(controller.log().path().to_path_buf());
    let mut original = fixture.broker("runtime.loop.post-append", clock);
    assert!(controller
        .drive(
            &mut original,
            &CountingCompletedExecutor::default(),
            fixture.input(
                b"old\n",
                "lease.loop.post-append",
                "workspace.loop.post-append",
                "recovery.loop.post-append",
                "grant.loop.post-append",
                &fixture.environment_digest,
            ),
        )
        .is_err());
    let pending = controller
        .execution()
        .load(&fixture.plan.run_id)
        .unwrap()
        .envelope
        .engineer_verifier
        .unwrap()
        .pending_projection
        .unwrap();
    projection_file.restore();
    let mut frozen_line = pending.event_bytes.clone();
    frozen_line.push(b'\n');
    fs::write(controller.log().path(), &frozen_line).unwrap();

    let recovered = fixture.loop_with_clock(MutableClock::new(at(12)));
    let mut broker = fixture.broker(
        "runtime.loop.post-append-recovered",
        MutableClock::new(at(12)),
    );
    assert!(matches!(
        recovered
            .drive(
                &mut broker,
                &CountingCompletedExecutor::default(),
                fixture.input(
                    b"old\n",
                    "lease.loop.post-append",
                    "workspace.loop.post-append",
                    "recovery.loop.post-append",
                    "grant.loop.post-append",
                    &fixture.environment_digest,
                ),
            )
            .unwrap(),
        EngineerVerifierLoopOutcome::Reviewing { .. }
    ));
    let raw = fs::read(recovered.log().path()).unwrap();
    assert!(raw.starts_with(&frozen_line));
    assert_eq!(frozen_event_occurrences(&raw, &pending), 1);
}

#[test]
fn verifier_started_with_absent_bank_replays_from_exact_resupply() {
    let fixture = Fixture::new();
    let controller = EngineerVerifierLoop::try_new(
        fixture.durable.path(),
        Box::new(PanicAtVerifierNotStartedClock {
            now: at(10),
            durable_root: fixture.durable.path().to_path_buf(),
            triggered: AtomicBool::new(false),
        }),
    )
    .unwrap();
    fixture.initialize(&controller);
    fixture.publish_capability();
    let mut original = fixture.broker("runtime.loop.verifier-started", MutableClock::new(at(10)));
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = controller.drive(
            &mut original,
            &CountingCompletedExecutor::default(),
            fixture.input(
                b"old\n",
                "lease.loop.verifier-started",
                "workspace.loop.verifier-started",
                "recovery.loop.verifier-started",
                "grant.loop.verifier-started",
                &fixture.environment_digest,
            ),
        );
    }))
    .is_err());
    assert_eq!(fixture.verifier_calls(), 0);
    assert!(controller
        .evidence()
        .load_current(&loop_evidence_key())
        .unwrap()
        .is_none());

    let loaded = controller.execution().load(&fixture.plan.run_id).unwrap();
    let prior_digest = loaded
        .envelope
        .engineer_verifier
        .as_ref()
        .unwrap()
        .state_digest
        .clone();
    let mut started = loaded.envelope.engineer_verifier.unwrap();
    let replay_plan_digest = match started.verifier.as_ref().unwrap() {
        VerifierExecutionStateV1::NotStarted { replay_plan_digest } => replay_plan_digest.clone(),
        other => panic!("expected verifier not_started, got {other:?}"),
    };
    started.verifier = Some(VerifierExecutionStateV1::Started {
        replay_plan_digest,
        started_at: at(10),
    });
    started.refresh_digest().unwrap();
    assert!(matches!(
        controller
            .execution()
            .compare_and_swap_engineer_verifier(
                &fixture.plan.run_id,
                loaded.revision,
                Some(&prior_digest),
                started,
            )
            .unwrap(),
        EngineerVerifierCasOutcome::Applied(_)
    ));

    let recovered = fixture.loop_with_clock(MutableClock::new(at(12)));
    let mut broker = fixture.broker(
        "runtime.loop.verifier-started-recovered",
        MutableClock::new(at(12)),
    );
    let never = NeverExecutor::default();
    assert!(matches!(
        recovered
            .drive(
                &mut broker,
                &never,
                fixture.input(
                    b"old\n",
                    "lease.loop.verifier-started",
                    "workspace.loop.verifier-started",
                    "recovery.loop.verifier-started",
                    "grant.loop.verifier-started",
                    &fixture.environment_digest,
                ),
            )
            .unwrap(),
        EngineerVerifierLoopOutcome::Reviewing { .. }
    ));
    assert_eq!(never.calls.load(Ordering::SeqCst), 0);
    assert_eq!(broker.backend_calls(), 0);
    assert_eq!(fixture.verifier_calls(), 1);
}

#[test]
fn published_bank_before_observation_replays_disposably_without_mutating_authority() {
    let fixture = Fixture::new();
    let controller = EngineerVerifierLoop::try_new(
        fixture.durable.path(),
        Box::new(PanicAfterEvidencePublicationClock {
            now: at(10),
            durable_root: fixture.durable.path().to_path_buf(),
            triggered: AtomicBool::new(false),
        }),
    )
    .unwrap();
    fixture.initialize(&controller);
    fixture.publish_capability();
    let mut original = fixture.broker("runtime.loop.bank-published", MutableClock::new(at(10)));
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = controller.drive(
            &mut original,
            &CountingCompletedExecutor::default(),
            fixture.input(
                b"old\n",
                "lease.loop.bank-published",
                "workspace.loop.bank-published",
                "recovery.loop.bank-published",
                "grant.loop.bank-published",
                &fixture.environment_digest,
            ),
        );
    }))
    .is_err());
    assert_eq!(fixture.verifier_calls(), 1);
    let authoritative_current = controller
        .evidence()
        .load_current(&loop_evidence_key())
        .unwrap()
        .unwrap();
    let authoritative_record = controller
        .evidence()
        .load_bundle(&authoritative_current.record_digest)
        .unwrap()
        .unwrap();

    let recovered = fixture.loop_with_clock(MutableClock::new(at(12)));
    let mut broker = fixture.broker(
        "runtime.loop.bank-published-recovered",
        MutableClock::new(at(12)),
    );
    let never = NeverExecutor::default();
    assert!(matches!(
        recovered
            .drive(
                &mut broker,
                &never,
                fixture.input(
                    b"old\n",
                    "lease.loop.bank-published",
                    "workspace.loop.bank-published",
                    "recovery.loop.bank-published",
                    "grant.loop.bank-published",
                    &fixture.environment_digest,
                ),
            )
            .unwrap(),
        EngineerVerifierLoopOutcome::Reviewing { .. }
    ));
    assert_eq!(fixture.verifier_calls(), 2);
    assert_eq!(never.calls.load(Ordering::SeqCst), 0);
    assert_eq!(broker.backend_calls(), 0);
    assert_eq!(
        recovered
            .evidence()
            .load_current(&loop_evidence_key())
            .unwrap(),
        Some(authoritative_current.clone())
    );
    assert_eq!(
        recovered
            .evidence()
            .load_bundle(&authoritative_current.record_digest)
            .unwrap(),
        Some(authoritative_record)
    );
}

#[test]
fn publication_observed_before_admission_resumes_without_verifier_rerun() {
    let fixture = Fixture::new();
    let controller = EngineerVerifierLoop::try_new(
        fixture.durable.path(),
        Box::new(PanicBeforeAdmissionClock {
            now: at(10),
            durable_root: fixture.durable.path().to_path_buf(),
            triggered: AtomicBool::new(false),
        }),
    )
    .unwrap();
    fixture.initialize(&controller);
    fixture.publish_capability();
    let mut original = fixture.broker("runtime.loop.pre-admission", MutableClock::new(at(10)));
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = controller.drive(
            &mut original,
            &CountingCompletedExecutor::default(),
            fixture.input(
                b"old\n",
                "lease.loop.pre-admission",
                "workspace.loop.pre-admission",
                "recovery.loop.pre-admission",
                "grant.loop.pre-admission",
                &fixture.environment_digest,
            ),
        );
    }))
    .is_err());
    assert_eq!(fixture.verifier_calls(), 1);
    assert!(matches!(
        controller
            .execution()
            .load(&fixture.plan.run_id)
            .unwrap()
            .envelope
            .engineer_verifier
            .unwrap()
            .verifier,
        Some(VerifierExecutionStateV1::PublicationObserved { .. })
    ));

    let recovered = fixture.loop_with_clock(MutableClock::new(at(12)));
    let mut broker = fixture.broker(
        "runtime.loop.pre-admission-recovered",
        MutableClock::new(at(12)),
    );
    let never = NeverExecutor::default();
    assert!(matches!(
        recovered
            .drive(
                &mut broker,
                &never,
                fixture.input(
                    b"old\n",
                    "lease.loop.pre-admission",
                    "workspace.loop.pre-admission",
                    "recovery.loop.pre-admission",
                    "grant.loop.pre-admission",
                    &fixture.environment_digest,
                ),
            )
            .unwrap(),
        EngineerVerifierLoopOutcome::Reviewing { .. }
    ));
    assert_eq!(fixture.verifier_calls(), 1);
    assert_eq!(never.calls.load(Ordering::SeqCst), 0);
    assert_eq!(broker.backend_calls(), 0);
}

#[test]
fn prepared_and_physically_written_crash_resume_skips_executor_and_duplicate_write() {
    let fixture = Fixture::new();
    let controller_clock = MutableClock::new(at(10));
    let controller = fixture.loop_with_clock(controller_clock.clone());
    fixture.initialize(&controller);
    fixture.publish_capability();
    let mut original = WorkspaceCapabilityBroker::try_new(
        "runtime.loop.prepared-crash",
        fixture.workspaces.path(),
        vec![fixture.protected.path().to_path_buf()],
        Box::new(PanicOnceBrokerClock {
            now: at(10),
            panicked: AtomicBool::new(false),
        }),
    )
    .unwrap();
    let executor = CountingCompletedExecutor::default();
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = controller.drive(
            &mut original,
            &executor,
            fixture.input(
                b"old\n",
                "lease.loop.prepared-crash",
                "workspace.loop.prepared-crash",
                "recovery.loop.prepared-crash",
                "grant.loop.prepared-crash",
                &fixture.environment_digest,
            ),
        );
    }))
    .is_err());
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    assert_eq!(original.backend_calls(), 0);
    let prepared = controller
        .execution()
        .load(&fixture.plan.run_id)
        .unwrap()
        .envelope
        .engineer_verifier
        .unwrap();
    assert!(prepared.engineer_result.is_some());
    assert!(prepared.engineer_result_digest.is_some());
    assert!(prepared.prepared_write.is_some());
    assert!(matches!(
        prepared.executor,
        ExecutorCallStateV1::OutcomeRecorded { .. }
    ));

    let roots = fs::read_dir(fixture.workspaces.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(roots.len(), 1);
    fs::write(roots[0].join("input.txt"), b"new\n").unwrap();

    controller_clock.set(at(12));
    let recovered_controller = fixture.loop_with_clock(controller_clock.clone());
    let mut recovered = fixture.broker("runtime.loop.prepared-recovered", controller_clock);
    let never = NeverExecutor::default();
    let outcome = recovered_controller
        .drive(
            &mut recovered,
            &never,
            fixture.input(
                b"old\n",
                "lease.loop.prepared-crash",
                "workspace.loop.prepared-crash",
                "recovery.loop.prepared-crash",
                "grant.loop.prepared-crash",
                &fixture.environment_digest,
            ),
        )
        .unwrap();
    assert!(matches!(
        outcome,
        EngineerVerifierLoopOutcome::Reviewing { .. }
    ));
    assert_eq!(never.calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    assert_eq!(recovered.backend_calls(), 0);
    assert_eq!(recovered.active_root_count(), 0);
    let completed = recovered_controller
        .execution()
        .load(&fixture.plan.run_id)
        .unwrap()
        .envelope
        .engineer_verifier
        .unwrap();
    assert_eq!(completed.phase, EngineerVerifierPhaseV1::Reviewing);
    assert_eq!(completed.ledger.entries.len(), 1);
    assert!(completed.workspace.unwrap().closed);
}

#[test]
fn successor_claim_after_physical_write_fences_old_cas_and_reconciles_without_rewrite() {
    let fixture = Fixture::new();
    let (effect_visible, observe_effect) = mpsc::sync_channel(1);
    let (claim_complete, release_clock) = mpsc::sync_channel(1);
    let (claim_ready, receive_claim) = mpsc::sync_channel(1);
    let controller = EngineerVerifierLoop::try_new(
        fixture.durable.path(),
        Box::new(PostEffectClock {
            now: at(10),
            workspaces: fixture.workspaces.path().to_path_buf(),
            effect_visible,
            claim_complete: Mutex::new(Some(release_clock)),
            triggered: Arc::new(AtomicBool::new(false)),
        }),
    )
    .unwrap();
    fixture.initialize(&controller);
    fixture.publish_capability();
    let authority = controller.execution().clone();
    let run_id = fixture.plan.run_id.clone();
    let claim_thread = std::thread::spawn(move || {
        observe_effect
            .recv_timeout(SUCCESSOR_HANDOFF_TIMEOUT)
            .expect("physical effect was not observed before the successor deadline");
        let loaded = authority.load(&run_id).unwrap();
        let state = loaded.envelope.engineer_verifier.as_ref().unwrap();
        let claim = authority
            .claim_workspace_recovery(
                &run_id,
                loaded.revision,
                &state.state_digest,
                "runtime.loop.effect-successor",
                at(11),
            )
            .unwrap()
            .unwrap();
        claim_complete.try_send(()).unwrap();
        claim_ready.try_send(claim).unwrap();
    });

    let mut original = fixture.broker("runtime.loop.effect-original", MutableClock::new(at(10)));
    let executor = CountingCompletedExecutor::default();
    let result = controller.drive(
        &mut original,
        &executor,
        fixture.input(
            b"old\n",
            "lease.loop.effect-race",
            "workspace.loop.effect-race",
            "recovery.loop.effect-race",
            "grant.loop.effect-race",
            &fixture.environment_digest,
        ),
    );
    let claim = receive_claim
        .recv_timeout(SUCCESSOR_HANDOFF_TIMEOUT)
        .expect("successor claim result was not returned before the deadline");
    claim_thread.join().unwrap();
    assert!(matches!(
        result,
        Err(ovca_langgraph::engineer_verifier_loop::EngineerVerifierLoopError::ProjectionConflict)
    ));
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    assert_eq!(original.backend_calls(), 1);
    let prepared = claim
        .state
        .envelope
        .engineer_verifier
        .as_ref()
        .unwrap()
        .prepared_write
        .clone()
        .unwrap();
    let mut successor = fixture.broker("runtime.loop.effect-successor", MutableClock::new(at(12)));
    let (successor_lease, _successor_grant) = successor.recover_lease(claim.permit).unwrap();
    assert_eq!(
        successor
            .inspect_prepared_write(&successor_lease, &prepared)
            .unwrap(),
        PreparedWorkspaceState::IntendedAfter
    );
    let reconciled = successor
        .adopt_reconciled_write(&successor_lease, &prepared)
        .unwrap();
    assert_eq!(reconciled, prepared.intended_after_snapshot);
    assert_eq!(successor.backend_calls(), 0);
    drop(original);
    assert_eq!(successor.snapshot(&successor_lease).unwrap(), reconciled);
    successor
        .close_lease(&successor_lease, CleanupReason::Completed)
        .unwrap();
    assert_eq!(successor.active_root_count(), 0);
}

#[test]
fn ambiguous_executor_recovery_fails_without_reinvoke_and_pending_cancel_cannot_win() {
    let fixture = Fixture::new();
    let clock = MutableClock::new(at(10));
    let controller = fixture.loop_with_clock(clock.clone());
    fixture.initialize(&controller);
    let mut original = fixture.broker("runtime.loop.crashed", clock.clone());
    let panic_executor = PanicExecutor::default();
    let crashed = catch_unwind(AssertUnwindSafe(|| {
        let _ = controller.drive(
            &mut original,
            &panic_executor,
            fixture.input(
                b"old\n",
                "lease.loop.crash",
                "workspace.loop.crash",
                "recovery.loop.crash",
                "grant.loop.crash",
                &fixture.environment_digest,
            ),
        );
    }));
    assert!(crashed.is_err());
    assert_eq!(panic_executor.calls.load(Ordering::SeqCst), 1);
    let started = controller.execution().load(&fixture.plan.run_id).unwrap();
    assert!(matches!(
        started.envelope.engineer_verifier.unwrap().executor,
        ExecutorCallStateV1::Started { .. }
    ));

    assert!(controller.heartbeat(&fixture.plan.run_id).is_err());
    clock.set(at(11));
    controller.heartbeat(&fixture.plan.run_id).unwrap();
    assert!(controller.heartbeat(&fixture.plan.run_id).is_err());
    assert!(matches!(
        controller
            .request_cancellation(&fixture.plan.run_id, "cancel.loop.crash")
            .unwrap(),
        EngineerVerifierLoopOutcome::CancellationPending { .. }
    ));

    clock.set(at(12));
    let recovered_controller = fixture.loop_with_clock(clock.clone());
    let mut recovered = fixture.broker("runtime.loop.recovered", clock);
    let never = NeverExecutor::default();
    let outcome = recovered_controller
        .drive(
            &mut recovered,
            &never,
            fixture.input(
                b"old\n",
                "lease.loop.crash",
                "workspace.loop.crash",
                "recovery.loop.crash",
                "grant.loop.crash",
                &fixture.environment_digest,
            ),
        )
        .unwrap();
    assert!(matches!(
        outcome,
        EngineerVerifierLoopOutcome::Failed {
            reason: EngineerVerifierFailureReason::ExecutorOutcomeUnknown,
            ..
        }
    ));
    assert_eq!(never.calls.load(Ordering::SeqCst), 0);
    assert_eq!(recovered.backend_calls(), 0);
    assert_eq!(recovered.active_root_count(), 0);
    let state = recovered_controller
        .execution()
        .load(&fixture.plan.run_id)
        .unwrap()
        .envelope
        .engineer_verifier
        .unwrap();
    assert_eq!(state.phase, EngineerVerifierPhaseV1::Failed);
    assert!(state.workspace.unwrap().closed);
    let phase_events = recovered_controller
        .log()
        .load_run(&fixture.plan.run_id)
        .unwrap();
    let phase_json = phase_events
        .last()
        .unwrap()
        .metadata
        .get("engineer_verifier_phase_v1")
        .unwrap()
        .as_str()
        .unwrap();
    let phase: EngineerVerifierPhaseProjectionV1 = serde_json::from_str(phase_json).unwrap();
    assert_eq!(
        phase.trigger,
        EngineerVerifierTriggerV1::ExecutorOutcomeUnknown
    );
}

#[test]
fn changed_existing_jsonl_byte_fails_before_recovery_authority_or_effect() {
    let fixture = Fixture::new();
    let clock = MutableClock::new(at(10));
    let controller = fixture.loop_with_clock(clock.clone());
    fixture.initialize(&controller);
    let mut original = fixture.broker("runtime.loop.jsonl-crashed", clock.clone());
    let panic_executor = PanicExecutor::default();
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = controller.drive(
            &mut original,
            &panic_executor,
            fixture.input(
                b"old\n",
                "lease.loop.jsonl",
                "workspace.loop.jsonl",
                "recovery.loop.jsonl",
                "grant.loop.jsonl",
                &fixture.environment_digest,
            ),
        );
    }))
    .is_err());
    let raw = fs::read(controller.log().path()).unwrap();
    let mut event: ovca_types::RunEvent =
        serde_json::from_slice(raw.strip_suffix(b"\n").unwrap()).unwrap();
    event.sequence = 1;
    let mut changed = serde_json::to_vec(&event).unwrap();
    changed.push(b'\n');
    assert_ne!(changed, raw);
    fs::write(controller.log().path(), changed).unwrap();

    clock.set(at(12));
    let recovered_controller = fixture.loop_with_clock(clock.clone());
    let mut recovered = fixture.broker("runtime.loop.jsonl-recovered", clock);
    let never = NeverExecutor::default();
    assert!(matches!(
        recovered_controller.drive(
            &mut recovered,
            &never,
            fixture.input(
                b"old\n",
                "lease.loop.jsonl",
                "workspace.loop.jsonl",
                "recovery.loop.jsonl",
                "grant.loop.jsonl",
                &fixture.environment_digest,
            ),
        ),
        Err(ovca_langgraph::engineer_verifier_loop::EngineerVerifierLoopError::ProjectionConflict)
    ));
    assert_eq!(never.calls.load(Ordering::SeqCst), 0);
    assert_eq!(recovered.backend_calls(), 0);
    assert_eq!(recovered.active_root_count(), 0);
}

#[test]
fn retry_closes_attempt_one_and_derives_a_fresh_attempt_two_authority() {
    let fixture = Fixture::new();
    let clock = MutableClock::new(at(10));
    let controller = fixture.loop_with_clock(clock.clone());
    fixture.initialize(&controller);
    fixture.publish_capability();
    let mut broker = fixture.broker("runtime.loop.retry", clock.clone());
    let retry = RoleExecutionOutcome::RetryRequired {
        completed_attempt: 1,
        next_attempt: 2,
        cause: ovca_runtime_core::RoleRetryCause::Failed,
        usage: RoleExecutionUsage::Unavailable,
    };
    let executor = DeterministicFakeRoleExecutor::try_new([
        RoleExecutionScript {
            request: RoleExecutionRequest {
                invocation: invocation(),
                attempt: 1,
            },
            outcome: retry,
        },
        RoleExecutionScript {
            request: RoleExecutionRequest {
                invocation: invocation(),
                attempt: 2,
            },
            outcome: completed_outcome(2),
        },
    ])
    .unwrap();
    let first = controller
        .drive(
            &mut broker,
            &executor,
            fixture.input(
                b"old\n",
                "lease.loop.retry.1",
                "workspace.loop.retry.1",
                "recovery.loop.retry.1",
                "grant.loop.retry.1",
                &fixture.environment_digest,
            ),
        )
        .unwrap();
    assert!(matches!(
        first,
        EngineerVerifierLoopOutcome::RetryPending { .. }
    ));
    assert_eq!(broker.backend_calls(), 0);
    assert_eq!(broker.active_root_count(), 0);

    let changed_seed = controller.drive(
        &mut broker,
        &executor,
        fixture.input(
            b"different\n",
            "lease.loop.retry.2",
            "workspace.loop.retry.2",
            "recovery.loop.retry.2",
            "grant.loop.retry.2",
            &fixture.environment_digest,
        ),
    );
    assert!(matches!(
        changed_seed,
        Err(ovca_langgraph::engineer_verifier_loop::EngineerVerifierLoopError::ProjectionConflict)
    ));
    assert_eq!(broker.backend_calls(), 0);
    assert_eq!(broker.active_root_count(), 0);
    let retry_pending = controller
        .execution()
        .load(&fixture.plan.run_id)
        .unwrap()
        .envelope
        .engineer_verifier
        .unwrap();
    assert_eq!(retry_pending.attempt, 1);
    assert_eq!(retry_pending.phase, EngineerVerifierPhaseV1::RetryPending);

    let mut corrected = fixture.broker("runtime.loop.retry.corrected", clock);
    let second = controller
        .drive(
            &mut corrected,
            &executor,
            fixture.input(
                b"old\n",
                "lease.loop.retry.2",
                "workspace.loop.retry.2",
                "recovery.loop.retry.2",
                "grant.loop.retry.2",
                &fixture.environment_digest,
            ),
        )
        .unwrap();
    assert!(matches!(
        second,
        EngineerVerifierLoopOutcome::Reviewing { .. }
    ));
    let state = controller
        .execution()
        .load(&fixture.plan.run_id)
        .unwrap()
        .envelope
        .engineer_verifier
        .unwrap();
    assert_eq!(state.attempt, 2);
    assert_eq!(state.phase, EngineerVerifierPhaseV1::Reviewing);
    assert_eq!(corrected.backend_calls(), 1);
    assert_eq!(corrected.active_root_count(), 0);
}

#[test]
fn retry_pending_cancellation_wins_before_a_new_lease_or_executor_call() {
    let fixture = Fixture::new();
    let clock = MutableClock::new(at(10));
    let controller = fixture.loop_with_clock(clock.clone());
    fixture.initialize(&controller);
    let mut broker = fixture.broker("runtime.loop.retry-cancel", clock);
    let retry_executor = DeterministicFakeRoleExecutor::try_new([RoleExecutionScript {
        request: RoleExecutionRequest {
            invocation: invocation(),
            attempt: 1,
        },
        outcome: RoleExecutionOutcome::RetryRequired {
            completed_attempt: 1,
            next_attempt: 2,
            cause: ovca_runtime_core::RoleRetryCause::Failed,
            usage: RoleExecutionUsage::Unavailable,
        },
    }])
    .unwrap();
    let first = controller
        .drive(
            &mut broker,
            &retry_executor,
            fixture.input(
                b"old\n",
                "lease.loop.retry-cancel.1",
                "workspace.loop.retry-cancel.1",
                "recovery.loop.retry-cancel.1",
                "grant.loop.retry-cancel.1",
                &fixture.environment_digest,
            ),
        )
        .unwrap();
    assert!(matches!(
        first,
        EngineerVerifierLoopOutcome::RetryPending { .. }
    ));
    controller
        .request_cancellation(&fixture.plan.run_id, "cancel.loop.retry")
        .unwrap();

    let never = NeverExecutor::default();
    let cancelled = controller
        .drive(
            &mut broker,
            &never,
            fixture.input(
                b"old\n",
                "lease.loop.retry-cancel.2",
                "workspace.loop.retry-cancel.2",
                "recovery.loop.retry-cancel.2",
                "grant.loop.retry-cancel.2",
                &fixture.environment_digest,
            ),
        )
        .unwrap();
    assert!(matches!(
        cancelled,
        EngineerVerifierLoopOutcome::Cancelled { .. }
    ));
    assert_eq!(never.calls.load(Ordering::SeqCst), 0);
    assert_eq!(broker.backend_calls(), 0);
    assert_eq!(broker.active_root_count(), 0);
    let state = controller
        .execution()
        .load(&fixture.plan.run_id)
        .unwrap()
        .envelope
        .engineer_verifier
        .unwrap();
    assert_eq!(state.attempt, 1);
    assert_eq!(state.phase, EngineerVerifierPhaseV1::Cancelled);
}

#[test]
fn evidence_verdict_is_independently_bound_and_pass_only() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.behavior.criteria[0].kind,
        BehaviorKind::Verification
    );
    assert!(fixture.selection.validate().is_ok());
    assert!(fixture.capability.validate_commands().is_ok());
    assert_ne!(VerificationVerdict::Pass, VerificationVerdict::Fail);
}
