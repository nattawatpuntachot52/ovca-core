use chrono::{TimeZone, Utc};
use ovca_storage::{CasOutcome, EvidenceBank, EvidenceKey, ProjectionExpectation};
use ovca_types::{
    select_targeted_rerun, verification_policy_digest, verification_sha256_hex, BehaviorBinding,
    BehaviorCriterion, BehaviorKind, BehavioralAcceptanceContract, CapabilityDefinition,
    CapabilityRegistryRow, CapabilityRegistrySnapshot, ChangedPathEntry, ChangedPathKind,
    ChangedPathManifest, ChangedPathSelector, ContractVersion, DeniedAccess, DigestAlgorithm,
    GoalId, LocalMachinePolicy, PathSelectorKind, RunId, ShellPolicy, TargetedRerunOutcome,
    TargetedRerunRequest, TargetedRerunSelection, TaskId, UnknownPathPolicy, VerificationCommand,
    VerificationFailureCategory, VerificationVerdict, WorkerId, WorkingDirectory,
    LOCAL_VERIFICATION_CONTRACT_VERSION,
};
use ovca_verifier::bundle::{expected_failure_identity_keys, FailureIdentityMap};
use ovca_verifier::execution::{
    EnvironmentBindings, ExecutableProfile, ExecutableRegistry, ExecutionLimits,
};
use ovca_verifier::snapshot::{SourceFile, SourceManifest};
use ovca_verifier::{
    verify_and_publish, VerifierOutcome, VerifierRequest, VerifierRequestRejectionCode,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;
use tempfile::{tempdir, TempDir};

const RAW_SENTINEL: &str = "RAW_SECRET_SENTINEL_MUST_NOT_BE_SERIALIZED";

fn executable_profile_tempdir() -> TempDir {
    let current_executable = std::env::current_exe().unwrap();
    let trusted_parent = current_executable.parent().unwrap();
    tempfile::tempdir_in(trusted_parent).unwrap()
}

#[cfg(windows)]
fn create_directory_redirect(target: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_dir(target, link)
}

#[cfg(unix)]
fn create_directory_redirect(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[test]
#[allow(clippy::zombie_processes)] // Exercises verifier cleanup after the parent exits unwaited.
fn child_probe() {
    let Ok(mode) =
        std::env::var("OVCA_CHILD_MODE").or_else(|_| std::env::var("OVCA_CHILD_MODE_SECOND"))
    else {
        return;
    };
    match mode.as_str() {
        "pass" => {
            writeln!(io::stdout(), "{RAW_SENTINEL}").unwrap();
            writeln!(io::stderr(), "stderr-{RAW_SENTINEL}").unwrap();
        }
        "fail" => {
            writeln!(io::stderr(), "intentional child failure {RAW_SENTINEL}").unwrap();
            io::stderr().flush().unwrap();
            std::process::exit(7);
        }
        "output" => {
            io::stdout().write_all(b"0123456789").unwrap();
            io::stdout().flush().unwrap();
            thread::sleep(Duration::from_secs(5));
        }
        "mutate_snapshot" => {
            fs::write("input.txt", b"tampered snapshot").unwrap();
        }
        "tree_timeout" => {
            let marker = std::env::var_os("OVCA_CHILD_MARKER").unwrap();
            let mut grandchild = Command::new(std::env::current_exe().unwrap())
                .arg("child_probe")
                .arg("--exact")
                .arg("--nocapture")
                .env_clear()
                .env("OVCA_CHILD_MODE", "grandchild")
                .env("OVCA_CHILD_MARKER", marker)
                .spawn()
                .unwrap();
            thread::sleep(Duration::from_secs(5));
            let _ = grandchild.wait();
        }
        "grandchild" => {
            thread::sleep(Duration::from_millis(400));
            fs::write(std::env::var_os("OVCA_CHILD_MARKER").unwrap(), b"escaped").unwrap();
        }
        "tamper_later_executable" => {
            let path = std::env::var_os("OVCA_LATER_EXECUTABLE").unwrap();
            let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
            file.write_all(b"changed-after-command-one").unwrap();
            file.flush().unwrap();
        }
        "mark_execution" => {
            fs::write(std::env::var_os("OVCA_CHILD_MARKER").unwrap(), b"executed").unwrap();
        }
        "parent_exit_with_descendant" => {
            Command::new(std::env::current_exe().unwrap())
                .arg("child_probe")
                .arg("--exact")
                .arg("--nocapture")
                .env_clear()
                .env("OVCA_CHILD_MODE", "grandchild_hold_pipes")
                .env(
                    "OVCA_CHILD_MARKER",
                    std::env::var_os("OVCA_CHILD_MARKER").unwrap(),
                )
                .spawn()
                .unwrap();
        }
        "grandchild_hold_pipes" => {
            thread::sleep(Duration::from_millis(500));
            fs::write(std::env::var_os("OVCA_CHILD_MARKER").unwrap(), b"escaped").unwrap();
            thread::sleep(Duration::from_secs(5));
        }
        "redirect_later_cwd" => {
            let later = std::env::current_dir().unwrap().join("later");
            fs::remove_dir_all(&later).unwrap();
            create_directory_redirect(
                Path::new(&std::env::var_os("OVCA_REDIRECT_TARGET").unwrap()),
                &later,
            )
            .unwrap();
        }
        _ => panic!("unexpected child mode"),
    }
    io::stdout().flush().unwrap();
    io::stderr().flush().unwrap();
    std::process::exit(0);
}

struct Fixture {
    source: TempDir,
    durable: TempDir,
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
    fn new(mode: &str, extra_environment: BTreeMap<String, String>) -> Self {
        let source = tempdir().unwrap();
        let durable = tempdir().unwrap();
        fs::write(source.path().join("input.txt"), b"frozen source\n").unwrap();
        let manifest = SourceManifest {
            files: vec![SourceFile {
                logical_path: "input.txt".to_owned(),
                sha256: verification_sha256_hex(b"frozen source\n"),
            }],
        };
        let executable = std::env::current_exe().unwrap();
        let executable_digest = verification_sha256_hex(&fs::read(&executable).unwrap());
        let mut environment_names = BTreeSet::from(["OVCA_CHILD_MODE".to_owned()]);
        environment_names.extend(extra_environment.keys().cloned());
        let policy = LocalMachinePolicy {
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
        };
        let capability = CapabilityDefinition {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            capability_id: "capability.v3".to_owned(),
            revision: 1,
            criterion_ids: vec!["criterion.v3".to_owned()],
            dependencies: vec![],
            changed_path_selectors: vec![ChangedPathSelector {
                kind: PathSelectorKind::Exact,
                path: "input.txt".to_owned(),
            }],
            policy,
            commands: vec![VerificationCommand {
                command_id: "command.v3".to_owned(),
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
            contract_id: "behavior.v3".to_owned(),
            binding: BehaviorBinding::Bound {
                goal_id: GoalId::from("goal.v3"),
                task_id: TaskId::from("task.v3"),
            },
            criteria: vec![BehaviorCriterion {
                criterion_id: "criterion.v3".to_owned(),
                order: 0,
                kind: BehaviorKind::Verification,
                text: "local verifier proves the frozen behavior".to_owned(),
                required: true,
                capability_ids: vec!["capability.v3".to_owned()],
            }],
        };
        let policy_digest = verification_policy_digest(std::slice::from_ref(&capability)).unwrap();
        let selection = selection(&capability, manifest.fingerprint().unwrap(), policy_digest);
        let registry = ExecutableRegistry {
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
        let mut values = BTreeMap::from([("OVCA_CHILD_MODE".to_owned(), mode.into())]);
        values.extend(
            extra_environment
                .into_iter()
                .map(|(name, value)| (name, value.into())),
        );
        let bindings = EnvironmentBindings { values };
        let environment_digest = bindings.digest_for(&environment_names).unwrap();
        let failures = failure_identities(1);
        Self {
            source,
            durable,
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

    fn bank(&self) -> EvidenceBank {
        EvidenceBank::try_new(self.durable.path()).unwrap()
    }

    fn add_later_executable_tamper_command(
        &mut self,
        later_executable: &Path,
        execution_marker: &Path,
    ) {
        let first_names = &mut self.capability.commands[0].environment_names;
        first_names.insert("OVCA_LATER_EXECUTABLE".to_owned());
        self.capability
            .policy
            .allowed_environment_names
            .insert("OVCA_LATER_EXECUTABLE".to_owned());
        self.capability
            .policy
            .allowed_environment_names
            .insert("OVCA_CHILD_MODE_SECOND".to_owned());
        self.capability
            .policy
            .allowed_environment_names
            .insert("OVCA_CHILD_MARKER".to_owned());
        self.capability
            .policy
            .allowed_executable_ids
            .insert("later-runner".to_owned());
        self.capability.commands.push(VerificationCommand {
            command_id: "command.v3.later".to_owned(),
            executable_id: "later-runner".to_owned(),
            argv: vec![
                "child_probe".to_owned(),
                "--exact".to_owned(),
                "--nocapture".to_owned(),
            ],
            cwd: WorkingDirectory::SnapshotRoot,
            environment_names: BTreeSet::from([
                "OVCA_CHILD_MARKER".to_owned(),
                "OVCA_CHILD_MODE_SECOND".to_owned(),
            ]),
        });

        self.registry
            .profiles
            .get_mut("test-runner")
            .unwrap()
            .allowed_environment_names
            .insert("OVCA_LATER_EXECUTABLE".to_owned());
        self.registry.profiles.insert(
            "later-runner".to_owned(),
            ExecutableProfile {
                executable_id: "later-runner".to_owned(),
                executable_path: later_executable.to_path_buf(),
                sha256: verification_sha256_hex(&fs::read(later_executable).unwrap()),
                enabled: true,
                approved: true,
                reviewed_offline: true,
                allowed_environment_names: BTreeSet::from([
                    "OVCA_CHILD_MARKER".to_owned(),
                    "OVCA_CHILD_MODE_SECOND".to_owned(),
                ]),
            },
        );
        self.bindings.values.insert(
            "OVCA_LATER_EXECUTABLE".to_owned(),
            later_executable.as_os_str().to_owned(),
        );
        self.bindings
            .values
            .insert("OVCA_CHILD_MODE_SECOND".to_owned(), "mark_execution".into());
        self.bindings.values.insert(
            "OVCA_CHILD_MARKER".to_owned(),
            execution_marker.as_os_str().to_owned(),
        );
        self.refresh_plan_bindings();
    }

    fn add_later_cwd_redirect_command(&mut self, redirect_target: &Path, marker: &Path) {
        fs::create_dir(self.source.path().join("later")).unwrap();
        fs::write(
            self.source.path().join("later").join("work.txt"),
            b"frozen later cwd\n",
        )
        .unwrap();
        self.manifest.files.push(SourceFile {
            logical_path: "later/work.txt".to_owned(),
            sha256: verification_sha256_hex(b"frozen later cwd\n"),
        });

        self.capability.commands[0]
            .environment_names
            .insert("OVCA_REDIRECT_TARGET".to_owned());
        for name in [
            "OVCA_REDIRECT_TARGET",
            "OVCA_CHILD_MODE_SECOND",
            "OVCA_CHILD_MARKER",
        ] {
            self.capability
                .policy
                .allowed_environment_names
                .insert(name.to_owned());
            self.registry
                .profiles
                .get_mut("test-runner")
                .unwrap()
                .allowed_environment_names
                .insert(name.to_owned());
        }
        self.capability.commands.push(VerificationCommand {
            command_id: "command.v3.redirected-cwd".to_owned(),
            executable_id: "test-runner".to_owned(),
            argv: vec![
                "child_probe".to_owned(),
                "--exact".to_owned(),
                "--nocapture".to_owned(),
            ],
            cwd: WorkingDirectory::Relative {
                path: "later".to_owned(),
            },
            environment_names: BTreeSet::from([
                "OVCA_CHILD_MARKER".to_owned(),
                "OVCA_CHILD_MODE_SECOND".to_owned(),
            ]),
        });
        self.bindings.values.insert(
            "OVCA_REDIRECT_TARGET".to_owned(),
            redirect_target.as_os_str().to_owned(),
        );
        self.bindings
            .values
            .insert("OVCA_CHILD_MODE_SECOND".to_owned(), "mark_execution".into());
        self.bindings.values.insert(
            "OVCA_CHILD_MARKER".to_owned(),
            marker.as_os_str().to_owned(),
        );
        self.refresh_plan_bindings();
    }

    fn refresh_plan_bindings(&mut self) {
        let environment_names = self
            .capability
            .commands
            .iter()
            .flat_map(|command| command.environment_names.iter().cloned())
            .collect();
        self.environment_digest = self.bindings.digest_for(&environment_names).unwrap();
        let policy_digest =
            verification_policy_digest(std::slice::from_ref(&self.capability)).unwrap();
        self.selection = selection(
            &self.capability,
            self.manifest.fingerprint().unwrap(),
            policy_digest,
        );
        self.failures = failure_identities(self.capability.commands.len());
    }

    fn run(
        &self,
        snapshot_root: &Path,
        registry: &ExecutableRegistry,
        expectation: &ProjectionExpectation,
        limits: ExecutionLimits,
    ) -> VerifierOutcome {
        verify_and_publish(
            VerifierRequest {
                behavior: &self.behavior,
                capabilities: std::slice::from_ref(&self.capability),
                selection: &self.selection,
                source_manifest: &self.manifest,
                source_root: self.source.path(),
                snapshot_root,
                executable_registry: registry,
                environment_bindings: &self.bindings,
                environment_digest: &self.environment_digest,
                limits,
                implementation_actor: WorkerId::from("engineer.implementation"),
                verifier_actor: WorkerId::from("auditor.independent"),
                created_at: Utc.with_ymd_and_hms(2026, 8, 10, 12, 0, 0).unwrap(),
                failure_identities: &self.failures,
            },
            &self.bank(),
            expectation,
        )
        .unwrap()
    }
}

fn default_limits() -> ExecutionLimits {
    ExecutionLimits {
        timeout_millis: 5_000,
        stdout_cap_bytes: 16_384,
        stderr_cap_bytes: 16_384,
    }
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
        run_id: RunId::from("run.v3"),
        goal_id: GoalId::from("goal.v3"),
        task_id: TaskId::from("task.v3"),
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

fn failure_identities(command_count: usize) -> FailureIdentityMap {
    expected_failure_identity_keys(command_count)
        .unwrap()
        .into_iter()
        .enumerate()
        .map(|(index, key)| (key, format!("failure.v3.{index:03}")))
        .collect()
}

fn published(outcome: VerifierOutcome) -> ovca_verifier::PublishedVerification {
    match outcome {
        VerifierOutcome::Published(value) => *value,
        VerifierOutcome::Rejected(value) => panic!("unexpected rejection: {:?}", value.code),
    }
}

fn assert_profile_rejected_without_execution_or_publication(
    fixture: &Fixture,
    registry: &ExecutableRegistry,
    marker: &Path,
) {
    assert!(!registry.validate_structure());
    let bank = fixture.bank();
    assert!(
        !bank.database_path().exists(),
        "structural preflight must not open the evidence database"
    );
    let snapshot = tempdir().unwrap();
    let outcome = fixture.run(
        snapshot.path(),
        registry,
        &ProjectionExpectation::Absent,
        default_limits(),
    );
    assert!(matches!(
        outcome,
        VerifierOutcome::Rejected(value)
            if value.code == VerifierRequestRejectionCode::InvalidExecutableProfile
    ));
    assert!(!marker.exists(), "rejected profile produced a side effect");
    assert!(
        !bank.database_path().exists(),
        "rejection created a bundle record or advanced the CAS projection"
    );
}

#[test]
fn deterministic_pass_reopens_and_raw_output_never_enters_evidence() {
    let fixture = Fixture::new("pass", BTreeMap::new());
    let first_snapshot = tempdir().unwrap();
    let first = published(fixture.run(
        first_snapshot.path(),
        &fixture.registry,
        &ProjectionExpectation::Absent,
        default_limits(),
    ));
    assert_eq!(first.bundle.verdict, VerificationVerdict::Pass);
    assert_eq!(first.transcript.commands.len(), 1);
    let canonical = first.bundle.canonical_json_bytes().unwrap();
    assert!(!String::from_utf8(canonical.clone())
        .unwrap()
        .contains(RAW_SENTINEL));
    assert!(
        !String::from_utf8(first.transcript.canonical_json_bytes().unwrap())
            .unwrap()
            .contains(RAW_SENTINEL)
    );

    let token = match &first.storage.projection {
        CasOutcome::Applied(current) => current.token.clone(),
        other => panic!("expected applied projection: {other:?}"),
    };
    let digest = match &first.storage.publication {
        ovca_storage::PublishOutcome::Inserted(record)
        | ovca_storage::PublishOutcome::ExistingIdentical(record) => record.digest.clone(),
    };
    let second_snapshot = tempdir().unwrap();
    let second = published(fixture.run(
        second_snapshot.path(),
        &fixture.registry,
        &ProjectionExpectation::Token(token),
        default_limits(),
    ));
    assert_eq!(canonical, second.bundle.canonical_json_bytes().unwrap());
    assert_eq!(first.bundle.bundle_id, second.bundle.bundle_id);
    let reopened = EvidenceBank::try_new(fixture.durable.path()).unwrap();
    assert_eq!(
        reopened.load_bundle(&digest).unwrap().unwrap().bundle,
        first.bundle
    );
}

#[test]
fn all_nonpass_verdicts_use_closed_failure_categories() {
    let fail = Fixture::new("fail", BTreeMap::new());
    let fail_snapshot = tempdir().unwrap();
    let fail_result = published(fail.run(
        fail_snapshot.path(),
        &fail.registry,
        &ProjectionExpectation::Absent,
        default_limits(),
    ));
    assert_eq!(fail_result.bundle.verdict, VerificationVerdict::Fail);
    assert_eq!(
        fail_result.bundle.failures[0].category,
        VerificationFailureCategory::TestFailedUnclassified
    );

    let blocked = Fixture::new("pass", BTreeMap::new());
    let blocked_snapshot = tempdir().unwrap();
    let blocked_result = published(blocked.run(
        blocked_snapshot.path(),
        &ExecutableRegistry::default(),
        &ProjectionExpectation::Absent,
        default_limits(),
    ));
    assert_eq!(blocked_result.bundle.verdict, VerificationVerdict::Blocked);
    assert!(blocked_result.transcript.commands.is_empty());
    assert_eq!(
        blocked_result.bundle.failures[0].category,
        VerificationFailureCategory::PolicyBlock
    );

    let invalid = Fixture::new("pass", BTreeMap::new());
    let mut bad_registry = invalid.registry.clone();
    bad_registry.profiles.get_mut("test-runner").unwrap().sha256 = "0".repeat(64);
    let invalid_snapshot = tempdir().unwrap();
    let invalid_result = published(invalid.run(
        invalid_snapshot.path(),
        &bad_registry,
        &ProjectionExpectation::Absent,
        default_limits(),
    ));
    assert_eq!(invalid_result.bundle.verdict, VerificationVerdict::Invalid);
    assert!(invalid_result.transcript.commands.is_empty());
    assert_eq!(
        invalid_result.bundle.failures[0].category,
        VerificationFailureCategory::ContractViolation
    );
}

#[test]
fn output_limit_and_zero_cap_are_bounded_without_raw_output() {
    let fixture = Fixture::new("output", BTreeMap::new());
    let snapshot = tempdir().unwrap();
    let result = published(fixture.run(
        snapshot.path(),
        &fixture.registry,
        &ProjectionExpectation::Absent,
        ExecutionLimits {
            timeout_millis: 2_000,
            stdout_cap_bytes: 0,
            stderr_cap_bytes: 128,
        },
    ));
    assert_eq!(result.bundle.verdict, VerificationVerdict::Blocked);
    assert_eq!(result.transcript.commands[0].stdout_bytes, 0);
    assert_eq!(
        result.transcript.commands[0].stdout_sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        result.bundle.failures[0].category,
        VerificationFailureCategory::PolicyBlock
    );
}

#[test]
fn timeout_terminates_the_contained_process_tree_before_publication() {
    let marker_root = tempdir().unwrap();
    let marker = marker_root.path().join("escaped.txt");
    let fixture = Fixture::new(
        "tree_timeout",
        BTreeMap::from([(
            "OVCA_CHILD_MARKER".to_owned(),
            marker.to_string_lossy().into_owned(),
        )]),
    );
    let snapshot = tempdir().unwrap();
    let result = published(fixture.run(
        snapshot.path(),
        &fixture.registry,
        &ProjectionExpectation::Absent,
        ExecutionLimits {
            timeout_millis: 100,
            stdout_cap_bytes: 16_384,
            stderr_cap_bytes: 16_384,
        },
    ));
    assert_eq!(result.bundle.verdict, VerificationVerdict::Timeout);
    assert_eq!(
        result.bundle.failures[0].category,
        VerificationFailureCategory::Timeout
    );
    thread::sleep(Duration::from_millis(700));
    assert!(!marker.exists(), "grandchild escaped containment");
}

#[test]
fn later_executable_change_is_blocked_before_its_own_spawn() {
    let executable_root = executable_profile_tempdir();
    let later_executable = executable_root.path().join(if cfg!(windows) {
        "later-runner.exe"
    } else {
        "later-runner"
    });
    fs::copy(std::env::current_exe().unwrap(), &later_executable).unwrap();
    let marker = executable_root.path().join("later-command-executed.txt");
    let mut fixture = Fixture::new("tamper_later_executable", BTreeMap::new());
    fixture.add_later_executable_tamper_command(&later_executable, &marker);

    let snapshot = tempdir().unwrap();
    let result = published(fixture.run(
        snapshot.path(),
        &fixture.registry,
        &ProjectionExpectation::Absent,
        default_limits(),
    ));

    assert_eq!(result.bundle.verdict, VerificationVerdict::Invalid);
    assert_eq!(result.transcript.commands.len(), 1);
    assert_eq!(result.bundle.failures.len(), 1);
    assert_eq!(
        result.bundle.failures[0].summary,
        "verification executable digest mismatch"
    );
    assert!(!marker.exists(), "changed later executable was spawned");
}

#[test]
fn normal_parent_exit_reaps_descendant_before_pipe_join_and_publication() {
    let marker_root = tempdir().unwrap();
    let marker = marker_root.path().join("escaped-after-parent-exit.txt");
    let fixture = Fixture::new(
        "parent_exit_with_descendant",
        BTreeMap::from([(
            "OVCA_CHILD_MARKER".to_owned(),
            marker.to_string_lossy().into_owned(),
        )]),
    );
    let snapshot = tempdir().unwrap();
    let result = published(fixture.run(
        snapshot.path(),
        &fixture.registry,
        &ProjectionExpectation::Absent,
        ExecutionLimits {
            timeout_millis: 3_000,
            stdout_cap_bytes: 16_384,
            stderr_cap_bytes: 16_384,
        },
    ));
    assert_eq!(result.bundle.verdict, VerificationVerdict::Pass);
    thread::sleep(Duration::from_millis(700));
    assert!(!marker.exists(), "descendant survived bundle publication");
}

#[test]
fn cmd_and_bat_profiles_are_rejected_structurally_without_side_effects() {
    for extension in ["CmD", "BAT"] {
        let executable_root = tempdir().unwrap();
        let executable = executable_root
            .path()
            .join(format!("innocent-runner.{extension}"));
        fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        let marker = executable_root.path().join("shell-profile-executed.txt");
        let fixture = Fixture::new(
            "mark_execution",
            BTreeMap::from([(
                "OVCA_CHILD_MARKER".to_owned(),
                marker.to_string_lossy().into_owned(),
            )]),
        );
        assert!(fixture.registry.validate_structure());
        let mut registry = fixture.registry.clone();
        let profile = registry.profiles.get_mut("test-runner").unwrap();
        profile.executable_path = executable.clone();
        profile.sha256 = verification_sha256_hex(&fs::read(executable).unwrap());
        assert_profile_rejected_without_execution_or_publication(&fixture, &registry, &marker);
    }
}

#[test]
fn safe_logical_id_cannot_resolve_to_a_frozen_shell_basename() {
    for basename in [
        "sh",
        "sh.ExE",
        "BASH",
        "bash.exe",
        "zsh",
        "ZSH.EXE",
        "cmd",
        "CmD.eXe",
        "powershell",
        "PowerShell.EXE",
        "pwsh",
        "PWSH.exe",
    ] {
        let executable_root = tempdir().unwrap();
        let executable = executable_root.path().join(basename);
        fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        let marker = executable_root.path().join("shell-basename-executed.txt");
        let fixture = Fixture::new(
            "mark_execution",
            BTreeMap::from([(
                "OVCA_CHILD_MARKER".to_owned(),
                marker.to_string_lossy().into_owned(),
            )]),
        );
        let mut registry = fixture.registry.clone();
        let profile = registry.profiles.get_mut("test-runner").unwrap();
        profile.executable_path = executable.clone();
        profile.sha256 = verification_sha256_hex(&fs::read(executable).unwrap());
        assert_profile_rejected_without_execution_or_publication(&fixture, &registry, &marker);
    }
}

#[test]
fn formerly_missing_shell_executable_ids_map_to_invalid_command() {
    for executable_id in ["sh.exe", "bash.exe", "zsh.exe", "pwsh.exe"] {
        let marker_root = tempdir().unwrap();
        let marker = marker_root.path().join("invalid-command-executed.txt");
        let mut fixture = Fixture::new(
            "mark_execution",
            BTreeMap::from([(
                "OVCA_CHILD_MARKER".to_owned(),
                marker.to_string_lossy().into_owned(),
            )]),
        );
        fixture.capability.commands[0].executable_id = executable_id.to_owned();
        let bank = fixture.bank();
        let snapshot = tempdir().unwrap();
        let outcome = fixture.run(
            snapshot.path(),
            &fixture.registry,
            &ProjectionExpectation::Absent,
            default_limits(),
        );
        assert!(matches!(
            outcome,
            VerifierOutcome::Rejected(value)
                if value.code == VerifierRequestRejectionCode::InvalidCommand
        ));
        assert!(!marker.exists(), "invalid command produced a side effect");
        assert!(
            !bank.database_path().exists(),
            "invalid command created a bundle or advanced CAS"
        );
    }
}

#[cfg(windows)]
#[test]
fn trailing_dot_or_space_win32_aliases_are_rejected_before_resolution() {
    for (canonical_name, alias_name) in [
        ("cmd.exe", "cmd.exe."),
        ("powershell.exe", "powershell.exe "),
        ("runner.cmd", "runner.cmd."),
        ("runner.bat", "runner.bat "),
    ] {
        let executable_root = tempdir().unwrap();
        let canonical = executable_root.path().join(canonical_name);
        fs::copy(std::env::current_exe().unwrap(), &canonical).unwrap();
        let alias = executable_root.path().join(alias_name);
        let marker = executable_root.path().join("win32-alias-executed.txt");
        let fixture = Fixture::new(
            "mark_execution",
            BTreeMap::from([(
                "OVCA_CHILD_MARKER".to_owned(),
                marker.to_string_lossy().into_owned(),
            )]),
        );
        let mut registry = fixture.registry.clone();
        let profile = registry.profiles.get_mut("test-runner").unwrap();
        profile.executable_path = alias;
        profile.sha256 = verification_sha256_hex(&fs::read(canonical).unwrap());
        assert_profile_rejected_without_execution_or_publication(&fixture, &registry, &marker);
    }

    let executable_root = tempdir().unwrap();
    let canonical_directory = executable_root.path().join("reviewed-bin");
    fs::create_dir(&canonical_directory).unwrap();
    let canonical = canonical_directory.join("runner.exe");
    fs::copy(std::env::current_exe().unwrap(), &canonical).unwrap();
    let alias = executable_root
        .path()
        .join("reviewed-bin.")
        .join("runner.exe");
    let marker = executable_root.path().join("win32-component-executed.txt");
    let fixture = Fixture::new(
        "mark_execution",
        BTreeMap::from([(
            "OVCA_CHILD_MARKER".to_owned(),
            marker.to_string_lossy().into_owned(),
        )]),
    );
    let mut registry = fixture.registry.clone();
    let profile = registry.profiles.get_mut("test-runner").unwrap();
    profile.executable_path = alias;
    profile.sha256 = verification_sha256_hex(&fs::read(canonical).unwrap());
    assert_profile_rejected_without_execution_or_publication(&fixture, &registry, &marker);
}

#[cfg(windows)]
#[test]
fn ads_and_short_name_alias_grammar_is_rejected_in_final_and_intermediate_components() {
    for alias in [
        Path::new("runner.exe:stream").to_path_buf(),
        Path::new("RUNNER~1.EXE").to_path_buf(),
        Path::new("reviewed:bin").join("runner.exe"),
        Path::new("REVIEW~1").join("runner.exe"),
    ] {
        let executable_root = tempdir().unwrap();
        let marker = executable_root.path().join("alias-grammar-executed.txt");
        let fixture = Fixture::new(
            "mark_execution",
            BTreeMap::from([(
                "OVCA_CHILD_MARKER".to_owned(),
                marker.to_string_lossy().into_owned(),
            )]),
        );
        let mut registry = fixture.registry.clone();
        registry
            .profiles
            .get_mut("test-runner")
            .unwrap()
            .executable_path = executable_root.path().join(alias);
        assert_profile_rejected_without_execution_or_publication(&fixture, &registry, &marker);
    }
}

#[cfg(windows)]
#[test]
fn stable_executable_ancestor_reparse_is_blocked_without_execution() {
    let target_root = executable_profile_tempdir();
    let executable = target_root.path().join("runner.exe");
    fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let profile_root = executable_profile_tempdir();
    let redirect = profile_root.path().join("reviewed-bin");
    create_directory_redirect(target_root.path(), &redirect).unwrap();
    let marker = profile_root.path().join("ancestor-reparse-executed.txt");
    let fixture = Fixture::new(
        "mark_execution",
        BTreeMap::from([(
            "OVCA_CHILD_MARKER".to_owned(),
            marker.to_string_lossy().into_owned(),
        )]),
    );
    let mut registry = fixture.registry.clone();
    let profile = registry.profiles.get_mut("test-runner").unwrap();
    profile.executable_path = redirect.join("runner.exe");
    profile.sha256 = verification_sha256_hex(&fs::read(executable).unwrap());
    assert!(registry.validate_structure());
    let snapshot = tempdir().unwrap();

    let result = published(fixture.run(
        snapshot.path(),
        &registry,
        &ProjectionExpectation::Absent,
        default_limits(),
    ));

    assert_eq!(result.bundle.verdict, VerificationVerdict::Invalid);
    assert!(result.transcript.commands.is_empty());
    assert_eq!(
        result.bundle.failures[0].summary,
        "verification executable digest mismatch"
    );
    assert!(!marker.exists(), "reparse ancestor command was executed");
}

#[test]
fn earlier_command_cannot_redirect_later_cwd_outside_snapshot() {
    let external = tempdir().unwrap();
    let marker = external.path().join("redirected-command-executed.txt");
    let mut fixture = Fixture::new("redirect_later_cwd", BTreeMap::new());
    fixture.add_later_cwd_redirect_command(external.path(), &marker);
    let snapshot = tempdir().unwrap();

    let result = published(fixture.run(
        snapshot.path(),
        &fixture.registry,
        &ProjectionExpectation::Absent,
        default_limits(),
    ));

    assert_eq!(result.bundle.verdict, VerificationVerdict::Invalid);
    assert_eq!(result.transcript.commands.len(), 1);
    assert_eq!(result.bundle.failures.len(), 1);
    assert_eq!(
        result.bundle.failures[0].summary,
        "verification snapshot integrity mismatch"
    );
    assert!(
        fs::symlink_metadata(snapshot.path().join("later"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "first command did not create the redirect fixture"
    );
    assert!(!marker.exists(), "redirected later command was executed");
}

#[test]
fn snapshot_tamper_is_invalid_and_never_passes() {
    let fixture = Fixture::new("mutate_snapshot", BTreeMap::new());
    let snapshot = tempdir().unwrap();
    let result = published(fixture.run(
        snapshot.path(),
        &fixture.registry,
        &ProjectionExpectation::Absent,
        default_limits(),
    ));
    assert_eq!(result.bundle.verdict, VerificationVerdict::Invalid);
    assert!(result
        .bundle
        .failures
        .iter()
        .any(|failure| failure.category == VerificationFailureCategory::ContractViolation));
}

#[test]
fn structural_rejection_partition_has_no_bundle_or_current_pointer() {
    let mut fixture = Fixture::new("pass", BTreeMap::new());
    fixture.behavior.contract_version = ContractVersion(2);
    fixture.capability.commands[0].argv[0] = "C:/unsafe".to_owned();
    let snapshot = tempdir().unwrap();
    let outcome = fixture.run(
        snapshot.path(),
        &fixture.registry,
        &ProjectionExpectation::Absent,
        default_limits(),
    );
    assert!(matches!(
        outcome,
        VerifierOutcome::Rejected(value)
            if value.code == VerifierRequestRejectionCode::InvalidContract
    ));
    assert!(fixture
        .bank()
        .load_current(&EvidenceKey {
            run_id: RunId::from("run.v3"),
            goal_id: GoalId::from("goal.v3"),
            task_id: TaskId::from("task.v3"),
        })
        .unwrap()
        .is_none());

    let mut command_only = Fixture::new("pass", BTreeMap::new());
    command_only.capability.commands[0].argv[0] = "C:/unsafe".to_owned();
    let snapshot = tempdir().unwrap();
    let outcome = command_only.run(
        snapshot.path(),
        &command_only.registry,
        &ProjectionExpectation::Absent,
        default_limits(),
    );
    assert!(matches!(
        outcome,
        VerifierOutcome::Rejected(value)
            if value.code == VerifierRequestRejectionCode::InvalidCommand
    ));
}

#[test]
fn extra_source_and_cas_conflict_fail_closed() {
    let extra = Fixture::new("pass", BTreeMap::new());
    fs::write(extra.source.path().join("extra.txt"), b"extra").unwrap();
    let snapshot = tempdir().unwrap();
    let outcome = extra.run(
        snapshot.path(),
        &extra.registry,
        &ProjectionExpectation::Absent,
        default_limits(),
    );
    assert!(matches!(
        outcome,
        VerifierOutcome::Rejected(value)
            if value.code == VerifierRequestRejectionCode::InvalidSourceManifest
    ));

    let conflict = Fixture::new("pass", BTreeMap::new());
    let first_snapshot = tempdir().unwrap();
    let first = published(conflict.run(
        first_snapshot.path(),
        &conflict.registry,
        &ProjectionExpectation::Absent,
        default_limits(),
    ));
    let wrong = match first.storage.projection {
        CasOutcome::Applied(mut current) => {
            current.token.state_digest = "f".repeat(64);
            current.token
        }
        other => panic!("expected applied projection: {other:?}"),
    };
    let second_snapshot = tempdir().unwrap();
    let second = published(conflict.run(
        second_snapshot.path(),
        &conflict.registry,
        &ProjectionExpectation::Token(wrong),
        default_limits(),
    ));
    assert!(matches!(second.storage.projection, CasOutcome::Conflict(_)));
}
