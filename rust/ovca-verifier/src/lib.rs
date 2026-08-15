//! Local deterministic independent verifier.
//!
//! This leaf crate executes only caller-reviewed local executable profiles. Its
//! egress enforcement status is policy-only; it does not claim kernel network
//! isolation. V3 publishes immutable bundles but creates no completion evidence.

pub mod bundle;
pub mod execution;
pub mod snapshot;

use bundle::{
    apply_verdict, build_bundle, failure_for_event, validate_failure_identity_map,
    BundleBuildError, BundleBuildInput, FailureCode, FailureEvent, FailureIdentityMap,
};
use chrono::{DateTime, Utc};
use execution::{
    execute_prepared, EnvironmentBindings, ExecutableRegistry, ExecutionError, ExecutionLimits,
    ExecutionTermination, PreparedExecution, RuntimePreflightFailure,
};
use ovca_storage::{
    EvidenceBank, LocalVerificationStoreError, ProjectionExpectation, PublishAndCasOutcome,
};
use ovca_types::{
    verification_command_digest, verification_policy_digest, verification_sha256_hex,
    BehavioralAcceptanceContract, CapabilityDefinition, CriterionResultVerdict,
    TargetedRerunSelection, VerificationTermination, VerificationTranscriptCommandIdentity,
    VerificationTranscriptIdentity, WorkerId,
};
use snapshot::{FrozenSnapshot, SnapshotError, SourceManifest};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierRequestRejectionCode {
    InvalidContract,
    InvalidCrossBinding,
    InvalidActorIdentity,
    VerifierNotIndependent,
    InvalidSourceManifest,
    InvalidCommand,
    InvalidExecutionLimits,
    InvalidFailureIdentity,
    InvalidExecutableProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifierRequestRejected {
    pub code: VerifierRequestRejectionCode,
}

pub struct VerifierRequest<'a> {
    pub behavior: &'a BehavioralAcceptanceContract,
    pub capabilities: &'a [CapabilityDefinition],
    pub selection: &'a TargetedRerunSelection,
    pub source_manifest: &'a SourceManifest,
    pub source_root: &'a Path,
    pub snapshot_root: &'a Path,
    pub executable_registry: &'a ExecutableRegistry,
    pub environment_bindings: &'a EnvironmentBindings,
    pub environment_digest: &'a str,
    pub limits: ExecutionLimits,
    pub implementation_actor: WorkerId,
    pub verifier_actor: WorkerId,
    pub created_at: DateTime<Utc>,
    pub failure_identities: &'a FailureIdentityMap,
}

#[derive(Debug)]
pub struct PublishedVerification {
    pub bundle: ovca_types::VerificationBundle,
    pub transcript: VerificationTranscriptIdentity,
    pub storage: PublishAndCasOutcome,
}

#[derive(Debug)]
pub enum VerifierOutcome {
    Rejected(VerifierRequestRejected),
    Published(Box<PublishedVerification>),
}

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("snapshot operation failed")]
    Snapshot(#[from] SnapshotError),
    #[error("contained command execution failed")]
    Execution(#[from] ExecutionError),
    #[error("bundle construction failed")]
    Bundle(#[from] BundleBuildError),
    #[error("Evidence Bank publication failed")]
    Storage(#[from] LocalVerificationStoreError),
}

pub fn verify_and_publish(
    request: VerifierRequest<'_>,
    evidence_bank: &EvidenceBank,
    expectation: &ProjectionExpectation,
) -> Result<VerifierOutcome, VerifierError> {
    if let Err(code) = structural_preflight(&request) {
        return Ok(VerifierOutcome::Rejected(VerifierRequestRejected { code }));
    }

    let planned = planned_commands(request.capabilities);
    let mut prepared = Vec::with_capacity(planned.len());
    for (sequence, (capability_index, command_index)) in planned.iter().copied().enumerate() {
        let command = &request.capabilities[capability_index].commands[command_index];
        match request
            .executable_registry
            .prepare(command, request.environment_bindings)
        {
            Ok(value) => prepared.push(value),
            Err(failure) => {
                let (verdict, failure_code) = runtime_preflight_shape(failure);
                return publish_pre_spawn(
                    &request,
                    evidence_bank,
                    expectation,
                    verdict,
                    failure_code,
                    sequence as u32,
                );
            }
        }
    }

    let snapshot = match FrozenSnapshot::materialize(
        request.source_root,
        request.snapshot_root,
        request.source_manifest,
    ) {
        Ok(value) => value,
        Err(SnapshotError::SourceChanged | SnapshotError::SourceMismatch) => {
            return publish_global_integrity(
                &request,
                evidence_bank,
                expectation,
                FailureCode::SourceDrift,
                request.selection.source_fingerprint.clone(),
                drift_digest("source"),
            );
        }
        Err(SnapshotError::SnapshotMismatch) => {
            return publish_global_integrity(
                &request,
                evidence_bank,
                expectation,
                FailureCode::SnapshotTamper,
                request.selection.source_fingerprint.clone(),
                request.selection.source_fingerprint.clone(),
            );
        }
        Err(error) => return Err(error.into()),
    };

    // Recheck the complete executable plan after snapshot materialization and
    // immediately before the first spawn. A changed executable is still a
    // publishable pre-spawn invalid outcome with no transcript entry.
    if let Some((sequence, _)) = prepared
        .iter()
        .enumerate()
        .find(|(_, command)| !command.digest_matches())
    {
        return publish_pre_spawn(
            &request,
            evidence_bank,
            expectation,
            CriterionResultVerdict::Invalid,
            FailureCode::ExecutableTamper,
            sequence as u32,
        );
    }

    let mut verdicts = request
        .behavior
        .criteria
        .iter()
        .map(|criterion| (criterion.criterion_id.clone(), CriterionResultVerdict::Pass))
        .collect::<BTreeMap<_, _>>();
    let mut failures = Vec::new();
    let mut transcript = VerificationTranscriptIdentity::default();

    for (sequence, ((capability_index, command_index), prepared)) in
        planned.iter().copied().zip(prepared.iter()).enumerate()
    {
        let capability = &request.capabilities[capability_index];
        let command = &capability.commands[command_index];
        let evidence = match execute_prepared(prepared, command, snapshot.root(), request.limits)? {
            PreparedExecution::Executed(value) => value,
            PreparedExecution::SnapshotTamper => {
                apply_verdict(
                    &mut verdicts,
                    request
                        .behavior
                        .criteria
                        .iter()
                        .map(|criterion| criterion.criterion_id.clone()),
                    CriterionResultVerdict::Invalid,
                );
                let failure = failure_for_event(
                    FailureEvent {
                        code: FailureCode::SnapshotTamper,
                        command_sequence: None,
                        pre_spawn: false,
                    },
                    request.failure_identities,
                    request.created_at,
                )?;
                push_failure_once(&mut failures, failure);
                break;
            }
            PreparedExecution::PreSpawn(failure) => {
                let (contribution, failure_code) = runtime_preflight_shape(failure);
                let remaining = request.capabilities[capability_index..]
                    .iter()
                    .flat_map(|capability| capability.criterion_ids.iter().cloned())
                    .collect::<BTreeSet<_>>();
                apply_verdict(&mut verdicts, remaining, contribution);
                failures.push(failure_for_event(
                    FailureEvent {
                        code: failure_code,
                        command_sequence: Some(sequence as u32),
                        pre_spawn: failure_code == FailureCode::ExecutableTamper,
                    },
                    request.failure_identities,
                    request.created_at,
                )?);
                break;
            }
        };
        let (termination, contribution, failure_code, terminal) = execution_shape(&evidence);
        transcript
            .commands
            .push(VerificationTranscriptCommandIdentity {
                sequence: sequence as u32,
                command_digest: verification_command_digest(capability, command_index)
                    .map_err(|_| BundleBuildError::InvalidBinding)?,
                executable_digest: evidence.executable_digest,
                termination,
                exit_code: evidence.exit_code,
                stdout_sha256: evidence.stdout_sha256,
                stderr_sha256: evidence.stderr_sha256,
                stdout_bytes: evidence.stdout_bytes,
                stderr_bytes: evidence.stderr_bytes,
            });
        apply_verdict(
            &mut verdicts,
            capability.criterion_ids.iter().cloned(),
            contribution,
        );
        if terminal {
            let remaining = request.capabilities[capability_index..]
                .iter()
                .flat_map(|capability| capability.criterion_ids.iter().cloned())
                .collect::<BTreeSet<_>>();
            apply_verdict(&mut verdicts, remaining, contribution);
        }
        if let Some(code) = failure_code {
            failures.push(failure_for_event(
                FailureEvent {
                    code,
                    command_sequence: Some(sequence as u32),
                    pre_spawn: false,
                },
                request.failure_identities,
                request.created_at,
            )?);
        }
        if terminal {
            break;
        }
    }

    let mut source_post = snapshot
        .source_post_fingerprint()
        .unwrap_or_else(|_| drift_digest("source"));
    if source_post != snapshot.source_pre_fingerprint() {
        apply_verdict(
            &mut verdicts,
            request
                .behavior
                .criteria
                .iter()
                .map(|criterion| criterion.criterion_id.clone()),
            CriterionResultVerdict::Invalid,
        );
        failures.push(failure_for_event(
            FailureEvent {
                code: FailureCode::SourceDrift,
                command_sequence: None,
                pre_spawn: false,
            },
            request.failure_identities,
            request.created_at,
        )?);
    } else {
        source_post = snapshot.source_pre_fingerprint().to_owned();
    }
    if snapshot.verify_snapshot_integrity().is_err() {
        apply_verdict(
            &mut verdicts,
            request
                .behavior
                .criteria
                .iter()
                .map(|criterion| criterion.criterion_id.clone()),
            CriterionResultVerdict::Invalid,
        );
        let failure = failure_for_event(
            FailureEvent {
                code: FailureCode::SnapshotTamper,
                command_sequence: None,
                pre_spawn: false,
            },
            request.failure_identities,
            request.created_at,
        )?;
        push_failure_once(&mut failures, failure);
    }

    publish(
        &request,
        evidence_bank,
        expectation,
        verdicts,
        failures,
        transcript,
        snapshot.source_pre_fingerprint().to_owned(),
        source_post,
    )
}

fn structural_preflight(request: &VerifierRequest<'_>) -> Result<(), VerifierRequestRejectionCode> {
    request
        .behavior
        .validate()
        .map_err(|_| VerifierRequestRejectionCode::InvalidContract)?;
    request
        .selection
        .validate()
        .map_err(|_| VerifierRequestRejectionCode::InvalidContract)?;
    for capability in request.capabilities {
        capability
            .validate_non_command_fields()
            .map_err(|_| VerifierRequestRejectionCode::InvalidContract)?;
    }

    validate_cross_bindings(request)
        .map_err(|_| VerifierRequestRejectionCode::InvalidCrossBinding)?;
    let source_preflight = request
        .source_manifest
        .preflight_roots(request.source_root, request.snapshot_root);
    if source_preflight
        .as_ref()
        .is_ok_and(|fingerprint| fingerprint != &request.selection.source_fingerprint)
    {
        return Err(VerifierRequestRejectionCode::InvalidCrossBinding);
    }
    if !valid_actor_id(request.implementation_actor.as_str())
        || !valid_actor_id(request.verifier_actor.as_str())
    {
        return Err(VerifierRequestRejectionCode::InvalidActorIdentity);
    }
    if request.implementation_actor == request.verifier_actor {
        return Err(VerifierRequestRejectionCode::VerifierNotIndependent);
    }
    source_preflight.map_err(|_| VerifierRequestRejectionCode::InvalidSourceManifest)?;
    for capability in request.capabilities {
        capability
            .validate_commands()
            .map_err(|_| VerifierRequestRejectionCode::InvalidCommand)?;
    }
    if !request.limits.is_valid() {
        return Err(VerifierRequestRejectionCode::InvalidExecutionLimits);
    }
    if !validate_failure_identity_map(
        request.failure_identities,
        planned_commands(request.capabilities).len(),
        &request.created_at,
    ) {
        return Err(VerifierRequestRejectionCode::InvalidFailureIdentity);
    }
    if !request.executable_registry.validate_structure() {
        return Err(VerifierRequestRejectionCode::InvalidExecutableProfile);
    }
    Ok(())
}

fn validate_cross_bindings(request: &VerifierRequest<'_>) -> Result<(), ()> {
    let ovca_types::BehaviorBinding::Bound { goal_id, task_id } = &request.behavior.binding else {
        return Err(());
    };
    if goal_id != &request.selection.goal_id || task_id != &request.selection.task_id {
        return Err(());
    }
    if request.capabilities.len() != request.selection.capabilities.len()
        || request.capabilities.is_empty()
    {
        return Err(());
    }
    for (capability, selected) in request
        .capabilities
        .iter()
        .zip(&request.selection.capabilities)
    {
        let bytes = serde_json::to_vec(capability).map_err(|_| ())?;
        if capability.capability_id != selected.capability_id
            || capability.revision != selected.revision
            || (capability.validate_commands().is_ok()
                && verification_sha256_hex(&bytes) != selected.record_digest)
        {
            return Err(());
        }
    }
    let selected_ids = request
        .selection
        .capabilities
        .iter()
        .map(|value| value.capability_id.as_str())
        .collect::<BTreeSet<_>>();
    for criterion in &request.behavior.criteria {
        if criterion.capability_ids.is_empty()
            || criterion
                .capability_ids
                .iter()
                .any(|id| !selected_ids.contains(id.as_str()))
        {
            return Err(());
        }
        for capability_id in &criterion.capability_ids {
            let capability = request
                .capabilities
                .iter()
                .find(|capability| &capability.capability_id == capability_id)
                .ok_or(())?;
            if capability
                .criterion_ids
                .binary_search(&criterion.criterion_id)
                .is_err()
            {
                return Err(());
            }
        }
    }
    for capability in request.capabilities {
        if capability
            .dependencies
            .iter()
            .any(|id| !selected_ids.contains(id.as_str()))
        {
            return Err(());
        }
        for criterion_id in &capability.criterion_ids {
            let criterion = request
                .behavior
                .criteria
                .iter()
                .find(|criterion| &criterion.criterion_id == criterion_id)
                .ok_or(())?;
            if criterion
                .capability_ids
                .binary_search(&capability.capability_id)
                .is_err()
            {
                return Err(());
            }
        }
    }
    let commands_valid = request
        .capabilities
        .iter()
        .all(|capability| capability.validate_commands().is_ok());
    let environment_names = request
        .capabilities
        .iter()
        .flat_map(|capability| {
            capability
                .commands
                .iter()
                .flat_map(|command| command.environment_names.iter().cloned())
        })
        .collect::<BTreeSet<_>>();
    if verification_policy_digest(request.capabilities).map_err(|_| ())?
        != request.selection.policy_digest
        || !valid_digest(request.environment_digest)
        || (commands_valid
            && request
                .environment_bindings
                .digest_for(&environment_names)
                .as_deref()
                != Some(request.environment_digest))
    {
        return Err(());
    }
    Ok(())
}

fn planned_commands(capabilities: &[CapabilityDefinition]) -> Vec<(usize, usize)> {
    capabilities
        .iter()
        .enumerate()
        .flat_map(|(capability_index, capability)| {
            (0..capability.commands.len())
                .map(move |command_index| (capability_index, command_index))
        })
        .collect()
}

fn publish_pre_spawn(
    request: &VerifierRequest<'_>,
    evidence_bank: &EvidenceBank,
    expectation: &ProjectionExpectation,
    contribution: CriterionResultVerdict,
    failure_code: FailureCode,
    sequence: u32,
) -> Result<VerifierOutcome, VerifierError> {
    let verdicts = request
        .behavior
        .criteria
        .iter()
        .map(|criterion| (criterion.criterion_id.clone(), contribution))
        .collect();
    let failure = failure_for_event(
        FailureEvent {
            code: failure_code,
            command_sequence: Some(sequence),
            pre_spawn: failure_code == FailureCode::ExecutableTamper,
        },
        request.failure_identities,
        request.created_at,
    )?;
    publish(
        request,
        evidence_bank,
        expectation,
        verdicts,
        vec![failure],
        VerificationTranscriptIdentity::default(),
        request.selection.source_fingerprint.clone(),
        request.selection.source_fingerprint.clone(),
    )
}

fn publish_global_integrity(
    request: &VerifierRequest<'_>,
    evidence_bank: &EvidenceBank,
    expectation: &ProjectionExpectation,
    failure_code: FailureCode,
    source_pre: String,
    source_post: String,
) -> Result<VerifierOutcome, VerifierError> {
    let verdicts = request
        .behavior
        .criteria
        .iter()
        .map(|criterion| {
            (
                criterion.criterion_id.clone(),
                CriterionResultVerdict::Invalid,
            )
        })
        .collect();
    let failure = failure_for_event(
        FailureEvent {
            code: failure_code,
            command_sequence: None,
            pre_spawn: false,
        },
        request.failure_identities,
        request.created_at,
    )?;
    publish(
        request,
        evidence_bank,
        expectation,
        verdicts,
        vec![failure],
        VerificationTranscriptIdentity::default(),
        source_pre,
        source_post,
    )
}

#[allow(clippy::too_many_arguments)]
fn publish(
    request: &VerifierRequest<'_>,
    evidence_bank: &EvidenceBank,
    expectation: &ProjectionExpectation,
    verdicts: BTreeMap<String, CriterionResultVerdict>,
    failures: Vec<ovca_types::VerificationFailure>,
    transcript: VerificationTranscriptIdentity,
    source_pre: String,
    source_post: String,
) -> Result<VerifierOutcome, VerifierError> {
    let bundle = build_bundle(BundleBuildInput {
        behavior: request.behavior,
        capabilities: request.capabilities,
        selection: request.selection,
        implementation_actor: &request.implementation_actor,
        verifier_actor: &request.verifier_actor,
        environment_digest: request.environment_digest,
        source_pre: &source_pre,
        source_post: &source_post,
        criterion_verdicts: &verdicts,
        failures,
        transcript: &transcript,
        created_at: request.created_at,
    })?;
    let storage = evidence_bank.publish_bundle_and_cas(&bundle, expectation)?;
    Ok(VerifierOutcome::Published(Box::new(
        PublishedVerification {
            bundle,
            transcript,
            storage,
        },
    )))
}

fn runtime_preflight_shape(
    failure: RuntimePreflightFailure,
) -> (CriterionResultVerdict, FailureCode) {
    match failure {
        RuntimePreflightFailure::UnknownOrDisallowedProfile => {
            (CriterionResultVerdict::Blocked, FailureCode::PolicyBlock)
        }
        RuntimePreflightFailure::EnvironmentBlock => (
            CriterionResultVerdict::Blocked,
            FailureCode::EnvironmentBlock,
        ),
        RuntimePreflightFailure::ExecutableUnavailable => (
            CriterionResultVerdict::Blocked,
            FailureCode::ExecutableUnavailable,
        ),
        RuntimePreflightFailure::ExecutableDigestMismatch => (
            CriterionResultVerdict::Invalid,
            FailureCode::ExecutableTamper,
        ),
    }
}

fn execution_shape(
    evidence: &execution::ExecutionEvidence,
) -> (
    VerificationTermination,
    CriterionResultVerdict,
    Option<FailureCode>,
    bool,
) {
    match evidence.termination {
        ExecutionTermination::Completed if evidence.exit_code == Some(0) => (
            VerificationTermination::Completed,
            CriterionResultVerdict::Pass,
            None,
            false,
        ),
        ExecutionTermination::Completed => (
            VerificationTermination::Completed,
            CriterionResultVerdict::Fail,
            Some(FailureCode::TestFailedUnclassified),
            false,
        ),
        ExecutionTermination::Timeout => (
            VerificationTermination::Timeout,
            CriterionResultVerdict::Timeout,
            Some(FailureCode::CommandTimeout),
            true,
        ),
        ExecutionTermination::OutputLimit => (
            VerificationTermination::OutputLimit,
            CriterionResultVerdict::Blocked,
            Some(FailureCode::OutputLimit),
            true,
        ),
        ExecutionTermination::Invalid => (
            VerificationTermination::Invalid,
            CriterionResultVerdict::Invalid,
            Some(FailureCode::ExecutableTamper),
            true,
        ),
    }
}

fn valid_actor_id(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn push_failure_once(
    failures: &mut Vec<ovca_types::VerificationFailure>,
    failure: ovca_types::VerificationFailure,
) {
    if failures
        .iter()
        .all(|current| current.failure_id != failure.failure_id)
    {
        failures.push(failure);
    }
}

fn drift_digest(kind: &str) -> String {
    verification_sha256_hex(format!("ovca.{kind}-drift.v1\n").as_bytes())
}
