//! Pure admission policy for verifier-backed durable completion.
//!
//! This module performs no I/O. Its storage snapshot input becomes authoritative
//! only when a caller supplies it from `EvidenceBank::with_completion_admission_lease`
//! and keeps that lease through its final synced event append.

use ovca_storage::{CompletionAdmissionSnapshot, EvidenceKey};
use ovca_types::{
    admit_current_pass_bundle, aggregate_completion_evidence, verification_behavior_digest,
    verification_capability_set_digest, verification_command_set_digest,
    verification_policy_digest, verification_sha256_hex, BehaviorBinding,
    BehavioralAcceptanceContract, CapabilityDefinition, CapabilityRegistryRow,
    CapabilityRegistrySnapshot, CompletionEvidence, CurrentBundleProof, EvidenceRef, GoalContract,
    LocalVerificationError, RunId, TargetedRerunRequest, TargetedRerunSelection, TaskId,
    LOCAL_VERIFICATION_CONTRACT_VERSION,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVerificationCompletionTask {
    pub behavior: BehavioralAcceptanceContract,
    pub selection: TargetedRerunSelection,
    pub capabilities: Vec<CapabilityDefinition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVerificationCompletionContract {
    pub goal: GoalContract,
    pub task_ids: Vec<TaskId>,
    pub tasks: Vec<LocalVerificationCompletionTask>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVerificationObservation {
    pub task_id: TaskId,
    pub source_pre_digest: String,
    pub source_post_digest: String,
    pub environment_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCompletionMaterial {
    pub evidence_references: Vec<EvidenceRef>,
    pub completion_evidence: CompletionEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVerificationCompletionError {
    pub code: &'static str,
    pub detail: String,
}

impl LocalVerificationCompletionError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for LocalVerificationCompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl Error for LocalVerificationCompletionError {}

impl From<LocalVerificationError> for LocalVerificationCompletionError {
    fn from(error: LocalVerificationError) -> Self {
        Self::new(error.code, error.detail)
    }
}

fn invalid(code: &'static str, detail: impl Into<String>) -> LocalVerificationCompletionError {
    LocalVerificationCompletionError::new(code, detail)
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn task_id(task: &LocalVerificationCompletionTask) -> &TaskId {
    &task.selection.task_id
}

pub fn validate_local_verification_completion_contract(
    contract: &LocalVerificationCompletionContract,
) -> Result<(), LocalVerificationCompletionError> {
    if contract.goal.contract_version != LOCAL_VERIFICATION_CONTRACT_VERSION
        || contract.goal.permission_profile.contract_version != LOCAL_VERIFICATION_CONTRACT_VERSION
        || contract.goal.completion_precondition.contract_version
            != LOCAL_VERIFICATION_CONTRACT_VERSION
    {
        return Err(invalid(
            "unsupported_contract_version",
            "goal and nested completion contracts must use the current version",
        ));
    }
    if !strictly_sorted_unique(&contract.task_ids) {
        return Err(invalid(
            "noncanonical_completion_tasks",
            "completion task IDs must be nonempty, strictly sorted, and unique",
        ));
    }
    if contract.tasks.len() != contract.task_ids.len()
        || contract
            .tasks
            .iter()
            .map(task_id)
            .ne(contract.task_ids.iter())
    {
        return Err(invalid(
            "completion_task_set_mismatch",
            "task policies must exactly match the authoritative task ID set",
        ));
    }

    for task in &contract.tasks {
        let behavior_digest = verification_behavior_digest(&task.behavior)?;
        task.selection.validate()?;
        if task.selection.goal_id != contract.goal.id {
            return Err(invalid(
                "completion_goal_binding_mismatch",
                task.selection.task_id.to_string(),
            ));
        }
        match &task.behavior.binding {
            BehaviorBinding::Bound { goal_id, task_id }
                if goal_id == &contract.goal.id && task_id == &task.selection.task_id => {}
            _ => {
                return Err(invalid(
                    "completion_behavior_binding_mismatch",
                    task.selection.task_id.to_string(),
                ));
            }
        }
        if task.behavior.contract_id.trim().is_empty() || behavior_digest.len() != 64 {
            return Err(invalid(
                "invalid_completion_behavior",
                task.selection.task_id.to_string(),
            ));
        }
        if task.capabilities.is_empty()
            || task
                .capabilities
                .windows(2)
                .any(|pair| pair[0].capability_id.as_str() >= pair[1].capability_id.as_str())
        {
            return Err(invalid(
                "noncanonical_completion_capabilities",
                task.selection.task_id.to_string(),
            ));
        }
        for capability in &task.capabilities {
            capability.validate()?;
        }
        if task.capabilities.len() != task.selection.capabilities.len() {
            return Err(invalid(
                "completion_capability_set_mismatch",
                task.selection.task_id.to_string(),
            ));
        }
        for (definition, selected) in task.capabilities.iter().zip(&task.selection.capabilities) {
            let digest = verification_sha256_hex(&definition.canonical_json_bytes()?);
            if definition.capability_id != selected.capability_id
                || definition.revision != selected.revision
                || digest != selected.record_digest
            {
                return Err(invalid(
                    "completion_capability_selection_mismatch",
                    selected.capability_id.clone(),
                ));
            }
        }
        if verification_policy_digest(&task.capabilities)? != task.selection.policy_digest {
            return Err(invalid(
                "completion_policy_digest_mismatch",
                task.selection.task_id.to_string(),
            ));
        }
    }
    Ok(())
}

/// Returns the exact environment names required by one task's selected commands.
pub fn completion_environment_names(
    task: &LocalVerificationCompletionTask,
) -> Result<BTreeSet<String>, LocalVerificationCompletionError> {
    for capability in &task.capabilities {
        capability.validate()?;
    }
    Ok(task
        .capabilities
        .iter()
        .flat_map(|capability| capability.commands.iter())
        .flat_map(|command| command.environment_names.iter().cloned())
        .collect())
}

pub fn completion_evidence_keys(
    contract: &LocalVerificationCompletionContract,
    run_id: &RunId,
) -> Result<Vec<EvidenceKey>, LocalVerificationCompletionError> {
    validate_local_verification_completion_contract(contract)?;
    if contract
        .tasks
        .iter()
        .any(|task| &task.selection.run_id != run_id)
    {
        return Err(invalid(
            "completion_run_binding_mismatch",
            "every task selection must bind the exact run",
        ));
    }
    Ok(contract
        .task_ids
        .iter()
        .map(|task_id| EvidenceKey {
            run_id: run_id.clone(),
            goal_id: contract.goal.id.clone(),
            task_id: task_id.clone(),
        })
        .collect())
}

/// Derives completion material from a fully revalidated current storage snapshot.
///
/// The caller must obtain `snapshot` from the storage lease API. This function
/// deliberately accepts neither a `CurrentBundleProof` nor any verified boolean.
pub fn admit_local_verification_completion(
    contract: &LocalVerificationCompletionContract,
    run_id: &RunId,
    declared_task_ids: &[TaskId],
    snapshot: &CompletionAdmissionSnapshot,
    observations: &[LocalVerificationObservation],
) -> Result<VerifiedCompletionMaterial, LocalVerificationCompletionError> {
    validate_local_verification_completion_contract(contract)?;
    if declared_task_ids != contract.task_ids.as_slice() {
        return Err(invalid(
            "declared_completion_task_set_mismatch",
            "persisted run task IDs differ from the authoritative completion policy",
        ));
    }
    if contract
        .tasks
        .iter()
        .any(|task| &task.selection.run_id != run_id)
    {
        return Err(invalid(
            "completion_run_binding_mismatch",
            "every task selection must bind the persisted run",
        ));
    }
    if observations.len() != contract.task_ids.len()
        || observations
            .iter()
            .map(|observation| &observation.task_id)
            .ne(contract.task_ids.iter())
    {
        return Err(invalid(
            "completion_observation_set_mismatch",
            "live observations must exactly match the authoritative task set",
        ));
    }
    if snapshot.bundles.len() != contract.task_ids.len()
        || snapshot
            .bundles
            .iter()
            .map(|bundle| &bundle.current.key.task_id)
            .ne(contract.task_ids.iter())
    {
        return Err(invalid(
            "completion_bundle_set_mismatch",
            "guarded current bundles must exactly match the authoritative task set",
        ));
    }

    let registry_rows = snapshot
        .capabilities
        .iter()
        .map(|capability| CapabilityRegistryRow {
            definition: capability.record.definition.clone(),
            record_digest: capability.current.record_digest.clone(),
            generation: capability.current.token.generation,
            state_digest: capability.current.token.state_digest.clone(),
        })
        .collect::<Vec<_>>();
    let registry = CapabilityRegistrySnapshot::new(registry_rows)?;
    let current_capabilities = snapshot
        .capabilities
        .iter()
        .map(|capability| {
            (
                capability.current.capability_id.as_str(),
                (&capability.current, &capability.record),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut admitted = Vec::with_capacity(contract.tasks.len());
    for (((task, observation), guarded), expected_task_id) in contract
        .tasks
        .iter()
        .zip(observations)
        .zip(&snapshot.bundles)
        .zip(&contract.task_ids)
    {
        if &observation.task_id != expected_task_id
            || &guarded.current.key.run_id != run_id
            || guarded.current.key.goal_id != contract.goal.id
            || &guarded.current.key.task_id != expected_task_id
            || guarded.record.bundle.run_id != *run_id
            || guarded.record.bundle.goal_id != contract.goal.id
            || &guarded.record.bundle.task_id != expected_task_id
        {
            return Err(invalid(
                "guarded_completion_binding_mismatch",
                expected_task_id.to_string(),
            ));
        }
        if task.selection.registry_snapshot_digest != registry.registry_snapshot_digest {
            return Err(invalid(
                "completion_registry_snapshot_mismatch",
                expected_task_id.to_string(),
            ));
        }
        let rerun_request = TargetedRerunRequest {
            contract_version: task.selection.contract_version,
            run_id: task.selection.run_id.clone(),
            goal_id: task.selection.goal_id.clone(),
            task_id: task.selection.task_id.clone(),
            source_fingerprint: task.selection.source_fingerprint.clone(),
            policy_digest: task.selection.policy_digest.clone(),
            changed_paths: task.selection.changed_path_manifest.clone(),
            unknown_path_policy: task.selection.unknown_path_policy,
        };
        task.selection.validate_against(&rerun_request, &registry)?;
        for (definition, selected) in task.capabilities.iter().zip(&task.selection.capabilities) {
            let Some((current, record)) = current_capabilities.get(selected.capability_id.as_str())
            else {
                return Err(invalid(
                    "missing_current_completion_capability",
                    selected.capability_id.clone(),
                ));
            };
            if current.revision != selected.revision
                || current.record_digest != selected.record_digest
                || record.digest != selected.record_digest
                || record.definition != *definition
            {
                return Err(invalid(
                    "stale_completion_capability",
                    selected.capability_id.clone(),
                ));
            }
        }

        let behavior_digest = verification_behavior_digest(&task.behavior)?;
        let capability_set_digest = verification_capability_set_digest(&task.selection)?;
        let command_digest = verification_command_set_digest(&task.capabilities)?;
        let policy_digest = verification_policy_digest(&task.capabilities)?;
        if task.selection.policy_digest != policy_digest
            || task.selection.source_fingerprint != observation.source_pre_digest
            || observation.source_pre_digest != observation.source_post_digest
        {
            return Err(invalid(
                "stale_completion_observation",
                expected_task_id.to_string(),
            ));
        }

        let proof = CurrentBundleProof {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            bundle_digest: guarded.record.digest.clone(),
            checksum_verified: true,
            integrity_verified: true,
            current_pointer_verified: true,
            current_pointer_digest: guarded.current.record_digest.clone(),
            expected_run_id: run_id.clone(),
            expected_goal_id: contract.goal.id.clone(),
            expected_task_id: expected_task_id.clone(),
            expected_behavior_contract_digest: behavior_digest,
            expected_capability_set_digest: capability_set_digest,
            expected_command_digest: command_digest,
            expected_policy_digest: policy_digest,
            expected_source_digest: observation.source_pre_digest.clone(),
            expected_environment_digest: observation.environment_digest.clone(),
        };
        admitted.push(admit_current_pass_bundle(
            &task.behavior,
            &task.capabilities,
            &guarded.record.bundle,
            &proof,
        )?);
    }

    let completion_evidence = aggregate_completion_evidence(&contract.goal, run_id, &admitted)?;
    let mut evidence_references = admitted
        .into_iter()
        .map(|evidence| evidence.evidence_ref)
        .collect::<Vec<_>>();
    evidence_references.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(VerifiedCompletionMaterial {
        evidence_references,
        completion_evidence,
    })
}

/// Confirms exact persisted material while allowing unrelated catalog entries.
pub fn validate_persisted_completion_material(
    expected: &VerifiedCompletionMaterial,
    persisted_references: &[EvidenceRef],
    persisted_completion: Option<&CompletionEvidence>,
) -> Result<(), LocalVerificationCompletionError> {
    let catalog = persisted_references
        .iter()
        .map(|reference| (reference.id.as_str(), reference))
        .collect::<BTreeMap<_, _>>();
    for expected_reference in &expected.evidence_references {
        if catalog.get(expected_reference.id.as_str()).copied() != Some(expected_reference) {
            return Err(invalid(
                "persisted_evidence_reference_mismatch",
                expected_reference.id.to_string(),
            ));
        }
    }
    if persisted_completion != Some(&expected.completion_evidence) {
        return Err(invalid(
            "persisted_completion_evidence_mismatch",
            "recorded completion evidence differs from current admitted material",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use ovca_types::{
        CompletionPrecondition, ContractVersion, PermissionProfile, ProjectId, RiskTier,
    };

    fn goal() -> GoalContract {
        GoalContract {
            contract_version: ContractVersion::current(),
            id: ovca_types::GoalId::from("goal.v4c"),
            project_id: ProjectId::from("project.v4c"),
            objective: "verified completion".to_owned(),
            constraints: Vec::new(),
            acceptance_criteria: Vec::new(),
            verification_criteria: Vec::new(),
            permission_profile: PermissionProfile {
                contract_version: ContractVersion::current(),
                risk_tier: RiskTier::R0,
                resource_keys: Vec::new(),
                write_keys: Vec::new(),
                approval_required: false,
                review_required: false,
                audit_required: false,
            },
            definition_of_done: Vec::new(),
            completion_precondition: CompletionPrecondition::default(),
            created_at: Utc.with_ymd_and_hms(2026, 8, 12, 0, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2026, 8, 12, 0, 0, 0).unwrap(),
        }
    }

    #[test]
    fn empty_policy_is_rejected_before_storage_admission() {
        let contract = LocalVerificationCompletionContract {
            goal: goal(),
            task_ids: Vec::new(),
            tasks: Vec::new(),
        };
        assert_eq!(
            validate_local_verification_completion_contract(&contract)
                .unwrap_err()
                .code,
            "noncanonical_completion_tasks"
        );
    }
}
