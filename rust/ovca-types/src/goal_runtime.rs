//! Provider-independent goal runtime contracts.
//!
//! This module defines data and validation only. It does not persist records,
//! schedule work, execute tasks, approve actions, or call providers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Current schema version for every top-level goal runtime contract.
pub const GOAL_RUNTIME_CONTRACT_VERSION: ContractVersion = ContractVersion(1);

/// Explicit version carried by goal runtime contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContractVersion(pub u32);

impl ContractVersion {
    pub const fn current() -> Self {
        GOAL_RUNTIME_CONTRACT_VERSION
    }
}

impl Default for ContractVersion {
    fn default() -> Self {
        Self::current()
    }
}

impl fmt::Display for ContractVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

macro_rules! string_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }
    };
}

string_id!(ProjectId);
string_id!(GoalId);
string_id!(TaskId);
string_id!(RunId);
string_id!(EvidenceId);
string_id!(EventId);
string_id!(WorkerId);
string_id!(LeaseId);
string_id!(IdempotencyKey);

/// Public runtime roles. Legacy identities are intentionally not part of this contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Coordinator,
    Engineer,
    Reviewer,
    Auditor,
}

impl Role {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Coordinator => "coordinator",
            Self::Engineer => "engineer",
            Self::Reviewer => "reviewer",
            Self::Auditor => "auditor",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable R0-R3 policy classification. This type does not grant authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskTier {
    R0,
    R1,
    R2,
    R3,
}

impl RiskTier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::R0 => "r0",
            Self::R1 => "r1",
            Self::R2 => "r2",
            Self::R3 => "r3",
        }
    }
}

impl fmt::Display for RiskTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Declared permission boundary for a goal. Enforcement belongs to later phases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionProfile {
    pub contract_version: ContractVersion,
    pub risk_tier: RiskTier,
    #[serde(default)]
    pub resource_keys: Vec<String>,
    #[serde(default)]
    pub write_keys: Vec<String>,
    pub approval_required: bool,
    pub review_required: bool,
    pub audit_required: bool,
}

/// A project groups goal contracts without embedding runtime behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    pub contract_version: ContractVersion,
    pub id: ProjectId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub goal_ids: Vec<GoalId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Contract-level completion rules consumed by the transition validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionPrecondition {
    pub contract_version: ContractVersion,
    /// Zero is treated as one so completion always has evidence.
    pub minimum_evidence_refs: u32,
    pub require_all_acceptance_criteria: bool,
    pub require_all_verification_criteria: bool,
}

impl Default for CompletionPrecondition {
    fn default() -> Self {
        Self {
            contract_version: ContractVersion::current(),
            minimum_evidence_refs: 1,
            require_all_acceptance_criteria: true,
            require_all_verification_criteria: true,
        }
    }
}

/// Provider-independent statement of goal intent and completion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalContract {
    pub contract_version: ContractVersion,
    pub id: GoalId,
    pub project_id: ProjectId,
    pub objective: String,
    #[serde(default)]
    pub constraints: Vec<String>,
    #[serde(default)]
    pub acceptance_criteria: Vec<String>,
    #[serde(default)]
    pub verification_criteria: Vec<String>,
    pub permission_profile: PermissionProfile,
    #[serde(default)]
    pub definition_of_done: Vec<String>,
    pub completion_precondition: CompletionPrecondition,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Lifecycle of one outcome-oriented task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    Ready,
    Running,
    AwaitingApproval,
    Reviewing,
    Completed,
    Failed,
    Cancelled,
}

/// One distinct outcome within a goal contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub contract_version: ContractVersion,
    pub id: TaskId,
    pub goal_id: GoalId,
    pub outcome: String,
    #[serde(default)]
    pub dependencies: Vec<TaskId>,
    pub assigned_role: Role,
    #[serde(default)]
    pub resource_keys: Vec<String>,
    #[serde(default)]
    pub write_keys: Vec<String>,
    pub status: TaskStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Caller-supplied retry policy data interpreted and enforced by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryBudget {
    pub contract_version: ContractVersion,
    /// Total allowed claim attempts, including the first claim.
    ///
    /// The kernel must interpret and enforce this value.
    pub max_attempts: u32,
}

/// Caller-supplied claim data for one task execution lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskLease {
    pub contract_version: ContractVersion,
    pub run_id: RunId,
    pub task_id: TaskId,
    pub worker_id: WorkerId,
    pub worker_role: Role,
    pub lease_id: LeaseId,
    /// Sorted keys make serialized lease fixtures deterministic.
    #[serde(default)]
    pub write_keys: BTreeSet<String>,
    /// Caller-supplied claim attempt number; interpretation belongs to the kernel.
    pub attempt: u32,
    /// Total allowed claim attempts, including the first claim.
    pub max_attempts: u32,
    pub claimed_at: DateTime<Utc>,
    pub heartbeat_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Role-neutral terminal outcomes for a task claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskTerminalOutcome {
    Completed,
    Cancelled,
}

/// Caller-supplied terminal record for one task claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskTerminalRecord {
    pub contract_version: ContractVersion,
    pub run_id: RunId,
    pub task_id: TaskId,
    pub worker_id: WorkerId,
    pub lease_id: LeaseId,
    pub idempotency_key: IdempotencyKey,
    pub outcome: TaskTerminalOutcome,
    pub occurred_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Stable evidence categories independent of any storage or provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Artifact,
    Document,
    TestResult,
    Log,
    Review,
    Audit,
    ExternalReference,
    Other,
}

/// Optional digest data for an evidence reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityMetadata {
    pub contract_version: ContractVersion,
    pub algorithm: String,
    pub digest: String,
}

/// Reference to evidence; the referenced bytes remain outside this pure contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub contract_version: ContractVersion,
    pub id: EvidenceId,
    pub kind: EvidenceKind,
    pub reference: String,
    pub producer_role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<IntegrityMetadata>,
    pub produced_at: DateTime<Utc>,
}

/// Ordered run lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Draft,
    Accepted,
    Planned,
    Running,
    AwaitingApproval,
    Reviewing,
    Auditing,
    Completed,
    Failed,
    Cancelled,
}

impl RunStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Accepted => "accepted",
            Self::Planned => "planned",
            Self::Running => "running",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Reviewing => "reviewing",
            Self::Auditing => "auditing",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

impl fmt::Display for RunStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Snapshot that can be reconstructed from ordered [`RunEvent`] values later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    pub contract_version: ContractVersion,
    pub id: RunId,
    pub project_id: ProjectId,
    pub goal_id: GoalId,
    #[serde(default)]
    pub task_ids: Vec<TaskId>,
    pub status: RunStatus,
    pub event_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<EventId>,
    #[serde(default)]
    pub evidence_refs: Vec<EvidenceId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
}

/// Whether one deterministic execution wave contains one or multiple tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    Sequential,
    Parallel,
}

/// Tasks that may run together after their dependencies have completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionWave {
    /// Zero-based position in the plan.
    pub index: u32,
    pub mode: ExecutionMode,
    /// Sorted task IDs make the plan stable across input ordering.
    pub task_ids: Vec<TaskId>,
}

/// Provider-independent output of deterministic scheduling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub contract_version: ContractVersion,
    pub waves: Vec<ExecutionWave>,
}

/// Task-scoped output from a public specialist role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecialistOutput {
    pub contract_version: ContractVersion,
    pub task_id: TaskId,
    pub specialist_role: Role,
    pub summary: String,
    #[serde(default)]
    pub evidence_refs: Vec<EvidenceId>,
}

/// Owner-facing response that only the Coordinator may finalize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorFinalResponse {
    pub contract_version: ContractVersion,
    pub response: String,
    #[serde(default)]
    pub evidence_refs: Vec<EvidenceId>,
}

/// Replayable event payload. Side effects are represented, never executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RunEventPayload {
    RunCreated {
        project_id: ProjectId,
        goal_id: GoalId,
        #[serde(default)]
        task_ids: Vec<TaskId>,
        status: RunStatus,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        started_at: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        finished_at: Option<DateTime<Utc>>,
    },
    ExecutionPlanRecorded {
        plan: ExecutionPlan,
    },
    StatusTransition {
        from: RunStatus,
        to: RunStatus,
    },
    TaskStatusChanged {
        task_id: TaskId,
        from: TaskStatus,
        to: TaskStatus,
    },
    EvidenceAttached {
        evidence_id: EvidenceId,
    },
    CompletionEvidenceRecorded {
        evidence: CompletionEvidence,
    },
    SpecialistOutputRecorded {
        output: SpecialistOutput,
    },
    CoordinatorFinalResponseRecorded {
        response: CoordinatorFinalResponse,
    },
    NoteRecorded {
        message: String,
    },
}

/// Ordered durable-replay input. Persistence is deliberately outside P0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunEvent {
    pub contract_version: ContractVersion,
    pub id: EventId,
    pub run_id: RunId,
    /// Zero-based, contiguous sequence within one run.
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_event_id: Option<EventId>,
    pub occurred_at: DateTime<Utc>,
    pub producer_role: Role,
    pub payload: RunEventPayload,
    /// Sorted keys make serialized test fixtures deterministic.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

/// Contract-level proof supplied when a run requests completion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionEvidence {
    pub contract_version: ContractVersion,
    #[serde(default)]
    pub evidence_refs: Vec<EvidenceId>,
    #[serde(default)]
    pub satisfied_acceptance_criteria: Vec<String>,
    #[serde(default)]
    pub satisfied_verification_criteria: Vec<String>,
    /// Exact items; missing values are reported in goal declaration order.
    #[serde(default)]
    pub satisfied_definition_of_done: Vec<String>,
}

/// Explicit, closed run state-transition table.
pub const RUN_STATUS_TRANSITIONS: &[(RunStatus, RunStatus)] = &[
    (RunStatus::Draft, RunStatus::Accepted),
    (RunStatus::Draft, RunStatus::Cancelled),
    (RunStatus::Accepted, RunStatus::Planned),
    (RunStatus::Accepted, RunStatus::Cancelled),
    (RunStatus::Planned, RunStatus::Running),
    (RunStatus::Planned, RunStatus::Cancelled),
    (RunStatus::Running, RunStatus::AwaitingApproval),
    (RunStatus::Running, RunStatus::Reviewing),
    (RunStatus::Running, RunStatus::Completed),
    (RunStatus::Running, RunStatus::Failed),
    (RunStatus::Running, RunStatus::Cancelled),
    (RunStatus::AwaitingApproval, RunStatus::Running),
    (RunStatus::AwaitingApproval, RunStatus::Failed),
    (RunStatus::AwaitingApproval, RunStatus::Cancelled),
    (RunStatus::Reviewing, RunStatus::Running),
    (RunStatus::Reviewing, RunStatus::Auditing),
    (RunStatus::Reviewing, RunStatus::Completed),
    (RunStatus::Reviewing, RunStatus::Failed),
    (RunStatus::Reviewing, RunStatus::Cancelled),
    (RunStatus::Auditing, RunStatus::Reviewing),
    (RunStatus::Auditing, RunStatus::Completed),
    (RunStatus::Auditing, RunStatus::Failed),
    (RunStatus::Auditing, RunStatus::Cancelled),
];

/// Structured failure from [`validate_run_transition`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum RunTransitionError {
    #[error("terminal run status {from} cannot transition to {to}")]
    TerminalState { from: RunStatus, to: RunStatus },
    #[error("invalid run status transition from {from} to {to}")]
    InvalidTransition { from: RunStatus, to: RunStatus },
    #[error("completion requires a goal contract")]
    CompletionContractMissing,
    #[error("completion requires completion evidence")]
    CompletionEvidenceMissing,
    #[error("completion from {from} requires the {required} completion gate")]
    WrongCompletionGate {
        from: RunStatus,
        required: RunStatus,
    },
    #[error("unsupported {contract} version {actual}; expected {expected}")]
    UnsupportedContractVersion {
        contract: String,
        expected: ContractVersion,
        actual: ContractVersion,
    },
    #[error("completion requires {required} unique evidence references; found {actual}")]
    InsufficientCompletionEvidence { required: u32, actual: u32 },
    #[error("completion evidence is missing acceptance criteria: {missing:?}")]
    AcceptanceCriteriaUnsatisfied { missing: Vec<String> },
    #[error("completion evidence is missing verification criteria: {missing:?}")]
    VerificationCriteriaUnsatisfied { missing: Vec<String> },
    #[error("completion evidence is missing definition-of-done items: {missing:?}")]
    DefinitionOfDoneUnsatisfied { missing: Vec<String> },
}

/// Validate a requested run transition without mutating state.
///
/// `goal_contract` and `completion_evidence` are required for transitions to
/// `completed`. The goal's permission profile selects `running`, `reviewing`,
/// or `auditing` as the required completion gate. P1 can persist an event only
/// after this function returns `Ok(())`.
pub fn validate_run_transition(
    from: RunStatus,
    to: RunStatus,
    goal_contract: Option<&GoalContract>,
    completion_evidence: Option<&CompletionEvidence>,
) -> Result<(), RunTransitionError> {
    if from.is_terminal() {
        return Err(RunTransitionError::TerminalState { from, to });
    }

    if !RUN_STATUS_TRANSITIONS.contains(&(from, to)) {
        return Err(RunTransitionError::InvalidTransition { from, to });
    }

    if to != RunStatus::Completed {
        return Ok(());
    }

    let goal = goal_contract.ok_or(RunTransitionError::CompletionContractMissing)?;

    validate_contract_version("goal_contract", goal.contract_version)?;
    validate_contract_version(
        "permission_profile",
        goal.permission_profile.contract_version,
    )?;
    validate_contract_version(
        "completion_precondition",
        goal.completion_precondition.contract_version,
    )?;

    let required_gate = required_completion_gate(&goal.permission_profile);
    if from != required_gate {
        return Err(RunTransitionError::WrongCompletionGate {
            from,
            required: required_gate,
        });
    }

    let evidence = completion_evidence.ok_or(RunTransitionError::CompletionEvidenceMissing)?;
    validate_contract_version("completion_evidence", evidence.contract_version)?;

    let unique_evidence_count = evidence.evidence_refs.iter().collect::<BTreeSet<_>>().len() as u32;
    let required_evidence = goal.completion_precondition.minimum_evidence_refs.max(1);
    if unique_evidence_count < required_evidence {
        return Err(RunTransitionError::InsufficientCompletionEvidence {
            required: required_evidence,
            actual: unique_evidence_count,
        });
    }

    if goal.completion_precondition.require_all_acceptance_criteria {
        let satisfied = evidence
            .satisfied_acceptance_criteria
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let missing = missing_criteria(&goal.acceptance_criteria, &satisfied);
        if !missing.is_empty() {
            return Err(RunTransitionError::AcceptanceCriteriaUnsatisfied { missing });
        }
    }

    if goal
        .completion_precondition
        .require_all_verification_criteria
    {
        let satisfied = evidence
            .satisfied_verification_criteria
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let missing = missing_criteria(&goal.verification_criteria, &satisfied);
        if !missing.is_empty() {
            return Err(RunTransitionError::VerificationCriteriaUnsatisfied { missing });
        }
    }

    let satisfied_definition_of_done = evidence
        .satisfied_definition_of_done
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let missing = missing_criteria(&goal.definition_of_done, &satisfied_definition_of_done);
    if !missing.is_empty() {
        return Err(RunTransitionError::DefinitionOfDoneUnsatisfied { missing });
    }

    Ok(())
}

fn required_completion_gate(permission_profile: &PermissionProfile) -> RunStatus {
    if permission_profile.audit_required {
        RunStatus::Auditing
    } else if permission_profile.review_required {
        RunStatus::Reviewing
    } else {
        RunStatus::Running
    }
}

fn validate_contract_version(
    contract: &str,
    actual: ContractVersion,
) -> Result<(), RunTransitionError> {
    if actual == GOAL_RUNTIME_CONTRACT_VERSION {
        Ok(())
    } else {
        Err(RunTransitionError::UnsupportedContractVersion {
            contract: contract.to_owned(),
            expected: GOAL_RUNTIME_CONTRACT_VERSION,
            actual,
        })
    }
}

fn missing_criteria(criteria: &[String], satisfied: &BTreeSet<&str>) -> Vec<String> {
    criteria
        .iter()
        .filter(|criterion| !satisfied.contains(criterion.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde::de::DeserializeOwned;
    use serde_json::json;
    use std::fmt::Debug;

    fn timestamp() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 16, 9, 30, 0)
            .single()
            .unwrap()
    }

    fn permission_profile() -> PermissionProfile {
        PermissionProfile {
            contract_version: ContractVersion::current(),
            risk_tier: RiskTier::R1,
            resource_keys: vec!["repo:ovca-core".into()],
            write_keys: vec!["rust:ovca-types".into()],
            approval_required: false,
            review_required: true,
            audit_required: false,
        }
    }

    fn goal_contract() -> GoalContract {
        GoalContract {
            contract_version: ContractVersion::current(),
            id: GoalId::from("goal-1"),
            project_id: ProjectId::from("project-1"),
            objective: "Define the contract baseline".into(),
            constraints: vec!["No runtime execution".into()],
            acceptance_criteria: vec!["Contracts serialize".into()],
            verification_criteria: vec!["Unit tests pass".into()],
            permission_profile: permission_profile(),
            definition_of_done: vec!["Evidence is attached".into()],
            completion_precondition: CompletionPrecondition::default(),
            created_at: timestamp(),
            updated_at: timestamp(),
        }
    }

    fn completion_evidence() -> CompletionEvidence {
        CompletionEvidence {
            contract_version: ContractVersion::current(),
            evidence_refs: vec![EvidenceId::from("evidence-1")],
            satisfied_acceptance_criteria: vec!["Contracts serialize".into()],
            satisfied_verification_criteria: vec!["Unit tests pass".into()],
            satisfied_definition_of_done: vec!["Evidence is attached".into()],
        }
    }

    fn assert_round_trip<T>(value: &T)
    where
        T: Debug + PartialEq + Serialize + DeserializeOwned,
    {
        let json = serde_json::to_string(value).unwrap();
        assert_eq!(&serde_json::from_str::<T>(&json).unwrap(), value);
    }

    #[test]
    fn typed_ids_are_transparent_strings() {
        let id = ProjectId::new("project-1");
        assert_eq!(serde_json::to_value(&id).unwrap(), json!("project-1"));
        assert_eq!(id.as_str(), "project-1");
    }

    #[test]
    fn lifecycle_ids_are_transparent_strings() {
        let worker_id = WorkerId::new("worker-1");
        let lease_id = LeaseId::new("lease-1");
        let idempotency_key = IdempotencyKey::new("terminal:run-1:task-1:attempt-1");

        assert_eq!(serde_json::to_value(&worker_id).unwrap(), json!("worker-1"));
        assert_eq!(serde_json::to_value(&lease_id).unwrap(), json!("lease-1"));
        assert_eq!(
            serde_json::to_value(&idempotency_key).unwrap(),
            json!("terminal:run-1:task-1:attempt-1")
        );
        assert_round_trip(&worker_id);
        assert_round_trip(&lease_id);
        assert_round_trip(&idempotency_key);
    }

    #[test]
    fn retry_budget_max_attempts_includes_first_claim_as_kernel_input() {
        let budget = RetryBudget {
            contract_version: ContractVersion::current(),
            max_attempts: 3,
        };

        assert_eq!(
            serde_json::to_value(budget).unwrap(),
            json!({"contract_version": 1, "max_attempts": 3})
        );
        assert_eq!(budget.contract_version, GOAL_RUNTIME_CONTRACT_VERSION);
        assert_eq!(budget.max_attempts, 3);
        assert_round_trip(&budget);
    }

    #[test]
    fn task_lease_has_exact_json_shape_and_deterministic_write_keys() {
        let lease = TaskLease {
            contract_version: ContractVersion::current(),
            run_id: RunId::from("run-1"),
            task_id: TaskId::from("task-1"),
            worker_id: WorkerId::from("worker-1"),
            worker_role: Role::Engineer,
            lease_id: LeaseId::from("lease-1"),
            write_keys: BTreeSet::from([
                "rust:ovca-types:alpha".to_owned(),
                "rust:ovca-types:zeta".to_owned(),
            ]),
            attempt: 1,
            max_attempts: 3,
            claimed_at: timestamp(),
            heartbeat_at: timestamp(),
            expires_at: timestamp(),
        };

        let value = serde_json::to_value(&lease).unwrap();
        assert_eq!(
            value,
            json!({
                "contract_version": 1,
                "run_id": "run-1",
                "task_id": "task-1",
                "worker_id": "worker-1",
                "worker_role": "engineer",
                "lease_id": "lease-1",
                "write_keys": ["rust:ovca-types:alpha", "rust:ovca-types:zeta"],
                "attempt": 1,
                "max_attempts": 3,
                "claimed_at": "2026-07-16T09:30:00Z",
                "heartbeat_at": "2026-07-16T09:30:00Z",
                "expires_at": "2026-07-16T09:30:00Z"
            })
        );
        assert_eq!(lease.contract_version, GOAL_RUNTIME_CONTRACT_VERSION);
        assert_round_trip(&lease);

        let first = serde_json::to_string(&lease).unwrap();
        let second = serde_json::to_string(&lease).unwrap();
        assert_eq!(first, second);
        assert!(
            first.find("rust:ovca-types:alpha").unwrap()
                < first.find("rust:ovca-types:zeta").unwrap()
        );
    }

    #[test]
    fn terminal_outcome_has_exact_completed_cancelled_shape() {
        assert_eq!(
            serde_json::to_value(TaskTerminalOutcome::Completed).unwrap(),
            json!("completed")
        );
        assert_eq!(
            serde_json::to_value(TaskTerminalOutcome::Cancelled).unwrap(),
            json!("cancelled")
        );
        assert_round_trip(&TaskTerminalOutcome::Completed);
        assert_round_trip(&TaskTerminalOutcome::Cancelled);
    }

    #[test]
    fn terminal_record_has_exact_json_shape_and_round_trips() {
        let record = TaskTerminalRecord {
            contract_version: ContractVersion::current(),
            run_id: RunId::from("run-1"),
            task_id: TaskId::from("task-1"),
            worker_id: WorkerId::from("worker-1"),
            lease_id: LeaseId::from("lease-1"),
            idempotency_key: IdempotencyKey::from("terminal:run-1:task-1:attempt-1"),
            outcome: TaskTerminalOutcome::Cancelled,
            occurred_at: timestamp(),
            reason: Some("owner cancelled".into()),
        };

        assert_eq!(
            serde_json::to_value(&record).unwrap(),
            json!({
                "contract_version": 1,
                "run_id": "run-1",
                "task_id": "task-1",
                "worker_id": "worker-1",
                "lease_id": "lease-1",
                "idempotency_key": "terminal:run-1:task-1:attempt-1",
                "outcome": "cancelled",
                "occurred_at": "2026-07-16T09:30:00Z",
                "reason": "owner cancelled"
            })
        );
        assert_eq!(record.contract_version, GOAL_RUNTIME_CONTRACT_VERSION);
        assert_round_trip(&record);

        let without_reason = TaskTerminalRecord {
            reason: None,
            ..record
        };
        assert_eq!(
            serde_json::to_value(without_reason).unwrap().get("reason"),
            None
        );
    }

    #[test]
    fn goal_contract_round_trips_with_explicit_versions() {
        let goal = goal_contract();
        let value = serde_json::to_value(&goal).unwrap();
        assert_eq!(value["contract_version"], json!(1));
        assert_eq!(value["permission_profile"]["contract_version"], json!(1));
        assert_eq!(value["permission_profile"]["audit_required"], json!(false));
        assert_eq!(
            value["completion_precondition"]["contract_version"],
            json!(1)
        );

        let round_trip: GoalContract = serde_json::from_value(value).unwrap();
        assert_eq!(round_trip, goal);
    }

    #[test]
    fn all_named_top_level_contracts_round_trip() {
        let project = Project {
            contract_version: ContractVersion::current(),
            id: ProjectId::from("project-1"),
            name: "Goal runtime".into(),
            description: Some("Contract-only P0".into()),
            goal_ids: vec![GoalId::from("goal-1")],
            created_at: timestamp(),
            updated_at: timestamp(),
        };
        let task = Task {
            contract_version: ContractVersion::current(),
            id: TaskId::from("task-1"),
            goal_id: GoalId::from("goal-1"),
            outcome: "A versioned contract baseline".into(),
            dependencies: Vec::new(),
            assigned_role: Role::Engineer,
            resource_keys: vec!["repo:ovca-core".into()],
            write_keys: vec!["rust:ovca-types".into()],
            status: TaskStatus::Running,
            created_at: timestamp(),
            updated_at: timestamp(),
        };
        let evidence = EvidenceRef {
            contract_version: ContractVersion::current(),
            id: EvidenceId::from("evidence-1"),
            kind: EvidenceKind::TestResult,
            reference: "test:ovca-types".into(),
            producer_role: Role::Engineer,
            integrity: Some(IntegrityMetadata {
                contract_version: ContractVersion::current(),
                algorithm: "sha256".into(),
                digest: "0123456789abcdef".into(),
            }),
            produced_at: timestamp(),
        };
        let run = RunRecord {
            contract_version: ContractVersion::current(),
            id: RunId::from("run-1"),
            project_id: ProjectId::from("project-1"),
            goal_id: GoalId::from("goal-1"),
            task_ids: vec![TaskId::from("task-1")],
            status: RunStatus::Running,
            event_count: 2,
            last_event_sequence: Some(1),
            last_event_id: Some(EventId::from("event-2")),
            evidence_refs: vec![EvidenceId::from("evidence-1")],
            created_at: timestamp(),
            updated_at: timestamp(),
            started_at: Some(timestamp()),
            finished_at: None,
        };

        assert_round_trip(&project);
        assert_round_trip(&goal_contract());
        assert_round_trip(&task);
        assert_round_trip(&run);
        assert_round_trip(&evidence);
        assert_round_trip(&permission_profile());
        assert_round_trip(&completion_evidence());
        assert_round_trip(&RiskTier::R3);
        assert_round_trip(&RunStatus::AwaitingApproval);
    }

    #[test]
    fn run_event_serialization_is_deterministic_and_replay_ordered() {
        let mut metadata = BTreeMap::new();
        metadata.insert("zeta".into(), json!(2));
        metadata.insert("alpha".into(), json!(1));
        let event = RunEvent {
            contract_version: ContractVersion::current(),
            id: EventId::from("event-2"),
            run_id: RunId::from("run-1"),
            sequence: 1,
            previous_event_id: Some(EventId::from("event-1")),
            occurred_at: timestamp(),
            producer_role: Role::Engineer,
            payload: RunEventPayload::StatusTransition {
                from: RunStatus::Planned,
                to: RunStatus::Running,
            },
            metadata,
        };

        let first = serde_json::to_string(&event).unwrap();
        let second = serde_json::to_string(&event).unwrap();
        assert_eq!(first, second);
        assert!(first.find("alpha").unwrap() < first.find("zeta").unwrap());
        assert_eq!(serde_json::from_str::<RunEvent>(&first).unwrap(), event);
    }

    #[test]
    fn valid_state_path_including_approval_and_review_completion_passes() {
        let transitions = [
            (RunStatus::Draft, RunStatus::Accepted),
            (RunStatus::Accepted, RunStatus::Planned),
            (RunStatus::Planned, RunStatus::Running),
            (RunStatus::Running, RunStatus::AwaitingApproval),
            (RunStatus::AwaitingApproval, RunStatus::Running),
            (RunStatus::Running, RunStatus::Reviewing),
        ];

        for (from, to) in transitions {
            validate_run_transition(from, to, None, None).unwrap();
        }

        validate_run_transition(
            RunStatus::Reviewing,
            RunStatus::Completed,
            Some(&goal_contract()),
            Some(&completion_evidence()),
        )
        .unwrap();
    }

    #[test]
    fn approval_alone_does_not_imply_review_or_audit() {
        let mut goal = goal_contract();
        goal.permission_profile.approval_required = true;
        goal.permission_profile.review_required = false;

        validate_run_transition(
            RunStatus::Running,
            RunStatus::Completed,
            Some(&goal),
            Some(&completion_evidence()),
        )
        .unwrap();
    }

    #[test]
    fn review_required_selects_reviewing_completion_gate() {
        let goal = goal_contract();

        validate_run_transition(
            RunStatus::Reviewing,
            RunStatus::Completed,
            Some(&goal),
            Some(&completion_evidence()),
        )
        .unwrap();

        let error = validate_run_transition(
            RunStatus::Running,
            RunStatus::Completed,
            Some(&goal),
            Some(&completion_evidence()),
        )
        .unwrap_err();
        assert_eq!(
            error,
            RunTransitionError::WrongCompletionGate {
                from: RunStatus::Running,
                required: RunStatus::Reviewing,
            }
        );
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            json!({
                "code": "wrong_completion_gate",
                "from": "running",
                "required": "reviewing"
            })
        );
    }

    #[test]
    fn audit_required_selects_auditing_completion_gate() {
        let mut goal = goal_contract();
        goal.permission_profile.audit_required = true;

        validate_run_transition(
            RunStatus::Auditing,
            RunStatus::Completed,
            Some(&goal),
            Some(&completion_evidence()),
        )
        .unwrap();

        for from in [RunStatus::Running, RunStatus::Reviewing] {
            assert_eq!(
                validate_run_transition(
                    from,
                    RunStatus::Completed,
                    Some(&goal),
                    Some(&completion_evidence()),
                ),
                Err(RunTransitionError::WrongCompletionGate {
                    from,
                    required: RunStatus::Auditing,
                })
            );
        }
    }

    #[test]
    fn skipped_and_invalid_transitions_fail_structurally() {
        let error =
            validate_run_transition(RunStatus::Draft, RunStatus::Running, None, None).unwrap_err();
        assert_eq!(
            error,
            RunTransitionError::InvalidTransition {
                from: RunStatus::Draft,
                to: RunStatus::Running,
            }
        );
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            json!({"code": "invalid_transition", "from": "draft", "to": "running"})
        );
    }

    #[test]
    fn terminal_states_cannot_be_mutated() {
        for from in [
            RunStatus::Completed,
            RunStatus::Failed,
            RunStatus::Cancelled,
        ] {
            assert_eq!(
                validate_run_transition(from, RunStatus::Running, None, None),
                Err(RunTransitionError::TerminalState {
                    from,
                    to: RunStatus::Running,
                })
            );
        }
    }

    #[test]
    fn completion_requires_contract_and_evidence() {
        assert_eq!(
            validate_run_transition(RunStatus::Reviewing, RunStatus::Completed, None, None),
            Err(RunTransitionError::CompletionContractMissing)
        );

        assert_eq!(
            validate_run_transition(
                RunStatus::Reviewing,
                RunStatus::Completed,
                Some(&goal_contract()),
                None,
            ),
            Err(RunTransitionError::CompletionEvidenceMissing)
        );

        let empty = CompletionEvidence {
            contract_version: ContractVersion::current(),
            evidence_refs: Vec::new(),
            satisfied_acceptance_criteria: vec!["Contracts serialize".into()],
            satisfied_verification_criteria: vec!["Unit tests pass".into()],
            satisfied_definition_of_done: vec!["Evidence is attached".into()],
        };
        assert_eq!(
            validate_run_transition(
                RunStatus::Reviewing,
                RunStatus::Completed,
                Some(&goal_contract()),
                Some(&empty),
            ),
            Err(RunTransitionError::InsufficientCompletionEvidence {
                required: 1,
                actual: 0,
            })
        );
    }

    #[test]
    fn completion_requires_declared_criteria() {
        let evidence = CompletionEvidence {
            contract_version: ContractVersion::current(),
            evidence_refs: vec![EvidenceId::from("evidence-1")],
            satisfied_acceptance_criteria: Vec::new(),
            satisfied_verification_criteria: vec!["Unit tests pass".into()],
            satisfied_definition_of_done: vec!["Evidence is attached".into()],
        };

        assert_eq!(
            validate_run_transition(
                RunStatus::Reviewing,
                RunStatus::Completed,
                Some(&goal_contract()),
                Some(&evidence),
            ),
            Err(RunTransitionError::AcceptanceCriteriaUnsatisfied {
                missing: vec!["Contracts serialize".into()],
            })
        );

        let evidence = CompletionEvidence {
            satisfied_acceptance_criteria: vec!["Contracts serialize".into()],
            satisfied_verification_criteria: Vec::new(),
            ..completion_evidence()
        };
        assert_eq!(
            validate_run_transition(
                RunStatus::Reviewing,
                RunStatus::Completed,
                Some(&goal_contract()),
                Some(&evidence),
            ),
            Err(RunTransitionError::VerificationCriteriaUnsatisfied {
                missing: vec!["Unit tests pass".into()],
            })
        );
    }

    #[test]
    fn completion_requires_definition_of_done_items() {
        let mut goal = goal_contract();
        goal.definition_of_done = vec![
            "Evidence is attached".into(),
            "Checks are recorded".into(),
            "Handoff is ready".into(),
        ];
        let evidence = CompletionEvidence {
            satisfied_definition_of_done: vec!["Checks are recorded".into()],
            ..completion_evidence()
        };

        assert_eq!(
            validate_run_transition(
                RunStatus::Reviewing,
                RunStatus::Completed,
                Some(&goal),
                Some(&evidence),
            ),
            Err(RunTransitionError::DefinitionOfDoneUnsatisfied {
                missing: vec!["Evidence is attached".into(), "Handoff is ready".into()],
            })
        );
    }

    #[test]
    fn completion_rejects_mismatched_permission_profile_version() {
        let mut goal = goal_contract();
        goal.permission_profile.contract_version = ContractVersion(2);

        assert_eq!(
            validate_run_transition(
                RunStatus::Reviewing,
                RunStatus::Completed,
                Some(&goal),
                Some(&completion_evidence()),
            ),
            Err(RunTransitionError::UnsupportedContractVersion {
                contract: "permission_profile".into(),
                expected: ContractVersion::current(),
                actual: ContractVersion(2),
            })
        );
    }

    #[test]
    fn existing_agent_id_serialization_remains_compatible() {
        assert_eq!(
            serde_json::to_value(crate::AgentId::Coordinator).unwrap(),
            json!("coordinator")
        );
    }
}
