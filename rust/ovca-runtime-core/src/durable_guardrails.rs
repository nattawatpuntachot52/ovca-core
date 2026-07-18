//! Durable approval ledger backed by the shared versioned state store.

use crate::guardrails::{evaluate_guard_request, GuardEvaluationContext};
use ovca_storage::{
    CompareAndSwapOutcome, InitializeOutcome, VersionedState, VersionedStateError,
    VersionedStateStore,
};
use ovca_types::goal_runtime::{
    ApprovalAuthority, ApprovalDecisionRecord, ApprovalDisposition, ApprovalRequest,
    ApprovalRequestId, ApprovalState, ContractVersion, GuardDenyReason, GuardOutcome, GuardRequest,
    GuardRequirement,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

pub const DEFAULT_APPROVAL_CAS_RETRY_LIMIT: usize = 16;
const APPROVAL_ENTITY_PREFIX: &str = "guard_approval:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalEnvelope {
    pub contract_version: ContractVersion,
    pub approval_request: ApprovalRequest,
    pub required_gates: BTreeSet<GuardRequirement>,
    pub state: ApprovalState,
    pub decision: Option<ApprovalDecisionRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableApprovalRecord {
    pub envelope: ApprovalEnvelope,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableDecisionResult {
    pub record: DurableApprovalRecord,
    pub applied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableApprovalEvaluation {
    Allow {
        required_gates: BTreeSet<GuardRequirement>,
    },
    Deny {
        reasons: BTreeSet<ovca_types::goal_runtime::GuardDenyReason>,
    },
    Pending {
        record: Box<DurableApprovalRecord>,
        initialized: bool,
    },
}

#[derive(Debug)]
pub enum GuardedExecution<T, E> {
    Executed {
        output: T,
        required_gates: BTreeSet<GuardRequirement>,
    },
    PausedForApproval {
        record: Box<DurableApprovalRecord>,
        initialized: bool,
        required_gates: BTreeSet<GuardRequirement>,
    },
    DeniedByPolicy {
        reasons: BTreeSet<GuardDenyReason>,
        required_gates: BTreeSet<GuardRequirement>,
    },
    StillPending {
        record: Box<DurableApprovalRecord>,
        required_gates: BTreeSet<GuardRequirement>,
    },
    DeniedByOwner {
        record: Box<DurableApprovalRecord>,
        required_gates: BTreeSet<GuardRequirement>,
    },
    AlreadyConsumed {
        record: Box<DurableApprovalRecord>,
        required_gates: BTreeSet<GuardRequirement>,
    },
    EffectFailed {
        error: E,
        required_gates: BTreeSet<GuardRequirement>,
    },
    EffectFailedAfterConsumption {
        error: E,
        consumed_record: Box<DurableApprovalRecord>,
        required_gates: BTreeSet<GuardRequirement>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStateCorruption {
    UnsupportedEnvelopeVersion,
    UnsupportedApprovalRequestVersion,
    UnsupportedGuardRequestVersion,
    UnsupportedPermissionProfileVersion,
    UnsupportedDecisionVersion,
    EnvelopeApprovalIdMismatch,
    PendingHasDecision,
    TerminalDecisionMissing,
    StateDispositionMismatch,
    ConsumedDecisionNotApproved,
    DecisionApprovalIdMismatch,
    DecisionGuardIdMismatch,
    UnsupportedAuthority,
    DecisionBeforeRequest,
    StoredRequestNoLongerRequiresApproval,
    StoredApprovalRequestBindingMismatch,
    RequiredGatesMismatch,
}

impl fmt::Display for ApprovalStateCorruption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ApprovalStateCorruption {}

#[derive(Debug)]
pub enum DurableApprovalError {
    NotFound {
        approval_request_id: ApprovalRequestId,
    },
    DefinitionConflict {
        approval_request_id: ApprovalRequestId,
        existing_revision: u64,
    },
    DecisionConflict {
        approval_request_id: ApprovalRequestId,
        existing_revision: u64,
    },
    RequestMismatch {
        approval_request_id: ApprovalRequestId,
    },
    InvalidDecision(ApprovalStateCorruption),
    CorruptState {
        approval_request_id: ApprovalRequestId,
        source: ApprovalStateCorruption,
    },
    CorruptPayload {
        approval_request_id: ApprovalRequestId,
        source: serde_json::Error,
    },
    Storage(VersionedStateError),
    Serialization(serde_json::Error),
    ContentionExhausted {
        approval_request_id: ApprovalRequestId,
        retry_limit: usize,
        current_revision: u64,
    },
}

impl fmt::Display for DurableApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for DurableApprovalError {}

impl From<VersionedStateError> for DurableApprovalError {
    fn from(source: VersionedStateError) -> Self {
        Self::Storage(source)
    }
}

#[derive(Clone, Debug)]
pub struct DurableGuardrailAuthority {
    store: VersionedStateStore,
    cas_retry_limit: usize,
}

impl DurableGuardrailAuthority {
    pub fn new(root: impl Into<PathBuf>, cas_retry_limit: usize) -> Self {
        Self {
            store: VersionedStateStore::new(root),
            cas_retry_limit,
        }
    }

    pub fn evaluate_and_record(
        &self,
        request: &GuardRequest,
        context: &GuardEvaluationContext,
    ) -> Result<DurableApprovalEvaluation, DurableApprovalError> {
        match evaluate_guard_request(request, context) {
            GuardOutcome::Allow { required_gates } => {
                Ok(DurableApprovalEvaluation::Allow { required_gates })
            }
            GuardOutcome::Deny { reasons } => Ok(DurableApprovalEvaluation::Deny { reasons }),
            GuardOutcome::PauseForApproval {
                approval_request,
                required_gates,
            } => {
                let envelope = ApprovalEnvelope {
                    contract_version: ContractVersion::current(),
                    approval_request,
                    required_gates,
                    state: ApprovalState::Pending,
                    decision: None,
                };
                let id = envelope.approval_request.id.clone();
                validate_envelope(&id, &envelope).map_err(DurableApprovalError::InvalidDecision)?;
                let payload =
                    serde_json::to_vec(&envelope).map_err(DurableApprovalError::Serialization)?;
                let (state, initialized) = match self.store.initialize(&entity_key(&id), payload)? {
                    InitializeOutcome::Initialized(state) => (state, true),
                    InitializeOutcome::Existing(state) => (state, false),
                };
                let existing = decode_state(&id, state)?;
                if existing.envelope != envelope {
                    return Err(DurableApprovalError::DefinitionConflict {
                        approval_request_id: id,
                        existing_revision: existing.revision,
                    });
                }
                Ok(DurableApprovalEvaluation::Pending {
                    record: Box::new(existing),
                    initialized,
                })
            }
        }
    }

    pub fn execute_guarded<T, E, F>(
        &self,
        request: &GuardRequest,
        context: &GuardEvaluationContext,
        effect: F,
    ) -> Result<GuardedExecution<T, E>, DurableApprovalError>
    where
        F: FnOnce() -> Result<T, E>,
    {
        match self.evaluate_and_record(request, context)? {
            DurableApprovalEvaluation::Allow { required_gates } => match effect() {
                Ok(output) => Ok(GuardedExecution::Executed {
                    output,
                    required_gates,
                }),
                Err(error) => Ok(GuardedExecution::EffectFailed {
                    error,
                    required_gates,
                }),
            },
            DurableApprovalEvaluation::Deny { reasons } => Ok(GuardedExecution::DeniedByPolicy {
                reasons,
                required_gates: BTreeSet::new(),
            }),
            DurableApprovalEvaluation::Pending {
                record,
                initialized,
            } => {
                let required_gates = record.envelope.required_gates.clone();
                Ok(GuardedExecution::PausedForApproval {
                    record,
                    initialized,
                    required_gates,
                })
            }
        }
    }

    pub fn resume_approved<T, E, F>(
        &self,
        approval_request_id: &ApprovalRequestId,
        request: &GuardRequest,
        effect: F,
    ) -> Result<GuardedExecution<T, E>, DurableApprovalError>
    where
        F: FnOnce() -> Result<T, E>,
    {
        let loaded = self.load(approval_request_id)?;
        if loaded.envelope.approval_request.guard_request != *request {
            return Err(DurableApprovalError::RequestMismatch {
                approval_request_id: approval_request_id.clone(),
            });
        }
        let required_gates = loaded.envelope.required_gates.clone();
        match loaded.envelope.state {
            ApprovalState::Pending => Ok(GuardedExecution::StillPending {
                record: Box::new(loaded),
                required_gates,
            }),
            ApprovalState::Denied => Ok(GuardedExecution::DeniedByOwner {
                record: Box::new(loaded),
                required_gates,
            }),
            ApprovalState::Consumed => Ok(GuardedExecution::AlreadyConsumed {
                record: Box::new(loaded),
                required_gates,
            }),
            ApprovalState::Approved => {
                let mut consumed = loaded.envelope.clone();
                consumed.state = ApprovalState::Consumed;
                validate_envelope(approval_request_id, &consumed)
                    .map_err(DurableApprovalError::InvalidDecision)?;
                let payload =
                    serde_json::to_vec(&consumed).map_err(DurableApprovalError::Serialization)?;
                match self.store.compare_and_swap(
                    &entity_key(approval_request_id),
                    loaded.revision,
                    payload,
                )? {
                    CompareAndSwapOutcome::Applied(state) => {
                        let consumed_record = decode_state(approval_request_id, state)?;
                        match effect() {
                            Ok(output) => Ok(GuardedExecution::Executed {
                                output,
                                required_gates,
                            }),
                            Err(error) => Ok(GuardedExecution::EffectFailedAfterConsumption {
                                error,
                                consumed_record: Box::new(consumed_record),
                                required_gates,
                            }),
                        }
                    }
                    CompareAndSwapOutcome::Conflict(state) => {
                        let current = decode_state(approval_request_id, state)?;
                        let current_gates = current.envelope.required_gates.clone();
                        match current.envelope.state {
                            ApprovalState::Consumed => Ok(GuardedExecution::AlreadyConsumed {
                                record: Box::new(current),
                                required_gates: current_gates,
                            }),
                            _ => Err(DurableApprovalError::DecisionConflict {
                                approval_request_id: approval_request_id.clone(),
                                existing_revision: current.revision,
                            }),
                        }
                    }
                }
            }
        }
    }

    pub fn load(
        &self,
        approval_request_id: &ApprovalRequestId,
    ) -> Result<DurableApprovalRecord, DurableApprovalError> {
        let state = self
            .store
            .load(&entity_key(approval_request_id))?
            .ok_or_else(|| DurableApprovalError::NotFound {
                approval_request_id: approval_request_id.clone(),
            })?;
        decode_state(approval_request_id, state)
    }

    pub fn record_decision(
        &self,
        decision: ApprovalDecisionRecord,
    ) -> Result<DurableDecisionResult, DurableApprovalError> {
        validate_decision_shape(&decision).map_err(DurableApprovalError::InvalidDecision)?;
        let id = decision.approval_request_id.clone();
        let mut loaded = self.load(&id)?;
        for attempt in 0..=self.cas_retry_limit {
            validate_decision_for(&loaded.envelope, &decision)
                .map_err(DurableApprovalError::InvalidDecision)?;
            if loaded.envelope.decision.as_ref() == Some(&decision) {
                return Ok(DurableDecisionResult {
                    record: loaded,
                    applied: false,
                });
            }
            if loaded.envelope.state != ApprovalState::Pending {
                return Err(DurableApprovalError::DecisionConflict {
                    approval_request_id: id,
                    existing_revision: loaded.revision,
                });
            }
            let mut next = loaded.envelope.clone();
            next.state = match decision.disposition {
                ApprovalDisposition::Approved => ApprovalState::Approved,
                ApprovalDisposition::Denied => ApprovalState::Denied,
            };
            next.decision = Some(decision.clone());
            validate_envelope(&id, &next).map_err(DurableApprovalError::InvalidDecision)?;
            let payload = serde_json::to_vec(&next).map_err(DurableApprovalError::Serialization)?;
            match self
                .store
                .compare_and_swap(&entity_key(&id), loaded.revision, payload)?
            {
                CompareAndSwapOutcome::Applied(state) => {
                    return Ok(DurableDecisionResult {
                        record: decode_state(&id, state)?,
                        applied: true,
                    })
                }
                CompareAndSwapOutcome::Conflict(state) => {
                    loaded = decode_state(&id, state)?;
                    if attempt == self.cas_retry_limit {
                        return Err(DurableApprovalError::ContentionExhausted {
                            approval_request_id: id,
                            retry_limit: self.cas_retry_limit,
                            current_revision: loaded.revision,
                        });
                    }
                }
            }
        }
        unreachable!()
    }
}

fn entity_key(id: &ApprovalRequestId) -> String {
    format!("{APPROVAL_ENTITY_PREFIX}{}", id.as_str())
}

fn decode_state(
    id: &ApprovalRequestId,
    state: VersionedState,
) -> Result<DurableApprovalRecord, DurableApprovalError> {
    let envelope: ApprovalEnvelope = serde_json::from_slice(&state.payload).map_err(|source| {
        DurableApprovalError::CorruptPayload {
            approval_request_id: id.clone(),
            source,
        }
    })?;
    validate_envelope(id, &envelope).map_err(|source| DurableApprovalError::CorruptState {
        approval_request_id: id.clone(),
        source,
    })?;
    Ok(DurableApprovalRecord {
        envelope,
        revision: state.revision,
    })
}

fn validate_envelope(
    id: &ApprovalRequestId,
    envelope: &ApprovalEnvelope,
) -> Result<(), ApprovalStateCorruption> {
    let current = ContractVersion::current();
    if envelope.contract_version != current {
        return Err(ApprovalStateCorruption::UnsupportedEnvelopeVersion);
    }
    if envelope.approval_request.contract_version != current {
        return Err(ApprovalStateCorruption::UnsupportedApprovalRequestVersion);
    }
    if envelope.approval_request.guard_request.contract_version != current {
        return Err(ApprovalStateCorruption::UnsupportedGuardRequestVersion);
    }
    if envelope
        .approval_request
        .guard_request
        .permission_profile
        .contract_version
        != current
    {
        return Err(ApprovalStateCorruption::UnsupportedPermissionProfileVersion);
    }
    if &envelope.approval_request.id != id {
        return Err(ApprovalStateCorruption::EnvelopeApprovalIdMismatch);
    }
    let context = GuardEvaluationContext {
        approval_request_id: envelope.approval_request.id.clone(),
        requested_at: envelope.approval_request.requested_at,
    };
    let GuardOutcome::PauseForApproval {
        approval_request,
        required_gates,
    } = evaluate_guard_request(&envelope.approval_request.guard_request, &context)
    else {
        return Err(ApprovalStateCorruption::StoredRequestNoLongerRequiresApproval);
    };
    if approval_request != envelope.approval_request {
        return Err(ApprovalStateCorruption::StoredApprovalRequestBindingMismatch);
    }
    if required_gates != envelope.required_gates {
        return Err(ApprovalStateCorruption::RequiredGatesMismatch);
    }
    match (envelope.state, envelope.decision.as_ref()) {
        (ApprovalState::Pending, None) => Ok(()),
        (ApprovalState::Pending, Some(_)) => Err(ApprovalStateCorruption::PendingHasDecision),
        (ApprovalState::Approved | ApprovalState::Denied | ApprovalState::Consumed, None) => {
            Err(ApprovalStateCorruption::TerminalDecisionMissing)
        }
        (state, Some(decision)) => {
            validate_decision_for(envelope, decision)?;
            match (state, decision.disposition) {
                (ApprovalState::Approved, ApprovalDisposition::Approved)
                | (ApprovalState::Denied, ApprovalDisposition::Denied)
                | (ApprovalState::Consumed, ApprovalDisposition::Approved) => Ok(()),
                (ApprovalState::Consumed, _) => {
                    Err(ApprovalStateCorruption::ConsumedDecisionNotApproved)
                }
                _ => Err(ApprovalStateCorruption::StateDispositionMismatch),
            }
        }
    }
}

fn validate_decision_shape(
    decision: &ApprovalDecisionRecord,
) -> Result<(), ApprovalStateCorruption> {
    if decision.contract_version != ContractVersion::current() {
        return Err(ApprovalStateCorruption::UnsupportedDecisionVersion);
    }
    if decision.authority != ApprovalAuthority::ExplicitOwner {
        return Err(ApprovalStateCorruption::UnsupportedAuthority);
    }
    Ok(())
}

fn validate_decision_for(
    envelope: &ApprovalEnvelope,
    decision: &ApprovalDecisionRecord,
) -> Result<(), ApprovalStateCorruption> {
    validate_decision_shape(decision)?;
    if decision.approval_request_id != envelope.approval_request.id {
        return Err(ApprovalStateCorruption::DecisionApprovalIdMismatch);
    }
    if decision.guard_request_id != envelope.approval_request.guard_request.id {
        return Err(ApprovalStateCorruption::DecisionGuardIdMismatch);
    }
    if decision.decided_at < envelope.approval_request.requested_at {
        return Err(ApprovalStateCorruption::DecisionBeforeRequest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use ovca_storage::VERSIONED_STATE_DB_RELATIVE_PATH;
    use ovca_types::goal_runtime::{
        GuardRequestId, GuardSurface, PermissionProfile, RiskTier, SideEffectClass,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::TempDir;

    fn at(second: i64) -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(second, 0).unwrap()
    }

    fn context(id: &str) -> GuardEvaluationContext {
        GuardEvaluationContext {
            approval_request_id: ApprovalRequestId::from(id),
            requested_at: at(10),
        }
    }

    fn request(tier: RiskTier, side_effect: SideEffectClass) -> GuardRequest {
        let (approval_required, review_required, audit_required) = match tier {
            RiskTier::R0 => (false, false, false),
            RiskTier::R1 => (false, true, false),
            RiskTier::R2 => (true, true, true),
            RiskTier::R3 => (true, true, true),
        };
        GuardRequest {
            contract_version: ContractVersion::current(),
            id: GuardRequestId::from("guard-1"),
            surface: GuardSurface::Tool,
            side_effect,
            operation_label: "bounded operation".into(),
            resource_keys: vec!["resource:runtime".into()],
            write_keys: if side_effect == SideEffectClass::ReadOnly {
                vec![]
            } else {
                vec!["write:runtime".into()]
            },
            permission_profile: PermissionProfile {
                contract_version: ContractVersion::current(),
                risk_tier: tier,
                resource_keys: vec!["resource:runtime".into()],
                write_keys: if side_effect == SideEffectClass::ReadOnly {
                    vec![]
                } else {
                    vec!["write:runtime".into()]
                },
                approval_required,
                review_required,
                audit_required,
            },
        }
    }

    fn pending(temp: &TempDir) -> DurableApprovalRecord {
        let authority = DurableGuardrailAuthority::new(temp.path(), 8);
        let DurableApprovalEvaluation::Pending { record, .. } = authority
            .evaluate_and_record(
                &request(RiskTier::R2, SideEffectClass::NetworkAction),
                &context("approval-1"),
            )
            .unwrap()
        else {
            panic!("expected pause")
        };
        *record
    }

    fn decision(disposition: ApprovalDisposition) -> ApprovalDecisionRecord {
        ApprovalDecisionRecord {
            contract_version: ContractVersion::current(),
            approval_request_id: ApprovalRequestId::from("approval-1"),
            guard_request_id: GuardRequestId::from("guard-1"),
            authority: ApprovalAuthority::ExplicitOwner,
            disposition,
            decided_at: at(11),
        }
    }

    #[test]
    fn constructor_and_non_pause_outcomes_do_not_touch_filesystem() {
        for (tier, side_effect) in [
            (RiskTier::R0, SideEffectClass::ReadOnly),
            (RiskTier::R3, SideEffectClass::Destructive),
        ] {
            let temp = TempDir::new().unwrap();
            let root = temp.path().join("missing");
            let authority = DurableGuardrailAuthority::new(&root, 2);
            assert!(!root.exists());
            let outcome = authority
                .evaluate_and_record(&request(tier, side_effect), &context("approval-1"))
                .unwrap();
            assert!(matches!(
                outcome,
                DurableApprovalEvaluation::Allow { .. } | DurableApprovalEvaluation::Deny { .. }
            ));
            assert!(!root.exists());
        }
    }

    #[test]
    fn pause_persists_revision_zero_reopens_exactly_and_retries_idempotently() {
        let temp = TempDir::new().unwrap();
        let first = pending(&temp);
        assert_eq!(first.revision, 0);
        assert_eq!(first.envelope.state, ApprovalState::Pending);
        let reopened = DurableGuardrailAuthority::new(temp.path(), 8)
            .load(&ApprovalRequestId::from("approval-1"))
            .unwrap();
        assert_eq!(reopened, first);
        let DurableApprovalEvaluation::Pending {
            record,
            initialized,
        } = DurableGuardrailAuthority::new(temp.path(), 8)
            .evaluate_and_record(
                &request(RiskTier::R2, SideEffectClass::NetworkAction),
                &context("approval-1"),
            )
            .unwrap()
        else {
            panic!("expected pause")
        };
        assert!(!initialized);
        assert_eq!(*record, first);
    }

    #[test]
    fn approval_id_definition_collision_does_not_mutate() {
        let temp = TempDir::new().unwrap();
        let before = pending(&temp);
        let mut changed = request(RiskTier::R2, SideEffectClass::NetworkAction);
        changed.operation_label = "different operation".into();
        assert!(matches!(
            DurableGuardrailAuthority::new(temp.path(), 8)
                .evaluate_and_record(&changed, &context("approval-1")),
            Err(DurableApprovalError::DefinitionConflict {
                existing_revision: 0,
                ..
            })
        ));
        assert_eq!(
            DurableGuardrailAuthority::new(temp.path(), 8)
                .load(&ApprovalRequestId::from("approval-1"))
                .unwrap(),
            before
        );
    }

    #[test]
    fn approve_and_deny_persist_and_exact_duplicates_are_idempotent() {
        for (disposition, expected) in [
            (ApprovalDisposition::Approved, ApprovalState::Approved),
            (ApprovalDisposition::Denied, ApprovalState::Denied),
        ] {
            let temp = TempDir::new().unwrap();
            pending(&temp);
            let authority = DurableGuardrailAuthority::new(temp.path(), 8);
            let first = authority.record_decision(decision(disposition)).unwrap();
            assert!(first.applied);
            assert_eq!(first.record.revision, 1);
            assert_eq!(first.record.envelope.state, expected);
            let duplicate = authority.record_decision(decision(disposition)).unwrap();
            assert!(!duplicate.applied);
            assert_eq!(duplicate.record, first.record);
            assert_eq!(
                DurableGuardrailAuthority::new(temp.path(), 8)
                    .load(&ApprovalRequestId::from("approval-1"))
                    .unwrap(),
                first.record
            );
        }
    }

    #[test]
    fn independent_approve_deny_race_has_exactly_one_winner() {
        let temp = TempDir::new().unwrap();
        pending(&temp);
        let root = temp.path().to_owned();
        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = [ApprovalDisposition::Approved, ApprovalDisposition::Denied]
            .into_iter()
            .map(|disposition| {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let authority = DurableGuardrailAuthority::new(root, 8);
                    barrier.wait();
                    authority.record_decision(decision(disposition))
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(DurableApprovalError::DecisionConflict { .. })
                ))
                .count(),
            1
        );
        let stored = DurableGuardrailAuthority::new(temp.path(), 8)
            .load(&ApprovalRequestId::from("approval-1"))
            .unwrap();
        assert_eq!(stored.revision, 1);
        assert!(matches!(
            stored.envelope.state,
            ApprovalState::Approved | ApprovalState::Denied
        ));
    }

    #[test]
    fn malformed_decisions_reject_without_mutation() {
        type DecisionMutation = Box<dyn Fn(&mut ApprovalDecisionRecord)>;
        let mutations: Vec<DecisionMutation> = vec![
            Box::new(|value| value.contract_version = ContractVersion(2)),
            Box::new(|value| value.approval_request_id = ApprovalRequestId::from("other")),
            Box::new(|value| value.guard_request_id = GuardRequestId::from("other")),
            Box::new(|value| value.decided_at = at(9)),
        ];
        for mutate in mutations {
            let temp = TempDir::new().unwrap();
            let before = pending(&temp);
            let mut invalid = decision(ApprovalDisposition::Approved);
            mutate(&mut invalid);
            assert!(matches!(
                DurableGuardrailAuthority::new(temp.path(), 8).record_decision(invalid),
                Err(DurableApprovalError::InvalidDecision(_))
                    | Err(DurableApprovalError::NotFound { .. })
            ));
            assert_eq!(
                DurableGuardrailAuthority::new(temp.path(), 8)
                    .load(&ApprovalRequestId::from("approval-1"))
                    .unwrap(),
                before
            );
        }
    }

    #[test]
    fn corrupt_payload_and_envelope_are_rejected_and_consumed_invariant_is_ready() {
        let temp = TempDir::new().unwrap();
        pending(&temp);
        let raw = VersionedStateStore::new(temp.path());
        raw.compare_and_swap(
            &entity_key(&ApprovalRequestId::from("approval-1")),
            0,
            b"not-json",
        )
        .unwrap();
        assert!(matches!(
            DurableGuardrailAuthority::new(temp.path(), 8)
                .load(&ApprovalRequestId::from("approval-1")),
            Err(DurableApprovalError::CorruptPayload { .. })
        ));

        let temp = TempDir::new().unwrap();
        let stored = pending(&temp);
        let mut corrupt = stored.envelope.clone();
        corrupt.contract_version = ContractVersion(2);
        VersionedStateStore::new(temp.path())
            .compare_and_swap(
                &entity_key(&ApprovalRequestId::from("approval-1")),
                0,
                serde_json::to_vec(&corrupt).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            DurableGuardrailAuthority::new(temp.path(), 8)
                .load(&ApprovalRequestId::from("approval-1")),
            Err(DurableApprovalError::CorruptState {
                source: ApprovalStateCorruption::UnsupportedEnvelopeVersion,
                ..
            })
        ));

        let mut consumed = stored.envelope;
        consumed.state = ApprovalState::Consumed;
        consumed.decision = Some(decision(ApprovalDisposition::Approved));
        assert!(validate_envelope(&ApprovalRequestId::from("approval-1"), &consumed).is_ok());
        consumed.decision = Some(decision(ApprovalDisposition::Denied));
        assert_eq!(
            validate_envelope(&ApprovalRequestId::from("approval-1"), &consumed),
            Err(ApprovalStateCorruption::ConsumedDecisionNotApproved)
        );
    }

    fn assert_corrupt_load_does_not_mutate(
        temp: &TempDir,
        envelope: ApprovalEnvelope,
        expected: ApprovalStateCorruption,
    ) {
        let id = ApprovalRequestId::from("approval-1");
        let raw = VersionedStateStore::new(temp.path());
        let replaced = raw
            .compare_and_swap(&entity_key(&id), 0, serde_json::to_vec(&envelope).unwrap())
            .unwrap();
        assert!(matches!(replaced, CompareAndSwapOutcome::Applied(_)));
        let before = raw.load(&entity_key(&id)).unwrap().unwrap();

        for _ in 0..2 {
            assert!(matches!(
                DurableGuardrailAuthority::new(temp.path(), 8).load(&id),
                Err(DurableApprovalError::CorruptState { source, .. }) if source == expected
            ));
        }

        let after = raw.load(&entity_key(&id)).unwrap().unwrap();
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.payload, before.payload);
    }

    #[test]
    fn policy_binding_corruption_rejects_on_fresh_load_without_mutation() {
        for removed_gate in [GuardRequirement::Reviewer, GuardRequirement::Auditor] {
            let temp = TempDir::new().unwrap();
            let mut corrupt = pending(&temp).envelope;
            assert!(corrupt.required_gates.remove(&removed_gate));
            assert_corrupt_load_does_not_mutate(
                &temp,
                corrupt,
                ApprovalStateCorruption::RequiredGatesMismatch,
            );
        }

        let temp = TempDir::new().unwrap();
        let mut corrupt = pending(&temp).envelope;
        corrupt.approval_request.guard_request = request(RiskTier::R0, SideEffectClass::ReadOnly);
        assert_corrupt_load_does_not_mutate(
            &temp,
            corrupt,
            ApprovalStateCorruption::StoredRequestNoLongerRequiresApproval,
        );
    }

    #[test]
    fn valid_pending_approved_denied_and_consumed_envelopes_restore() {
        let pending_temp = TempDir::new().unwrap();
        let pending_record = pending(&pending_temp);
        assert_eq!(
            DurableGuardrailAuthority::new(pending_temp.path(), 8)
                .load(&ApprovalRequestId::from("approval-1"))
                .unwrap(),
            pending_record
        );

        for (disposition, expected_state) in [
            (ApprovalDisposition::Approved, ApprovalState::Approved),
            (ApprovalDisposition::Denied, ApprovalState::Denied),
        ] {
            let temp = TempDir::new().unwrap();
            pending(&temp);
            let decided = DurableGuardrailAuthority::new(temp.path(), 8)
                .record_decision(decision(disposition))
                .unwrap()
                .record;
            assert_eq!(decided.envelope.state, expected_state);
            assert_eq!(
                DurableGuardrailAuthority::new(temp.path(), 8)
                    .load(&ApprovalRequestId::from("approval-1"))
                    .unwrap(),
                decided
            );
        }

        let temp = TempDir::new().unwrap();
        let approved = pending(&temp);
        let mut consumed = approved.envelope;
        consumed.state = ApprovalState::Consumed;
        consumed.decision = Some(decision(ApprovalDisposition::Approved));
        let raw = VersionedStateStore::new(temp.path());
        let replaced = raw
            .compare_and_swap(
                &entity_key(&ApprovalRequestId::from("approval-1")),
                0,
                serde_json::to_vec(&consumed).unwrap(),
            )
            .unwrap();
        let CompareAndSwapOutcome::Applied(stored) = replaced else {
            panic!("consumed envelope should replace pending state")
        };
        let restored = DurableGuardrailAuthority::new(temp.path(), 8)
            .load(&ApprovalRequestId::from("approval-1"))
            .unwrap();
        assert_eq!(restored.envelope, consumed);
        assert_eq!(restored.revision, stored.revision);
    }

    #[test]
    fn missing_approval_is_explicit_and_source_has_no_process_global_mutex() {
        let temp = TempDir::new().unwrap();
        assert!(matches!(
            DurableGuardrailAuthority::new(temp.path(), 8)
                .load(&ApprovalRequestId::from("missing")),
            Err(DurableApprovalError::NotFound { .. })
        ));
        assert!(
            !temp.path().join(VERSIONED_STATE_DB_RELATIVE_PATH).exists()
                || temp.path().join(VERSIONED_STATE_DB_RELATIVE_PATH).is_file()
        );
        let source = include_str!("durable_guardrails.rs");
        for forbidden in [
            ["static ", "Mutex"].concat(),
            ["OnceLock<", "Mutex"].concat(),
        ] {
            assert!(!source.contains(&forbidden));
        }
    }

    #[test]
    fn guarded_initial_allow_pause_and_deny_matrix_never_bypass_policy() {
        for (tier, side_effect, expected_gates) in [
            (RiskTier::R0, SideEffectClass::ReadOnly, BTreeSet::new()),
            (
                RiskTier::R1,
                SideEffectClass::ReversibleLocalWrite,
                BTreeSet::from([GuardRequirement::Reviewer]),
            ),
        ] {
            let temp = TempDir::new().unwrap();
            let calls = AtomicUsize::new(0);
            let result = DurableGuardrailAuthority::new(temp.path(), 8)
                .execute_guarded(&request(tier, side_effect), &context("unused"), || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>("ok")
                })
                .unwrap();
            assert!(
                matches!(result, GuardedExecution::Executed { output: "ok", required_gates } if required_gates == expected_gates)
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(!temp.path().join(VERSIONED_STATE_DB_RELATIVE_PATH).exists());
        }

        let surfaces = [
            GuardSurface::Input,
            GuardSurface::Output,
            GuardSurface::Tool,
        ];
        let r2_classes = [
            SideEffectClass::RepositoryWrite,
            SideEffectClass::NetworkAction,
            SideEffectClass::Publication,
            SideEffectClass::ExternalSideEffect,
        ];
        let r3_classes = [
            SideEffectClass::Destructive,
            SideEffectClass::SecretBearing,
            SideEffectClass::Irreversible,
            SideEffectClass::Privileged,
        ];
        let mut paused = 0;
        let mut denied = 0;
        for (tier, classes) in [(RiskTier::R2, r2_classes), (RiskTier::R3, r3_classes)] {
            for surface in surfaces {
                for side_effect in classes {
                    let temp = TempDir::new().unwrap();
                    let calls = AtomicUsize::new(0);
                    let mut guarded = request(tier, side_effect);
                    guarded.surface = surface;
                    let result = DurableGuardrailAuthority::new(temp.path(), 8)
                        .execute_guarded(&guarded, &context("approval-1"), || {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, ()>(())
                        })
                        .unwrap();
                    match result {
                        GuardedExecution::PausedForApproval { .. } => paused += 1,
                        GuardedExecution::DeniedByPolicy { .. } => denied += 1,
                        other => panic!("unexpected guarded result: {other:?}"),
                    }
                    assert_eq!(calls.load(Ordering::SeqCst), 0);
                }
            }
        }
        assert_eq!((paused, denied), (12, 12));
    }

    #[test]
    fn approved_resume_consumes_once_and_effect_failure_is_not_retryable() {
        let temp = TempDir::new().unwrap();
        pending(&temp);
        DurableGuardrailAuthority::new(temp.path(), 8)
            .record_decision(decision(ApprovalDisposition::Approved))
            .unwrap();
        let authority = DurableGuardrailAuthority::new(temp.path(), 8);
        let guarded = request(RiskTier::R2, SideEffectClass::NetworkAction);
        let failed = authority
            .resume_approved(&ApprovalRequestId::from("approval-1"), &guarded, || {
                Err::<(), _>("effect failed")
            })
            .unwrap();
        assert!(
            matches!(failed, GuardedExecution::EffectFailedAfterConsumption { error: "effect failed", consumed_record, required_gates } if consumed_record.envelope.state == ApprovalState::Consumed && required_gates == consumed_record.envelope.required_gates)
        );
        let calls = AtomicUsize::new(0);
        let retry = authority
            .resume_approved(&ApprovalRequestId::from("approval-1"), &guarded, || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(matches!(retry, GuardedExecution::AlreadyConsumed { .. }));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn independent_authorities_racing_resume_invoke_effect_once_total() {
        let temp = TempDir::new().unwrap();
        pending(&temp);
        DurableGuardrailAuthority::new(temp.path(), 8)
            .record_decision(decision(ApprovalDisposition::Approved))
            .unwrap();
        let root = temp.path().to_path_buf();
        let barrier = Arc::new(Barrier::new(2));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            let calls = Arc::clone(&calls);
            handles.push(thread::spawn(move || {
                barrier.wait();
                DurableGuardrailAuthority::new(root, 8)
                    .resume_approved(
                        &ApprovalRequestId::from("approval-1"),
                        &request(RiskTier::R2, SideEffectClass::NetworkAction),
                        || {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, ()>(())
                        },
                    )
                    .unwrap()
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, GuardedExecution::Executed { .. }))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, GuardedExecution::AlreadyConsumed { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn pending_denied_and_mismatched_resume_do_not_invoke_effect() {
        for disposition in [None, Some(ApprovalDisposition::Denied)] {
            let temp = TempDir::new().unwrap();
            pending(&temp);
            if let Some(disposition) = disposition {
                DurableGuardrailAuthority::new(temp.path(), 8)
                    .record_decision(decision(disposition))
                    .unwrap();
            }
            let calls = AtomicUsize::new(0);
            let result = DurableGuardrailAuthority::new(temp.path(), 8)
                .resume_approved(
                    &ApprovalRequestId::from("approval-1"),
                    &request(RiskTier::R2, SideEffectClass::NetworkAction),
                    || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, ()>(())
                    },
                )
                .unwrap();
            assert!(matches!(
                result,
                GuardedExecution::StillPending { .. } | GuardedExecution::DeniedByOwner { .. }
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }

        let temp = TempDir::new().unwrap();
        pending(&temp);
        let calls = AtomicUsize::new(0);
        let mut mismatch = request(RiskTier::R2, SideEffectClass::NetworkAction);
        mismatch.operation_label = "different".into();
        assert!(matches!(
            DurableGuardrailAuthority::new(temp.path(), 8).resume_approved(
                &ApprovalRequestId::from("approval-1"),
                &mismatch,
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(())
                },
            ),
            Err(DurableApprovalError::RequestMismatch { .. })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
