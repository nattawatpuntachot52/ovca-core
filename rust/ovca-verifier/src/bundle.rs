use chrono::{DateTime, Utc};
use ovca_types::{
    derive_verification_bundle_id, validate_verification_bundle_bindings,
    verification_behavior_digest, verification_capability_set_digest,
    verification_command_set_digest, verification_policy_digest, BehaviorCriterion,
    BehavioralAcceptanceContract, CapabilityDefinition, CriterionResult, CriterionResultVerdict,
    FailureConfirmation, TargetedRerunSelection, VerificationBundle, VerificationFailure,
    VerificationFailureCategory, VerificationFingerprints, VerificationTranscriptIdentity,
    VerificationVerdict, WorkerId, LOCAL_VERIFICATION_CONTRACT_VERSION,
};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailureCode {
    TestFailedUnclassified,
    PolicyBlock,
    EnvironmentBlock,
    ExecutableUnavailable,
    ExecutableTamper,
    CommandTimeout,
    OutputLimit,
    SourceDrift,
    SnapshotTamper,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FailureIdentityKey {
    pub failure_code: FailureCode,
    pub command_sequence: Option<u32>,
}

pub type FailureIdentityMap = BTreeMap<FailureIdentityKey, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureEvent {
    pub code: FailureCode,
    pub command_sequence: Option<u32>,
    pub pre_spawn: bool,
}

#[derive(Debug, Error)]
pub enum BundleBuildError {
    #[error("failure identity map is not the exact canonical set")]
    InvalidFailureIdentity,
    #[error("bundle contract binding is invalid")]
    InvalidBinding,
}

pub fn expected_failure_identity_keys(
    command_count: usize,
) -> Option<BTreeSet<FailureIdentityKey>> {
    let mut keys = BTreeSet::new();
    for sequence in 0..command_count {
        let sequence = u32::try_from(sequence).ok()?;
        for failure_code in [
            FailureCode::TestFailedUnclassified,
            FailureCode::PolicyBlock,
            FailureCode::EnvironmentBlock,
            FailureCode::ExecutableUnavailable,
            FailureCode::ExecutableTamper,
            FailureCode::CommandTimeout,
            FailureCode::OutputLimit,
        ] {
            keys.insert(FailureIdentityKey {
                failure_code,
                command_sequence: Some(sequence),
            });
        }
    }
    keys.insert(FailureIdentityKey {
        failure_code: FailureCode::SourceDrift,
        command_sequence: None,
    });
    keys.insert(FailureIdentityKey {
        failure_code: FailureCode::SnapshotTamper,
        command_sequence: None,
    });
    Some(keys)
}

pub fn validate_failure_identity_map(
    identities: &FailureIdentityMap,
    command_count: usize,
    created_at: &DateTime<Utc>,
) -> bool {
    if created_at.timestamp_subsec_nanos() % 1_000 != 0 {
        return false;
    }
    let Some(expected) = expected_failure_identity_keys(command_count) else {
        return false;
    };
    if identities.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return false;
    }
    let mut values = BTreeSet::new();
    identities
        .values()
        .all(|failure_id| values.insert(failure_id.as_str()) && valid_stable_id(failure_id))
}

pub fn failure_for_event(
    event: FailureEvent,
    identities: &FailureIdentityMap,
    created_at: DateTime<Utc>,
) -> Result<VerificationFailure, BundleBuildError> {
    let key = FailureIdentityKey {
        failure_code: event.code,
        command_sequence: event.command_sequence,
    };
    let failure_id = identities
        .get(&key)
        .ok_or(BundleBuildError::InvalidFailureIdentity)?
        .clone();
    let (category, confirmation, summary) = failure_shape(event);
    Ok(VerificationFailure {
        contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
        failure_id,
        category,
        confirmation,
        supersedes_failure_id: None,
        criterion_id: None,
        summary: summary.to_owned(),
        recorded_at: created_at,
    })
}

pub struct BundleBuildInput<'a> {
    pub behavior: &'a BehavioralAcceptanceContract,
    pub capabilities: &'a [CapabilityDefinition],
    pub selection: &'a TargetedRerunSelection,
    pub implementation_actor: &'a WorkerId,
    pub verifier_actor: &'a WorkerId,
    pub environment_digest: &'a str,
    pub source_pre: &'a str,
    pub source_post: &'a str,
    pub criterion_verdicts: &'a BTreeMap<String, CriterionResultVerdict>,
    pub failures: Vec<VerificationFailure>,
    pub transcript: &'a VerificationTranscriptIdentity,
    pub created_at: DateTime<Utc>,
}

pub fn build_bundle(input: BundleBuildInput<'_>) -> Result<VerificationBundle, BundleBuildError> {
    let mut criterion_results = Vec::with_capacity(input.behavior.criteria.len());
    for criterion in &input.behavior.criteria {
        let verdict = input
            .criterion_verdicts
            .get(&criterion.criterion_id)
            .copied()
            .ok_or(BundleBuildError::InvalidBinding)?;
        criterion_results.push(result(criterion, verdict));
    }
    let verdict = criterion_results
        .iter()
        .map(|result| result.verdict)
        .max_by_key(|value| verdict_rank(*value))
        .map(bundle_verdict)
        .ok_or(BundleBuildError::InvalidBinding)?;
    let mut failures = input.failures;
    failures.sort_by(|left, right| left.failure_id.cmp(&right.failure_id));

    let bundle_id = derive_verification_bundle_id(
        &input.selection.run_id,
        &input.selection.goal_id,
        &input.selection.task_id,
        &input.selection.selection_digest,
        input.transcript,
        input.implementation_actor,
        input.verifier_actor,
        &input.created_at,
    )
    .map_err(|_| BundleBuildError::InvalidBinding)?;
    let bundle = VerificationBundle {
        contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
        bundle_id,
        run_id: input.selection.run_id.clone(),
        goal_id: input.selection.goal_id.clone(),
        task_id: input.selection.task_id.clone(),
        behavior_contract_id: input.behavior.contract_id.clone(),
        capability_ids: input
            .selection
            .capabilities
            .iter()
            .map(|value| value.capability_id.clone())
            .collect(),
        implementation_actor: input.implementation_actor.clone(),
        verifier_actor: input.verifier_actor.clone(),
        fingerprints: VerificationFingerprints {
            source_pre: input.source_pre.to_owned(),
            source_post: input.source_post.to_owned(),
            behavior_contract: verification_behavior_digest(input.behavior)
                .map_err(|_| BundleBuildError::InvalidBinding)?,
            capability_set: verification_capability_set_digest(input.selection)
                .map_err(|_| BundleBuildError::InvalidBinding)?,
            command: verification_command_set_digest(input.capabilities)
                .map_err(|_| BundleBuildError::InvalidBinding)?,
            policy: verification_policy_digest(input.capabilities)
                .map_err(|_| BundleBuildError::InvalidBinding)?,
            environment: input.environment_digest.to_owned(),
        },
        criterion_results,
        failures,
        verdict,
        created_at: input.created_at,
    };
    validate_verification_bundle_bindings(
        input.behavior,
        input.capabilities,
        input.selection,
        &bundle,
        input.transcript,
    )
    .map_err(|_| BundleBuildError::InvalidBinding)?;
    Ok(bundle)
}

pub fn apply_verdict(
    verdicts: &mut BTreeMap<String, CriterionResultVerdict>,
    criterion_ids: impl IntoIterator<Item = String>,
    contribution: CriterionResultVerdict,
) {
    for criterion_id in criterion_ids {
        verdicts
            .entry(criterion_id)
            .and_modify(|current| {
                if verdict_rank(contribution) > verdict_rank(*current) {
                    *current = contribution;
                }
            })
            .or_insert(contribution);
    }
}

fn result(criterion: &BehaviorCriterion, verdict: CriterionResultVerdict) -> CriterionResult {
    CriterionResult {
        criterion_id: criterion.criterion_id.clone(),
        order: criterion.order,
        kind: criterion.kind,
        text: criterion.text.clone(),
        verdict,
    }
}

fn verdict_rank(value: CriterionResultVerdict) -> u8 {
    match value {
        CriterionResultVerdict::Pass => 0,
        CriterionResultVerdict::Fail => 1,
        CriterionResultVerdict::Blocked => 2,
        CriterionResultVerdict::Timeout => 3,
        CriterionResultVerdict::Invalid => 4,
    }
}

fn bundle_verdict(value: CriterionResultVerdict) -> VerificationVerdict {
    match value {
        CriterionResultVerdict::Pass => VerificationVerdict::Pass,
        CriterionResultVerdict::Fail => VerificationVerdict::Fail,
        CriterionResultVerdict::Blocked => VerificationVerdict::Blocked,
        CriterionResultVerdict::Timeout => VerificationVerdict::Timeout,
        CriterionResultVerdict::Invalid => VerificationVerdict::Invalid,
    }
}

fn failure_shape(
    event: FailureEvent,
) -> (
    VerificationFailureCategory,
    FailureConfirmation,
    &'static str,
) {
    match event.code {
        FailureCode::TestFailedUnclassified => (
            VerificationFailureCategory::TestFailedUnclassified,
            FailureConfirmation::Provisional,
            "verification command exited nonzero",
        ),
        FailureCode::PolicyBlock => (
            VerificationFailureCategory::PolicyBlock,
            FailureConfirmation::Confirmed,
            "verification command policy blocked",
        ),
        FailureCode::EnvironmentBlock => (
            VerificationFailureCategory::Environment,
            FailureConfirmation::Confirmed,
            "verification environment policy blocked",
        ),
        FailureCode::ExecutableUnavailable => (
            VerificationFailureCategory::Infrastructure,
            FailureConfirmation::Confirmed,
            "verification executable unavailable",
        ),
        FailureCode::ExecutableTamper => (
            VerificationFailureCategory::ContractViolation,
            FailureConfirmation::Confirmed,
            if event.pre_spawn {
                "verification executable digest mismatch"
            } else {
                "verification executable changed during execution"
            },
        ),
        FailureCode::CommandTimeout => (
            VerificationFailureCategory::Timeout,
            FailureConfirmation::Confirmed,
            "verification command timed out",
        ),
        FailureCode::OutputLimit => (
            VerificationFailureCategory::PolicyBlock,
            FailureConfirmation::Confirmed,
            "verification output limit exceeded",
        ),
        FailureCode::SourceDrift => (
            VerificationFailureCategory::SourceDrift,
            FailureConfirmation::Confirmed,
            "verification source changed during execution",
        ),
        FailureCode::SnapshotTamper => (
            VerificationFailureCategory::ContractViolation,
            FailureConfirmation::Confirmed,
            "verification snapshot integrity mismatch",
        ),
    }
}

fn valid_stable_id(value: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn failure_identity_set_is_exact_and_executable_summaries_are_closed() {
        let created_at = Utc.with_ymd_and_hms(2026, 8, 10, 0, 0, 0).unwrap();
        let identities = expected_failure_identity_keys(1)
            .unwrap()
            .into_iter()
            .enumerate()
            .map(|(index, key)| (key, format!("failure.{index:03}")))
            .collect::<FailureIdentityMap>();
        assert!(validate_failure_identity_map(&identities, 1, &created_at));
        let pre = failure_for_event(
            FailureEvent {
                code: FailureCode::ExecutableTamper,
                command_sequence: Some(0),
                pre_spawn: true,
            },
            &identities,
            created_at,
        )
        .unwrap();
        let post = failure_for_event(
            FailureEvent {
                code: FailureCode::ExecutableTamper,
                command_sequence: Some(0),
                pre_spawn: false,
            },
            &identities,
            created_at,
        )
        .unwrap();
        assert_eq!(pre.summary, "verification executable digest mismatch");
        assert_eq!(
            post.summary,
            "verification executable changed during execution"
        );
        let mut missing = identities;
        missing.pop_first();
        assert!(!validate_failure_identity_map(&missing, 1, &created_at));
    }
}
