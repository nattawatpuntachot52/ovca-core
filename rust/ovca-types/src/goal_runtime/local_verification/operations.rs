//! Pure, deterministic operations for local-verification contracts.
//!
//! These helpers derive contracts only. They never read storage, infer a goal or
//! task binding, execute commands, or create completion evidence.

use super::{
    invalid, validate_text, verification_sha256_hex, BehaviorBinding, BehaviorCriterion,
    BehaviorKind, BehavioralAcceptanceContract, LocalVerificationResult,
    LOCAL_VERIFICATION_CONTRACT_VERSION,
};
use crate::GoalContract;
use serde::Serialize;

const MIGRATION_SOURCE_VERSION: &str = "ovca.goal-free-text-migration-source.v1";
const MIGRATION_CRITERION_VERSION: &str = "ovca.goal-free-text-migration-criterion.v1";

#[derive(Serialize)]
struct MigrationSource<'a> {
    version: &'static str,
    acceptance_criteria: &'a [String],
    verification_criteria: &'a [String],
    definition_of_done: &'a [String],
}

#[derive(Serialize)]
struct MigrationCriterionIdentity<'a> {
    version: &'static str,
    source_sha256: &'a str,
    kind: BehaviorKind,
    ordinal: u32,
    text: &'a str,
}

/// Converts the three legacy free-text criterion arrays into one deterministic,
/// deliberately unbound behavioral contract.
///
/// Declaration order is acceptance, verification, then definition-of-done.
/// Duplicates remain distinct because every identity binds the closed kind and
/// kind-local ordinal. The operation has no persistence side effect, so invalid
/// input cannot leave a partial result.
pub fn migrate_goal_free_text_contract(
    goal: &GoalContract,
) -> LocalVerificationResult<BehavioralAcceptanceContract> {
    if goal.contract_version != LOCAL_VERIFICATION_CONTRACT_VERSION {
        return Err(invalid(
            "unsupported_contract_version",
            format!(
                "goal_contract expected {}, got {}",
                LOCAL_VERIFICATION_CONTRACT_VERSION, goal.contract_version
            ),
        ));
    }

    let total = goal
        .acceptance_criteria
        .len()
        .checked_add(goal.verification_criteria.len())
        .and_then(|value| value.checked_add(goal.definition_of_done.len()))
        .ok_or_else(|| invalid("criterion_count_overflow", "criterion count exceeds usize"))?;
    if total == 0 {
        return Err(invalid(
            "empty_behavior_criteria",
            "legacy goal has no free-text criteria",
        ));
    }
    u32::try_from(total)
        .map_err(|_| invalid("criterion_count_overflow", "criterion count exceeds u32"))?;

    for (kind, values) in [
        ("acceptance", goal.acceptance_criteria.as_slice()),
        ("verification", goal.verification_criteria.as_slice()),
        ("definition_of_done", goal.definition_of_done.as_slice()),
    ] {
        for (ordinal, text) in values.iter().enumerate() {
            validate_text(text, &format!("{kind}[{ordinal}]"))?;
        }
    }

    let source_bytes = serde_json::to_vec(&MigrationSource {
        version: MIGRATION_SOURCE_VERSION,
        acceptance_criteria: &goal.acceptance_criteria,
        verification_criteria: &goal.verification_criteria,
        definition_of_done: &goal.definition_of_done,
    })
    .map_err(|error| invalid("canonical_serialization_failed", error.to_string()))?;
    let source_sha256 = verification_sha256_hex(&source_bytes);

    let mut criteria = Vec::with_capacity(total);
    for (kind, values) in [
        (
            BehaviorKind::Acceptance,
            goal.acceptance_criteria.as_slice(),
        ),
        (
            BehaviorKind::Verification,
            goal.verification_criteria.as_slice(),
        ),
        (
            BehaviorKind::DefinitionOfDone,
            goal.definition_of_done.as_slice(),
        ),
    ] {
        for (ordinal, text) in values.iter().enumerate() {
            let ordinal = u32::try_from(ordinal)
                .map_err(|_| invalid("criterion_count_overflow", "ordinal exceeds u32"))?;
            let identity_bytes = serde_json::to_vec(&MigrationCriterionIdentity {
                version: MIGRATION_CRITERION_VERSION,
                source_sha256: &source_sha256,
                kind,
                ordinal,
                text,
            })
            .map_err(|error| invalid("canonical_serialization_failed", error.to_string()))?;
            criteria.push(BehaviorCriterion {
                criterion_id: format!(
                    "criterion.migrated.{kind:?}.{ordinal}.sha256.{}",
                    verification_sha256_hex(&identity_bytes)
                )
                .to_ascii_lowercase(),
                order: u32::try_from(criteria.len())
                    .map_err(|_| invalid("criterion_count_overflow", "order exceeds u32"))?,
                kind,
                text: text.clone(),
                required: true,
                capability_ids: Vec::new(),
            });
        }
    }

    let migrated = BehavioralAcceptanceContract {
        contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
        contract_id: format!("behavior.migrated.sha256.{source_sha256}"),
        binding: BehaviorBinding::Unbound,
        criteria,
    };
    migrated.validate()?;
    Ok(migrated)
}

/// Closed result of read-only ambiguous-append reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionAppendReconciliation {
    AlreadyCommitted,
    RetryRequired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CompletionPrecondition, ContractVersion, GoalId, PermissionProfile, ProjectId, RiskTier,
    };
    use chrono::{TimeZone, Utc};

    fn goal() -> GoalContract {
        let timestamp = Utc.with_ymd_and_hms(2026, 8, 12, 0, 0, 0).unwrap();
        GoalContract {
            contract_version: ContractVersion::current(),
            id: GoalId::from("goal.migration"),
            project_id: ProjectId::from("project.oracle"),
            objective: "ignored by migration identity".to_owned(),
            constraints: vec!["also ignored".to_owned()],
            acceptance_criteria: vec!["duplicate".to_owned(), "duplicate".to_owned()],
            verification_criteria: vec!["verify".to_owned()],
            permission_profile: PermissionProfile {
                contract_version: ContractVersion::current(),
                risk_tier: RiskTier::R1,
                resource_keys: vec![],
                write_keys: vec![],
                approval_required: false,
                review_required: true,
                audit_required: true,
            },
            definition_of_done: vec!["done".to_owned()],
            completion_precondition: CompletionPrecondition::default(),
            created_at: timestamp,
            updated_at: timestamp,
        }
    }

    #[test]
    fn migration_is_unbound_ordered_duplicate_preserving_and_byte_idempotent() {
        let first = migrate_goal_free_text_contract(&goal()).unwrap();
        let second = migrate_goal_free_text_contract(&goal()).unwrap();
        assert_eq!(first.binding, BehaviorBinding::Unbound);
        assert_eq!(first.criteria.len(), 4);
        assert_eq!(first.criteria[0].kind, BehaviorKind::Acceptance);
        assert_eq!(first.criteria[1].kind, BehaviorKind::Acceptance);
        assert_eq!(first.criteria[2].kind, BehaviorKind::Verification);
        assert_eq!(first.criteria[3].kind, BehaviorKind::DefinitionOfDone);
        assert_ne!(
            first.criteria[0].criterion_id,
            first.criteria[1].criterion_id
        );
        assert_eq!(
            first.canonical_json_bytes().unwrap(),
            second.canonical_json_bytes().unwrap()
        );
    }

    #[test]
    fn migration_identity_consumes_only_the_three_frozen_arrays() {
        let first = goal();
        let mut second = first.clone();
        second.objective = "different ignored objective".to_owned();
        second.id = GoalId::from("goal.other");
        second.updated_at = Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(
            migrate_goal_free_text_contract(&first)
                .unwrap()
                .canonical_json_bytes()
                .unwrap(),
            migrate_goal_free_text_contract(&second)
                .unwrap()
                .canonical_json_bytes()
                .unwrap()
        );
    }

    #[test]
    fn malformed_or_empty_input_returns_no_contract() {
        let mut empty = goal();
        empty.acceptance_criteria.clear();
        empty.verification_criteria.clear();
        empty.definition_of_done.clear();
        assert_eq!(
            migrate_goal_free_text_contract(&empty).unwrap_err().code,
            "empty_behavior_criteria"
        );

        let mut malformed = goal();
        malformed.verification_criteria = vec![" \t".to_owned()];
        assert_eq!(
            migrate_goal_free_text_contract(&malformed)
                .unwrap_err()
                .code,
            "blank_text"
        );
    }
}
