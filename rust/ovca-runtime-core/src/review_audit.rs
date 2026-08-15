//! Pure validation and resolution of evidence-backed Reviewer and Auditor decisions.
//!
//! Referenced evidence bytes remain outside this module. Validation only
//! inspects caller-supplied contracts and in-memory evidence metadata.

use chrono::{DateTime, Utc};
use ovca_types::goal_runtime::{
    AuditDecision, CompletionEvidence, ContractVersion, CriterionAssessment,
    CriterionAssessmentVerdict, CriterionKind, EvidenceId, EvidenceRef, GoalContract, GoalId,
    GuardRequirement, ReviewAuditResolution, ReviewDecision, ReviewDecisionId, ReviewVerdict, Role,
    RunId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Caller-supplied contracts and evidence metadata used to validate one review.
#[derive(Debug, Clone, Copy)]
pub struct ReviewDecisionValidationContext<'a> {
    pub expected_run_id: &'a RunId,
    pub goal_contract: &'a GoalContract,
    pub completion_evidence: &'a CompletionEvidence,
    pub evidence_catalog: &'a [EvidenceRef],
}

/// Caller-supplied contracts and validated review used to validate one audit.
#[derive(Debug, Clone, Copy)]
pub struct AuditDecisionValidationContext<'a> {
    pub expected_run_id: &'a RunId,
    pub goal_contract: &'a GoalContract,
    pub completion_evidence: &'a CompletionEvidence,
    pub evidence_catalog: &'a [EvidenceRef],
    pub validated_review_decision: &'a ValidatedReviewDecision,
}

/// Caller-supplied inputs used to select and evaluate the review/audit gate.
#[derive(Debug, Clone, Copy)]
pub struct ReviewAuditEvaluationContext<'a> {
    pub expected_run_id: &'a RunId,
    pub goal_contract: &'a GoalContract,
    pub completion_evidence: &'a CompletionEvidence,
    pub evidence_catalog: &'a [EvidenceRef],
    pub guard_requirements: &'a BTreeSet<GuardRequirement>,
}

/// Deterministic gate requirements derived from goal and guard policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewAuditPolicy {
    pub reviewer_required: bool,
    pub auditor_required: bool,
}

/// A [`ReviewDecision`] that passed all structural and evidence-binding checks.
///
/// The inner decision is private so this type can only be constructed by
/// [`validate_review_decision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedReviewDecision {
    decision: ReviewDecision,
}

impl ValidatedReviewDecision {
    /// Returns the validated caller-authored decision.
    pub fn decision(&self) -> &ReviewDecision {
        &self.decision
    }

    /// Returns the validated verdict re-derived from required assessments.
    pub fn verdict(&self) -> ReviewVerdict {
        self.decision.verdict
    }

    /// Consumes the validation wrapper and returns the caller-authored record.
    pub fn into_decision(self) -> ReviewDecision {
        self.decision
    }
}

/// An [`AuditDecision`] that passed all structural and evidence-binding checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAuditDecision {
    decision: AuditDecision,
}

impl ValidatedAuditDecision {
    /// Returns the validated caller-authored decision.
    pub fn decision(&self) -> &AuditDecision {
        &self.decision
    }

    /// Returns the validated verdict re-derived from required assessments.
    pub fn verdict(&self) -> ReviewVerdict {
        self.decision.verdict
    }

    /// Consumes the validation wrapper and returns the caller-authored record.
    pub fn into_decision(self) -> AuditDecision {
        self.decision
    }
}

/// Structured validation failures. Malformed input is never converted to Fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewAuditError {
    AuditWithoutReview,
    UnsupportedContractVersion {
        contract: String,
        expected: ContractVersion,
        actual: ContractVersion,
    },
    BlankField {
        field: String,
    },
    DuplicateGoalCriterion {
        kind: CriterionKind,
        criterion: String,
    },
    UnknownSatisfiedCriterion {
        kind: CriterionKind,
        criterion: String,
    },
    DuplicateSatisfiedCriterion {
        kind: CriterionKind,
        criterion: String,
    },
    ReorderedSatisfiedCriterion {
        kind: CriterionKind,
        criterion: String,
    },
    DuplicateCompletionEvidenceId {
        evidence_id: EvidenceId,
    },
    UnsortedCompletionEvidenceIds {
        index: usize,
        previous: EvidenceId,
        actual: EvidenceId,
    },
    DuplicateCatalogEvidenceId {
        evidence_id: EvidenceId,
    },
    UnsortedCatalogEvidenceIds {
        index: usize,
        previous: EvidenceId,
        actual: EvidenceId,
    },
    CompletionEvidenceNotInCatalog {
        evidence_id: EvidenceId,
    },
    InsufficientCompletionEvidence {
        required: u32,
        actual: u32,
    },
    ProducerRoleMismatch {
        expected: Role,
        actual: Role,
    },
    RunIdMismatch {
        expected: RunId,
        actual: RunId,
    },
    GoalIdMismatch {
        expected: GoalId,
        actual: GoalId,
    },
    ReviewDecisionIdMismatch {
        expected: ReviewDecisionId,
        actual: ReviewDecisionId,
    },
    AuditDecisionBeforeReview {
        review_decided_at: DateTime<Utc>,
        audit_decided_at: DateTime<Utc>,
    },
    DuplicateCriterionAssessment {
        kind: CriterionKind,
        criterion: String,
    },
    UnknownCriterionAssessment {
        kind: CriterionKind,
        criterion: String,
    },
    MissingCriterionAssessment {
        kind: CriterionKind,
        criterion: String,
    },
    ReorderedCriterionAssessment {
        index: usize,
        expected_kind: CriterionKind,
        expected_criterion: String,
        actual_kind: CriterionKind,
        actual_criterion: String,
    },
    UnsortedAssessmentEvidenceIds {
        assessment_index: usize,
    },
    DuplicateAssessmentEvidenceId {
        assessment_index: usize,
        evidence_id: EvidenceId,
    },
    AssessmentEvidenceNotInCompletion {
        assessment_index: usize,
        evidence_id: EvidenceId,
    },
    AssessmentEvidenceNotInCatalog {
        assessment_index: usize,
        evidence_id: EvidenceId,
    },
    SatisfiedAssessmentWithoutEvidence {
        assessment_index: usize,
    },
    CompletionSatisfiedCriteriaMismatch {
        kind: CriterionKind,
        expected: Vec<String>,
        actual: Vec<String>,
    },
    VerdictMismatch {
        expected: ReviewVerdict,
        actual: ReviewVerdict,
    },
}

impl fmt::Display for ReviewAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "review decision validation error: {self:?}")
    }
}

impl std::error::Error for ReviewAuditError {}

/// Validates a Reviewer decision against one exact run, goal, and evidence set.
///
/// This function is deterministic and has no side effects.
pub fn validate_review_decision(
    context: &ReviewDecisionValidationContext<'_>,
    decision: &ReviewDecision,
) -> Result<ValidatedReviewDecision, ReviewAuditError> {
    let catalog = validate_context(context)?;

    validate_version("review_decision", decision.contract_version)?;
    validate_nonblank("review_decision.id", decision.id.as_str())?;
    validate_nonblank("review_decision.run_id", decision.run_id.as_str())?;
    validate_nonblank("review_decision.goal_id", decision.goal_id.as_str())?;
    validate_nonblank("review_decision.summary", &decision.summary)?;

    if decision.producer_role != Role::Reviewer {
        return Err(ReviewAuditError::ProducerRoleMismatch {
            expected: Role::Reviewer,
            actual: decision.producer_role,
        });
    }
    if decision.run_id != *context.expected_run_id {
        return Err(ReviewAuditError::RunIdMismatch {
            expected: context.expected_run_id.clone(),
            actual: decision.run_id.clone(),
        });
    }
    if decision.goal_id != context.goal_contract.id {
        return Err(ReviewAuditError::GoalIdMismatch {
            expected: context.goal_contract.id.clone(),
            actual: decision.goal_id.clone(),
        });
    }

    let derived = validate_assessments(
        context,
        &decision.assessments,
        &catalog,
        "review_decision",
        true,
    )?;
    validate_completion_catalog(context.completion_evidence, &catalog)?;
    if derived != decision.verdict {
        return Err(ReviewAuditError::VerdictMismatch {
            expected: derived,
            actual: decision.verdict,
        });
    }

    Ok(ValidatedReviewDecision {
        decision: decision.clone(),
    })
}

/// Validates an Auditor decision against one exact validated review and evidence set.
///
/// Auditor assessments independently countercheck the completion claim. The
/// completion record is validated structurally and binds available evidence,
/// but its claimed satisfied lists do not override the Auditor's assessment.
pub fn validate_audit_decision(
    context: &AuditDecisionValidationContext<'_>,
    decision: &AuditDecision,
) -> Result<ValidatedAuditDecision, ReviewAuditError> {
    let review_context = ReviewDecisionValidationContext {
        expected_run_id: context.expected_run_id,
        goal_contract: context.goal_contract,
        completion_evidence: context.completion_evidence,
        evidence_catalog: context.evidence_catalog,
    };
    let catalog = validate_context(&review_context)?;

    validate_version("audit_decision", decision.contract_version)?;
    validate_nonblank("audit_decision.id", decision.id.as_str())?;
    validate_nonblank("audit_decision.run_id", decision.run_id.as_str())?;
    validate_nonblank("audit_decision.goal_id", decision.goal_id.as_str())?;
    validate_nonblank(
        "audit_decision.review_decision_id",
        decision.review_decision_id.as_str(),
    )?;
    validate_nonblank("audit_decision.summary", &decision.summary)?;

    if decision.producer_role != Role::Auditor {
        return Err(ReviewAuditError::ProducerRoleMismatch {
            expected: Role::Auditor,
            actual: decision.producer_role,
        });
    }
    if decision.run_id != *context.expected_run_id {
        return Err(ReviewAuditError::RunIdMismatch {
            expected: context.expected_run_id.clone(),
            actual: decision.run_id.clone(),
        });
    }
    if decision.goal_id != context.goal_contract.id {
        return Err(ReviewAuditError::GoalIdMismatch {
            expected: context.goal_contract.id.clone(),
            actual: decision.goal_id.clone(),
        });
    }

    let review = context.validated_review_decision.decision();
    if decision.review_decision_id != review.id {
        return Err(ReviewAuditError::ReviewDecisionIdMismatch {
            expected: review.id.clone(),
            actual: decision.review_decision_id.clone(),
        });
    }
    if decision.decided_at < review.decided_at {
        return Err(ReviewAuditError::AuditDecisionBeforeReview {
            review_decided_at: review.decided_at,
            audit_decided_at: decision.decided_at,
        });
    }

    let derived = validate_assessments(
        &review_context,
        &decision.assessments,
        &catalog,
        "audit_decision",
        false,
    )?;
    validate_completion_catalog(context.completion_evidence, &catalog)?;
    if derived != decision.verdict {
        return Err(ReviewAuditError::VerdictMismatch {
            expected: derived,
            actual: decision.verdict,
        });
    }

    Ok(ValidatedAuditDecision {
        decision: decision.clone(),
    })
}

/// Derives review and audit requirements from goal policy and guard requirements.
pub fn derive_review_audit_policy(
    goal_contract: &GoalContract,
    guard_requirements: &BTreeSet<GuardRequirement>,
) -> ReviewAuditPolicy {
    let auditor_required = goal_contract.permission_profile.audit_required
        || guard_requirements.contains(&GuardRequirement::Auditor);
    let reviewer_required = goal_contract.permission_profile.review_required
        || auditor_required
        || guard_requirements.contains(&GuardRequirement::Reviewer);
    ReviewAuditPolicy {
        reviewer_required,
        auditor_required,
    }
}

/// Validates every supplied decision and deterministically resolves the gate.
pub fn evaluate_review_audit(
    context: &ReviewAuditEvaluationContext<'_>,
    review_decision: Option<&ReviewDecision>,
    audit_decision: Option<&AuditDecision>,
) -> Result<ReviewAuditResolution, ReviewAuditError> {
    let policy = derive_review_audit_policy(context.goal_contract, context.guard_requirements);
    let Some(review_decision) = review_decision else {
        if audit_decision.is_some() {
            return Err(ReviewAuditError::AuditWithoutReview);
        }
        return if policy.reviewer_required {
            Ok(ReviewAuditResolution::AwaitingReview)
        } else {
            Ok(ReviewAuditResolution::Pass {
                review_decision_id: None,
                audit_decision_id: None,
            })
        };
    };

    let review_context = ReviewDecisionValidationContext {
        expected_run_id: context.expected_run_id,
        goal_contract: context.goal_contract,
        completion_evidence: context.completion_evidence,
        evidence_catalog: context.evidence_catalog,
    };
    let validated_review = validate_review_decision(&review_context, review_decision)?;

    let Some(audit_decision) = audit_decision else {
        if policy.auditor_required {
            return Ok(ReviewAuditResolution::AwaitingAudit {
                review_decision_id: validated_review.decision().id.clone(),
            });
        }
        return Ok(resolution_from_review(&validated_review));
    };

    let audit_context = AuditDecisionValidationContext {
        expected_run_id: context.expected_run_id,
        goal_contract: context.goal_contract,
        completion_evidence: context.completion_evidence,
        evidence_catalog: context.evidence_catalog,
        validated_review_decision: &validated_review,
    };
    let validated_audit = validate_audit_decision(&audit_context, audit_decision)?;
    Ok(resolve_validated_decisions(
        &validated_review,
        &validated_audit,
    ))
}

fn resolution_from_review(review: &ValidatedReviewDecision) -> ReviewAuditResolution {
    match review.verdict() {
        ReviewVerdict::Pass => ReviewAuditResolution::Pass {
            review_decision_id: Some(review.decision().id.clone()),
            audit_decision_id: None,
        },
        ReviewVerdict::Fail => ReviewAuditResolution::Fail {
            review_decision_id: review.decision().id.clone(),
            audit_decision_id: None,
        },
    }
}

fn resolve_validated_decisions(
    review: &ValidatedReviewDecision,
    audit: &ValidatedAuditDecision,
) -> ReviewAuditResolution {
    let review_id = review.decision().id.clone();
    let audit_id = audit.decision().id.clone();
    match (review.verdict(), audit.verdict()) {
        (ReviewVerdict::Pass, ReviewVerdict::Pass) => ReviewAuditResolution::Pass {
            review_decision_id: Some(review_id),
            audit_decision_id: Some(audit_id),
        },
        (ReviewVerdict::Fail, ReviewVerdict::Fail) => ReviewAuditResolution::Fail {
            review_decision_id: review_id,
            audit_decision_id: Some(audit_id),
        },
        (reviewer_verdict, auditor_verdict) => ReviewAuditResolution::OwnerEscalation {
            review_decision_id: review_id,
            audit_decision_id: audit_id,
            reviewer_verdict,
            auditor_verdict,
        },
    }
}

fn validate_context<'a>(
    context: &ReviewDecisionValidationContext<'a>,
) -> Result<BTreeMap<&'a str, &'a EvidenceRef>, ReviewAuditError> {
    validate_version("goal_contract", context.goal_contract.contract_version)?;
    validate_version(
        "goal_contract.permission_profile",
        context.goal_contract.permission_profile.contract_version,
    )?;
    validate_version(
        "goal_contract.completion_precondition",
        context
            .goal_contract
            .completion_precondition
            .contract_version,
    )?;
    validate_version(
        "completion_evidence",
        context.completion_evidence.contract_version,
    )?;

    validate_nonblank("expected_run_id", context.expected_run_id.as_str())?;
    validate_nonblank("goal_contract.id", context.goal_contract.id.as_str())?;
    validate_nonblank(
        "goal_contract.project_id",
        context.goal_contract.project_id.as_str(),
    )?;
    validate_nonblank("goal_contract.objective", &context.goal_contract.objective)?;
    validate_nonblank_values(
        "goal_contract.constraints",
        &context.goal_contract.constraints,
    )?;
    validate_nonblank_values(
        "goal_contract.permission_profile.resource_keys",
        &context.goal_contract.permission_profile.resource_keys,
    )?;
    validate_nonblank_values(
        "goal_contract.permission_profile.write_keys",
        &context.goal_contract.permission_profile.write_keys,
    )?;
    validate_goal_criteria(context.goal_contract)?;

    let catalog = validate_catalog(context.evidence_catalog)?;
    validate_completion_evidence(context)?;
    Ok(catalog)
}

fn validate_catalog(
    evidence_catalog: &[EvidenceRef],
) -> Result<BTreeMap<&str, &EvidenceRef>, ReviewAuditError> {
    let mut catalog = BTreeMap::new();
    let mut previous_id: Option<&EvidenceId> = None;
    for (index, evidence) in evidence_catalog.iter().enumerate() {
        validate_version(
            &format!("evidence_catalog[{index}]"),
            evidence.contract_version,
        )?;
        validate_nonblank(
            &format!("evidence_catalog[{index}].id"),
            evidence.id.as_str(),
        )?;
        validate_nonblank(
            &format!("evidence_catalog[{index}].reference"),
            &evidence.reference,
        )?;
        if let Some(integrity) = &evidence.integrity {
            validate_version(
                &format!("evidence_catalog[{index}].integrity"),
                integrity.contract_version,
            )?;
            validate_nonblank(
                &format!("evidence_catalog[{index}].integrity.algorithm"),
                &integrity.algorithm,
            )?;
            validate_nonblank(
                &format!("evidence_catalog[{index}].integrity.digest"),
                &integrity.digest,
            )?;
        }

        // Role is a closed enum, so every representable producer is structurally valid.
        if catalog.insert(evidence.id.as_str(), evidence).is_some() {
            return Err(ReviewAuditError::DuplicateCatalogEvidenceId {
                evidence_id: evidence.id.clone(),
            });
        }
        if let Some(previous) = previous_id {
            if evidence.id.as_str() < previous.as_str() {
                return Err(ReviewAuditError::UnsortedCatalogEvidenceIds {
                    index,
                    previous: previous.clone(),
                    actual: evidence.id.clone(),
                });
            }
        }
        previous_id = Some(&evidence.id);
    }
    Ok(catalog)
}

fn validate_completion_evidence(
    context: &ReviewDecisionValidationContext<'_>,
) -> Result<(), ReviewAuditError> {
    let mut unique = BTreeSet::new();
    let mut previous_id: Option<&EvidenceId> = None;
    for (index, evidence_id) in context.completion_evidence.evidence_refs.iter().enumerate() {
        validate_nonblank(
            &format!("completion_evidence.evidence_refs[{index}]"),
            evidence_id.as_str(),
        )?;
        if !unique.insert(evidence_id.as_str()) {
            return Err(ReviewAuditError::DuplicateCompletionEvidenceId {
                evidence_id: evidence_id.clone(),
            });
        }
        if let Some(previous) = previous_id {
            if evidence_id.as_str() < previous.as_str() {
                return Err(ReviewAuditError::UnsortedCompletionEvidenceIds {
                    index,
                    previous: previous.clone(),
                    actual: evidence_id.clone(),
                });
            }
        }
        previous_id = Some(evidence_id);
    }

    let required = context
        .goal_contract
        .completion_precondition
        .minimum_evidence_refs
        .max(1);
    let actual = unique.len() as u32;
    if actual < required {
        return Err(ReviewAuditError::InsufficientCompletionEvidence { required, actual });
    }

    validate_satisfied_list(
        context.goal_contract,
        CriterionKind::Acceptance,
        &context.completion_evidence.satisfied_acceptance_criteria,
    )?;
    validate_satisfied_list(
        context.goal_contract,
        CriterionKind::Verification,
        &context.completion_evidence.satisfied_verification_criteria,
    )?;
    validate_satisfied_list(
        context.goal_contract,
        CriterionKind::DefinitionOfDone,
        &context.completion_evidence.satisfied_definition_of_done,
    )
}

fn validate_completion_catalog(
    completion: &CompletionEvidence,
    catalog: &BTreeMap<&str, &EvidenceRef>,
) -> Result<(), ReviewAuditError> {
    for evidence_id in &completion.evidence_refs {
        if !catalog.contains_key(evidence_id.as_str()) {
            return Err(ReviewAuditError::CompletionEvidenceNotInCatalog {
                evidence_id: evidence_id.clone(),
            });
        }
    }
    Ok(())
}

fn validate_goal_criteria(goal: &GoalContract) -> Result<(), ReviewAuditError> {
    for kind in criterion_kinds() {
        let mut seen = BTreeSet::new();
        for (index, criterion) in declared_criteria(goal, kind).iter().enumerate() {
            validate_nonblank(
                &format!("goal_contract.{}[{index}]", criterion_kind_name(kind)),
                criterion,
            )?;
            if !seen.insert(criterion.as_str()) {
                return Err(ReviewAuditError::DuplicateGoalCriterion {
                    kind,
                    criterion: criterion.clone(),
                });
            }
        }
    }
    Ok(())
}

fn validate_satisfied_list(
    goal: &GoalContract,
    kind: CriterionKind,
    actual: &[String],
) -> Result<(), ReviewAuditError> {
    let positions: BTreeMap<&str, usize> = declared_criteria(goal, kind)
        .iter()
        .enumerate()
        .map(|(index, criterion)| (criterion.as_str(), index))
        .collect();
    let mut seen = BTreeSet::new();
    let mut previous_position = None;

    for (index, criterion) in actual.iter().enumerate() {
        validate_nonblank(
            &format!(
                "completion_evidence.satisfied_{}[{index}]",
                criterion_kind_name(kind)
            ),
            criterion,
        )?;
        let Some(position) = positions.get(criterion.as_str()).copied() else {
            return Err(ReviewAuditError::UnknownSatisfiedCriterion {
                kind,
                criterion: criterion.clone(),
            });
        };
        if !seen.insert(criterion.as_str()) {
            return Err(ReviewAuditError::DuplicateSatisfiedCriterion {
                kind,
                criterion: criterion.clone(),
            });
        }
        if previous_position.is_some_and(|previous| position < previous) {
            return Err(ReviewAuditError::ReorderedSatisfiedCriterion {
                kind,
                criterion: criterion.clone(),
            });
        }
        previous_position = Some(position);
    }
    Ok(())
}

fn validate_assessments(
    context: &ReviewDecisionValidationContext<'_>,
    assessments: &[CriterionAssessment],
    catalog: &BTreeMap<&str, &EvidenceRef>,
    decision_name: &str,
    enforce_completion_alignment: bool,
) -> Result<ReviewVerdict, ReviewAuditError> {
    for (index, assessment) in assessments.iter().enumerate() {
        validate_version(
            &format!("{decision_name}.assessments[{index}]"),
            assessment.contract_version,
        )?;
        validate_nonblank(
            &format!("{decision_name}.assessments[{index}].criterion"),
            &assessment.criterion,
        )?;
        validate_nonblank(
            &format!("{decision_name}.assessments[{index}].rationale"),
            &assessment.rationale,
        )?;
        validate_assessment_evidence(index, assessment, context, catalog, decision_name)?;
    }

    validate_criterion_coverage(context.goal_contract, assessments)?;
    if enforce_completion_alignment {
        validate_completion_alignment(context.completion_evidence, assessments)?;
    }
    Ok(derive_verdict(context.goal_contract, assessments))
}

fn validate_assessment_evidence(
    assessment_index: usize,
    assessment: &CriterionAssessment,
    context: &ReviewDecisionValidationContext<'_>,
    catalog: &BTreeMap<&str, &EvidenceRef>,
    decision_name: &str,
) -> Result<(), ReviewAuditError> {
    let completion_ids: BTreeSet<&str> = context
        .completion_evidence
        .evidence_refs
        .iter()
        .map(|id| id.as_str())
        .collect();
    let mut seen = BTreeSet::new();

    for (evidence_index, evidence_id) in assessment.evidence_refs.iter().enumerate() {
        validate_nonblank(
            &format!(
                "{decision_name}.assessments[{assessment_index}].evidence_refs[{evidence_index}]"
            ),
            evidence_id.as_str(),
        )?;
        if !seen.insert(evidence_id.as_str()) {
            return Err(ReviewAuditError::DuplicateAssessmentEvidenceId {
                assessment_index,
                evidence_id: evidence_id.clone(),
            });
        }
    }

    if assessment
        .evidence_refs
        .windows(2)
        .any(|pair| pair[0] > pair[1])
    {
        return Err(ReviewAuditError::UnsortedAssessmentEvidenceIds { assessment_index });
    }

    for evidence_id in &assessment.evidence_refs {
        if !completion_ids.contains(evidence_id.as_str()) {
            return Err(ReviewAuditError::AssessmentEvidenceNotInCompletion {
                assessment_index,
                evidence_id: evidence_id.clone(),
            });
        }
        if !catalog.contains_key(evidence_id.as_str()) {
            return Err(ReviewAuditError::AssessmentEvidenceNotInCatalog {
                assessment_index,
                evidence_id: evidence_id.clone(),
            });
        }
    }

    if assessment.verdict == CriterionAssessmentVerdict::Satisfied
        && assessment.evidence_refs.is_empty()
    {
        return Err(ReviewAuditError::SatisfiedAssessmentWithoutEvidence { assessment_index });
    }
    Ok(())
}

fn validate_criterion_coverage(
    goal: &GoalContract,
    assessments: &[CriterionAssessment],
) -> Result<(), ReviewAuditError> {
    let declared = canonical_criteria(goal);
    let declared_set: BTreeSet<(CriterionKind, &str)> = declared.iter().copied().collect();
    let mut seen = BTreeSet::new();

    for assessment in assessments {
        let key = (assessment.kind, assessment.criterion.as_str());
        if !seen.insert(key) {
            return Err(ReviewAuditError::DuplicateCriterionAssessment {
                kind: assessment.kind,
                criterion: assessment.criterion.clone(),
            });
        }
        if !declared_set.contains(&key) {
            return Err(ReviewAuditError::UnknownCriterionAssessment {
                kind: assessment.kind,
                criterion: assessment.criterion.clone(),
            });
        }
    }

    for (kind, criterion) in &declared {
        if !seen.contains(&(*kind, *criterion)) {
            return Err(ReviewAuditError::MissingCriterionAssessment {
                kind: *kind,
                criterion: (*criterion).to_owned(),
            });
        }
    }

    for (index, ((expected_kind, expected_criterion), actual)) in
        declared.iter().zip(assessments).enumerate()
    {
        if *expected_kind != actual.kind || *expected_criterion != actual.criterion {
            return Err(ReviewAuditError::ReorderedCriterionAssessment {
                index,
                expected_kind: *expected_kind,
                expected_criterion: (*expected_criterion).to_owned(),
                actual_kind: actual.kind,
                actual_criterion: actual.criterion.clone(),
            });
        }
    }
    Ok(())
}

fn validate_completion_alignment(
    completion: &CompletionEvidence,
    assessments: &[CriterionAssessment],
) -> Result<(), ReviewAuditError> {
    for kind in criterion_kinds() {
        let expected: Vec<String> = assessments
            .iter()
            .filter(|assessment| {
                assessment.kind == kind
                    && assessment.verdict == CriterionAssessmentVerdict::Satisfied
            })
            .map(|assessment| assessment.criterion.clone())
            .collect();
        let actual = completion_satisfied_criteria(completion, kind);
        if expected != actual {
            return Err(ReviewAuditError::CompletionSatisfiedCriteriaMismatch {
                kind,
                expected,
                actual: actual.to_vec(),
            });
        }
    }
    Ok(())
}

fn derive_verdict(goal: &GoalContract, assessments: &[CriterionAssessment]) -> ReviewVerdict {
    let failed_required = assessments.iter().any(|assessment| {
        assessment.verdict == CriterionAssessmentVerdict::Unsatisfied
            && match assessment.kind {
                CriterionKind::Acceptance => {
                    goal.completion_precondition.require_all_acceptance_criteria
                }
                CriterionKind::Verification => {
                    goal.completion_precondition
                        .require_all_verification_criteria
                }
                CriterionKind::DefinitionOfDone => true,
            }
    });
    if failed_required {
        ReviewVerdict::Fail
    } else {
        ReviewVerdict::Pass
    }
}

fn validate_version(contract: &str, actual: ContractVersion) -> Result<(), ReviewAuditError> {
    let expected = ContractVersion::current();
    if actual == expected {
        Ok(())
    } else {
        Err(ReviewAuditError::UnsupportedContractVersion {
            contract: contract.to_owned(),
            expected,
            actual,
        })
    }
}

fn validate_nonblank(field: &str, value: &str) -> Result<(), ReviewAuditError> {
    if value.trim().is_empty() {
        Err(ReviewAuditError::BlankField {
            field: field.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn validate_nonblank_values(field: &str, values: &[String]) -> Result<(), ReviewAuditError> {
    for (index, value) in values.iter().enumerate() {
        validate_nonblank(&format!("{field}[{index}]"), value)?;
    }
    Ok(())
}

fn canonical_criteria(goal: &GoalContract) -> Vec<(CriterionKind, &str)> {
    criterion_kinds()
        .into_iter()
        .flat_map(|kind| {
            declared_criteria(goal, kind)
                .iter()
                .map(move |criterion| (kind, criterion.as_str()))
        })
        .collect()
}

fn declared_criteria(goal: &GoalContract, kind: CriterionKind) -> &[String] {
    match kind {
        CriterionKind::Acceptance => &goal.acceptance_criteria,
        CriterionKind::Verification => &goal.verification_criteria,
        CriterionKind::DefinitionOfDone => &goal.definition_of_done,
    }
}

fn completion_satisfied_criteria(
    completion: &CompletionEvidence,
    kind: CriterionKind,
) -> &[String] {
    match kind {
        CriterionKind::Acceptance => &completion.satisfied_acceptance_criteria,
        CriterionKind::Verification => &completion.satisfied_verification_criteria,
        CriterionKind::DefinitionOfDone => &completion.satisfied_definition_of_done,
    }
}

const fn criterion_kinds() -> [CriterionKind; 3] {
    [
        CriterionKind::Acceptance,
        CriterionKind::Verification,
        CriterionKind::DefinitionOfDone,
    ]
}

const fn criterion_kind_name(kind: CriterionKind) -> &'static str {
    match kind {
        CriterionKind::Acceptance => "acceptance_criteria",
        CriterionKind::Verification => "verification_criteria",
        CriterionKind::DefinitionOfDone => "definition_of_done",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use ovca_types::goal_runtime::{
        AuditDecisionId, CompletionPrecondition, EvidenceKind, IntegrityMetadata,
        PermissionProfile, ProjectId, RiskTier,
    };

    struct Fixture {
        run_id: RunId,
        goal: GoalContract,
        completion: CompletionEvidence,
        catalog: Vec<EvidenceRef>,
        review: ReviewDecision,
        audit: AuditDecision,
        guard_requirements: BTreeSet<GuardRequirement>,
    }

    impl Fixture {
        fn context(&self) -> ReviewDecisionValidationContext<'_> {
            ReviewDecisionValidationContext {
                expected_run_id: &self.run_id,
                goal_contract: &self.goal,
                completion_evidence: &self.completion,
                evidence_catalog: &self.catalog,
            }
        }

        fn validate(&self) -> Result<ValidatedReviewDecision, ReviewAuditError> {
            validate_review_decision(&self.context(), &self.review)
        }

        fn validate_audit(&self) -> Result<ValidatedAuditDecision, ReviewAuditError> {
            let validated_review = self.validate()?;
            validate_audit_decision(
                &AuditDecisionValidationContext {
                    expected_run_id: &self.run_id,
                    goal_contract: &self.goal,
                    completion_evidence: &self.completion,
                    evidence_catalog: &self.catalog,
                    validated_review_decision: &validated_review,
                },
                &self.audit,
            )
        }

        fn evaluation_context(&self) -> ReviewAuditEvaluationContext<'_> {
            ReviewAuditEvaluationContext {
                expected_run_id: &self.run_id,
                goal_contract: &self.goal,
                completion_evidence: &self.completion,
                evidence_catalog: &self.catalog,
                guard_requirements: &self.guard_requirements,
            }
        }

        fn evaluate(
            &self,
            include_review: bool,
            include_audit: bool,
        ) -> Result<ReviewAuditResolution, ReviewAuditError> {
            evaluate_review_audit(
                &self.evaluation_context(),
                include_review.then_some(&self.review),
                include_audit.then_some(&self.audit),
            )
        }
    }

    fn time(hour: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 18, hour, 0, 0).unwrap()
    }

    fn fixture() -> Fixture {
        let goal = GoalContract {
            contract_version: ContractVersion::current(),
            id: GoalId::from("goal-1"),
            project_id: ProjectId::from("project-1"),
            objective: "Ship the bounded Reviewer validator".into(),
            constraints: vec!["pure".into()],
            acceptance_criteria: vec!["API is deterministic".into(), "Evidence is bound".into()],
            verification_criteria: vec!["Tests pass".into(), "Clippy passes".into()],
            permission_profile: PermissionProfile {
                contract_version: ContractVersion::current(),
                risk_tier: RiskTier::R1,
                resource_keys: vec![],
                write_keys: vec![],
                approval_required: false,
                review_required: true,
                audit_required: false,
            },
            definition_of_done: vec!["Diff is bounded".into()],
            completion_precondition: CompletionPrecondition {
                contract_version: ContractVersion::current(),
                minimum_evidence_refs: 2,
                require_all_acceptance_criteria: true,
                require_all_verification_criteria: true,
            },
            created_at: time(8),
            updated_at: time(9),
        };
        let completion = CompletionEvidence {
            contract_version: ContractVersion::current(),
            evidence_refs: vec![
                EvidenceId::from("evidence-1"),
                EvidenceId::from("evidence-2"),
            ],
            satisfied_acceptance_criteria: goal.acceptance_criteria.clone(),
            satisfied_verification_criteria: goal.verification_criteria.clone(),
            satisfied_definition_of_done: goal.definition_of_done.clone(),
        };
        let catalog = vec![
            evidence("evidence-1", Role::Engineer),
            evidence("evidence-2", Role::Reviewer),
        ];
        let review = ReviewDecision {
            contract_version: ContractVersion::current(),
            id: ReviewDecisionId::from("review-1"),
            run_id: RunId::from("run-1"),
            goal_id: goal.id.clone(),
            producer_role: Role::Reviewer,
            verdict: ReviewVerdict::Pass,
            assessments: assessments(&goal, CriterionAssessmentVerdict::Satisfied),
            summary: "All required criteria are structurally supported".into(),
            decided_at: time(11),
        };
        let audit = AuditDecision {
            contract_version: ContractVersion::current(),
            id: AuditDecisionId::from("audit-1"),
            run_id: RunId::from("run-1"),
            goal_id: goal.id.clone(),
            review_decision_id: review.id.clone(),
            producer_role: Role::Auditor,
            verdict: ReviewVerdict::Pass,
            assessments: assessments(&goal, CriterionAssessmentVerdict::Satisfied),
            summary: "Independent countercheck supports the completion claim".into(),
            decided_at: time(12),
        };
        Fixture {
            run_id: RunId::from("run-1"),
            goal,
            completion,
            catalog,
            review,
            audit,
            guard_requirements: BTreeSet::new(),
        }
    }

    fn evidence(id: &str, producer_role: Role) -> EvidenceRef {
        EvidenceRef {
            contract_version: ContractVersion::current(),
            id: EvidenceId::from(id),
            kind: EvidenceKind::TestResult,
            reference: format!("memory://{id}"),
            producer_role,
            integrity: Some(IntegrityMetadata {
                contract_version: ContractVersion::current(),
                algorithm: "sha256".into(),
                digest: format!("digest-{id}"),
            }),
            produced_at: time(10),
        }
    }

    fn assessments(
        goal: &GoalContract,
        verdict: CriterionAssessmentVerdict,
    ) -> Vec<CriterionAssessment> {
        canonical_criteria(goal)
            .into_iter()
            .map(|(kind, criterion)| CriterionAssessment {
                contract_version: ContractVersion::current(),
                kind,
                criterion: criterion.to_owned(),
                verdict,
                evidence_refs: vec![EvidenceId::from("evidence-1")],
                rationale: "Evidence binding checked".into(),
            })
            .collect()
    }

    fn make_review_fail(fixture: &mut Fixture, index: usize) {
        fixture.review.assessments[index].verdict = CriterionAssessmentVerdict::Unsatisfied;
        fixture.review.verdict = ReviewVerdict::Fail;
        let kind = fixture.review.assessments[index].kind;
        let criterion = fixture.review.assessments[index].criterion.clone();
        completion_satisfied_criteria_mut(&mut fixture.completion, kind)
            .retain(|value| value != &criterion);
    }

    fn make_audit_fail(fixture: &mut Fixture, index: usize) {
        fixture.audit.assessments[index].verdict = CriterionAssessmentVerdict::Unsatisfied;
        fixture.audit.verdict = ReviewVerdict::Fail;
    }

    fn completion_satisfied_criteria_mut(
        completion: &mut CompletionEvidence,
        kind: CriterionKind,
    ) -> &mut Vec<String> {
        match kind {
            CriterionKind::Acceptance => &mut completion.satisfied_acceptance_criteria,
            CriterionKind::Verification => &mut completion.satisfied_verification_criteria,
            CriterionKind::DefinitionOfDone => &mut completion.satisfied_definition_of_done,
        }
    }

    #[test]
    fn pass_returns_a_distinct_validated_result() {
        let f = fixture();
        let validated = f.validate().unwrap();
        assert_eq!(validated.decision(), &f.review);
        assert_eq!(validated.verdict(), ReviewVerdict::Pass);
        assert_eq!(validated.into_decision(), f.review);
    }

    #[test]
    fn required_unsatisfied_criterion_derives_fail_with_evidence() {
        let mut f = fixture();
        make_review_fail(&mut f, 4);
        assert!(!f.review.assessments[4].evidence_refs.is_empty());

        let validated = f.validate().unwrap();
        assert_eq!(validated.verdict(), ReviewVerdict::Fail);
    }

    #[test]
    fn optional_acceptance_and_verification_do_not_force_fail() {
        let mut f = fixture();
        f.goal
            .completion_precondition
            .require_all_acceptance_criteria = false;
        f.goal
            .completion_precondition
            .require_all_verification_criteria = false;
        f.review.assessments[0].verdict = CriterionAssessmentVerdict::Unsatisfied;
        f.review.assessments[2].verdict = CriterionAssessmentVerdict::Unsatisfied;
        f.completion.satisfied_acceptance_criteria.remove(0);
        f.completion.satisfied_verification_criteria.remove(0);

        assert_eq!(f.validate().unwrap().verdict(), ReviewVerdict::Pass);
    }

    #[test]
    fn every_definition_of_done_item_is_required() {
        let mut f = fixture();
        make_review_fail(&mut f, 4);
        assert_eq!(f.validate().unwrap().verdict(), ReviewVerdict::Fail);
    }

    #[test]
    fn wrong_role_run_and_goal_are_rejected() {
        let mut wrong_role = fixture();
        wrong_role.review.producer_role = Role::Engineer;
        assert!(matches!(
            wrong_role.validate(),
            Err(ReviewAuditError::ProducerRoleMismatch { .. })
        ));

        let mut wrong_run = fixture();
        wrong_run.review.run_id = RunId::from("other-run");
        assert!(matches!(
            wrong_run.validate(),
            Err(ReviewAuditError::RunIdMismatch { .. })
        ));

        let mut wrong_goal = fixture();
        wrong_goal.review.goal_id = GoalId::from("other-goal");
        assert!(matches!(
            wrong_goal.validate(),
            Err(ReviewAuditError::GoalIdMismatch { .. })
        ));
    }

    #[test]
    fn every_nested_contract_version_must_be_current() {
        let mut goal = fixture();
        goal.goal.contract_version = ContractVersion(2);
        assert!(matches!(
            goal.validate(),
            Err(ReviewAuditError::UnsupportedContractVersion { contract, .. })
                if contract == "goal_contract"
        ));

        let mut permission = fixture();
        permission.goal.permission_profile.contract_version = ContractVersion(2);
        assert!(matches!(
            permission.validate(),
            Err(ReviewAuditError::UnsupportedContractVersion { contract, .. })
                if contract == "goal_contract.permission_profile"
        ));

        let mut precondition = fixture();
        precondition.goal.completion_precondition.contract_version = ContractVersion(2);
        assert!(matches!(
            precondition.validate(),
            Err(ReviewAuditError::UnsupportedContractVersion { contract, .. })
                if contract == "goal_contract.completion_precondition"
        ));

        let mut completion = fixture();
        completion.completion.contract_version = ContractVersion(2);
        assert!(matches!(
            completion.validate(),
            Err(ReviewAuditError::UnsupportedContractVersion { contract, .. })
                if contract == "completion_evidence"
        ));

        let mut catalog = fixture();
        catalog.catalog[0].contract_version = ContractVersion(2);
        assert!(matches!(
            catalog.validate(),
            Err(ReviewAuditError::UnsupportedContractVersion { contract, .. })
                if contract == "evidence_catalog[0]"
        ));

        let mut integrity = fixture();
        integrity.catalog[0]
            .integrity
            .as_mut()
            .unwrap()
            .contract_version = ContractVersion(2);
        assert!(matches!(
            integrity.validate(),
            Err(ReviewAuditError::UnsupportedContractVersion { contract, .. })
                if contract == "evidence_catalog[0].integrity"
        ));

        let mut review = fixture();
        review.review.contract_version = ContractVersion(2);
        assert!(matches!(
            review.validate(),
            Err(ReviewAuditError::UnsupportedContractVersion { contract, .. })
                if contract == "review_decision"
        ));

        let mut assessment = fixture();
        assessment.review.assessments[0].contract_version = ContractVersion(2);
        assert!(matches!(
            assessment.validate(),
            Err(ReviewAuditError::UnsupportedContractVersion { contract, .. })
                if contract == "review_decision.assessments[0]"
        ));
    }

    #[test]
    fn caller_verdict_mismatch_is_rejected() {
        let mut f = fixture();
        f.review.verdict = ReviewVerdict::Fail;
        assert_eq!(
            f.validate(),
            Err(ReviewAuditError::VerdictMismatch {
                expected: ReviewVerdict::Pass,
                actual: ReviewVerdict::Fail,
            })
        );
    }

    #[test]
    fn blank_decision_assessment_and_evidence_fields_are_rejected() {
        let mut expected_run = fixture();
        expected_run.run_id = RunId::from(" ");
        assert_blank(expected_run, "expected_run_id");

        let mut goal_id = fixture();
        goal_id.goal.id = GoalId::from(" ");
        assert_blank(goal_id, "goal_contract.id");

        let mut project_id = fixture();
        project_id.goal.project_id = ProjectId::from(" ");
        assert_blank(project_id, "goal_contract.project_id");

        let mut objective = fixture();
        objective.goal.objective = " ".into();
        assert_blank(objective, "goal_contract.objective");

        let mut constraint = fixture();
        constraint.goal.constraints[0] = " ".into();
        assert_blank(constraint, "goal_contract.constraints[0]");

        let mut resource_key = fixture();
        resource_key.goal.permission_profile.resource_keys = vec![" ".into()];
        assert_blank(
            resource_key,
            "goal_contract.permission_profile.resource_keys[0]",
        );

        let mut write_key = fixture();
        write_key.goal.permission_profile.write_keys = vec![" ".into()];
        assert_blank(write_key, "goal_contract.permission_profile.write_keys[0]");

        let mut goal_criterion = fixture();
        goal_criterion.goal.acceptance_criteria[0] = " ".into();
        assert_blank(goal_criterion, "goal_contract.acceptance_criteria[0]");

        let mut decision_id = fixture();
        decision_id.review.id = ReviewDecisionId::from(" ");
        assert_blank(decision_id, "review_decision.id");

        let mut decision_run = fixture();
        decision_run.review.run_id = RunId::from(" ");
        assert_blank(decision_run, "review_decision.run_id");

        let mut decision_goal = fixture();
        decision_goal.review.goal_id = GoalId::from(" ");
        assert_blank(decision_goal, "review_decision.goal_id");

        let mut summary = fixture();
        summary.review.summary = " ".into();
        assert_blank(summary, "review_decision.summary");

        let mut criterion = fixture();
        criterion.review.assessments[0].criterion = " ".into();
        assert_blank(criterion, "review_decision.assessments[0].criterion");

        let mut rationale = fixture();
        rationale.review.assessments[0].rationale = " ".into();
        assert_blank(rationale, "review_decision.assessments[0].rationale");

        let mut assessment_id = fixture();
        assessment_id.review.assessments[0].evidence_refs = vec![EvidenceId::from(" ")];
        assert_blank(
            assessment_id,
            "review_decision.assessments[0].evidence_refs[0]",
        );

        let mut catalog_id = fixture();
        catalog_id.catalog[0].id = EvidenceId::from(" ");
        assert_blank(catalog_id, "evidence_catalog[0].id");

        let mut reference = fixture();
        reference.catalog[0].reference = " ".into();
        assert_blank(reference, "evidence_catalog[0].reference");

        let mut algorithm = fixture();
        algorithm.catalog[0].integrity.as_mut().unwrap().algorithm = " ".into();
        assert_blank(algorithm, "evidence_catalog[0].integrity.algorithm");

        let mut digest = fixture();
        digest.catalog[0].integrity.as_mut().unwrap().digest = " ".into();
        assert_blank(digest, "evidence_catalog[0].integrity.digest");

        let mut satisfied_criterion = fixture();
        satisfied_criterion.completion.satisfied_acceptance_criteria[0] = " ".into();
        assert_blank(
            satisfied_criterion,
            "completion_evidence.satisfied_acceptance_criteria[0]",
        );
    }

    fn assert_blank(fixture: Fixture, expected_field: &str) {
        assert!(matches!(
            fixture.validate(),
            Err(ReviewAuditError::BlankField { field }) if field == expected_field
        ));
    }

    #[test]
    fn missing_unknown_duplicate_and_reordered_criteria_are_rejected() {
        let mut missing = fixture();
        missing.review.assessments.pop();
        assert!(matches!(
            missing.validate(),
            Err(ReviewAuditError::MissingCriterionAssessment { .. })
        ));

        let mut unknown = fixture();
        unknown.review.assessments[0].criterion = "Unknown criterion".into();
        assert!(matches!(
            unknown.validate(),
            Err(ReviewAuditError::UnknownCriterionAssessment { .. })
        ));

        let mut duplicate = fixture();
        duplicate.review.assessments[1] = duplicate.review.assessments[0].clone();
        assert!(matches!(
            duplicate.validate(),
            Err(ReviewAuditError::DuplicateCriterionAssessment { .. })
        ));

        let mut reordered = fixture();
        reordered.review.assessments.swap(0, 1);
        assert!(matches!(
            reordered.validate(),
            Err(ReviewAuditError::ReorderedCriterionAssessment { index: 0, .. })
        ));
    }

    #[test]
    fn satisfied_assessment_requires_evidence() {
        let mut f = fixture();
        f.review.assessments[0].evidence_refs.clear();
        assert_eq!(
            f.validate(),
            Err(ReviewAuditError::SatisfiedAssessmentWithoutEvidence {
                assessment_index: 0,
            })
        );
    }

    #[test]
    fn assessment_evidence_must_be_in_completion_and_catalog() {
        let mut absent_completion = fixture();
        absent_completion.review.assessments[0].evidence_refs =
            vec![EvidenceId::from("evidence-3")];
        absent_completion
            .catalog
            .push(evidence("evidence-3", Role::Coordinator));
        assert!(matches!(
            absent_completion.validate(),
            Err(ReviewAuditError::AssessmentEvidenceNotInCompletion { .. })
        ));

        let mut absent_catalog = fixture();
        absent_catalog.review.assessments[0].evidence_refs = vec![EvidenceId::from("evidence-3")];
        absent_catalog
            .completion
            .evidence_refs
            .push(EvidenceId::from("evidence-3"));
        assert!(matches!(
            absent_catalog.validate(),
            Err(ReviewAuditError::AssessmentEvidenceNotInCatalog { .. })
        ));
    }

    #[test]
    fn assessment_evidence_ids_must_be_nonblank_unique_and_sorted() {
        let mut duplicate = fixture();
        duplicate.review.assessments[0].evidence_refs = vec![
            EvidenceId::from("evidence-1"),
            EvidenceId::from("evidence-1"),
        ];
        assert!(matches!(
            duplicate.validate(),
            Err(ReviewAuditError::DuplicateAssessmentEvidenceId { .. })
        ));

        let mut unsorted = fixture();
        unsorted.review.assessments[0].evidence_refs = vec![
            EvidenceId::from("evidence-2"),
            EvidenceId::from("evidence-1"),
        ];
        assert!(matches!(
            unsorted.validate(),
            Err(ReviewAuditError::UnsortedAssessmentEvidenceIds {
                assessment_index: 0
            })
        ));
    }

    #[test]
    fn duplicate_and_invalid_catalog_entries_are_rejected() {
        let mut duplicate = fixture();
        duplicate.catalog[1].id = duplicate.catalog[0].id.clone();
        assert!(matches!(
            duplicate.validate(),
            Err(ReviewAuditError::DuplicateCatalogEvidenceId { .. })
        ));

        let mut incomplete = fixture();
        incomplete.catalog.pop();
        assert!(matches!(
            incomplete.validate(),
            Err(ReviewAuditError::CompletionEvidenceNotInCatalog { .. })
        ));
    }

    #[test]
    fn completion_evidence_ids_are_structurally_valid() {
        let mut blank = fixture();
        blank.completion.evidence_refs[0] = EvidenceId::from(" ");
        assert_blank(blank, "completion_evidence.evidence_refs[0]");

        let mut duplicate = fixture();
        duplicate.completion.evidence_refs[1] = duplicate.completion.evidence_refs[0].clone();
        assert!(matches!(
            duplicate.validate(),
            Err(ReviewAuditError::DuplicateCompletionEvidenceId { .. })
        ));

        let mut insufficient = fixture();
        insufficient.completion.evidence_refs.pop();
        assert_eq!(
            insufficient.validate(),
            Err(ReviewAuditError::InsufficientCompletionEvidence {
                required: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn catalog_and_completion_evidence_ids_must_be_canonically_ordered() {
        let mut catalog = fixture();
        catalog.catalog.swap(0, 1);
        assert_eq!(
            catalog.validate(),
            Err(ReviewAuditError::UnsortedCatalogEvidenceIds {
                index: 1,
                previous: EvidenceId::from("evidence-2"),
                actual: EvidenceId::from("evidence-1"),
            })
        );

        let mut completion = fixture();
        completion.completion.evidence_refs.swap(0, 1);
        assert_eq!(
            completion.validate(),
            Err(ReviewAuditError::UnsortedCompletionEvidenceIds {
                index: 1,
                previous: EvidenceId::from("evidence-2"),
                actual: EvidenceId::from("evidence-1"),
            })
        );
    }

    #[test]
    fn completion_satisfied_lists_exactly_match_assessments() {
        let mut missing = fixture();
        missing.completion.satisfied_acceptance_criteria.pop();
        assert!(matches!(
            missing.validate(),
            Err(ReviewAuditError::CompletionSatisfiedCriteriaMismatch {
                kind: CriterionKind::Acceptance,
                ..
            })
        ));

        let mut reordered = fixture();
        reordered
            .completion
            .satisfied_verification_criteria
            .swap(0, 1);
        assert!(matches!(
            reordered.validate(),
            Err(ReviewAuditError::ReorderedSatisfiedCriterion {
                kind: CriterionKind::Verification,
                ..
            })
        ));
    }

    #[test]
    fn policy_derivation_covers_goal_and_guard_requirements() {
        let mut f = fixture();
        f.goal.permission_profile.review_required = false;
        let none = BTreeSet::new();
        assert_eq!(
            derive_review_audit_policy(&f.goal, &none),
            ReviewAuditPolicy {
                reviewer_required: false,
                auditor_required: false,
            }
        );

        f.goal.permission_profile.review_required = true;
        assert_eq!(
            derive_review_audit_policy(&f.goal, &none),
            ReviewAuditPolicy {
                reviewer_required: true,
                auditor_required: false,
            }
        );

        f.goal.permission_profile.review_required = false;
        f.goal.permission_profile.audit_required = true;
        assert_eq!(
            derive_review_audit_policy(&f.goal, &none),
            ReviewAuditPolicy {
                reviewer_required: true,
                auditor_required: true,
            }
        );

        f.goal.permission_profile.audit_required = false;
        let reviewer_guard = BTreeSet::from([GuardRequirement::Reviewer]);
        assert_eq!(
            derive_review_audit_policy(&f.goal, &reviewer_guard),
            ReviewAuditPolicy {
                reviewer_required: true,
                auditor_required: false,
            }
        );

        let auditor_guard = BTreeSet::from([GuardRequirement::Auditor]);
        assert_eq!(
            derive_review_audit_policy(&f.goal, &auditor_guard),
            ReviewAuditPolicy {
                reviewer_required: true,
                auditor_required: true,
            }
        );

        let approval_guard = BTreeSet::from([GuardRequirement::OwnerApproval]);
        assert_eq!(
            derive_review_audit_policy(&f.goal, &approval_guard),
            ReviewAuditPolicy {
                reviewer_required: false,
                auditor_required: false,
            }
        );
    }

    #[test]
    fn no_decisions_pass_when_policy_requires_neither_gate() {
        let mut f = fixture();
        f.goal.permission_profile.review_required = false;
        assert_eq!(
            f.evaluate(false, false),
            Ok(ReviewAuditResolution::Pass {
                review_decision_id: None,
                audit_decision_id: None,
            })
        );
    }

    #[test]
    fn required_review_missing_awaits_review() {
        let f = fixture();
        assert_eq!(
            f.evaluate(false, false),
            Ok(ReviewAuditResolution::AwaitingReview)
        );
    }

    #[test]
    fn required_audit_missing_awaits_after_reviewer_pass_and_fail() {
        let mut pass = fixture();
        pass.goal.permission_profile.audit_required = true;
        assert_eq!(
            pass.evaluate(true, false),
            Ok(ReviewAuditResolution::AwaitingAudit {
                review_decision_id: ReviewDecisionId::from("review-1"),
            })
        );

        let mut fail = fixture();
        fail.goal.permission_profile.audit_required = true;
        make_review_fail(&mut fail, 4);
        assert_eq!(
            fail.evaluate(true, false),
            Ok(ReviewAuditResolution::AwaitingAudit {
                review_decision_id: ReviewDecisionId::from("review-1"),
            })
        );
    }

    #[test]
    fn reviewer_only_pass_and_fail_resolve_with_review_id() {
        let pass = fixture();
        assert_eq!(
            pass.evaluate(true, false),
            Ok(ReviewAuditResolution::Pass {
                review_decision_id: Some(ReviewDecisionId::from("review-1")),
                audit_decision_id: None,
            })
        );

        let mut fail = fixture();
        make_review_fail(&mut fail, 4);
        assert_eq!(
            fail.evaluate(true, false),
            Ok(ReviewAuditResolution::Fail {
                review_decision_id: ReviewDecisionId::from("review-1"),
                audit_decision_id: None,
            })
        );
    }

    #[test]
    fn agreeing_review_and_audit_pass_or_fail_with_exact_ids() {
        let pass = fixture();
        assert_eq!(
            pass.evaluate(true, true),
            Ok(ReviewAuditResolution::Pass {
                review_decision_id: Some(ReviewDecisionId::from("review-1")),
                audit_decision_id: Some(AuditDecisionId::from("audit-1")),
            })
        );

        let mut fail = fixture();
        make_review_fail(&mut fail, 4);
        make_audit_fail(&mut fail, 4);
        assert_eq!(
            fail.evaluate(true, true),
            Ok(ReviewAuditResolution::Fail {
                review_decision_id: ReviewDecisionId::from("review-1"),
                audit_decision_id: Some(AuditDecisionId::from("audit-1")),
            })
        );
    }

    #[test]
    fn both_disagreement_directions_escalate_with_verdicts_and_ids() {
        let mut reviewer_pass = fixture();
        make_audit_fail(&mut reviewer_pass, 4);
        assert_eq!(
            reviewer_pass.evaluate(true, true),
            Ok(ReviewAuditResolution::OwnerEscalation {
                review_decision_id: ReviewDecisionId::from("review-1"),
                audit_decision_id: AuditDecisionId::from("audit-1"),
                reviewer_verdict: ReviewVerdict::Pass,
                auditor_verdict: ReviewVerdict::Fail,
            })
        );

        let mut reviewer_fail = fixture();
        make_review_fail(&mut reviewer_fail, 4);
        assert_eq!(
            reviewer_fail.evaluate(true, true),
            Ok(ReviewAuditResolution::OwnerEscalation {
                review_decision_id: ReviewDecisionId::from("review-1"),
                audit_decision_id: AuditDecisionId::from("audit-1"),
                reviewer_verdict: ReviewVerdict::Fail,
                auditor_verdict: ReviewVerdict::Pass,
            })
        );
    }

    #[test]
    fn audit_without_review_is_always_a_structured_error() {
        let f = fixture();
        assert_eq!(
            f.evaluate(false, true),
            Err(ReviewAuditError::AuditWithoutReview)
        );

        let mut optional = fixture();
        optional.goal.permission_profile.review_required = false;
        assert_eq!(
            optional.evaluate(false, true),
            Err(ReviewAuditError::AuditWithoutReview)
        );
    }

    #[test]
    fn valid_audit_returns_a_distinct_validated_result() {
        let f = fixture();
        let validated = f.validate_audit().unwrap();
        assert_eq!(validated.decision(), &f.audit);
        assert_eq!(validated.verdict(), ReviewVerdict::Pass);
        assert_eq!(validated.into_decision(), f.audit);
    }

    #[test]
    fn wrong_audit_role_run_goal_review_version_and_time_are_rejected() {
        let mut role = fixture();
        role.audit.producer_role = Role::Reviewer;
        assert!(matches!(
            role.validate_audit(),
            Err(ReviewAuditError::ProducerRoleMismatch {
                expected: Role::Auditor,
                ..
            })
        ));

        let mut run = fixture();
        run.audit.run_id = RunId::from("other-run");
        assert!(matches!(
            run.validate_audit(),
            Err(ReviewAuditError::RunIdMismatch { .. })
        ));

        let mut goal = fixture();
        goal.audit.goal_id = GoalId::from("other-goal");
        assert!(matches!(
            goal.validate_audit(),
            Err(ReviewAuditError::GoalIdMismatch { .. })
        ));

        let mut review = fixture();
        review.audit.review_decision_id = ReviewDecisionId::from("other-review");
        assert_eq!(
            review.validate_audit(),
            Err(ReviewAuditError::ReviewDecisionIdMismatch {
                expected: ReviewDecisionId::from("review-1"),
                actual: ReviewDecisionId::from("other-review"),
            })
        );

        let mut version = fixture();
        version.audit.contract_version = ContractVersion(2);
        assert!(matches!(
            version.validate_audit(),
            Err(ReviewAuditError::UnsupportedContractVersion { contract, .. })
                if contract == "audit_decision"
        ));

        let mut time_order = fixture();
        time_order.audit.decided_at = time(10);
        assert_eq!(
            time_order.validate_audit(),
            Err(ReviewAuditError::AuditDecisionBeforeReview {
                review_decided_at: time(11),
                audit_decided_at: time(10),
            })
        );
    }

    #[test]
    fn audit_nonblank_assessment_evidence_and_verdict_checks_match_reviewer_rigor() {
        let mut id = fixture();
        id.audit.id = AuditDecisionId::from(" ");
        assert!(matches!(
            id.validate_audit(),
            Err(ReviewAuditError::BlankField { field }) if field == "audit_decision.id"
        ));

        let mut summary = fixture();
        summary.audit.summary = " ".into();
        assert!(matches!(
            summary.validate_audit(),
            Err(ReviewAuditError::BlankField { field }) if field == "audit_decision.summary"
        ));

        let mut assessment_version = fixture();
        assessment_version.audit.assessments[0].contract_version = ContractVersion(2);
        assert!(matches!(
            assessment_version.validate_audit(),
            Err(ReviewAuditError::UnsupportedContractVersion { contract, .. })
                if contract == "audit_decision.assessments[0]"
        ));

        let mut missing = fixture();
        missing.audit.assessments.pop();
        assert!(matches!(
            missing.validate_audit(),
            Err(ReviewAuditError::MissingCriterionAssessment { .. })
        ));

        let mut unknown = fixture();
        unknown.audit.assessments[0].criterion = "Unknown criterion".into();
        assert!(matches!(
            unknown.validate_audit(),
            Err(ReviewAuditError::UnknownCriterionAssessment { .. })
        ));

        let mut absent_completion = fixture();
        absent_completion.audit.assessments[0].evidence_refs = vec![EvidenceId::from("evidence-3")];
        absent_completion
            .catalog
            .push(evidence("evidence-3", Role::Auditor));
        assert!(matches!(
            absent_completion.validate_audit(),
            Err(ReviewAuditError::AssessmentEvidenceNotInCompletion { .. })
        ));

        let mut unsupported_verdict = fixture();
        unsupported_verdict.audit.verdict = ReviewVerdict::Fail;
        assert_eq!(
            unsupported_verdict.validate_audit(),
            Err(ReviewAuditError::VerdictMismatch {
                expected: ReviewVerdict::Pass,
                actual: ReviewVerdict::Fail,
            })
        );
    }

    #[test]
    fn audit_revalidates_completion_and_catalog_context() {
        let mut completion = fixture();
        let validated_review = completion.validate().unwrap();
        completion.completion.evidence_refs[1] = completion.completion.evidence_refs[0].clone();
        let result = validate_audit_decision(
            &AuditDecisionValidationContext {
                expected_run_id: &completion.run_id,
                goal_contract: &completion.goal,
                completion_evidence: &completion.completion,
                evidence_catalog: &completion.catalog,
                validated_review_decision: &validated_review,
            },
            &completion.audit,
        );
        assert!(matches!(
            result,
            Err(ReviewAuditError::DuplicateCompletionEvidenceId { .. })
        ));

        let mut catalog = fixture();
        let validated_review = catalog.validate().unwrap();
        catalog.catalog[1].id = catalog.catalog[0].id.clone();
        let result = validate_audit_decision(
            &AuditDecisionValidationContext {
                expected_run_id: &catalog.run_id,
                goal_contract: &catalog.goal,
                completion_evidence: &catalog.completion,
                evidence_catalog: &catalog.catalog,
                validated_review_decision: &validated_review,
            },
            &catalog.audit,
        );
        assert!(matches!(
            result,
            Err(ReviewAuditError::DuplicateCatalogEvidenceId { .. })
        ));
    }

    #[test]
    fn supplied_optional_decisions_are_validated_and_affect_resolution() {
        let mut reviewer_fail = fixture();
        reviewer_fail.goal.permission_profile.review_required = false;
        make_review_fail(&mut reviewer_fail, 4);
        assert!(matches!(
            reviewer_fail.evaluate(true, false),
            Ok(ReviewAuditResolution::Fail { .. })
        ));

        let mut malformed_review = fixture();
        malformed_review.goal.permission_profile.review_required = false;
        malformed_review.review.producer_role = Role::Engineer;
        assert!(matches!(
            malformed_review.evaluate(true, false),
            Err(ReviewAuditError::ProducerRoleMismatch { .. })
        ));

        let mut conflict = fixture();
        conflict.goal.permission_profile.review_required = false;
        make_audit_fail(&mut conflict, 4);
        assert!(matches!(
            conflict.evaluate(true, true),
            Ok(ReviewAuditResolution::OwnerEscalation { .. })
        ));

        let mut malformed_audit = fixture();
        malformed_audit.goal.permission_profile.review_required = false;
        malformed_audit.audit.producer_role = Role::Reviewer;
        assert!(matches!(
            malformed_audit.evaluate(true, true),
            Err(ReviewAuditError::ProducerRoleMismatch {
                expected: Role::Auditor,
                ..
            })
        ));
    }

    #[test]
    fn evaluator_never_returns_an_audit_id_without_a_review_id() {
        let mut no_gate = fixture();
        no_gate.goal.permission_profile.review_required = false;
        let resolutions = [
            no_gate.evaluate(false, false).unwrap(),
            no_gate.evaluate(true, false).unwrap(),
            no_gate.evaluate(true, true).unwrap(),
        ];
        for resolution in resolutions {
            assert!(!matches!(
                resolution,
                ReviewAuditResolution::Pass {
                    review_decision_id: None,
                    audit_decision_id: Some(_),
                }
            ));
        }
    }

    #[test]
    fn policy_and_resolution_are_repeated_and_construction_order_deterministic() {
        let mut first = fixture();
        first.goal.permission_profile.review_required = false;
        first.guard_requirements.insert(GuardRequirement::Reviewer);
        first.guard_requirements.insert(GuardRequirement::Auditor);

        let mut second = fixture();
        second.goal.permission_profile.review_required = false;
        second.guard_requirements.insert(GuardRequirement::Auditor);
        second.guard_requirements.insert(GuardRequirement::Reviewer);

        let expected_policy = derive_review_audit_policy(&first.goal, &first.guard_requirements);
        let expected_resolution = first.evaluate(true, true);
        for _ in 0..100 {
            assert_eq!(
                derive_review_audit_policy(&second.goal, &second.guard_requirements),
                expected_policy
            );
            assert_eq!(first.evaluate(true, true), expected_resolution);
            assert_eq!(second.evaluate(true, true), expected_resolution);
        }
    }

    #[test]
    fn repeated_validation_is_exactly_deterministic() {
        let f = fixture();
        let expected = f.validate();
        for _ in 0..100 {
            assert_eq!(f.validate(), expected);
        }
    }

    #[test]
    fn production_source_has_no_external_or_implicit_call_path() {
        let source = include_str!("review_audit.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "std::fs::",
            "std::process::",
            "std::net::",
            "std::env::",
            "SystemTime::now",
            "Instant::now",
            "Utc::now",
            "reqwest::",
            "ureq::",
        ] {
            assert!(
                !production.contains(forbidden),
                "production source contains forbidden call path: {forbidden}"
            );
        }
    }
}
