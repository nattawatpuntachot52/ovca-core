//! Pure policy evaluation for goal runtime guard requests.

use chrono::{DateTime, Utc};
use ovca_types::goal_runtime::{
    ApprovalRequest, ApprovalRequestId, ContractVersion, GuardDenyReason, GuardOutcome,
    GuardRequest, GuardRequirement, RiskTier, SideEffectClass,
};
use std::collections::BTreeSet;

/// Caller-controlled values needed to construct a deterministic approval pause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardEvaluationContext {
    pub approval_request_id: ApprovalRequestId,
    pub requested_at: DateTime<Utc>,
}

/// Evaluates a request without executing effects or reading external state.
pub fn evaluate_guard_request(
    request: &GuardRequest,
    context: &GuardEvaluationContext,
) -> GuardOutcome {
    let mut reasons = validate_request(request);
    if context.approval_request_id.as_str().trim().is_empty() {
        reasons.insert(GuardDenyReason::BlankApprovalRequestId);
    }
    let minimum_tier = minimum_risk_tier(request.side_effect);

    if request.permission_profile.risk_tier < minimum_tier {
        reasons.insert(GuardDenyReason::RiskTierMismatch);
    }
    if minimum_tier == RiskTier::R3 || request.permission_profile.risk_tier == RiskTier::R3 {
        reasons.insert(GuardDenyReason::R3DenyByDefault);
    }

    if !reasons.is_empty() {
        return GuardOutcome::Deny { reasons };
    }

    match request.permission_profile.risk_tier {
        RiskTier::R0 => GuardOutcome::Allow {
            required_gates: BTreeSet::new(),
        },
        RiskTier::R1 => {
            if !request.permission_profile.review_required {
                return deny_missing_declaration();
            }
            GuardOutcome::Allow {
                required_gates: BTreeSet::from([GuardRequirement::Reviewer]),
            }
        }
        RiskTier::R2 => evaluate_r2(request, context),
        RiskTier::R3 => GuardOutcome::Deny {
            reasons: BTreeSet::from([GuardDenyReason::R3DenyByDefault]),
        },
    }
}

fn validate_request(request: &GuardRequest) -> BTreeSet<GuardDenyReason> {
    let mut reasons = BTreeSet::new();
    if request.id.as_str().trim().is_empty() {
        reasons.insert(GuardDenyReason::BlankGuardRequestId);
    }
    if request.contract_version != ContractVersion::current()
        || request.permission_profile.contract_version != ContractVersion::current()
    {
        reasons.insert(GuardDenyReason::UnsupportedContractVersion);
    }
    if request.operation_label.trim().is_empty() {
        reasons.insert(GuardDenyReason::BlankOperationLabel);
    }

    validate_keys(&request.resource_keys, &mut reasons);
    validate_keys(&request.write_keys, &mut reasons);
    validate_keys(&request.permission_profile.resource_keys, &mut reasons);
    validate_keys(&request.permission_profile.write_keys, &mut reasons);

    if !is_subset(
        &request.resource_keys,
        &request.permission_profile.resource_keys,
    ) {
        reasons.insert(GuardDenyReason::MissingResourcePermission);
    }
    if !is_subset(&request.write_keys, &request.permission_profile.write_keys) {
        reasons.insert(GuardDenyReason::MissingWritePermission);
    }
    if request.side_effect == SideEffectClass::ReadOnly && !request.write_keys.is_empty() {
        reasons.insert(GuardDenyReason::MissingWritePermission);
    }
    reasons
}

fn validate_keys(keys: &[String], reasons: &mut BTreeSet<GuardDenyReason>) {
    if keys.iter().any(|key| key.trim().is_empty()) {
        reasons.insert(GuardDenyReason::BlankKey);
    }
    let unique: BTreeSet<_> = keys.iter().collect();
    if unique.len() != keys.len() {
        reasons.insert(GuardDenyReason::DuplicateKey);
    }
    if keys.windows(2).any(|pair| pair[0] > pair[1]) {
        reasons.insert(GuardDenyReason::InvalidKey);
    }
}

fn is_subset(requested: &[String], permitted: &[String]) -> bool {
    requested
        .iter()
        .all(|key| permitted.binary_search(key).is_ok())
}

const fn minimum_risk_tier(side_effect: SideEffectClass) -> RiskTier {
    match side_effect {
        SideEffectClass::ReadOnly => RiskTier::R0,
        SideEffectClass::ReversibleLocalWrite => RiskTier::R1,
        SideEffectClass::RepositoryWrite
        | SideEffectClass::NetworkAction
        | SideEffectClass::Publication
        | SideEffectClass::ExternalSideEffect => RiskTier::R2,
        SideEffectClass::Destructive
        | SideEffectClass::SecretBearing
        | SideEffectClass::Irreversible
        | SideEffectClass::Privileged => RiskTier::R3,
    }
}

fn evaluate_r2(request: &GuardRequest, context: &GuardEvaluationContext) -> GuardOutcome {
    let profile = &request.permission_profile;
    let conditional_audit = matches!(
        request.side_effect,
        SideEffectClass::NetworkAction
            | SideEffectClass::Publication
            | SideEffectClass::ExternalSideEffect
    );
    if !profile.approval_required
        || !profile.review_required
        || (conditional_audit && !profile.audit_required)
    {
        return deny_missing_declaration();
    }

    let mut required_gates =
        BTreeSet::from([GuardRequirement::OwnerApproval, GuardRequirement::Reviewer]);
    if profile.audit_required {
        required_gates.insert(GuardRequirement::Auditor);
    }
    GuardOutcome::PauseForApproval {
        approval_request: ApprovalRequest {
            contract_version: ContractVersion::current(),
            id: context.approval_request_id.clone(),
            guard_request: request.clone(),
            requested_at: context.requested_at,
        },
        required_gates,
    }
}

fn deny_missing_declaration() -> GuardOutcome {
    GuardOutcome::Deny {
        reasons: BTreeSet::from([GuardDenyReason::MissingRequiredDeclaration]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ovca_types::goal_runtime::{GuardRequestId, GuardSurface, PermissionProfile};
    use std::fs;
    use tempfile::TempDir;

    const SURFACES: [GuardSurface; 3] = [
        GuardSurface::Input,
        GuardSurface::Output,
        GuardSurface::Tool,
    ];
    const CLASSES: [SideEffectClass; 10] = [
        SideEffectClass::ReadOnly,
        SideEffectClass::ReversibleLocalWrite,
        SideEffectClass::RepositoryWrite,
        SideEffectClass::NetworkAction,
        SideEffectClass::Publication,
        SideEffectClass::ExternalSideEffect,
        SideEffectClass::Destructive,
        SideEffectClass::SecretBearing,
        SideEffectClass::Irreversible,
        SideEffectClass::Privileged,
    ];

    fn context() -> GuardEvaluationContext {
        GuardEvaluationContext {
            approval_request_id: ApprovalRequestId::from("approval-1"),
            requested_at: Utc.with_ymd_and_hms(2026, 7, 18, 8, 0, 0).unwrap(),
        }
    }

    fn request(surface: GuardSurface, side_effect: SideEffectClass) -> GuardRequest {
        let risk_tier = minimum_risk_tier(side_effect);
        let writes = if side_effect == SideEffectClass::ReadOnly {
            Vec::new()
        } else {
            vec!["write:runtime".into()]
        };
        let r2 = risk_tier == RiskTier::R2;
        let audit = matches!(
            side_effect,
            SideEffectClass::NetworkAction
                | SideEffectClass::Publication
                | SideEffectClass::ExternalSideEffect
        );
        GuardRequest {
            contract_version: ContractVersion::current(),
            id: GuardRequestId::from("guard-1"),
            surface,
            side_effect,
            operation_label: "guarded operation".into(),
            resource_keys: vec!["resource:runtime".into()],
            write_keys: writes.clone(),
            permission_profile: PermissionProfile {
                contract_version: ContractVersion::current(),
                risk_tier,
                resource_keys: vec!["resource:runtime".into()],
                write_keys: writes,
                approval_required: r2,
                review_required: risk_tier >= RiskTier::R1 && risk_tier < RiskTier::R3,
                audit_required: audit,
            },
        }
    }

    fn deny_reasons(outcome: GuardOutcome) -> BTreeSet<GuardDenyReason> {
        match outcome {
            GuardOutcome::Deny { reasons } => reasons,
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn exhaustive_surface_and_side_effect_matrix_has_exact_counts() {
        let mut allow = 0;
        let mut pause = 0;
        let mut deny = 0;
        for surface in SURFACES {
            for side_effect in CLASSES {
                match evaluate_guard_request(&request(surface, side_effect), &context()) {
                    GuardOutcome::Allow { .. } => allow += 1,
                    GuardOutcome::PauseForApproval { .. } => pause += 1,
                    GuardOutcome::Deny { .. } => deny += 1,
                }
            }
        }
        assert_eq!((allow, pause, deny), (6, 12, 12));
    }

    #[test]
    fn exactly_twelve_r2_surface_class_cases_pause() {
        let mut count = 0;
        for surface in SURFACES {
            for side_effect in [
                SideEffectClass::RepositoryWrite,
                SideEffectClass::NetworkAction,
                SideEffectClass::Publication,
                SideEffectClass::ExternalSideEffect,
            ] {
                assert!(matches!(
                    evaluate_guard_request(&request(surface, side_effect), &context()),
                    GuardOutcome::PauseForApproval { .. }
                ));
                count += 1;
            }
        }
        assert_eq!(count, 12);
    }

    #[test]
    fn exactly_twelve_r3_surface_class_cases_deny() {
        let mut count = 0;
        for surface in SURFACES {
            for side_effect in [
                SideEffectClass::Destructive,
                SideEffectClass::SecretBearing,
                SideEffectClass::Irreversible,
                SideEffectClass::Privileged,
            ] {
                let outcome = evaluate_guard_request(&request(surface, side_effect), &context());
                assert_eq!(
                    deny_reasons(outcome),
                    BTreeSet::from([GuardDenyReason::R3DenyByDefault])
                );
                count += 1;
            }
        }
        assert_eq!(count, 12);
    }

    #[test]
    fn r3_deny_reason_survives_other_validation_failures() {
        let mut invalid = request(GuardSurface::Tool, SideEffectClass::Destructive);
        invalid.operation_label = " ".into();
        let reasons = deny_reasons(evaluate_guard_request(&invalid, &context()));
        assert!(reasons.contains(&GuardDenyReason::R3DenyByDefault));
        assert!(reasons.contains(&GuardDenyReason::BlankOperationLabel));
    }

    #[test]
    fn blank_guard_request_id_denies() {
        let mut invalid = request(GuardSurface::Input, SideEffectClass::ReadOnly);
        invalid.id = GuardRequestId::from("  ");
        assert_eq!(
            deny_reasons(evaluate_guard_request(&invalid, &context())),
            BTreeSet::from([GuardDenyReason::BlankGuardRequestId])
        );
    }

    #[test]
    fn blank_approval_request_id_denies() {
        let mut invalid_context = context();
        invalid_context.approval_request_id = ApprovalRequestId::from("  ");
        assert_eq!(
            deny_reasons(evaluate_guard_request(
                &request(GuardSurface::Input, SideEffectClass::ReadOnly),
                &invalid_context,
            )),
            BTreeSet::from([GuardDenyReason::BlankApprovalRequestId])
        );
    }

    #[test]
    fn blank_operation_label_denies() {
        let mut invalid = request(GuardSurface::Input, SideEffectClass::ReadOnly);
        invalid.operation_label = "  ".into();
        assert_eq!(
            deny_reasons(evaluate_guard_request(&invalid, &context())),
            BTreeSet::from([GuardDenyReason::BlankOperationLabel])
        );
    }

    #[test]
    fn valid_r0_and_r1_have_exact_allow_gates() {
        assert_eq!(
            evaluate_guard_request(
                &request(GuardSurface::Input, SideEffectClass::ReadOnly),
                &context()
            ),
            GuardOutcome::Allow {
                required_gates: BTreeSet::new()
            }
        );
        assert_eq!(
            evaluate_guard_request(
                &request(GuardSurface::Output, SideEffectClass::ReversibleLocalWrite),
                &context()
            ),
            GuardOutcome::Allow {
                required_gates: BTreeSet::from([GuardRequirement::Reviewer])
            }
        );
    }

    #[test]
    fn lower_tier_mismatch_denies_and_higher_tier_applies_stronger_gate() {
        let mut lower = request(GuardSurface::Tool, SideEffectClass::RepositoryWrite);
        lower.permission_profile.risk_tier = RiskTier::R1;
        assert!(deny_reasons(evaluate_guard_request(&lower, &context()))
            .contains(&GuardDenyReason::RiskTierMismatch));

        let mut higher = request(GuardSurface::Input, SideEffectClass::ReadOnly);
        higher.permission_profile.risk_tier = RiskTier::R1;
        higher.permission_profile.review_required = true;
        assert!(matches!(
            evaluate_guard_request(&higher, &context()),
            GuardOutcome::Allow { required_gates }
                if required_gates == BTreeSet::from([GuardRequirement::Reviewer])
        ));
    }

    #[test]
    fn missing_required_declarations_deny() {
        let mut r1 = request(GuardSurface::Tool, SideEffectClass::ReversibleLocalWrite);
        r1.permission_profile.review_required = false;
        assert!(deny_reasons(evaluate_guard_request(&r1, &context()))
            .contains(&GuardDenyReason::MissingRequiredDeclaration));

        for field in ["approval", "review", "audit"] {
            let mut r2 = request(GuardSurface::Tool, SideEffectClass::NetworkAction);
            match field {
                "approval" => r2.permission_profile.approval_required = false,
                "review" => r2.permission_profile.review_required = false,
                "audit" => r2.permission_profile.audit_required = false,
                _ => unreachable!(),
            }
            assert!(deny_reasons(evaluate_guard_request(&r2, &context()))
                .contains(&GuardDenyReason::MissingRequiredDeclaration));
        }
    }

    #[test]
    fn repository_auditor_gate_is_required_only_when_declared() {
        let base = request(GuardSurface::Tool, SideEffectClass::RepositoryWrite);
        let GuardOutcome::PauseForApproval { required_gates, .. } =
            evaluate_guard_request(&base, &context())
        else {
            panic!("repository write should pause");
        };
        assert!(!required_gates.contains(&GuardRequirement::Auditor));

        let mut audited = base;
        audited.permission_profile.audit_required = true;
        let GuardOutcome::PauseForApproval { required_gates, .. } =
            evaluate_guard_request(&audited, &context())
        else {
            panic!("audited repository write should pause");
        };
        assert!(required_gates.contains(&GuardRequirement::Auditor));
    }

    #[test]
    fn missing_resource_and_write_authority_deny() {
        let mut missing_resource = request(GuardSurface::Tool, SideEffectClass::RepositoryWrite);
        missing_resource
            .resource_keys
            .push("resource:unknown".into());
        assert!(
            deny_reasons(evaluate_guard_request(&missing_resource, &context()))
                .contains(&GuardDenyReason::MissingResourcePermission)
        );

        let mut missing_write = request(GuardSurface::Tool, SideEffectClass::RepositoryWrite);
        missing_write.write_keys.push("write:unknown".into());
        assert!(
            deny_reasons(evaluate_guard_request(&missing_write, &context()))
                .contains(&GuardDenyReason::MissingWritePermission)
        );
    }

    #[test]
    fn blank_duplicate_unsorted_keys_and_blank_label_deny() {
        let mutations = [
            (vec!["".into()], GuardDenyReason::BlankKey),
            (
                vec![
                    "resource:z".into(),
                    "resource:a".into(),
                    "resource:z".into(),
                ],
                GuardDenyReason::DuplicateKey,
            ),
            (
                vec!["resource:z".into(), "resource:a".into()],
                GuardDenyReason::InvalidKey,
            ),
        ];
        for (keys, expected) in mutations {
            for target in [
                "request_resource",
                "request_write",
                "profile_resource",
                "profile_write",
            ] {
                let mut invalid = request(GuardSurface::Tool, SideEffectClass::RepositoryWrite);
                match target {
                    "request_resource" => invalid.resource_keys = keys.clone(),
                    "request_write" => invalid.write_keys = keys.clone(),
                    "profile_resource" => invalid.permission_profile.resource_keys = keys.clone(),
                    "profile_write" => invalid.permission_profile.write_keys = keys.clone(),
                    _ => unreachable!(),
                }
                assert!(
                    deny_reasons(evaluate_guard_request(&invalid, &context())).contains(&expected),
                    "target={target}"
                );
            }
        }
        let mut blank_label = request(GuardSurface::Input, SideEffectClass::ReadOnly);
        blank_label.operation_label = "  ".into();
        assert!(
            deny_reasons(evaluate_guard_request(&blank_label, &context()))
                .contains(&GuardDenyReason::BlankOperationLabel)
        );
    }

    #[test]
    fn read_only_rejects_write_keys_even_with_authority() {
        let mut read = request(GuardSurface::Input, SideEffectClass::ReadOnly);
        read.write_keys = vec!["write:runtime".into()];
        read.permission_profile.write_keys = read.write_keys.clone();
        assert!(deny_reasons(evaluate_guard_request(&read, &context()))
            .contains(&GuardDenyReason::MissingWritePermission));
    }

    #[test]
    fn request_and_profile_contract_version_mismatch_deny() {
        let mut request_version = request(GuardSurface::Input, SideEffectClass::ReadOnly);
        request_version.contract_version = ContractVersion(2);
        assert!(
            deny_reasons(evaluate_guard_request(&request_version, &context()))
                .contains(&GuardDenyReason::UnsupportedContractVersion)
        );

        let mut profile_version = request(GuardSurface::Input, SideEffectClass::ReadOnly);
        profile_version.permission_profile.contract_version = ContractVersion(2);
        assert!(
            deny_reasons(evaluate_guard_request(&profile_version, &context()))
                .contains(&GuardDenyReason::UnsupportedContractVersion)
        );
    }

    #[test]
    fn repeated_evaluation_is_deterministic() {
        let request = request(GuardSurface::Output, SideEffectClass::Publication);
        let first = evaluate_guard_request(&request, &context());
        let second = evaluate_guard_request(&request, &context());
        assert_eq!(first, second);
    }

    #[test]
    fn rejected_requests_do_not_modify_filesystem_state() {
        let root = TempDir::new().unwrap();
        let marker = root.path().join("marker.txt");
        fs::write(&marker, "unchanged").unwrap();
        let before = fs::read_dir(root.path()).unwrap().count();
        let request = request(GuardSurface::Tool, SideEffectClass::Destructive);

        assert!(matches!(
            evaluate_guard_request(&request, &context()),
            GuardOutcome::Deny { .. }
        ));
        assert_eq!(fs::read_to_string(marker).unwrap(), "unchanged");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), before);
    }
}
