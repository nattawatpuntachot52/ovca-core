/// Coordinator Governance Toolkit — policy tools (Tier 1 / 2 / 3)
///
/// Policy source: memory/oracle_coordinator_front_door_constitution.md
/// Spec:          docs/policy_tools_spec.md
pub mod http_server;
pub mod tier1;
pub mod tier2;
pub mod tier3;

// Re-export all public functions at crate root for convenience
pub use tier1::{
    certainty_zone, claim_tag, drift_check, sati_check, support_disclose, temporal_gate,
    CertaintyZoneResult, ClaimTagResult, DriftBug, DriftCheckResult, SatiCheckResult,
    SupportDiscloseResult, TemporalGateResult,
};
pub use tier2::{
    business_gate, decision_format, scamper_fill, BusinessGateResult, DecisionFormatResult,
    ScamperFillInput, ScamperFillResult,
};
pub use tier3::{
    dispatch_blocker_check, plan_before_dispatch, pre_change_notice, DispatchBlockerInput,
    DispatchBlockerResult, PlanBeforeDispatchResult, PreChangeNoticeResult,
};
