//! Tier 2 — ต้องออกแบบ schema ก่อน แต่ทำได้
//!
//! Tools: scamper_fill, business_gate, decision_format

use serde::{Deserialize, Serialize};

use crate::tier1::{certainty_zone, Zone};

// ── scamper_fill ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScamperIdeas {
    pub substitute: Vec<String>,
    pub combine: Vec<String>,
    pub adapt: Vec<String>,
    pub modify: Vec<String>,
    pub put_to_other_use: Vec<String>,
    pub eliminate: Vec<String>, // mandatory ≥1
    pub reverse: Vec<String>,   // mandatory ≥1
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScamperFillInput {
    pub base_object: String,
    pub improvement_target: String,
    pub eliminate: Vec<String>,
    pub reverse: Vec<String>,
    pub blind_spot: String,
    pub smallest_next_experiment: String,
    #[serde(default)]
    pub substitute: Vec<String>,
    #[serde(default)]
    pub combine: Vec<String>,
    #[serde(default)]
    pub adapt: Vec<String>,
    #[serde(default)]
    pub modify: Vec<String>,
    #[serde(default)]
    pub put_to_other_use: Vec<String>,
    #[serde(default)]
    pub guardrail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScamperFillResult {
    pub base_object: String,
    pub improvement_target: String,
    pub ideas: ScamperIdeas,
    pub blind_spot: String,
    pub guardrail: String,
    pub smallest_next_experiment: String,
    pub missing: Vec<String>,
    pub ready: bool,
}

/// SCAMPER Gate (filled) — validate completed SCAMPER pass ก่อน redesign
pub fn scamper_fill(input: ScamperFillInput) -> ScamperFillResult {
    let mut missing: Vec<String> = Vec::new();
    if input.eliminate.is_empty() {
        missing.push("eliminate".to_string());
    }
    if input.reverse.is_empty() {
        missing.push("reverse".to_string());
    }
    if input.blind_spot.trim().is_empty() {
        missing.push("blind_spot".to_string());
    }
    if input.smallest_next_experiment.trim().is_empty() {
        missing.push("smallest_next_experiment".to_string());
    }

    let ready = missing.is_empty();
    ScamperFillResult {
        base_object: input.base_object,
        improvement_target: input.improvement_target,
        ideas: ScamperIdeas {
            substitute: input.substitute,
            combine: input.combine,
            adapt: input.adapt,
            modify: input.modify,
            put_to_other_use: input.put_to_other_use,
            eliminate: input.eliminate,
            reverse: input.reverse,
        },
        blind_spot: input.blind_spot,
        guardrail: input.guardrail,
        smallest_next_experiment: input.smallest_next_experiment,
        missing,
        ready,
    }
}

// ── business_gate ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BottleneckArea {
    Lead,
    Sales,
    Delivery,
    Profit,
    Unknown,
}

impl BottleneckArea {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "lead" => Self::Lead,
            "sales" => Self::Sales,
            "delivery" => Self::Delivery,
            "profit" => Self::Profit,
            _ => Self::Unknown,
        }
    }

    fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KpiAnchor {
    pub do_x: String,
    pub measure_y: String,
    pub target_z: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessGateResult {
    pub bottleneck_diagnosed: bool,
    pub bottleneck_area: BottleneckArea,
    pub bottleneck_evidence: Option<String>,
    pub kpi_anchor: Option<KpiAnchor>,
    pub can_proceed: bool,
    pub block_reason: Option<String>,
}

/// Business OS Gate — diagnose bottleneck ก่อน recommend strategy/revenue
pub fn business_gate(
    recommendation: &str,
    domain: &str,
    bottleneck_evidence: Option<&str>,
) -> BusinessGateResult {
    let area = BottleneckArea::from_str(domain);
    let evidence = bottleneck_evidence
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let has_evidence = evidence.is_some();
    let diagnosed = has_evidence && area.is_known();

    let kpi_anchor = if diagnosed {
        Some(KpiAnchor {
            do_x: recommendation.to_string(),
            measure_y: format!("metric ที่วัดผล {:?}", area).to_lowercase(),
            target_z: "ระบุเป้าหมายเป็นตัวเลขชัดเจน".to_string(),
        })
    } else {
        None
    };

    let block_reason = if !diagnosed {
        if !area.is_known() {
            Some("ยังไม่ diagnose ว่าติดที่ lead/sales/delivery/profit — ต้องหา evidence ก่อน".to_string())
        } else {
            Some(format!(
                "domain='{domain}' แต่ยังไม่มี bottleneck_evidence — ต้องระบุก่อน"
            ))
        }
    } else {
        None
    };

    BusinessGateResult {
        bottleneck_diagnosed: diagnosed,
        bottleneck_area: area,
        bottleneck_evidence: evidence,
        kpi_anchor,
        can_proceed: diagnosed,
        block_reason,
    }
}

// ── decision_format ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionFormatResult {
    pub topic: String,
    pub options_considered: Vec<String>,
    pub what_to_do_now: String,
    pub what_not_to_do: String,
    pub what_to_revisit_when: String,
    pub metric_that_proves_it_worked: String,
    pub certainty_zone: Zone,
    pub missing: Vec<String>,
    pub complete: bool,
}

/// Decision Discipline — CEO output format validator
pub fn decision_format(
    topic: &str,
    options_considered: Vec<String>,
    what_to_do_now: &str,
    what_not_to_do: &str,
    what_to_revisit_when: &str,
    metric_that_proves_it_worked: &str,
    confidence: f64,
) -> DecisionFormatResult {
    let mut missing: Vec<String> = Vec::new();
    if what_to_do_now.trim().is_empty() {
        missing.push("what_to_do_NOW".to_string());
    }
    if what_not_to_do.trim().is_empty() {
        missing.push("what_NOT_to_do".to_string());
    }
    if what_to_revisit_when.trim().is_empty() {
        missing.push("what_to_revisit_when".to_string());
    }
    if metric_that_proves_it_worked.trim().is_empty() {
        missing.push("metric_that_proves_it_worked".to_string());
    }

    let zone = certainty_zone(confidence).zone;
    let complete = missing.is_empty();

    DecisionFormatResult {
        topic: topic.to_string(),
        options_considered,
        what_to_do_now: what_to_do_now.to_string(),
        what_not_to_do: what_not_to_do.to_string(),
        what_to_revisit_when: what_to_revisit_when.to_string(),
        metric_that_proves_it_worked: metric_that_proves_it_worked.to_string(),
        certainty_zone: zone,
        missing,
        complete,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // scamper_fill
    #[test]
    fn scamper_ready_when_all_mandatory_filled() {
        let r = scamper_fill(ScamperFillInput {
            base_object: "dispatch flow".to_string(),
            improvement_target: "ลด timeout".to_string(),
            eliminate: vec!["ตัด pre-flight ซ้ำ".to_string()],
            reverse: vec!["ให้ Engineer estimate ก่อน".to_string()],
            blind_spot: "hidden dependency ที่โตขึ้น runtime".to_string(),
            smallest_next_experiment: "เพิ่ม size_estimate field".to_string(),
            ..Default::default()
        });
        assert!(r.ready);
        assert!(r.missing.is_empty());
    }

    #[test]
    fn scamper_not_ready_when_eliminate_empty() {
        let r = scamper_fill(ScamperFillInput {
            base_object: "flow".to_string(),
            improvement_target: "improve".to_string(),
            eliminate: vec![],
            reverse: vec!["reverse idea".to_string()],
            blind_spot: "blind".to_string(),
            smallest_next_experiment: "exp".to_string(),
            ..Default::default()
        });
        assert!(!r.ready);
        assert!(r.missing.contains(&"eliminate".to_string()));
    }

    #[test]
    fn scamper_not_ready_when_reverse_empty() {
        let r = scamper_fill(ScamperFillInput {
            base_object: "x".to_string(),
            improvement_target: "y".to_string(),
            eliminate: vec!["e".to_string()],
            reverse: vec![],
            blind_spot: "b".to_string(),
            smallest_next_experiment: "s".to_string(),
            ..Default::default()
        });
        assert!(r.missing.contains(&"reverse".to_string()));
    }

    #[test]
    fn scamper_optional_fields_stored() {
        let r = scamper_fill(ScamperFillInput {
            base_object: "x".to_string(),
            improvement_target: "y".to_string(),
            eliminate: vec!["e".to_string()],
            reverse: vec!["r".to_string()],
            blind_spot: "b".to_string(),
            smallest_next_experiment: "s".to_string(),
            substitute: vec!["sub1".to_string()],
            guardrail: "be careful".to_string(),
            ..Default::default()
        });
        assert_eq!(r.ideas.substitute, vec!["sub1"]);
        assert_eq!(r.guardrail, "be careful");
    }

    // business_gate
    #[test]
    fn business_blocked_when_no_evidence() {
        let r = business_gate("เพิ่ม content ใน Telegram", "lead", None);
        assert!(!r.can_proceed);
        assert!(r.block_reason.is_some());
    }

    #[test]
    fn business_blocked_when_domain_unknown() {
        let r = business_gate("do something", "other", Some("some evidence"));
        assert!(!r.bottleneck_diagnosed);
    }

    #[test]
    fn business_proceeds_with_domain_and_evidence() {
        let r = business_gate(
            "เพิ่ม lead gen campaign",
            "lead",
            Some("lead count ลดลง 30% ใน 2 เดือน"),
        );
        assert!(r.can_proceed);
        assert!(r.kpi_anchor.is_some());
    }

    #[test]
    fn business_kpi_null_when_not_diagnosed() {
        let r = business_gate("recommend x", "other", None);
        assert!(r.kpi_anchor.is_none());
    }

    // decision_format
    #[test]
    fn decision_complete_when_all_filled() {
        let r = decision_format(
            "เลือก DB",
            vec![],
            "ใช้ PostgreSQL",
            "อย่า introduce ChromaDB",
            "latency > 200ms",
            "p95 < 100ms",
            0.8,
        );
        assert!(r.complete);
        assert!(r.missing.is_empty());
        assert_eq!(r.certainty_zone, Zone::C3);
    }

    #[test]
    fn decision_missing_fields_reported() {
        let r = decision_format("เลือก DB", vec![], "", "", "", "", 0.5);
        assert!(r.missing.contains(&"what_to_do_NOW".to_string()));
        assert!(!r.complete);
    }

    #[test]
    fn decision_zone_c0_for_low_confidence() {
        let r = decision_format("x", vec![], "do", "not", "when", "metric", 0.3);
        assert_eq!(r.certainty_zone, Zone::C0);
    }
}
