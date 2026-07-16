//! Tier 1 — tool-ready, เรียกได้ทันที
//!
//! Tools: sati_check, temporal_gate, support_disclose,
//!        certainty_zone, claim_tag, drift_check

use serde::{Deserialize, Serialize};

// ── sati_check ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SatiCheckResult {
    pub p1: Option<String>,
    pub p2: Option<String>,
    pub p3: String,
    pub proceed: bool,
    pub stop_reason: Option<String>,
}

/// สัมปชัญญะ P1/P2/P3 — 3 คำถามก่อนทุก action ที่มีผลต่อระบบ
pub fn sati_check(action: &str, context: &str) -> SatiCheckResult {
    let action = action.trim();
    let context = context.trim();

    let p1 = if action.is_empty() {
        None
    } else {
        Some(action.to_string())
    };
    let p2 = if context.is_empty() {
        None
    } else {
        Some(context.to_string())
    };

    let p3_tag = if context.is_empty() {
        "assumed"
    } else {
        "inferred"
    };
    let p3 = format!("[{p3_tag}] ผลที่ตามมายังไม่ verify — ต้องตรวจก่อนดำเนินการ");

    let proceed = p1.is_some() && p2.is_some();
    let stop_reason = if p1.is_none() {
        Some("P1 ยังไม่ชัด — ระบุ action ก่อน".to_string())
    } else if p2.is_none() {
        Some("P2 ยังตอบไม่ได้ — ต้องถาม owner ว่า authority คืออะไร".to_string())
    } else {
        None
    };

    SatiCheckResult {
        p1,
        p2,
        p3,
        proceed,
        stop_reason,
    }
}

// ── temporal_gate ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimType {
    Temporal,
    Causal,
    Numeric,
    Operational,
}

impl ClaimType {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "temporal" => Self::Temporal,
            "numeric" => Self::Numeric,
            "operational" => Self::Operational,
            _ => Self::Causal,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalGateResult {
    pub has_evidence: bool,
    pub verdict: String, // "allow" | "block"
    pub cite: Option<String>,
    pub safe_response: Option<String>,
}

const TEMPORAL_KEYWORDS: &[&str] = &[
    "ทำไม",
    "เมื่อไหร่",
    "root cause",
    "timing",
    "background task",
    "failed",
    "ไม่แจ้งเตือน",
    "race condition",
    "timeout",
    "ก่อน",
    "หลัง",
    "พร้อมกัน",
    "why",
    "when",
    "because",
    "caused by",
    "due to",
];

/// Temporal Claim Gate — บล็อก causal/temporal claims ที่ไม่มี evidence
pub fn temporal_gate(
    claim: &str,
    claim_type: &str,
    evidence_source: Option<&str>,
) -> TemporalGateResult {
    let _ = ClaimType::from_str(claim_type); // validate & discard; default causal
    let evidence = evidence_source.map(str::trim).filter(|s| !s.is_empty());
    let has_evidence = evidence.is_some();
    let verdict = if has_evidence { "allow" } else { "block" }.to_string();

    let safe_response = if has_evidence {
        None
    } else {
        let found: Vec<&str> = TEMPORAL_KEYWORDS
            .iter()
            .filter(|&&kw| claim.to_lowercase().contains(kw))
            .copied()
            .collect();
        let hint = if found.is_empty() {
            "ต้องมี log/timestamp/tool result รองรับ".to_string()
        } else {
            let python_list = found
                .iter()
                .map(|keyword| format!("'{keyword}'"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("คำที่ trigger: [{python_list}]")
        };
        Some(format!("ยังยืนยันไม่ได้ค่ะ ต้องดู evidence ก่อน ({hint})"))
    };

    TemporalGateResult {
        has_evidence,
        verdict,
        cite: evidence.map(str::to_string),
        safe_response,
    }
}

// ── support_disclose ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    NoSupport,
    LowSupport,
    Supported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportDiscloseResult {
    pub level: SupportLevel,
    pub label: String,
    pub can_assert: bool,
    pub disclosure_text: String,
}

/// Support Sufficiency Disclosure — วัดระดับ support ของ claim
pub fn support_disclose(claim: &str, evidence_items: &[&str]) -> SupportDiscloseResult {
    let real: Vec<&str> = evidence_items
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    let n = real.len();

    match n {
        0 => SupportDiscloseResult {
            level: SupportLevel::NoSupport,
            label: "ยังยืนยันไม่ได้".to_string(),
            can_assert: false,
            disclosure_text: format!("ยังยืนยันไม่ได้ค่ะ ไม่มี evidence รองรับ claim: '{claim}'"),
        },
        1..=2 => SupportDiscloseResult {
            level: SupportLevel::LowSupport,
            label: "support ต่ำ — หลักฐานยังน้อย".to_string(),
            can_assert: false,
            disclosure_text: format!("support ต่ำค่ะ มีแค่ {n} evidence item — ยังเป็นข้อสรุปชั่วคราว"),
        },
        _ => SupportDiscloseResult {
            level: SupportLevel::Supported,
            label: "supported".to_string(),
            can_assert: true,
            disclosure_text: format!("supported — มี {n} evidence items รองรับ"),
        },
    }
}

// ── certainty_zone ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Zone {
    C0,
    C1,
    C2,
    C3,
    C4,
}

impl std::fmt::Display for Zone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertaintyZoneResult {
    pub zone: Zone,
    pub range: String,
    pub action_required: String,
    pub can_proceed: bool,
    pub confidence: f64,
}

/// Certainty Zone C0–C4 — tag zone ก่อน recommend strategy/architecture
pub fn certainty_zone(confidence: f64) -> CertaintyZoneResult {
    let c = confidence.clamp(0.0, 1.0);
    let (zone, range, action, can_proceed) = if c < 0.40 {
        (
            Zone::C0,
            "[0.00–0.40)",
            "ไม่เสนอ — แจ้ง owner ว่าต้องการข้อมูลอะไรเพิ่ม",
            false,
        )
    } else if c < 0.60 {
        (
            Zone::C1,
            "[0.40–0.60)",
            "เสนอได้ แต่ต้องบอกชัดว่ายังต้องการหลักฐานเพิ่ม",
            true,
        )
    } else if c < 0.75 {
        (
            Zone::C2,
            "[0.60–0.75)",
            "เสนอพร้อม flag ให้ owner ตรวจก่อน dispatch",
            true,
        )
    } else if c < 0.90 {
        (
            Zone::C3,
            "[0.75–0.90)",
            "เสนอ + record decision + proceed after approval",
            true,
        )
    } else {
        (
            Zone::C4,
            "[0.90–1.00]",
            "เสนอพร้อม dispatch-ready plan",
            true,
        )
    };
    CertaintyZoneResult {
        zone,
        range: range.to_string(),
        action_required: action.to_string(),
        can_proceed,
        confidence: c,
    }
}

// ── claim_tag ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimTagKind {
    Observed,
    Inferred,
    Assumed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimTagResult {
    pub tag: ClaimTagKind,
    pub explanation: String,
    pub display_label: String,
}

const OBSERVED_KEYWORDS: &[&str] = &["log", "file", "test", "output", "result", "timestamp"];
const INFERRED_KEYWORDS: &[&str] = &["logic", "เพราะ", "therefore", "infer", "conclude"];
const ASSUMED_KEYWORDS: &[&str] = &["assume", "สมมติ", "probably", "likely", "คิดว่า"];

/// Reality-First Claim Tagging — tag observed/inferred/assumed/unknown
pub fn claim_tag(claim: &str, basis: Option<&str>) -> ClaimTagResult {
    let _ = claim; // claim stored for context; tag determined by basis
    let basis_str = basis.map(str::trim).unwrap_or("");

    let (tag, explanation) = if basis_str.is_empty() {
        (
            ClaimTagKind::Unknown,
            "ไม่มี basis ระบุ — ยังไม่รู้และต้องบอกตรง ๆ".to_string(),
        )
    } else {
        let lower = basis_str.to_lowercase();
        if OBSERVED_KEYWORDS.iter().any(|&k| lower.contains(k)) {
            (
                ClaimTagKind::Observed,
                format!("มี direct evidence: {basis_str}"),
            )
        } else if INFERRED_KEYWORDS.iter().any(|&k| lower.contains(k)) {
            (
                ClaimTagKind::Inferred,
                format!("สรุปจาก logic แต่ยังไม่ verify ตรง: {basis_str}"),
            )
        } else if ASSUMED_KEYWORDS.iter().any(|&k| lower.contains(k)) {
            (
                ClaimTagKind::Assumed,
                format!("สมมติฐานที่ยังไม่ยืนยัน: {basis_str}"),
            )
        } else {
            (
                ClaimTagKind::Inferred,
                format!("basis ไม่ชัดพอที่จะ verify ตรง: {basis_str}"),
            )
        }
    };

    let display_label = format!(
        "[{}]",
        match &tag {
            ClaimTagKind::Observed => "observed",
            ClaimTagKind::Inferred => "inferred",
            ClaimTagKind::Assumed => "assumed",
            ClaimTagKind::Unknown => "unknown",
        }
    );

    ClaimTagResult {
        tag,
        explanation,
        display_label,
    }
}

// ── drift_check ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Warn,
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftBug {
    pub bug: String,
    pub signal: String,
    pub description: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftCheckResult {
    pub bugs_detected: Vec<DriftBug>,
    pub clean: bool,
    pub stop: bool,
}

struct DriftPattern {
    name: &'static str,
    signals: &'static [&'static str],
    description: &'static str,
    severity: Severity,
}

const DRIFT_PATTERNS: &[DriftPattern] = &[
    DriftPattern {
        name: "sycophancy",
        signals: &["ขอโทษ", "sorry", "apologize", "โทษ", "ผิดพลาดที่"],
        description: "เริ่มด้วย apology โดยไม่มี analysis",
        severity: Severity::Stop,
    },
    DriftPattern {
        name: "self_created_plan",
        signals: &["จะทำเลย", "implement ทันที", "ลงมือ", "เริ่มได้เลย", "จัดการให้เลย"],
        description: "propose action โดยไม่มี authority_ref",
        severity: Severity::Stop,
    },
    DriftPattern {
        name: "recency_bias",
        signals: &["เมื่อกี้บอกว่า", "จากที่พึ่งพูด", "ข้อความล่าสุด", "เพิ่งบอก"],
        description: "override decision เดิมเพราะข้อความล่าสุด",
        severity: Severity::Warn,
    },
    DriftPattern {
        name: "performance_bias",
        signals: &["แก้โค้ด", "edit file", "แก้ไฟล์", "fix the code", "change line"],
        description: "เสนอ code change ก่อนเข้าใจ root cause",
        severity: Severity::Warn,
    },
    DriftPattern {
        name: "skip_foundation",
        signals: &["ข้ามไป", "skip", "ทำ step ถัดไป", "next task"],
        description: "dispatch งาน N+1 ก่อน N เสร็จ",
        severity: Severity::Warn,
    },
    DriftPattern {
        name: "lazy_reading",
        signals: &["น่าจะเป็น", "คงจะ", "probably the same", "ตามเดิม"],
        description: "หลุด critical constraint ใน task/spec",
        severity: Severity::Warn,
    },
];

/// Anti-Drift Self-Check — detect reasoning bugs ก่อนส่ง owner
pub fn drift_check(reasoning_snippet: &str, proposed_action: Option<&str>) -> DriftCheckResult {
    let combined = format!(
        "{} {}",
        reasoning_snippet.to_lowercase(),
        proposed_action.unwrap_or("").to_lowercase()
    );

    let mut bugs: Vec<DriftBug> = Vec::new();
    for p in DRIFT_PATTERNS {
        if let Some(&sig) = p.signals.iter().find(|&&s| combined.contains(s)) {
            bugs.push(DriftBug {
                bug: p.name.to_string(),
                signal: format!("พบ '{sig}' ใน reasoning"),
                description: p.description.to_string(),
                severity: p.severity.clone(),
            });
        }
    }

    let stop = bugs.iter().any(|b| b.severity == Severity::Stop);
    let clean = bugs.is_empty();
    DriftCheckResult {
        bugs_detected: bugs,
        clean,
        stop,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // sati_check
    #[test]
    fn sati_proceeds_with_action_and_context() {
        let r = sati_check("ลบ task.md", "task ถูก archive แล้ว");
        assert!(r.proceed);
        assert!(r.stop_reason.is_none());
        assert_eq!(r.p1.as_deref(), Some("ลบ task.md"));
    }

    #[test]
    fn sati_blocks_when_no_context() {
        let r = sati_check("ลบ task.md", "");
        assert!(!r.proceed);
        assert!(r.stop_reason.as_deref().unwrap_or("").contains("P2"));
    }

    #[test]
    fn sati_blocks_when_empty_action() {
        let r = sati_check("", "");
        assert!(!r.proceed);
        assert!(r.p1.is_none());
    }

    #[test]
    fn sati_p3_assumed_without_context() {
        let r = sati_check("edit config.py", "");
        assert!(r.p3.contains("assumed"));
    }

    #[test]
    fn sati_p3_inferred_with_context() {
        let r = sati_check("edit config.py", "เปลี่ยน timeout");
        assert!(r.p3.contains("inferred"));
    }

    // temporal_gate
    #[test]
    fn temporal_blocks_without_evidence() {
        let r = temporal_gate("task timeout เพราะ dispatch ช้า", "causal", None);
        assert_eq!(r.verdict, "block");
        assert!(!r.has_evidence);
        assert!(r.safe_response.is_some());
    }

    #[test]
    fn temporal_allows_with_evidence() {
        let r = temporal_gate(
            "dispatch ล้มเหลว",
            "causal",
            Some("logs/dispatch.log line 42"),
        );
        assert_eq!(r.verdict, "allow");
        assert!(r.has_evidence);
        assert_eq!(r.cite.as_deref(), Some("logs/dispatch.log line 42"));
    }

    #[test]
    fn temporal_unknown_type_defaults_to_causal_block() {
        let r = temporal_gate("something happened", "unknown_type", None);
        assert_eq!(r.verdict, "block");
    }

    #[test]
    fn temporal_safe_response_contains_verify() {
        let r = temporal_gate("race condition occurred", "causal", None);
        assert!(r.safe_response.as_deref().unwrap_or("").contains("ยืนยัน"));
    }

    #[test]
    fn temporal_safe_response_matches_python_quote_style() {
        let r = temporal_gate("race condition occurred", "causal", None);
        assert_eq!(
            r.safe_response.as_deref(),
            Some("ยังยืนยันไม่ได้ค่ะ ต้องดู evidence ก่อน (คำที่ trigger: ['race condition'])")
        );
    }

    // support_disclose
    #[test]
    fn support_no_support_for_empty_evidence() {
        let r = support_disclose("Engineer ทำงานปกติ", &[]);
        assert_eq!(r.level, SupportLevel::NoSupport);
        assert!(!r.can_assert);
    }

    #[test]
    fn support_low_for_one_item() {
        let r = support_disclose("Engineer ทำงานปกติ", &["handoff exists"]);
        assert_eq!(r.level, SupportLevel::LowSupport);
        assert!(!r.can_assert);
    }

    #[test]
    fn support_low_for_two_items() {
        let r = support_disclose("Engineer ทำงานปกติ", &["handoff", "log line"]);
        assert_eq!(r.level, SupportLevel::LowSupport);
    }

    #[test]
    fn support_supported_for_three_items() {
        let r = support_disclose("Engineer ทำงานปกติ", &["handoff", "log", "test pass"]);
        assert_eq!(r.level, SupportLevel::Supported);
        assert!(r.can_assert);
    }

    #[test]
    fn support_strips_blank_items() {
        // 1 real item after stripping blanks → low_support
        let r = support_disclose("claim", &["", "  ", "real evidence"]);
        assert_eq!(r.level, SupportLevel::LowSupport);
    }

    // certainty_zone
    #[test]
    fn zone_boundaries() {
        let cases = [
            (0.0_f64, Zone::C0, false),
            (0.39, Zone::C0, false),
            (0.40, Zone::C1, true),
            (0.59, Zone::C1, true),
            (0.60, Zone::C2, true),
            (0.74, Zone::C2, true),
            (0.75, Zone::C3, true),
            (0.89, Zone::C3, true),
            (0.90, Zone::C4, true),
            (1.00, Zone::C4, true),
        ];
        for (conf, zone, can_proceed) in cases {
            let r = certainty_zone(conf);
            assert_eq!(r.zone, zone, "conf={conf}");
            assert_eq!(r.can_proceed, can_proceed, "conf={conf}");
        }
    }

    #[test]
    fn zone_clamps_below_zero() {
        assert_eq!(certainty_zone(-1.0).zone, Zone::C0);
    }

    #[test]
    fn zone_clamps_above_one() {
        assert_eq!(certainty_zone(2.0).zone, Zone::C4);
    }

    // claim_tag
    #[test]
    fn tag_unknown_when_no_basis() {
        let r = claim_tag("Engineer is running", None);
        assert_eq!(r.tag, ClaimTagKind::Unknown);
    }

    #[test]
    fn tag_observed_with_log_basis() {
        let r = claim_tag("5 tests passed", Some("pytest output log showed 5 passed"));
        assert_eq!(r.tag, ClaimTagKind::Observed);
    }

    #[test]
    fn tag_inferred_with_logic_basis() {
        // basis that has "therefore" but NOT log/file/test/output/result/timestamp
        let r = claim_tag(
            "dispatch succeeded",
            Some("เพราะ exit code = 0 therefore it worked"),
        );
        assert_eq!(r.tag, ClaimTagKind::Inferred);
    }

    #[test]
    fn tag_assumed_with_assume_basis() {
        let r = claim_tag("task is done", Some("assume it completed because no error"));
        assert_eq!(r.tag, ClaimTagKind::Assumed);
    }

    #[test]
    fn tag_display_label_format() {
        let r = claim_tag("some claim", Some("test result showed pass"));
        assert_eq!(r.display_label, format!("[{}]", "observed"));
    }

    // drift_check
    #[test]
    fn drift_clean_when_no_bugs() {
        let r = drift_check("หนูได้อ่าน spec แล้ว root cause คือ timeout config", None);
        assert!(r.clean);
        assert!(!r.stop);
        assert!(r.bugs_detected.is_empty());
    }

    #[test]
    fn drift_detects_sycophancy() {
        let r = drift_check("ขอโทษที่ไม่ได้ทำก่อน", None);
        let bugs: Vec<&str> = r.bugs_detected.iter().map(|b| b.bug.as_str()).collect();
        assert!(bugs.contains(&"sycophancy"));
        assert!(r.stop);
    }

    #[test]
    fn drift_detects_performance_bias() {
        let r = drift_check("หนูจะแก้โค้ดตรงนี้เลย", None);
        let bugs: Vec<&str> = r.bugs_detected.iter().map(|b| b.bug.as_str()).collect();
        assert!(bugs.contains(&"performance_bias"));
    }

    #[test]
    fn drift_stop_true_for_stop_severity() {
        let r = drift_check("จะทำเลยไม่ต้องรอ", None);
        assert!(r.stop);
    }

    #[test]
    fn drift_multiple_bugs_detected() {
        let r = drift_check("ขอโทษมาก จะแก้ไฟล์เดี๋ยวนี้เลย", None);
        assert!(r.bugs_detected.len() >= 2);
    }
}
