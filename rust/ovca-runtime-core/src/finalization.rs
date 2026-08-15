use ovca_types::{CoordinatorFinalResponse, Role, RunEvent, RunEventPayload};
use std::fmt;

/// Coordinator finalization failures produced without executing side effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizationError {
    RoleNotAuthorized { role: Role },
    AlreadyFinalized,
}

impl fmt::Display for FinalizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoleNotAuthorized { role } => {
                write!(f, "role is not authorized to finalize: {role}")
            }
            Self::AlreadyFinalized => f.write_str("Coordinator response is already finalized"),
        }
    }
}

impl std::error::Error for FinalizationError {}

/// In-memory state reconstructed from replayable events for exactly-once finalization.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FinalizationKernel {
    final_response: Option<CoordinatorFinalResponse>,
}

impl FinalizationKernel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconstructs finalization state from ordered run events.
    pub fn replay(events: &[RunEvent]) -> Result<Self, FinalizationError> {
        let mut kernel = Self::new();
        for event in events {
            if let RunEventPayload::CoordinatorFinalResponseRecorded { response } = &event.payload {
                kernel.accept(event.producer_role, response.clone())?;
            }
        }
        Ok(kernel)
    }

    pub fn is_finalized(&self) -> bool {
        self.final_response.is_some()
    }

    pub fn final_response(&self) -> Option<&CoordinatorFinalResponse> {
        self.final_response.as_ref()
    }

    /// Accepts one Coordinator response and returns its replayable event payload.
    pub fn finalize(
        &mut self,
        producer_role: Role,
        response: CoordinatorFinalResponse,
    ) -> Result<RunEventPayload, FinalizationError> {
        self.accept(producer_role, response.clone())?;
        Ok(RunEventPayload::CoordinatorFinalResponseRecorded { response })
    }

    fn accept(
        &mut self,
        producer_role: Role,
        response: CoordinatorFinalResponse,
    ) -> Result<(), FinalizationError> {
        if producer_role != Role::Coordinator {
            return Err(FinalizationError::RoleNotAuthorized {
                role: producer_role,
            });
        }
        if self.final_response.is_some() {
            return Err(FinalizationError::AlreadyFinalized);
        }
        self.final_response = Some(response);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ovca_types::{ContractVersion, EventId, EvidenceId, RunId};
    use std::collections::BTreeMap;

    fn response(text: &str) -> CoordinatorFinalResponse {
        CoordinatorFinalResponse {
            contract_version: ContractVersion::current(),
            response: text.to_owned(),
            evidence_refs: vec![EvidenceId::from("evidence-1")],
        }
    }

    fn finalization_event(response: CoordinatorFinalResponse) -> RunEvent {
        RunEvent {
            contract_version: ContractVersion::current(),
            id: EventId::from("event-1"),
            run_id: RunId::from("run-1"),
            sequence: 0,
            previous_event_id: None,
            occurred_at: Utc::now(),
            producer_role: Role::Coordinator,
            payload: RunEventPayload::CoordinatorFinalResponseRecorded { response },
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn golden_coordinator_finalization_is_accepted_once() {
        let expected = response("owner-facing result");
        let mut kernel = FinalizationKernel::new();

        let payload = kernel
            .finalize(Role::Coordinator, expected.clone())
            .expect("Coordinator should finalize");

        assert_eq!(
            payload,
            RunEventPayload::CoordinatorFinalResponseRecorded {
                response: expected.clone(),
            }
        );
        assert!(kernel.is_finalized());
        assert_eq!(kernel.final_response(), Some(&expected));
    }

    #[test]
    fn golden_specialist_roles_cannot_finalize() {
        let mut kernel = FinalizationKernel::new();

        for role in [Role::Engineer, Role::Reviewer, Role::Auditor] {
            assert_eq!(
                kernel.finalize(role, response("not authorized")),
                Err(FinalizationError::RoleNotAuthorized { role })
            );
        }
        assert!(!kernel.is_finalized());
    }

    #[test]
    fn golden_duplicate_finalization_after_replay_is_rejected() {
        let original = response("original result");
        let event = finalization_event(original.clone());
        let mut kernel = FinalizationKernel::replay(&[event]).expect("event should replay");

        let error = kernel
            .finalize(Role::Coordinator, response("replacement result"))
            .expect_err("duplicate finalization must fail");

        assert_eq!(error, FinalizationError::AlreadyFinalized);
        assert_eq!(kernel.final_response(), Some(&original));
    }
}
