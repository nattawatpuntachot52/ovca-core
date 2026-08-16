//! Pure provider-neutral role execution ports.
//!
//! This module validates immutable control-plane invocations and normalizes
//! scripted outcomes. It does not execute providers, schedule retries, append
//! events, persist state, or grant authority.

use ovca_types::control_plane::{
    ControlPlaneState, RoleInvocationV1, RoleResultPayloadV1, RoleResultV1,
};
use ovca_types::IdempotencyKey;
use std::collections::BTreeMap;
use std::fmt;

pub const EXECUTION_TIMEOUT_CODE: &str = "execution_timeout";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleExecutionRequest {
    pub invocation: RoleInvocationV1,
    pub attempt: u32,
}

impl RoleExecutionRequest {
    pub fn validate(&self) -> Result<(), RoleExecutorError> {
        self.invocation
            .validate()
            .map_err(|_| RoleExecutorError::InvalidInvocation)?;
        if !self
            .invocation
            .authority
            .permission_profile
            .write_keys
            .is_empty()
        {
            return Err(RoleExecutorError::ForbiddenWriteAuthority);
        }
        if self.attempt == 0 || self.attempt > self.invocation.budget.max_attempts {
            return Err(RoleExecutorError::InvalidAttempt);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleExecutionUsage {
    Unavailable,
    Reported { input_units: u64, output_units: u64 },
}

impl RoleExecutionUsage {
    pub fn total_units(&self) -> Result<Option<u64>, RoleExecutorError> {
        match self {
            Self::Unavailable => Ok(None),
            Self::Reported {
                input_units,
                output_units,
            } => input_units
                .checked_add(*output_units)
                .map(Some)
                .ok_or(RoleExecutorError::UsageOverflow),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleRetryCause {
    Failed,
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleExecutionOutcome {
    Completed {
        result: RoleResultV1,
        usage: RoleExecutionUsage,
    },
    Failed {
        result: RoleResultV1,
        usage: RoleExecutionUsage,
    },
    TimedOut {
        result: RoleResultV1,
        usage: RoleExecutionUsage,
    },
    Cancelled {
        result: RoleResultV1,
        usage: RoleExecutionUsage,
    },
    RetryRequired {
        completed_attempt: u32,
        next_attempt: u32,
        cause: RoleRetryCause,
        usage: RoleExecutionUsage,
    },
}

impl RoleExecutionOutcome {
    pub fn usage(&self) -> &RoleExecutionUsage {
        match self {
            Self::Completed { usage, .. }
            | Self::Failed { usage, .. }
            | Self::TimedOut { usage, .. }
            | Self::Cancelled { usage, .. }
            | Self::RetryRequired { usage, .. } => usage,
        }
    }

    pub fn validate_against(
        &self,
        request: &RoleExecutionRequest,
    ) -> Result<(), RoleExecutorError> {
        request.validate()?;
        self.usage().total_units()?;
        match self {
            Self::Completed { result, .. } => {
                validate_terminal_result(request, result, TerminalKind::Completed)
            }
            Self::Failed { result, .. } => {
                validate_terminal_result(request, result, TerminalKind::Failed)
            }
            Self::TimedOut { result, .. } => {
                validate_terminal_result(request, result, TerminalKind::TimedOut)
            }
            Self::Cancelled { result, .. } => {
                validate_terminal_result(request, result, TerminalKind::Cancelled)
            }
            Self::RetryRequired {
                completed_attempt,
                next_attempt,
                ..
            } => {
                let expected_next = request
                    .attempt
                    .checked_add(1)
                    .ok_or(RoleExecutorError::InvalidOutcome)?;
                if *completed_attempt != request.attempt
                    || *next_attempt != expected_next
                    || *next_attempt > request.invocation.budget.max_attempts
                {
                    return Err(RoleExecutorError::InvalidOutcome);
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleExecutorError {
    InvalidInvocation,
    ForbiddenWriteAuthority,
    InvalidAttempt,
    MissingScript,
    DuplicateScript,
    ConflictingScript,
    IdempotencyConflict,
    InvalidOutcome,
    UsageOverflow,
}

impl fmt::Display for RoleExecutorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInvocation => "invalid role invocation",
            Self::ForbiddenWriteAuthority => "role execution forbids write authority",
            Self::InvalidAttempt => "invalid role execution attempt",
            Self::MissingScript => "role execution script is missing",
            Self::DuplicateScript => "role execution script is duplicated",
            Self::ConflictingScript => "role execution scripts conflict",
            Self::IdempotencyConflict => "role execution idempotency binding conflicts",
            Self::InvalidOutcome => "invalid role execution outcome",
            Self::UsageOverflow => "role execution usage overflows",
        })
    }
}

impl std::error::Error for RoleExecutorError {}

pub trait RoleExecutor {
    fn invoke(
        &self,
        request: RoleExecutionRequest,
    ) -> Result<RoleExecutionOutcome, RoleExecutorError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleExecutionScript {
    pub request: RoleExecutionRequest,
    pub outcome: RoleExecutionOutcome,
}

#[derive(Debug, Clone)]
pub struct DeterministicFakeRoleExecutor {
    scripts: BTreeMap<ScriptKey, ScriptEntry>,
    bindings_by_key: BTreeMap<IdempotencyKey, InvocationBinding>,
    bindings_by_invocation_id: BTreeMap<String, InvocationBinding>,
}

impl DeterministicFakeRoleExecutor {
    pub fn try_new(
        scripts: impl IntoIterator<Item = RoleExecutionScript>,
    ) -> Result<Self, RoleExecutorError> {
        let mut executor = Self {
            scripts: BTreeMap::new(),
            bindings_by_key: BTreeMap::new(),
            bindings_by_invocation_id: BTreeMap::new(),
        };

        for script in scripts {
            script.request.validate()?;
            script.outcome.validate_against(&script.request)?;
            let binding = InvocationBinding::from_request(&script.request)?;
            let key = ScriptKey::from_request(&script.request);

            if let Some(existing) = executor.scripts.get(&key) {
                return if existing.request == script.request && existing.outcome == script.outcome {
                    Err(RoleExecutorError::DuplicateScript)
                } else {
                    Err(RoleExecutorError::ConflictingScript)
                };
            }
            if executor
                .bindings_by_key
                .get(&binding.idempotency_key)
                .is_some_and(|existing| existing != &binding)
                || executor
                    .bindings_by_invocation_id
                    .get(&binding.invocation_id)
                    .is_some_and(|existing| existing != &binding)
            {
                return Err(RoleExecutorError::ConflictingScript);
            }

            executor
                .bindings_by_key
                .insert(binding.idempotency_key.clone(), binding.clone());
            executor
                .bindings_by_invocation_id
                .insert(binding.invocation_id.clone(), binding.clone());
            executor.scripts.insert(
                key,
                ScriptEntry {
                    request: script.request,
                    binding,
                    outcome: script.outcome,
                },
            );
        }
        Ok(executor)
    }
}

impl RoleExecutor for DeterministicFakeRoleExecutor {
    fn invoke(
        &self,
        request: RoleExecutionRequest,
    ) -> Result<RoleExecutionOutcome, RoleExecutorError> {
        request.validate()?;
        let binding = InvocationBinding::from_request(&request)?;
        if self
            .bindings_by_key
            .get(&binding.idempotency_key)
            .is_some_and(|existing| existing != &binding)
            || self
                .bindings_by_invocation_id
                .get(&binding.invocation_id)
                .is_some_and(|existing| existing != &binding)
        {
            return Err(RoleExecutorError::IdempotencyConflict);
        }

        let entry = self
            .scripts
            .get(&ScriptKey::from_request(&request))
            .ok_or(RoleExecutorError::MissingScript)?;
        if entry.request != request || entry.binding != binding {
            return Err(RoleExecutorError::IdempotencyConflict);
        }
        entry.outcome.validate_against(&request)?;
        Ok(entry.outcome.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ScriptKey {
    idempotency_key: IdempotencyKey,
    attempt: u32,
}

impl ScriptKey {
    fn from_request(request: &RoleExecutionRequest) -> Self {
        Self {
            idempotency_key: request.invocation.idempotency_key.clone(),
            attempt: request.attempt,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InvocationBinding {
    invocation_id: String,
    invocation_digest: String,
    idempotency_key: IdempotencyKey,
}

impl InvocationBinding {
    fn from_request(request: &RoleExecutionRequest) -> Result<Self, RoleExecutorError> {
        Ok(Self {
            invocation_id: request.invocation.invocation_id.clone(),
            invocation_digest: request
                .invocation
                .canonical_digest()
                .map_err(|_| RoleExecutorError::InvalidInvocation)?,
            idempotency_key: request.invocation.idempotency_key.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScriptEntry {
    request: RoleExecutionRequest,
    binding: InvocationBinding,
    outcome: RoleExecutionOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalKind {
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

fn validate_terminal_result(
    request: &RoleExecutionRequest,
    result: &RoleResultV1,
    expected: TerminalKind,
) -> Result<(), RoleExecutorError> {
    result
        .validate_against(&request.invocation)
        .map_err(|_| RoleExecutorError::InvalidOutcome)?;
    if result.attempt != request.attempt {
        return Err(RoleExecutorError::InvalidOutcome);
    }

    let matches = match expected {
        TerminalKind::Completed => result.state == ControlPlaneState::Completed,
        TerminalKind::Failed => {
            result.state == ControlPlaneState::Failed
                && matches!(
                    &result.payload,
                    RoleResultPayloadV1::Failure { code, .. } if code != EXECUTION_TIMEOUT_CODE
                )
        }
        TerminalKind::TimedOut => {
            result.state == ControlPlaneState::Failed
                && matches!(
                    &result.payload,
                    RoleResultPayloadV1::Failure { code, .. } if code == EXECUTION_TIMEOUT_CODE
                )
        }
        TerminalKind::Cancelled => result.state == ControlPlaneState::Cancelled,
    };
    if matches {
        Ok(())
    } else {
        Err(RoleExecutorError::InvalidOutcome)
    }
}
