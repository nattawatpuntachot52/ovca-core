//! Process-local capability broker for disposable workspaces.
//!
//! V1 deliberately has no command runner, child process, provider, network,
//! environment injection, persistence, or durable authority. Only native
//! bounded file reads and writes are admitted after exact broker-owned checks.

use crate::role_executor::RoleExecutionRequest;
use chrono::{DateTime, Utc};
use ovca_types::control_plane::RoleInvocationV1;
use ovca_types::foundation::{
    FoundationAuthorityV1, FoundationNamespaceV1, FoundationValidityStatusV1, PrincipalV1,
};
use ovca_types::goal_runtime::verification_sha256_hex;
use ovca_types::tool_boundary::{
    canonical_authority_digest, expected_read_permission_keys, expected_write_permission_keys,
    validate_logical_path, CapabilityGrantV1, ToolBoundaryValidationError, ToolDeniedCodeV1,
    ToolOperationV1, ToolReceiptOutcomeV1, ToolReceiptV1, ToolRequestV1, WorkspaceFileV1,
    WorkspaceLeaseV1, WorkspaceSnapshotV1, TOOL_BOUNDARY_CONTRACT_VERSION,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{fmt, io};

static NEXT_BROKER_NONCE: AtomicU64 = AtomicU64::new(1);
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

pub trait BrokerClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug, Default)]
pub struct SystemBrokerClock;

impl BrokerClock for SystemBrokerClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSeedFile {
    logical_path: String,
    bytes: Vec<u8>,
}

impl WorkspaceSeedFile {
    pub fn try_new(
        logical_path: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, WorkspaceCapabilityError> {
        let logical_path = logical_path.into();
        validate_logical_path(&logical_path)
            .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
        Ok(Self {
            logical_path,
            bytes: bytes.into(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupReason {
    Completed,
    Cancelled,
    Failed,
    Panicked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceLeaseState {
    Active,
    CleanupRequired(CleanupReason),
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedWorkspaceLease {
    broker_nonce: u64,
    registry_token: u64,
    observation: WorkspaceLeaseV1,
    digest: String,
    initial_snapshot: WorkspaceSnapshotV1,
}

impl TrustedWorkspaceLease {
    pub fn observation(&self) -> &WorkspaceLeaseV1 {
        &self.observation
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn initial_snapshot(&self) -> &WorkspaceSnapshotV1 {
        &self.initial_snapshot
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedCapabilityGrant {
    broker_nonce: u64,
    registry_token: u64,
    observation: CapabilityGrantV1,
    digest: String,
}

impl TrustedCapabilityGrant {
    pub fn observation(&self) -> &CapabilityGrantV1 {
        &self.observation
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedToolReceipt {
    broker_nonce: u64,
    observation: ToolReceiptV1,
}

impl TrustedToolReceipt {
    pub fn observation(&self) -> &ToolReceiptV1 {
        &self.observation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionResult {
    receipt: TrustedToolReceipt,
    read_bytes: Option<Vec<u8>>,
}

impl ToolExecutionResult {
    pub fn receipt(&self) -> &TrustedToolReceipt {
        &self.receipt
    }

    pub fn read_bytes(&self) -> Option<&[u8]> {
        self.read_bytes.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceCapabilityError {
    InvalidConfiguration,
    InvalidWorkspace,
    InvalidInvocation,
    InvalidLease,
    InvalidGrant,
    ForeignHandle,
    DuplicateIdentifier,
    InvalidRequest,
    BackendFailure,
    CleanupFailure,
    Serialization,
}

impl fmt::Display for WorkspaceCapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid workspace capability configuration",
            Self::InvalidWorkspace => "invalid disposable workspace",
            Self::InvalidInvocation => "invalid role invocation binding",
            Self::InvalidLease => "invalid workspace lease",
            Self::InvalidGrant => "invalid capability grant",
            Self::ForeignHandle => "opaque handle belongs to another broker",
            Self::DuplicateIdentifier => "identifier is already registered",
            Self::InvalidRequest => "tool request cannot produce a trusted receipt",
            Self::BackendFailure => "native workspace backend failed",
            Self::CleanupFailure => "disposable workspace cleanup failed",
            Self::Serialization => "canonical JSON serialization failed",
        })
    }
}

impl std::error::Error for WorkspaceCapabilityError {}

#[derive(Debug, Clone)]
struct LeaseRecord {
    registry_token: u64,
    dto: WorkspaceLeaseV1,
    canonical_bytes: Vec<u8>,
    digest: String,
    invocation: RoleInvocationV1,
    invocation_bytes: Vec<u8>,
    root: PathBuf,
    state: WorkspaceLeaseState,
    snapshot: WorkspaceSnapshotV1,
}

#[derive(Debug, Clone)]
struct GrantRecord {
    registry_token: u64,
    dto: CapabilityGrantV1,
    canonical_bytes: Vec<u8>,
    digest: String,
}

#[derive(Debug, Clone)]
struct IdempotencyRecord {
    canonical_request: Vec<u8>,
    result: ToolExecutionResult,
    conflicts: BTreeMap<Vec<u8>, ToolExecutionResult>,
}

#[derive(Debug, Clone)]
struct AdmissionContext {
    lease: LeaseRecord,
    grant: GrantRecord,
    before: WorkspaceSnapshotV1,
}

pub struct WorkspaceCapabilityBroker {
    runtime_instance_id: String,
    broker_nonce: u64,
    workspace_parent: PathBuf,
    protected_roots: Vec<PathBuf>,
    clock: Box<dyn BrokerClock>,
    leases: BTreeMap<String, LeaseRecord>,
    grants: BTreeMap<String, GrantRecord>,
    idempotency: BTreeMap<String, IdempotencyRecord>,
    next_registry_token: u64,
    next_sequence: u64,
    backend_calls: u64,
}

impl WorkspaceCapabilityBroker {
    pub fn try_new(
        runtime_instance_id: impl Into<String>,
        workspace_parent: impl Into<PathBuf>,
        protected_roots: impl IntoIterator<Item = PathBuf>,
        clock: Box<dyn BrokerClock>,
    ) -> Result<Self, WorkspaceCapabilityError> {
        let runtime_instance_id = runtime_instance_id.into();
        ovca_types::foundation::validate_stable_id(&runtime_instance_id, "runtime_instance_id")
            .map_err(|_| WorkspaceCapabilityError::InvalidConfiguration)?;
        let workspace_parent = canonical_ordinary_directory(&workspace_parent.into())?;
        let protected_roots = protected_roots
            .into_iter()
            .map(|path| canonical_ordinary_directory(&path))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            runtime_instance_id,
            broker_nonce: NEXT_BROKER_NONCE.fetch_add(1, Ordering::Relaxed),
            workspace_parent,
            protected_roots,
            clock,
            leases: BTreeMap::new(),
            grants: BTreeMap::new(),
            idempotency: BTreeMap::new(),
            next_registry_token: 1,
            next_sequence: 1,
            backend_calls: 0,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_lease(
        &mut self,
        execution: &RoleExecutionRequest,
        lease_id: impl Into<String>,
        workspace_id: impl Into<String>,
        seeds: impl IntoIterator<Item = WorkspaceSeedFile>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<TrustedWorkspaceLease, WorkspaceCapabilityError> {
        execution
            .validate()
            .map_err(|_| WorkspaceCapabilityError::InvalidInvocation)?;
        let invocation_digest = execution
            .invocation
            .canonical_digest()
            .map_err(|_| WorkspaceCapabilityError::InvalidInvocation)?;
        let invocation_bytes = execution
            .invocation
            .canonical_json_bytes()
            .map_err(|_| WorkspaceCapabilityError::InvalidInvocation)?;
        let lease_id = lease_id.into();
        let workspace_id = workspace_id.into();
        ovca_types::foundation::validate_stable_id(&lease_id, "lease_id")
            .and_then(|_| ovca_types::foundation::validate_stable_id(&workspace_id, "workspace_id"))
            .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
        if self.leases.contains_key(&lease_id)
            || self
                .leases
                .values()
                .any(|record| record.dto.workspace_id == workspace_id)
        {
            return Err(WorkspaceCapabilityError::DuplicateIdentifier);
        }

        let registry_token = self.take_registry_token()?;
        let root = self
            .workspace_parent
            .join(format!("workspace-{}-{registry_token}", self.broker_nonce));
        if root.exists() {
            return Err(WorkspaceCapabilityError::InvalidWorkspace);
        }
        fs::create_dir(&root).map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;

        let setup = (|| {
            let canonical_root = canonical_ordinary_directory(&root)?;
            if canonical_root != root
                || self
                    .protected_roots
                    .iter()
                    .any(|protected| paths_overlap(&canonical_root, protected))
            {
                return Err(WorkspaceCapabilityError::InvalidWorkspace);
            }
            materialize_seeds(&canonical_root, seeds)?;
            let snapshot = capture_snapshot(&canonical_root, &workspace_id, &lease_id, 0)?;
            let dto = WorkspaceLeaseV1 {
                contract_version: TOOL_BOUNDARY_CONTRACT_VERSION,
                lease_id: lease_id.clone(),
                workspace_id: workspace_id.clone(),
                invocation_id: execution.invocation.invocation_id.clone(),
                invocation_digest,
                attempt: execution.attempt,
                scope: execution.invocation.scope.clone(),
                initial_snapshot_digest: snapshot.snapshot_digest.clone(),
                issued_at,
                expires_at,
            };
            dto.validate()
                .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
            let canonical_bytes = dto
                .canonical_json_bytes()
                .map_err(|_| WorkspaceCapabilityError::Serialization)?;
            let digest = verification_sha256_hex(&canonical_bytes);
            Ok((canonical_root, snapshot, dto, canonical_bytes, digest))
        })();

        let (root, snapshot, dto, canonical_bytes, digest) = match setup {
            Ok(value) => value,
            Err(error) => {
                cleanup_owned_root(&self.workspace_parent, &root);
                return Err(error);
            }
        };

        let record = LeaseRecord {
            registry_token,
            dto: dto.clone(),
            canonical_bytes,
            digest: digest.clone(),
            invocation: execution.invocation.clone(),
            invocation_bytes,
            root,
            state: WorkspaceLeaseState::Active,
            snapshot: snapshot.clone(),
        };
        self.leases.insert(lease_id, record);
        Ok(TrustedWorkspaceLease {
            broker_nonce: self.broker_nonce,
            registry_token,
            observation: dto,
            digest,
            initial_snapshot: snapshot,
        })
    }

    pub fn issue_grant(
        &mut self,
        execution: &RoleExecutionRequest,
        lease: &TrustedWorkspaceLease,
        grant: CapabilityGrantV1,
    ) -> Result<TrustedCapabilityGrant, WorkspaceCapabilityError> {
        execution
            .validate()
            .map_err(|_| WorkspaceCapabilityError::InvalidInvocation)?;
        grant
            .validate()
            .map_err(|_| WorkspaceCapabilityError::InvalidGrant)?;
        if lease.broker_nonce != self.broker_nonce {
            return Err(WorkspaceCapabilityError::ForeignHandle);
        }
        if self.grants.contains_key(&grant.grant_id) {
            return Err(WorkspaceCapabilityError::DuplicateIdentifier);
        }
        let lease_record = self
            .leases
            .get(&grant.lease_id)
            .ok_or(WorkspaceCapabilityError::InvalidLease)?;
        if lease.registry_token != lease_record.registry_token
            || lease.observation != lease_record.dto
            || lease.digest != lease_record.digest
            || lease.initial_snapshot.snapshot_digest != lease_record.dto.initial_snapshot_digest
            || lease_record.state != WorkspaceLeaseState::Active
        {
            return Err(WorkspaceCapabilityError::InvalidLease);
        }
        validate_registry_lease(lease_record)?;
        validate_grant_binding(execution, lease_record, &grant)?;

        let canonical_bytes = grant
            .canonical_json_bytes()
            .map_err(|_| WorkspaceCapabilityError::Serialization)?;
        let digest = verification_sha256_hex(&canonical_bytes);
        let registry_token = self.take_registry_token()?;
        self.grants.insert(
            grant.grant_id.clone(),
            GrantRecord {
                registry_token,
                dto: grant.clone(),
                canonical_bytes,
                digest: digest.clone(),
            },
        );
        Ok(TrustedCapabilityGrant {
            broker_nonce: self.broker_nonce,
            registry_token,
            observation: grant,
            digest,
        })
    }

    pub fn snapshot(
        &self,
        lease: &TrustedWorkspaceLease,
    ) -> Result<WorkspaceSnapshotV1, WorkspaceCapabilityError> {
        if lease.broker_nonce != self.broker_nonce {
            return Err(WorkspaceCapabilityError::ForeignHandle);
        }
        let record = self
            .leases
            .get(&lease.observation.lease_id)
            .ok_or(WorkspaceCapabilityError::InvalidLease)?;
        if lease.registry_token != record.registry_token
            || lease.observation != record.dto
            || lease.digest != record.digest
            || record.state == WorkspaceLeaseState::Closed
        {
            return Err(WorkspaceCapabilityError::InvalidLease);
        }
        Ok(record.snapshot.clone())
    }

    pub fn lease_state(
        &self,
        lease_id: &str,
    ) -> Result<WorkspaceLeaseState, WorkspaceCapabilityError> {
        self.leases
            .get(lease_id)
            .map(|record| record.state)
            .ok_or(WorkspaceCapabilityError::InvalidLease)
    }

    pub fn backend_calls(&self) -> u64 {
        self.backend_calls
    }

    pub fn active_root_count(&self) -> usize {
        self.leases
            .values()
            .filter(|record| record.root.exists())
            .count()
    }

    pub fn grant_is_live(&self, grant: &TrustedCapabilityGrant) -> bool {
        grant.broker_nonce == self.broker_nonce
            && self
                .grants
                .get(&grant.observation.grant_id)
                .is_some_and(|record| {
                    record.registry_token == grant.registry_token
                        && record.dto == grant.observation
                        && record.digest == grant.digest
                })
    }

    pub fn receipt_is_from_this_broker(&self, receipt: &TrustedToolReceipt) -> bool {
        receipt.broker_nonce == self.broker_nonce
            && receipt.observation.runtime_instance_id == self.runtime_instance_id
    }

    pub fn close_lease(
        &mut self,
        lease: &TrustedWorkspaceLease,
        reason: CleanupReason,
    ) -> Result<(), WorkspaceCapabilityError> {
        if lease.broker_nonce != self.broker_nonce {
            return Err(WorkspaceCapabilityError::ForeignHandle);
        }
        let record = self
            .leases
            .get_mut(&lease.observation.lease_id)
            .ok_or(WorkspaceCapabilityError::InvalidLease)?;
        if record.registry_token != lease.registry_token
            || record.dto != lease.observation
            || record.digest != lease.digest
            || record.state != WorkspaceLeaseState::Active
        {
            return Err(WorkspaceCapabilityError::InvalidLease);
        }
        record.state = WorkspaceLeaseState::CleanupRequired(reason);
        if cleanup_owned_root(&self.workspace_parent, &record.root) {
            record.state = WorkspaceLeaseState::Closed;
            Ok(())
        } else {
            Err(WorkspaceCapabilityError::CleanupFailure)
        }
    }

    pub fn execute_json(
        &mut self,
        request_json: &[u8],
        write_bytes: Option<&[u8]>,
    ) -> Result<ToolExecutionResult, WorkspaceCapabilityError> {
        let request: ToolRequestV1 = serde_json::from_slice(request_json)
            .map_err(|_| WorkspaceCapabilityError::InvalidRequest)?;
        self.execute(request, write_bytes)
    }

    pub fn execute(
        &mut self,
        request: ToolRequestV1,
        write_bytes: Option<&[u8]>,
    ) -> Result<ToolExecutionResult, WorkspaceCapabilityError> {
        validate_receiptable_request(&request)?;
        let request_bytes =
            serde_json::to_vec(&request).map_err(|_| WorkspaceCapabilityError::Serialization)?;

        if let Some(record) = self.idempotency.get(&request.idempotency_key) {
            if record.canonical_request == request_bytes {
                return Ok(record.result.clone());
            }
            if let Some(existing) = record.conflicts.get(&request_bytes) {
                return Ok(existing.clone());
            }
            let basis = record.result.clone();
            let snapshot = SnapshotPoint {
                digest: basis.receipt.observation.after_snapshot_digest.clone(),
                generation: basis.receipt.observation.after_generation,
            };
            let occurred_at = basis.receipt.observation.occurred_at;
            let conflict = self.denied_result(
                &request,
                &request_bytes,
                ToolDeniedCodeV1::IdempotencyConflict,
                &snapshot,
                occurred_at,
            )?;
            self.idempotency
                .get_mut(&request.idempotency_key)
                .expect("idempotency record was observed above")
                .conflicts
                .insert(request_bytes, conflict.clone());
            return Ok(conflict);
        }

        let evaluation_time = self.clock.now();
        let result = self.execute_fresh(&request, &request_bytes, write_bytes, evaluation_time)?;
        self.idempotency.insert(
            request.idempotency_key.clone(),
            IdempotencyRecord {
                canonical_request: request_bytes,
                result: result.clone(),
                conflicts: BTreeMap::new(),
            },
        );
        Ok(result)
    }

    fn execute_fresh(
        &mut self,
        request: &ToolRequestV1,
        request_bytes: &[u8],
        write_bytes: Option<&[u8]>,
        evaluation_time: DateTime<Utc>,
    ) -> Result<ToolExecutionResult, WorkspaceCapabilityError> {
        let fallback = self.snapshot_point_for_request(request);
        let admission = match self.admit(request, evaluation_time) {
            Ok(context) => context,
            Err(code) => {
                return self.denied_result(request, request_bytes, code, &fallback, evaluation_time)
            }
        };
        let before_point = SnapshotPoint::from(&admission.before);

        let denial = match &request.operation {
            ToolOperationV1::Unsupported { .. } => Some(ToolDeniedCodeV1::UnsupportedOperation),
            ToolOperationV1::ReadFile { logical_path } => {
                match classify_logical_path(logical_path) {
                    Some(code) => Some(code),
                    None if write_bytes.is_some() => Some(ToolDeniedCodeV1::PayloadMismatch),
                    None if !path_is_exactly_granted(
                        logical_path,
                        &admission.grant.dto.read_paths,
                    ) =>
                    {
                        Some(path_denial(logical_path, &admission.grant.dto.read_paths))
                    }
                    None => admission
                        .before
                        .files
                        .iter()
                        .find(|file| file.logical_path == *logical_path)
                        .map_or(Some(ToolDeniedCodeV1::WorkspaceInvalid), |file| {
                            (file.byte_length > admission.grant.dto.max_read_bytes)
                                .then_some(ToolDeniedCodeV1::LimitExceeded)
                        }),
                }
            }
            ToolOperationV1::WriteFile {
                logical_path,
                content_sha256,
                byte_length,
            } => match classify_logical_path(logical_path) {
                Some(code) => Some(code),
                None if request.requester.role != PrincipalV1::Engineer => {
                    Some(ToolDeniedCodeV1::RoleForbidden)
                }
                None if !path_is_exactly_granted(
                    logical_path,
                    &admission.grant.dto.write_paths,
                ) =>
                {
                    Some(path_denial(logical_path, &admission.grant.dto.write_paths))
                }
                None if *byte_length > admission.grant.dto.max_write_bytes => {
                    Some(ToolDeniedCodeV1::LimitExceeded)
                }
                None => {
                    let Some(bytes) = write_bytes else {
                        return self.denied_result(
                            request,
                            request_bytes,
                            ToolDeniedCodeV1::PayloadMismatch,
                            &before_point,
                            evaluation_time,
                        );
                    };
                    if usize_to_u64(bytes.len())? != *byte_length
                        || verification_sha256_hex(bytes) != *content_sha256
                    {
                        Some(ToolDeniedCodeV1::PayloadMismatch)
                    } else if admission.before.files.iter().any(|file| {
                        file.logical_path == *logical_path
                            && file.sha256 == *content_sha256
                            && file.byte_length == *byte_length
                    }) {
                        Some(ToolDeniedCodeV1::NoChange)
                    } else {
                        None
                    }
                }
            },
        };

        if let Some(code) = denial {
            return self.denied_result(
                request,
                request_bytes,
                code,
                &before_point,
                evaluation_time,
            );
        }

        match &request.operation {
            ToolOperationV1::ReadFile { logical_path } => {
                self.backend_calls = self
                    .backend_calls
                    .checked_add(1)
                    .ok_or(WorkspaceCapabilityError::BackendFailure)?;
                let path = admission
                    .lease
                    .root
                    .join(logical_path_to_path(logical_path));
                let bytes = match fs::read(path) {
                    Ok(bytes) => bytes,
                    Err(_) => return self.backend_failure(&request.lease_id),
                };
                let expected = admission
                    .before
                    .files
                    .iter()
                    .find(|file| file.logical_path == *logical_path)
                    .ok_or(WorkspaceCapabilityError::BackendFailure)?;
                if verification_sha256_hex(&bytes) != expected.sha256
                    || usize_to_u64(bytes.len())? != expected.byte_length
                {
                    return self.backend_failure(&request.lease_id);
                }
                let receipt = self.build_receipt(
                    request,
                    request_bytes,
                    ToolReceiptOutcomeV1::Read {
                        content_sha256: expected.sha256.clone(),
                        byte_length: expected.byte_length,
                    },
                    &before_point,
                    &before_point,
                    evaluation_time,
                )?;
                Ok(ToolExecutionResult {
                    receipt,
                    read_bytes: Some(bytes),
                })
            }
            ToolOperationV1::WriteFile {
                logical_path,
                content_sha256,
                byte_length,
            } => {
                let bytes = write_bytes.expect("write payload was validated above");
                self.backend_calls = self
                    .backend_calls
                    .checked_add(1)
                    .ok_or(WorkspaceCapabilityError::BackendFailure)?;
                let path = admission
                    .lease
                    .root
                    .join(logical_path_to_path(logical_path));
                if fs::write(path, bytes).is_err() {
                    return self.backend_failure(&request.lease_id);
                }
                let next_generation = admission
                    .before
                    .generation
                    .checked_add(1)
                    .ok_or(WorkspaceCapabilityError::BackendFailure)?;
                let after = match capture_snapshot(
                    &admission.lease.root,
                    &admission.lease.dto.workspace_id,
                    &admission.lease.dto.lease_id,
                    next_generation,
                ) {
                    Ok(snapshot) => snapshot,
                    Err(_) => return self.backend_failure(&request.lease_id),
                };
                if !exactly_one_manifest_entry_changed(&admission.before, &after, logical_path)
                    || !after.files.iter().any(|file| {
                        file.logical_path == *logical_path
                            && file.sha256 == *content_sha256
                            && file.byte_length == *byte_length
                    })
                {
                    return self.backend_failure(&request.lease_id);
                }
                self.leases
                    .get_mut(&request.lease_id)
                    .ok_or(WorkspaceCapabilityError::BackendFailure)?
                    .snapshot = after.clone();
                let after_point = SnapshotPoint::from(&after);
                let receipt = self.build_receipt(
                    request,
                    request_bytes,
                    ToolReceiptOutcomeV1::Written {
                        content_sha256: content_sha256.clone(),
                        byte_length: *byte_length,
                    },
                    &before_point,
                    &after_point,
                    evaluation_time,
                )?;
                Ok(ToolExecutionResult {
                    receipt,
                    read_bytes: None,
                })
            }
            ToolOperationV1::Unsupported { .. } => unreachable!("denied above"),
        }
    }

    fn admit(
        &self,
        request: &ToolRequestV1,
        evaluation_time: DateTime<Utc>,
    ) -> Result<AdmissionContext, ToolDeniedCodeV1> {
        if request.requested_at > evaluation_time {
            return Err(ToolDeniedCodeV1::InvalidBinding);
        }
        let lease = self
            .leases
            .get(&request.lease_id)
            .cloned()
            .ok_or(ToolDeniedCodeV1::InvalidBinding)?;
        let grant = self
            .grants
            .get(&request.grant_id)
            .cloned()
            .ok_or(ToolDeniedCodeV1::InvalidBinding)?;
        if validate_registry_lease(&lease).is_err()
            || validate_registry_grant(&grant).is_err()
            || lease.state != WorkspaceLeaseState::Active
            || request.lease_digest != lease.digest
            || request.grant_digest != grant.digest
            || request.workspace_id != lease.dto.workspace_id
            || request.workspace_id != grant.dto.workspace_id
            || request.invocation_id != lease.dto.invocation_id
            || request.invocation_id != grant.dto.invocation_id
            || request.invocation_digest != lease.dto.invocation_digest
            || request.invocation_digest != grant.dto.invocation_digest
            || request.attempt != lease.dto.attempt
            || request.attempt != grant.dto.attempt
            || request.scope != lease.dto.scope
            || request.scope != grant.dto.scope
            || request.requester != grant.dto.grantee
            || grant.dto.lease_id != lease.dto.lease_id
            || grant.dto.lease_digest != lease.digest
            || grant.dto.snapshot_digest != request.expected_snapshot_digest
            || lease.invocation.invocation_id != request.invocation_id
            || lease.invocation_bytes
                != lease
                    .invocation
                    .canonical_json_bytes()
                    .map_err(|_| ToolDeniedCodeV1::InvalidBinding)?
            || lease
                .invocation
                .canonical_digest()
                .map_err(|_| ToolDeniedCodeV1::InvalidBinding)?
                != request.invocation_digest
        {
            return Err(ToolDeniedCodeV1::InvalidBinding);
        }
        if !authority_active_at(&lease.invocation.authority, evaluation_time)
            || !authority_active_at(&grant.dto.grant_authority, evaluation_time)
            || evaluation_time < grant.dto.valid_from
            || evaluation_time >= grant.dto.valid_until
            || evaluation_time < lease.dto.issued_at
            || evaluation_time >= lease.dto.expires_at
        {
            return Err(ToolDeniedCodeV1::Expired);
        }
        if request.expected_snapshot_digest != lease.snapshot.snapshot_digest {
            return Err(ToolDeniedCodeV1::StaleSnapshot);
        }
        if request.requester.role != lease.invocation.target.role
            || matches!(
                request.requester.role,
                PrincipalV1::Owner | PrincipalV1::Coordinator
            )
        {
            return Err(ToolDeniedCodeV1::RoleForbidden);
        }
        if self
            .protected_roots
            .iter()
            .any(|protected| paths_overlap(&lease.root, protected))
        {
            return Err(ToolDeniedCodeV1::ProtectedRoot);
        }
        verify_ordinary_tree(&lease.root, request.operation.logical_path())?;
        let observed = capture_snapshot(
            &lease.root,
            &lease.dto.workspace_id,
            &lease.dto.lease_id,
            lease.snapshot.generation,
        )
        .map_err(|_| ToolDeniedCodeV1::WorkspaceInvalid)?;
        if observed != lease.snapshot {
            return Err(ToolDeniedCodeV1::StaleSnapshot);
        }
        Ok(AdmissionContext {
            lease,
            grant,
            before: observed,
        })
    }

    fn snapshot_point_for_request(&self, request: &ToolRequestV1) -> SnapshotPoint {
        self.leases
            .get(&request.lease_id)
            .filter(|lease| lease.dto.workspace_id == request.workspace_id)
            .map(|lease| SnapshotPoint::from(&lease.snapshot))
            .unwrap_or_else(|| SnapshotPoint {
                digest: request.expected_snapshot_digest.clone(),
                generation: 0,
            })
    }

    fn denied_result(
        &mut self,
        request: &ToolRequestV1,
        request_bytes: &[u8],
        code: ToolDeniedCodeV1,
        snapshot: &SnapshotPoint,
        occurred_at: DateTime<Utc>,
    ) -> Result<ToolExecutionResult, WorkspaceCapabilityError> {
        let receipt = self.build_receipt(
            request,
            request_bytes,
            ToolReceiptOutcomeV1::Denied { code },
            snapshot,
            snapshot,
            occurred_at,
        )?;
        Ok(ToolExecutionResult {
            receipt,
            read_bytes: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn build_receipt(
        &mut self,
        request: &ToolRequestV1,
        request_bytes: &[u8],
        outcome: ToolReceiptOutcomeV1,
        before: &SnapshotPoint,
        after: &SnapshotPoint,
        occurred_at: DateTime<Utc>,
    ) -> Result<TrustedToolReceipt, WorkspaceCapabilityError> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(WorkspaceCapabilityError::BackendFailure)?;
        let receipt = ToolReceiptV1 {
            contract_version: TOOL_BOUNDARY_CONTRACT_VERSION,
            receipt_id: format!("receipt.{sequence}"),
            runtime_instance_id: self.runtime_instance_id.clone(),
            sequence,
            request_id: request.request_id.clone(),
            request_digest: verification_sha256_hex(request_bytes),
            idempotency_key: request.idempotency_key.clone(),
            invocation_id: request.invocation_id.clone(),
            invocation_digest: request.invocation_digest.clone(),
            grant_id: request.grant_id.clone(),
            grant_digest: request.grant_digest.clone(),
            lease_id: request.lease_id.clone(),
            lease_digest: request.lease_digest.clone(),
            workspace_id: request.workspace_id.clone(),
            actor: request.requester.clone(),
            before_snapshot_digest: before.digest.clone(),
            after_snapshot_digest: after.digest.clone(),
            before_generation: before.generation,
            after_generation: after.generation,
            outcome,
            occurred_at,
        };
        receipt
            .validate()
            .map_err(|_| WorkspaceCapabilityError::InvalidRequest)?;
        Ok(TrustedToolReceipt {
            broker_nonce: self.broker_nonce,
            observation: receipt,
        })
    }

    fn backend_failure<T>(&mut self, lease_id: &str) -> Result<T, WorkspaceCapabilityError> {
        if let Some(record) = self.leases.get_mut(lease_id) {
            record.state = WorkspaceLeaseState::CleanupRequired(CleanupReason::Failed);
            if cleanup_owned_root(&self.workspace_parent, &record.root) {
                record.state = WorkspaceLeaseState::Closed;
            }
        }
        Err(WorkspaceCapabilityError::BackendFailure)
    }

    fn take_registry_token(&mut self) -> Result<u64, WorkspaceCapabilityError> {
        let token = self.next_registry_token;
        self.next_registry_token = self
            .next_registry_token
            .checked_add(1)
            .ok_or(WorkspaceCapabilityError::InvalidConfiguration)?;
        Ok(token)
    }
}

impl Drop for WorkspaceCapabilityBroker {
    fn drop(&mut self) {
        for record in self.leases.values_mut() {
            if record.root.exists() {
                let reason = match record.state {
                    WorkspaceLeaseState::CleanupRequired(reason) => reason,
                    WorkspaceLeaseState::Active => CleanupReason::Panicked,
                    WorkspaceLeaseState::Closed => continue,
                };
                record.state = WorkspaceLeaseState::CleanupRequired(reason);
                if cleanup_owned_root(&self.workspace_parent, &record.root) {
                    record.state = WorkspaceLeaseState::Closed;
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotPoint {
    digest: String,
    generation: u64,
}

impl From<&WorkspaceSnapshotV1> for SnapshotPoint {
    fn from(snapshot: &WorkspaceSnapshotV1) -> Self {
        Self {
            digest: snapshot.snapshot_digest.clone(),
            generation: snapshot.generation,
        }
    }
}

fn validate_receiptable_request(request: &ToolRequestV1) -> Result<(), WorkspaceCapabilityError> {
    if request.contract_version != TOOL_BOUNDARY_CONTRACT_VERSION || request.attempt == 0 {
        return Err(WorkspaceCapabilityError::InvalidRequest);
    }
    let stable_ids = [
        (&request.request_id, "request_id"),
        (&request.idempotency_key, "idempotency_key"),
        (&request.invocation_id, "invocation_id"),
        (&request.grant_id, "grant_id"),
        (&request.lease_id, "lease_id"),
        (&request.workspace_id, "workspace_id"),
    ];
    for (value, field) in stable_ids {
        ovca_types::foundation::validate_stable_id(value, field)
            .map_err(|_| WorkspaceCapabilityError::InvalidRequest)?;
    }
    let digests = [
        (&request.invocation_digest, "invocation_digest"),
        (&request.grant_digest, "grant_digest"),
        (&request.lease_digest, "lease_digest"),
        (
            &request.expected_snapshot_digest,
            "expected_snapshot_digest",
        ),
    ];
    for (value, field) in digests {
        ovca_types::foundation::validate_sha256_digest(value, field)
            .map_err(|_| WorkspaceCapabilityError::InvalidRequest)?;
    }
    request
        .requester
        .validate()
        .and_then(|_| request.scope.validate())
        .map_err(|_| WorkspaceCapabilityError::InvalidRequest)?;
    match &request.operation {
        ToolOperationV1::ReadFile { .. } => {}
        ToolOperationV1::WriteFile { content_sha256, .. } => {
            ovca_types::foundation::validate_sha256_digest(
                content_sha256,
                "operation.content_sha256",
            )
            .map_err(|_| WorkspaceCapabilityError::InvalidRequest)?;
        }
        ToolOperationV1::Unsupported { intent_digest, .. } => {
            ovca_types::foundation::validate_sha256_digest(
                intent_digest,
                "operation.intent_digest",
            )
            .map_err(|_| WorkspaceCapabilityError::InvalidRequest)?;
        }
    }
    Ok(())
}

fn validate_registry_lease(record: &LeaseRecord) -> Result<(), WorkspaceCapabilityError> {
    record
        .dto
        .validate()
        .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
    let bytes = record
        .dto
        .canonical_json_bytes()
        .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
    if bytes != record.canonical_bytes
        || verification_sha256_hex(&bytes) != record.digest
        || record.invocation.invocation_id != record.dto.invocation_id
        || record
            .invocation
            .canonical_digest()
            .map_err(|_| WorkspaceCapabilityError::InvalidInvocation)?
            != record.dto.invocation_digest
        || record
            .invocation
            .canonical_json_bytes()
            .map_err(|_| WorkspaceCapabilityError::InvalidInvocation)?
            != record.invocation_bytes
        || record.dto.attempt == 0
        || record.dto.attempt > record.invocation.budget.max_attempts
        || record.dto.scope != record.invocation.scope
        || record.snapshot.workspace_id != record.dto.workspace_id
        || record.snapshot.lease_id != record.dto.lease_id
    {
        return Err(WorkspaceCapabilityError::InvalidLease);
    }
    record
        .snapshot
        .validate()
        .map_err(|_| WorkspaceCapabilityError::InvalidLease)
}

fn validate_registry_grant(record: &GrantRecord) -> Result<(), WorkspaceCapabilityError> {
    record
        .dto
        .validate()
        .map_err(|_| WorkspaceCapabilityError::InvalidGrant)?;
    let bytes = record
        .dto
        .canonical_json_bytes()
        .map_err(|_| WorkspaceCapabilityError::InvalidGrant)?;
    if bytes != record.canonical_bytes || verification_sha256_hex(&bytes) != record.digest {
        return Err(WorkspaceCapabilityError::InvalidGrant);
    }
    Ok(())
}

fn validate_grant_binding(
    execution: &RoleExecutionRequest,
    lease: &LeaseRecord,
    grant: &CapabilityGrantV1,
) -> Result<(), WorkspaceCapabilityError> {
    let invocation = &execution.invocation;
    let invocation_digest = invocation
        .canonical_digest()
        .map_err(|_| WorkspaceCapabilityError::InvalidInvocation)?;
    let invocation_authority_digest = canonical_authority_digest(&invocation.authority)
        .map_err(|_| WorkspaceCapabilityError::InvalidInvocation)?;
    let expected_reads = expected_read_permission_keys(&grant.read_paths)
        .map_err(|_| WorkspaceCapabilityError::InvalidGrant)?;
    let expected_writes = expected_write_permission_keys(&grant.write_paths)
        .map_err(|_| WorkspaceCapabilityError::InvalidGrant)?;

    if lease.invocation_bytes
        != invocation
            .canonical_json_bytes()
            .map_err(|_| WorkspaceCapabilityError::InvalidInvocation)?
        || lease.invocation != *invocation
        || grant.invocation_id != invocation.invocation_id
        || grant.invocation_digest != invocation_digest
        || grant.attempt != execution.attempt
        || execution.attempt != lease.dto.attempt
        || grant.issuer != invocation.invoker
        || grant.issuer.role != PrincipalV1::Coordinator
        || grant.grantee != invocation.target
        || grant.scope != invocation.scope
        || grant.lease_id != lease.dto.lease_id
        || grant.lease_digest != lease.digest
        || grant.workspace_id != lease.dto.workspace_id
        || grant.snapshot_digest != lease.snapshot.snapshot_digest
        || grant.grant_authority.authority_id == invocation.authority.authority_id
        || grant.grant_authority_digest == invocation.authority_digest
        || grant.grant_authority_digest == invocation_authority_digest
        || grant.grant_authority.principal != invocation.invoker
        || grant.grant_authority.namespace != FoundationNamespaceV1::CodeReview
        || grant.grant_authority.scope != invocation.authority.scope
        || grant.grant_authority.scope != invocation.scope
        || grant.grant_authority.visibility != invocation.authority.visibility
        || grant.grant_authority.sensitivity != invocation.authority.sensitivity
        || grant.grant_authority.validity.status != FoundationValidityStatusV1::Active
        || grant.grant_authority.permission_profile.resource_keys != expected_reads
        || grant.grant_authority.permission_profile.write_keys != expected_writes
        || !window_contains_authority(&invocation.authority, grant.valid_from, grant.valid_until)
        || !window_contains_authority(&grant.grant_authority, grant.valid_from, grant.valid_until)
        || grant.valid_from < lease.dto.issued_at
        || grant.valid_until > lease.dto.expires_at
    {
        return Err(WorkspaceCapabilityError::InvalidGrant);
    }
    Ok(())
}

fn window_contains_authority(
    authority: &FoundationAuthorityV1,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
) -> bool {
    authority.validity.status == FoundationValidityStatusV1::Active
        && valid_from >= authority.validity.valid_from
        && authority
            .validity
            .valid_until
            .is_none_or(|until| valid_until <= until)
}

fn authority_active_at(authority: &FoundationAuthorityV1, at: DateTime<Utc>) -> bool {
    authority.validity.status == FoundationValidityStatusV1::Active
        && at >= authority.validity.valid_from
        && authority
            .validity
            .valid_until
            .is_none_or(|until| at < until)
}

fn materialize_seeds(
    root: &Path,
    seeds: impl IntoIterator<Item = WorkspaceSeedFile>,
) -> Result<(), WorkspaceCapabilityError> {
    let mut seeds: Vec<_> = seeds.into_iter().collect();
    seeds.sort_by(|left, right| {
        left.logical_path
            .as_bytes()
            .cmp(right.logical_path.as_bytes())
    });
    let mut previous: Option<&str> = None;
    let mut folded = BTreeSet::new();
    for seed in &seeds {
        validate_logical_path(&seed.logical_path)
            .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
        if previous.is_some_and(|path| path == seed.logical_path)
            || !folded.insert(seed.logical_path.to_ascii_lowercase())
        {
            return Err(WorkspaceCapabilityError::InvalidWorkspace);
        }
        previous = Some(&seed.logical_path);
        let target = root.join(logical_path_to_path(&seed.logical_path));
        let parent = target
            .parent()
            .ok_or(WorkspaceCapabilityError::InvalidWorkspace)?;
        fs::create_dir_all(parent).map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
        fs::write(&target, &seed.bytes).map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
        let metadata = fs::symlink_metadata(&target)
            .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
        if !is_ordinary_file(&target, &metadata) {
            return Err(WorkspaceCapabilityError::InvalidWorkspace);
        }
    }
    Ok(())
}

fn capture_snapshot(
    root: &Path,
    workspace_id: &str,
    lease_id: &str,
    generation: u64,
) -> Result<WorkspaceSnapshotV1, WorkspaceCapabilityError> {
    let canonical_root = canonical_ordinary_directory(root)?;
    if canonical_root != root {
        return Err(WorkspaceCapabilityError::InvalidWorkspace);
    }
    let mut files = Vec::new();
    collect_workspace_files(root, root, &mut files)?;
    files.sort_by(|left, right| {
        left.logical_path
            .as_bytes()
            .cmp(right.logical_path.as_bytes())
    });
    WorkspaceSnapshotV1::try_new(
        workspace_id.to_owned(),
        lease_id.to_owned(),
        generation,
        files,
    )
    .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)
}

fn collect_workspace_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<WorkspaceFileV1>,
) -> Result<(), WorkspaceCapabilityError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?
        .collect::<Result<Vec<_>, io::Error>>()
        .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
        let logical_path = relative_path_to_logical(relative)?;
        validate_logical_path(&logical_path)
            .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
        if is_reparse_or_symlink(&metadata) {
            return Err(WorkspaceCapabilityError::InvalidWorkspace);
        }
        if metadata.is_dir() {
            collect_workspace_files(root, &path, files)?;
        } else if is_ordinary_file(&path, &metadata) {
            let bytes = fs::read(&path).map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
            files.push(WorkspaceFileV1 {
                logical_path,
                sha256: verification_sha256_hex(&bytes),
                byte_length: usize_to_u64(bytes.len())?,
            });
        } else {
            return Err(WorkspaceCapabilityError::InvalidWorkspace);
        }
    }
    Ok(())
}

fn verify_ordinary_tree(root: &Path, logical_path: Option<&str>) -> Result<(), ToolDeniedCodeV1> {
    let canonical =
        canonical_ordinary_directory(root).map_err(|_| ToolDeniedCodeV1::WorkspaceInvalid)?;
    if canonical != root {
        return Err(ToolDeniedCodeV1::WorkspaceInvalid);
    }
    let Some(logical_path) = logical_path else {
        return Ok(());
    };
    if let Some(code) = classify_logical_path(logical_path) {
        return Err(code);
    }
    let segments: Vec<&str> = logical_path.split('/').collect();
    let mut current = root.to_path_buf();
    for (index, segment) in segments.iter().enumerate() {
        current.push(segment);
        let is_final = index + 1 == segments.len();
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if is_reparse_or_symlink(&metadata)
                    || (!is_final && !metadata.is_dir())
                    || (is_final && !is_ordinary_file(&current, &metadata))
                {
                    return Err(ToolDeniedCodeV1::WorkspaceInvalid);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && is_final => return Ok(()),
            Err(_) => return Err(ToolDeniedCodeV1::WorkspaceInvalid),
        }
    }
    Ok(())
}

fn canonical_ordinary_directory(path: &Path) -> Result<PathBuf, WorkspaceCapabilityError> {
    if !path.is_absolute() {
        return Err(WorkspaceCapabilityError::InvalidConfiguration);
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| WorkspaceCapabilityError::InvalidConfiguration)?;
    if !metadata.is_dir() || is_reparse_or_symlink(&metadata) {
        return Err(WorkspaceCapabilityError::InvalidConfiguration);
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| WorkspaceCapabilityError::InvalidConfiguration)?;
    let canonical_metadata = fs::symlink_metadata(&canonical)
        .map_err(|_| WorkspaceCapabilityError::InvalidConfiguration)?;
    if !canonical_metadata.is_dir() || is_reparse_or_symlink(&canonical_metadata) {
        return Err(WorkspaceCapabilityError::InvalidConfiguration);
    }
    Ok(canonical)
}

fn is_reparse_or_symlink(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn is_ordinary_file(path: &Path, metadata: &fs::Metadata) -> bool {
    if !metadata.is_file() || is_reparse_or_symlink(metadata) {
        return false;
    }
    #[cfg(windows)]
    {
        windows_file_information::number_of_links(path).is_some_and(|links| links == 1)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink() == 1
    }
    #[cfg(not(any(windows, unix)))]
    {
        true
    }
}

#[cfg(windows)]
mod windows_file_information {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const INVALID_HANDLE_VALUE: *mut c_void = -1_isize as *mut c_void;

    #[repr(C)]
    struct FileTime {
        low_date_time: u32,
        high_date_time: u32,
    }

    #[repr(C)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        #[link_name = "CreateFileW"]
        fn create_file_w(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: *mut c_void,
        ) -> *mut c_void;

        #[link_name = "GetFileInformationByHandle"]
        fn get_file_information_by_handle(
            file: *mut c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;

        #[link_name = "CloseHandle"]
        fn close_handle(object: *mut c_void) -> i32;
    }

    pub(super) fn number_of_links(path: &Path) -> Option<u32> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: `wide` is NUL-terminated and lives for the call. The remaining
        // pointer arguments are null as permitted by CreateFileW, and the handle
        // is closed exactly once below.
        let handle = unsafe {
            create_file_w(
                wide.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut information = ByHandleFileInformation {
            file_attributes: 0,
            creation_time: FileTime {
                low_date_time: 0,
                high_date_time: 0,
            },
            last_access_time: FileTime {
                low_date_time: 0,
                high_date_time: 0,
            },
            last_write_time: FileTime {
                low_date_time: 0,
                high_date_time: 0,
            },
            volume_serial_number: 0,
            file_size_high: 0,
            file_size_low: 0,
            number_of_links: 0,
            file_index_high: 0,
            file_index_low: 0,
        };
        // SAFETY: `handle` is a live CreateFileW handle and `information` points
        // to writable storage with the Win32 BY_HANDLE_FILE_INFORMATION layout.
        let succeeded = unsafe { get_file_information_by_handle(handle, &mut information) } != 0;
        // SAFETY: `handle` is live and this is its single close operation.
        let _ = unsafe { close_handle(handle) };
        succeeded.then_some(information.number_of_links)
    }
}

fn classify_logical_path(path: &str) -> Option<ToolDeniedCodeV1> {
    match validate_logical_path(path) {
        Ok(()) => None,
        Err(ToolBoundaryValidationError::AliasForbidden)
        | Err(ToolBoundaryValidationError::CaseAlias) => Some(ToolDeniedCodeV1::AliasForbidden),
        Err(_) => Some(ToolDeniedCodeV1::PathForbidden),
    }
}

fn path_is_exactly_granted(path: &str, granted: &[String]) -> bool {
    granted
        .binary_search_by(|candidate| candidate.as_bytes().cmp(path.as_bytes()))
        .is_ok()
}

fn path_denial(path: &str, granted: &[String]) -> ToolDeniedCodeV1 {
    if granted
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(path))
    {
        ToolDeniedCodeV1::AliasForbidden
    } else {
        ToolDeniedCodeV1::PathForbidden
    }
}

fn logical_path_to_path(logical_path: &str) -> PathBuf {
    logical_path.split('/').collect()
}

fn relative_path_to_logical(path: &Path) -> Result<String, WorkspaceCapabilityError> {
    let mut segments = Vec::new();
    for component in path.components() {
        let Component::Normal(value) = component else {
            return Err(WorkspaceCapabilityError::InvalidWorkspace);
        };
        segments.push(
            value
                .to_str()
                .ok_or(WorkspaceCapabilityError::InvalidWorkspace)?,
        );
    }
    Ok(segments.join("/"))
}

fn exactly_one_manifest_entry_changed(
    before: &WorkspaceSnapshotV1,
    after: &WorkspaceSnapshotV1,
    expected_path: &str,
) -> bool {
    if before.generation.checked_add(1) != Some(after.generation)
        || before.workspace_id != after.workspace_id
        || before.lease_id != after.lease_id
    {
        return false;
    }
    let before_map: BTreeMap<_, _> = before
        .files
        .iter()
        .map(|file| (&file.logical_path, (&file.sha256, file.byte_length)))
        .collect();
    let after_map: BTreeMap<_, _> = after
        .files
        .iter()
        .map(|file| (&file.logical_path, (&file.sha256, file.byte_length)))
        .collect();
    let paths: BTreeSet<_> = before_map.keys().chain(after_map.keys()).copied().collect();
    let changed: Vec<_> = paths
        .into_iter()
        .filter(|path| before_map.get(path) != after_map.get(path))
        .collect();
    changed.len() == 1 && changed[0].as_str() == expected_path
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    let left = normalized_components(left);
    let right = normalized_components(right);
    components_start_with(&left, &right) || components_start_with(&right, &left)
}

fn normalized_components(path: &Path) -> Vec<String> {
    path.components()
        .map(|component| {
            let value = component.as_os_str().to_string_lossy().into_owned();
            if cfg!(windows) {
                value.to_ascii_lowercase()
            } else {
                value
            }
        })
        .collect()
}

fn components_start_with(value: &[String], prefix: &[String]) -> bool {
    value.len() >= prefix.len() && value.iter().zip(prefix).all(|(left, right)| left == right)
}

fn cleanup_owned_root(parent: &Path, root: &Path) -> bool {
    if !root.is_absolute() || root.parent() != Some(parent) || root == parent {
        return false;
    }
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    let removed = if is_reparse_or_symlink(&metadata) {
        if metadata.is_dir() {
            fs::remove_dir(root)
        } else {
            fs::remove_file(root)
        }
    } else if metadata.is_dir() {
        fs::remove_dir_all(root)
    } else {
        fs::remove_file(root)
    };
    removed.is_ok() && !root.exists()
}

fn usize_to_u64(value: usize) -> Result<u64, WorkspaceCapabilityError> {
    u64::try_from(value).map_err(|_| WorkspaceCapabilityError::BackendFailure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ovca_types::control_plane::{
        canonical_authority_digest as invocation_authority_digest, ExecutionBudget,
    };
    use ovca_types::foundation::{
        FoundationPermissionProfileV1, FoundationScopeV1, FoundationSensitivityV1,
        FoundationValidityV1, FoundationVisibilityV1, PrincipalIdentityV1,
    };
    use ovca_types::tool_boundary::{
        expected_read_permission_keys, expected_write_permission_keys, CapabilityPolicyV1,
    };
    use ovca_types::{IdempotencyKey, RiskTier, RunId, TaskId};
    use tempfile::TempDir;

    fn time(minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 17, 10, minute, 0)
            .single()
            .unwrap()
    }

    #[derive(Debug)]
    struct FixedClock(DateTime<Utc>);

    impl BrokerClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    fn identity(id: &str, role: PrincipalV1) -> PrincipalIdentityV1 {
        PrincipalIdentityV1 {
            principal_id: id.into(),
            role,
        }
    }

    fn test_scope() -> FoundationScopeV1 {
        FoundationScopeV1 {
            project_id: "project.unit".into(),
            goal_id: Some("goal.unit".into()),
            task_id: Some("task.unit".into()),
            run_id: Some("run.unit".into()),
        }
    }

    fn execution() -> RoleExecutionRequest {
        let scope = test_scope();
        let coordinator = identity("principal.unit.coordinator", PrincipalV1::Coordinator);
        let authority = FoundationAuthorityV1 {
            contract_version: 1,
            authority_id: "authority.unit.invocation".into(),
            principal: coordinator.clone(),
            scope: scope.clone(),
            namespace: FoundationNamespaceV1::CodeReview,
            permission_profile: FoundationPermissionProfileV1 {
                contract_version: 1,
                risk_tier: RiskTier::R1,
                resource_keys: vec!["resource.unit".into()],
                write_keys: vec![],
                approval_required: true,
                review_required: true,
                audit_required: true,
            },
            visibility: FoundationVisibilityV1::Private,
            sensitivity: FoundationSensitivityV1::Internal,
            validity: FoundationValidityV1 {
                status: FoundationValidityStatusV1::Active,
                valid_from: time(0),
                valid_until: Some(time(59)),
            },
        };
        RoleExecutionRequest {
            invocation: RoleInvocationV1 {
                contract_version: 1,
                invocation_id: "invocation.unit".into(),
                invoker: coordinator,
                target: identity("principal.unit.engineer", PrincipalV1::Engineer),
                task_id: TaskId::from("task.unit"),
                run_id: RunId::from("run.unit"),
                scope,
                budget: ExecutionBudget {
                    contract_version: 1,
                    max_attempts: 1,
                },
                idempotency_key: IdempotencyKey::from("invocation-key.unit"),
                authority_digest: invocation_authority_digest(&authority).unwrap(),
                authority,
                input_digest: "1".repeat(64),
                invoked_at: time(1),
            },
            attempt: 1,
        }
    }

    fn grant(execution: &RoleExecutionRequest, lease: &TrustedWorkspaceLease) -> CapabilityGrantV1 {
        let read_paths = vec!["src/lib.rs".to_owned()];
        let write_paths = read_paths.clone();
        let authority = FoundationAuthorityV1 {
            contract_version: 1,
            authority_id: "authority.unit.grant".into(),
            principal: execution.invocation.invoker.clone(),
            scope: execution.invocation.scope.clone(),
            namespace: FoundationNamespaceV1::CodeReview,
            permission_profile: FoundationPermissionProfileV1 {
                contract_version: 1,
                risk_tier: RiskTier::R2,
                resource_keys: expected_read_permission_keys(&read_paths).unwrap(),
                write_keys: expected_write_permission_keys(&write_paths).unwrap(),
                approval_required: true,
                review_required: true,
                audit_required: true,
            },
            visibility: execution.invocation.authority.visibility,
            sensitivity: execution.invocation.authority.sensitivity,
            validity: FoundationValidityV1 {
                status: FoundationValidityStatusV1::Active,
                valid_from: time(0),
                valid_until: Some(time(55)),
            },
        };
        CapabilityGrantV1 {
            contract_version: 1,
            grant_id: "grant.unit".into(),
            invocation_id: execution.invocation.invocation_id.clone(),
            invocation_digest: execution.invocation.canonical_digest().unwrap(),
            attempt: 1,
            issuer: execution.invocation.invoker.clone(),
            grantee: execution.invocation.target.clone(),
            scope: execution.invocation.scope.clone(),
            grant_authority_digest: canonical_authority_digest(&authority).unwrap(),
            grant_authority: authority,
            lease_id: lease.observation.lease_id.clone(),
            lease_digest: lease.digest.clone(),
            workspace_id: lease.observation.workspace_id.clone(),
            snapshot_digest: lease.initial_snapshot.snapshot_digest.clone(),
            read_paths,
            write_paths,
            max_read_bytes: 1024,
            max_write_bytes: 1024,
            command_policy: CapabilityPolicyV1::Denied,
            environment_policy: CapabilityPolicyV1::Denied,
            network_policy: CapabilityPolicyV1::Denied,
            valid_from: time(5),
            valid_until: time(40),
        }
    }

    fn setup() -> (
        TempDir,
        TempDir,
        WorkspaceCapabilityBroker,
        RoleExecutionRequest,
        TrustedWorkspaceLease,
        TrustedCapabilityGrant,
    ) {
        let parent = tempfile::tempdir().unwrap();
        let protected = tempfile::tempdir().unwrap();
        let mut broker = WorkspaceCapabilityBroker::try_new(
            "runtime.unit",
            parent.path().to_path_buf(),
            vec![protected.path().to_path_buf()],
            Box::new(FixedClock(time(10))),
        )
        .unwrap();
        let execution = execution();
        let lease = broker
            .open_lease(
                &execution,
                "lease.unit",
                "workspace.unit",
                [WorkspaceSeedFile::try_new("src/lib.rs", b"hello".to_vec()).unwrap()],
                time(2),
                time(50),
            )
            .unwrap();
        let grant = broker
            .issue_grant(&execution, &lease, grant(&execution, &lease))
            .unwrap();
        (parent, protected, broker, execution, lease, grant)
    }

    fn request(
        execution: &RoleExecutionRequest,
        lease: &TrustedWorkspaceLease,
        grant: &TrustedCapabilityGrant,
        suffix: &str,
    ) -> ToolRequestV1 {
        ToolRequestV1 {
            contract_version: 1,
            request_id: format!("request.{suffix}"),
            idempotency_key: format!("idempotency.{suffix}"),
            invocation_id: execution.invocation.invocation_id.clone(),
            invocation_digest: execution.invocation.canonical_digest().unwrap(),
            attempt: execution.attempt,
            grant_id: grant.observation.grant_id.clone(),
            grant_digest: grant.digest.clone(),
            lease_id: lease.observation.lease_id.clone(),
            lease_digest: lease.digest.clone(),
            workspace_id: lease.observation.workspace_id.clone(),
            expected_snapshot_digest: grant.observation.snapshot_digest.clone(),
            requester: execution.invocation.target.clone(),
            scope: execution.invocation.scope.clone(),
            operation: ToolOperationV1::ReadFile {
                logical_path: "src/lib.rs".into(),
            },
            requested_at: time(9),
        }
    }

    fn denied_code(result: ToolExecutionResult) -> ToolDeniedCodeV1 {
        match result.receipt.observation.outcome {
            ToolReceiptOutcomeV1::Denied { code } => code,
            outcome => panic!("expected denial, got {outcome:?}"),
        }
    }

    #[test]
    fn altered_private_registry_bytes_and_digest_fail_closed() {
        let (_parent, _protected, mut broker, execution, lease, grant) = setup();
        broker
            .grants
            .get_mut(&grant.observation.grant_id)
            .unwrap()
            .canonical_bytes
            .push(b' ');
        let result = broker
            .execute(request(&execution, &lease, &grant, "grant-bytes"), None)
            .unwrap();
        assert_eq!(denied_code(result), ToolDeniedCodeV1::InvalidBinding);
        assert_eq!(broker.backend_calls, 0);

        let (_parent, _protected, mut broker, execution, lease, grant) = setup();
        broker
            .leases
            .get_mut(&lease.observation.lease_id)
            .unwrap()
            .digest = "9".repeat(64);
        let result = broker
            .execute(request(&execution, &lease, &grant, "lease-digest"), None)
            .unwrap();
        assert_eq!(denied_code(result), ToolDeniedCodeV1::InvalidBinding);
        assert_eq!(broker.backend_calls, 0);
    }

    #[test]
    fn hardlink_and_special_final_targets_deny_before_backend() {
        let (_parent, _protected, mut broker, execution, lease, grant) = setup();
        let root = broker
            .leases
            .get(&lease.observation.lease_id)
            .unwrap()
            .root
            .clone();
        fs::hard_link(root.join("src/lib.rs"), root.join("alias.rs")).unwrap();
        let result = broker
            .execute(request(&execution, &lease, &grant, "hardlink"), None)
            .unwrap();
        assert_eq!(denied_code(result), ToolDeniedCodeV1::WorkspaceInvalid);
        assert_eq!(broker.backend_calls, 0);

        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("src")).unwrap();
        fs::create_dir(root.path().join("src/lib.rs")).unwrap();
        assert_eq!(
            verify_ordinary_tree(root.path(), Some("src/lib.rs")),
            Err(ToolDeniedCodeV1::WorkspaceInvalid)
        );
    }

    #[test]
    fn protected_overlap_is_rejected_and_failed_backend_cleanup_closes() {
        let parent = tempfile::tempdir().unwrap();
        let mut broker = WorkspaceCapabilityBroker::try_new(
            "runtime.overlap",
            parent.path().to_path_buf(),
            vec![parent.path().to_path_buf()],
            Box::new(FixedClock(time(10))),
        )
        .unwrap();
        let execution = execution();
        assert_eq!(
            broker.open_lease(
                &execution,
                "lease.overlap",
                "workspace.overlap",
                [WorkspaceSeedFile::try_new("src/lib.rs", b"hello".to_vec()).unwrap()],
                time(2),
                time(50),
            ),
            Err(WorkspaceCapabilityError::InvalidWorkspace)
        );
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);

        let (_parent, _protected, mut broker, _execution, lease, _grant) = setup();
        assert_eq!(
            broker.backend_failure::<()>(&lease.observation.lease_id),
            Err(WorkspaceCapabilityError::BackendFailure)
        );
        assert_eq!(
            broker.lease_state(&lease.observation.lease_id).unwrap(),
            WorkspaceLeaseState::Closed
        );
        assert_eq!(broker.active_root_count(), 0);
    }

    #[test]
    fn root_ancestor_and_final_symlink_reparse_are_rejected_when_available() {
        let external = tempfile::tempdir().unwrap();
        fs::write(external.path().join("outside.txt"), b"outside").unwrap();

        let parent = tempfile::tempdir().unwrap();
        let root_link = parent.path().join("root-link");
        if create_dir_symlink(external.path(), &root_link).is_ok() {
            assert!(canonical_ordinary_directory(&root_link).is_err());
        }

        let root = tempfile::tempdir().unwrap();
        let ancestor = root.path().join("src");
        if create_dir_symlink(external.path(), &ancestor).is_ok() {
            assert_eq!(
                verify_ordinary_tree(root.path(), Some("src/outside.txt")),
                Err(ToolDeniedCodeV1::WorkspaceInvalid)
            );
            remove_symlink(&ancestor);
        }

        fs::create_dir_all(root.path().join("safe")).unwrap();
        let final_link = root.path().join("safe/link.txt");
        if create_file_symlink(external.path().join("outside.txt"), &final_link).is_ok() {
            assert_eq!(
                verify_ordinary_tree(root.path(), Some("safe/link.txt")),
                Err(ToolDeniedCodeV1::WorkspaceInvalid)
            );
            remove_symlink(&final_link);
        }
    }

    #[cfg(unix)]
    fn create_dir_symlink(target: &Path, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_dir_symlink(target: &Path, link: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }

    #[cfg(unix)]
    fn create_file_symlink(target: PathBuf, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_file_symlink(target: PathBuf, link: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }

    fn remove_symlink(path: &Path) {
        let metadata = fs::symlink_metadata(path).unwrap();
        if metadata.is_dir() {
            let _ = fs::remove_dir(path);
        } else {
            let _ = fs::remove_file(path);
        }
    }
}
