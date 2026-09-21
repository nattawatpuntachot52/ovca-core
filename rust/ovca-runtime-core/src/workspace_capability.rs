//! Process-local capability broker for disposable workspaces.
//!
//! V1 deliberately has no command runner, child process, provider, network,
//! environment injection or independent durable authority. A stable lock
//! sidecar beside the SQLite state file provides only local effect exclusion;
//! SQLite remains the sole durable ownership authority.

use crate::role_executor::RoleExecutionRequest;
use crate::sqlite_execution::DurableExecutionAuthority;
use crate::PreparedWriteEffectV1;
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
use ovca_types::RunId;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{Duration, Instant};
use std::{fmt, io};

static NEXT_BROKER_NONCE: AtomicU64 = AtomicU64::new(1);
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const WORKSPACE_EFFECT_LOCK_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(crate) struct WorkspaceEffectCoordinator {
    inner: Arc<WorkspaceEffectLock>,
}

struct WorkspaceEffectLock {
    local: Mutex<()>,
    sidecar_path: PathBuf,
}

impl fmt::Debug for WorkspaceEffectCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceEffectCoordinator")
            .finish_non_exhaustive()
    }
}

pub(crate) struct WorkspaceEffectGuard<'a> {
    _sidecar: File,
    _local: MutexGuard<'a, ()>,
}

impl WorkspaceEffectCoordinator {
    pub(crate) fn enter(&self) -> io::Result<WorkspaceEffectGuard<'_>> {
        let local = self
            .inner
            .local
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let sidecar = acquire_sidecar(&self.inner.sidecar_path)?;
        Ok(WorkspaceEffectGuard {
            _sidecar: sidecar,
            _local: local,
        })
    }
}

pub(crate) fn workspace_effect_coordinator(database_path: &Path) -> WorkspaceEffectCoordinator {
    static REGISTRY: OnceLock<Mutex<BTreeMap<PathBuf, Weak<WorkspaceEffectLock>>>> =
        OnceLock::new();

    let identity = canonical_process_path(database_path);
    let sidecar_path = database_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("workspace-effects.lock");
    let registry = REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut entries = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    entries.retain(|_, lock| lock.strong_count() > 0);
    let inner = entries
        .get(&identity)
        .and_then(Weak::upgrade)
        .unwrap_or_else(|| {
            let lock = Arc::new(WorkspaceEffectLock {
                local: Mutex::new(()),
                sidecar_path,
            });
            entries.insert(identity, Arc::downgrade(&lock));
            lock
        });
    WorkspaceEffectCoordinator { inner }
}

#[cfg(windows)]
fn acquire_sidecar(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    let path = ordinary_effect_sidecar_path(path)?;
    let started = Instant::now();
    loop {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(&path)
        {
            Ok(file) => {
                validate_open_effect_sidecar(&path, &file)?;
                return Ok(file);
            }
            Err(error) if matches!(error.raw_os_error(), Some(32 | 33)) => {
                if started.elapsed() >= WORKSPACE_EFFECT_LOCK_WAIT {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "workspace effect exclusion is busy",
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn acquire_sidecar(path: &Path) -> io::Result<File> {
    use std::os::fd::AsRawFd;

    unsafe extern "C" {
        fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
    }
    const LOCK_EX: std::os::raw::c_int = 2;
    const LOCK_NB: std::os::raw::c_int = 4;

    let path = ordinary_effect_sidecar_path(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    let started = Instant::now();
    loop {
        if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } == 0 {
            validate_open_effect_sidecar(&path, &file)?;
            return Ok(file);
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted if started.elapsed() < WORKSPACE_EFFECT_LOCK_WAIT => {
                continue
            }
            io::ErrorKind::Interrupted => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "workspace effect exclusion was repeatedly interrupted",
                ));
            }
            io::ErrorKind::WouldBlock if started.elapsed() < WORKSPACE_EFFECT_LOCK_WAIT => {
                std::thread::sleep(Duration::from_millis(1));
            }
            io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "workspace effect exclusion is busy",
                ));
            }
            _ => return Err(error),
        }
    }
}

fn ordinary_effect_sidecar_path(path: &Path) -> io::Result<PathBuf> {
    if path.file_name().and_then(|name| name.to_str()) != Some("workspace-effects.lock") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unexpected workspace effect sidecar name",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "workspace effect sidecar has no parent",
        )
    })?;
    let canonical_parent = canonical_ordinary_directory(parent).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "workspace effect sidecar parent is not an ordinary directory",
        )
    })?;
    Ok(canonical_parent.join("workspace-effects.lock"))
}

fn validate_open_effect_sidecar(path: &Path, file: &File) -> io::Result<()> {
    let path_metadata = fs::symlink_metadata(path)?;
    let handle_metadata = file.metadata()?;
    if !is_ordinary_file(path, &path_metadata)
        || !handle_metadata.is_file()
        || is_reparse_or_symlink(&handle_metadata)
        || fs::canonicalize(path)? != path
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "workspace effect sidecar is not one ordinary canonical file",
        ));
    }
    Ok(())
}

#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn acquire_sidecar(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "workspace effect exclusion is unsupported on this platform",
    ))
}

fn canonical_process_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    let normalized = normalize_absolute_path(&absolute);
    let mut existing = normalized.clone();
    let mut missing = Vec::<OsString>::new();
    loop {
        if let Ok(mut canonical) = fs::canonicalize(&existing) {
            for component in missing.iter().rev() {
                canonical.push(component);
            }
            return platform_process_key(&normalize_absolute_path(&canonical));
        }
        let Some(component) = existing.file_name().map(ToOwned::to_owned) else {
            return platform_process_key(&normalized);
        };
        missing.push(component);
        if !existing.pop() {
            return platform_process_key(&normalized);
        }
    }
}

#[cfg(windows)]
fn platform_process_key(path: &Path) -> PathBuf {
    PathBuf::from(path.as_os_str().to_string_lossy().to_lowercase())
}

#[cfg(not(windows))]
fn platform_process_key(path: &Path) -> PathBuf {
    path.to_path_buf()
}

fn normalize_absolute_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
        }
    }
    normalized
}

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

    pub fn logical_path(&self) -> &str {
        &self.logical_path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
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

#[derive(Clone, Debug)]
struct DurableLeaseBinding {
    authority: DurableExecutionAuthority,
    run_id: RunId,
    pre_admission: Option<(u64, Option<String>)>,
    runtime_instance_id: String,
    runtime_epoch: u64,
    fence: u64,
    recovery_token: String,
    lease: WorkspaceLeaseV1,
    lease_digest: String,
    initial_snapshot: WorkspaceSnapshotV1,
    grant: Option<(CapabilityGrantV1, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurableLeaseOwnership {
    PreAdmission,
    Unadopted,
    Current,
}

impl DurableLeaseBinding {
    #[allow(clippy::too_many_arguments)]
    fn pending(
        authority: DurableExecutionAuthority,
        run_id: RunId,
        expected_revision: u64,
        expected_state_digest: Option<String>,
        runtime_instance_id: String,
        recovery_token: String,
        lease: WorkspaceLeaseV1,
        lease_digest: String,
        initial_snapshot: WorkspaceSnapshotV1,
    ) -> Self {
        Self {
            authority,
            run_id,
            pre_admission: Some((expected_revision, expected_state_digest)),
            runtime_instance_id,
            runtime_epoch: 1,
            fence: 1,
            recovery_token,
            lease,
            lease_digest,
            initial_snapshot,
            grant: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn recovered(
        authority: DurableExecutionAuthority,
        run_id: RunId,
        runtime_instance_id: String,
        runtime_epoch: u64,
        fence: u64,
        recovery_token: String,
        lease: WorkspaceLeaseV1,
        lease_digest: String,
        initial_snapshot: WorkspaceSnapshotV1,
        grant: CapabilityGrantV1,
        grant_digest: String,
    ) -> Self {
        Self {
            authority,
            run_id,
            pre_admission: None,
            runtime_instance_id,
            runtime_epoch,
            fence,
            recovery_token,
            lease,
            lease_digest,
            initial_snapshot,
            grant: Some((grant, grant_digest)),
        }
    }

    fn enter(&self) -> Result<WorkspaceEffectGuard<'_>, WorkspaceCapabilityError> {
        self.authority
            .enter_workspace_effect()
            .map_err(|_| WorkspaceCapabilityError::BackendFailure)
    }

    fn set_grant(&mut self, grant: CapabilityGrantV1, grant_digest: String) {
        self.grant = Some((grant, grant_digest));
    }

    fn ownership(&self) -> Result<DurableLeaseOwnership, WorkspaceCapabilityError> {
        let loaded = self
            .authority
            .load(&self.run_id)
            .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
        if let Some((revision, expected_digest)) = &self.pre_admission {
            let observed_digest = loaded
                .envelope
                .engineer_verifier
                .as_ref()
                .map(|state| state.state_digest.as_str());
            if loaded.revision == *revision && observed_digest == expected_digest.as_deref() {
                return Ok(DurableLeaseOwnership::PreAdmission);
            }
        }
        let state = loaded.envelope.engineer_verifier.as_ref();
        let workspace = state.and_then(|state| state.workspace.as_ref());
        if let Some(workspace) = workspace {
            if let Some((grant, grant_digest)) = &self.grant {
                if !workspace.closed
                    && workspace.runtime_instance_id == self.runtime_instance_id
                    && workspace.runtime_epoch == self.runtime_epoch
                    && workspace.fence == self.fence
                    && workspace.recovery_token == self.recovery_token
                    && workspace.lease == self.lease
                    && workspace.lease_digest == self.lease_digest
                    && workspace.initial_snapshot == self.initial_snapshot
                    && workspace.grant == *grant
                    && workspace.grant_digest == *grant_digest
                {
                    return Ok(DurableLeaseOwnership::Current);
                }
            }
            if self.pre_admission.is_some()
                && (workspace.recovery_token != self.recovery_token
                    || workspace.lease.lease_id != self.lease.lease_id
                    || workspace.lease.workspace_id != self.lease.workspace_id)
            {
                return Ok(DurableLeaseOwnership::Unadopted);
            }
        } else if self.pre_admission.is_some() {
            return Ok(DurableLeaseOwnership::Unadopted);
        }
        Err(WorkspaceCapabilityError::InvalidLease)
    }

    fn require_current(&self) -> Result<(), WorkspaceCapabilityError> {
        if self.ownership()? == DurableLeaseOwnership::Current {
            Ok(())
        } else {
            Err(WorkspaceCapabilityError::InvalidLease)
        }
    }

    fn require_owned(&self) -> Result<(), WorkspaceCapabilityError> {
        self.ownership().map(|_| ())
    }

    fn require_operable(&self) -> Result<(), WorkspaceCapabilityError> {
        match self.ownership()? {
            DurableLeaseOwnership::PreAdmission | DurableLeaseOwnership::Current => Ok(()),
            DurableLeaseOwnership::Unadopted => Err(WorkspaceCapabilityError::InvalidLease),
        }
    }

    fn require_live_capability(&self) -> Result<(), WorkspaceCapabilityError> {
        self.require_current()?;
        let loaded = self
            .authority
            .load(&self.run_id)
            .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
        let state = loaded
            .envelope
            .engineer_verifier
            .as_ref()
            .ok_or(WorkspaceCapabilityError::InvalidLease)?;
        if state.cancellation.is_some()
            || state.phase != crate::EngineerVerifierPhaseV1::Engineering
        {
            return Err(WorkspaceCapabilityError::InvalidLease);
        }
        Ok(())
    }

    fn require_request(
        &self,
        request: &ToolRequestV1,
        next_sequence: u64,
    ) -> Result<(), WorkspaceCapabilityError> {
        self.require_live_capability()?;
        let loaded = self
            .authority
            .load(&self.run_id)
            .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
        let state = loaded
            .envelope
            .engineer_verifier
            .as_ref()
            .ok_or(WorkspaceCapabilityError::InvalidLease)?;
        let workspace = state
            .workspace
            .as_ref()
            .ok_or(WorkspaceCapabilityError::InvalidLease)?;
        let template = state
            .plan
            .ordered_effects
            .get(state.ledger.entries.len())
            .ok_or(WorkspaceCapabilityError::InvalidRequest)?;
        let identity = crate::derive_tool_identity(&state.plan, &template.effect_id, state.attempt)
            .map_err(|_| WorkspaceCapabilityError::InvalidRequest)?;
        if request.attempt != state.attempt
            || request.request_id != identity.request_id
            || request.idempotency_key != identity.idempotency_key
            || request.operation != template.operation
            || request.expected_snapshot_digest != workspace.current_snapshot.snapshot_digest
            || workspace.next_receipt_sequence != next_sequence
        {
            return Err(WorkspaceCapabilityError::InvalidRequest);
        }
        match &request.operation {
            ToolOperationV1::WriteFile { .. } => {
                let prepared = state
                    .prepared_write
                    .as_ref()
                    .ok_or(WorkspaceCapabilityError::InvalidRequest)?;
                if prepared.request != *request || prepared.reserved_sequence != next_sequence {
                    return Err(WorkspaceCapabilityError::InvalidRequest);
                }
            }
            ToolOperationV1::ReadFile { .. } => {
                if state.prepared_write.is_some() {
                    return Err(WorkspaceCapabilityError::InvalidRequest);
                }
            }
            ToolOperationV1::Unsupported { .. } => {
                return Err(WorkspaceCapabilityError::InvalidRequest)
            }
        }
        Ok(())
    }

    fn require_target_check(&self) -> Result<(), WorkspaceCapabilityError> {
        match self.ownership()? {
            DurableLeaseOwnership::PreAdmission => Ok(()),
            DurableLeaseOwnership::Current => self.require_live_capability(),
            DurableLeaseOwnership::Unadopted => Err(WorkspaceCapabilityError::InvalidLease),
        }
    }

    fn require_prepared(
        &self,
        prepared: &PreparedWriteEffectV1,
    ) -> Result<(), WorkspaceCapabilityError> {
        self.require_current()?;
        let loaded = self
            .authority
            .load(&self.run_id)
            .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
        let state = loaded
            .envelope
            .engineer_verifier
            .as_ref()
            .ok_or(WorkspaceCapabilityError::InvalidLease)?;
        if state.phase != crate::EngineerVerifierPhaseV1::Engineering
            || state.prepared_write.as_ref() != Some(prepared)
        {
            return Err(WorkspaceCapabilityError::InvalidRequest);
        }
        Ok(())
    }

    fn require_verifying(
        &self,
        snapshot: &WorkspaceSnapshotV1,
    ) -> Result<(), WorkspaceCapabilityError> {
        self.require_current()?;
        let loaded = self
            .authority
            .load(&self.run_id)
            .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
        let state = loaded
            .envelope
            .engineer_verifier
            .as_ref()
            .ok_or(WorkspaceCapabilityError::InvalidLease)?;
        let workspace = state
            .workspace
            .as_ref()
            .ok_or(WorkspaceCapabilityError::InvalidLease)?;
        let phase_allows_seal = state.phase == crate::EngineerVerifierPhaseV1::Verifying
            || (state.phase == crate::EngineerVerifierPhaseV1::Engineering
                && state.ledger.entries.len() == state.plan.ordered_effects.len()
                && state.engineer_result.is_some());
        if !phase_allows_seal
            || state.cancellation.is_some()
            || workspace.current_snapshot != *snapshot
        {
            return Err(WorkspaceCapabilityError::InvalidLease);
        }
        Ok(())
    }
}

fn enter_durable_binding(
    binding: Option<&DurableLeaseBinding>,
) -> Result<Option<WorkspaceEffectGuard<'_>>, WorkspaceCapabilityError> {
    binding.map(DurableLeaseBinding::enter).transpose()
}

/// Opaque, process-local permission to re-adopt one deterministic owned
/// workspace after the durable execution authority has fenced the prior epoch.
///
/// The type is intentionally non-Serde and has no public constructor.
pub struct WorkspaceRecoveryPermit {
    runtime_instance_id: String,
    runtime_epoch: u64,
    fence: u64,
    recovery_token: String,
    execution: RoleExecutionRequest,
    lease: WorkspaceLeaseV1,
    lease_digest: String,
    initial_snapshot: WorkspaceSnapshotV1,
    current_snapshot: WorkspaceSnapshotV1,
    prepared_write: Option<PreparedWriteEffectV1>,
    grant: CapabilityGrantV1,
    grant_digest: String,
    next_receipt_sequence: u64,
    binding: DurableLeaseBinding,
    _private: PhantomData<fn() -> ()>,
}

impl fmt::Debug for WorkspaceRecoveryPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceRecoveryPermit")
            .field("runtime_epoch", &self.runtime_epoch)
            .field("fence", &self.fence)
            .finish_non_exhaustive()
    }
}

impl WorkspaceRecoveryPermit {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new(
        authority: DurableExecutionAuthority,
        run_id: RunId,
        runtime_instance_id: String,
        runtime_epoch: u64,
        fence: u64,
        recovery_token: String,
        execution: RoleExecutionRequest,
        lease: WorkspaceLeaseV1,
        lease_digest: String,
        initial_snapshot: WorkspaceSnapshotV1,
        current_snapshot: WorkspaceSnapshotV1,
        prepared_write: Option<PreparedWriteEffectV1>,
        grant: CapabilityGrantV1,
        grant_digest: String,
        next_receipt_sequence: u64,
    ) -> Result<Self, WorkspaceCapabilityError> {
        validate_stable_runtime_id(&runtime_instance_id)?;
        ovca_types::foundation::validate_stable_id(&recovery_token, "recovery_token")
            .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
        execution
            .validate()
            .map_err(|_| WorkspaceCapabilityError::InvalidInvocation)?;
        lease
            .validate()
            .and_then(|_| initial_snapshot.validate())
            .and_then(|_| current_snapshot.validate())
            .and_then(|_| grant.validate())
            .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
        if let Some(prepared) = &prepared_write {
            prepared
                .validate()
                .map_err(|_| WorkspaceCapabilityError::InvalidRequest)?;
            if prepared.expected_before_snapshot != current_snapshot
                || prepared.lease_digest != lease_digest
                || prepared.grant_digest != grant_digest
            {
                return Err(WorkspaceCapabilityError::InvalidRequest);
            }
        }
        if runtime_epoch == 0
            || fence == 0
            || next_receipt_sequence == 0
            || lease
                .canonical_digest()
                .map_err(|_| WorkspaceCapabilityError::InvalidLease)?
                != lease_digest
            || grant
                .canonical_digest()
                .map_err(|_| WorkspaceCapabilityError::InvalidGrant)?
                != grant_digest
            || execution.attempt != lease.attempt
            || execution.attempt != grant.attempt
            || execution.invocation.invocation_id != lease.invocation_id
            || execution.invocation.invocation_id != grant.invocation_id
            || initial_snapshot.snapshot_digest != lease.initial_snapshot_digest
            || current_snapshot.workspace_id != lease.workspace_id
            || current_snapshot.lease_id != lease.lease_id
            || grant.lease_digest != lease_digest
            || grant.snapshot_digest != initial_snapshot.snapshot_digest
        {
            return Err(WorkspaceCapabilityError::InvalidLease);
        }
        let binding = DurableLeaseBinding::recovered(
            authority,
            run_id,
            runtime_instance_id.clone(),
            runtime_epoch,
            fence,
            recovery_token.clone(),
            lease.clone(),
            lease_digest.clone(),
            initial_snapshot.clone(),
            grant.clone(),
            grant_digest.clone(),
        );
        Ok(Self {
            runtime_instance_id,
            runtime_epoch,
            fence,
            recovery_token,
            execution,
            lease,
            lease_digest,
            initial_snapshot,
            current_snapshot,
            prepared_write,
            grant,
            grant_digest,
            next_receipt_sequence,
            binding,
            _private: PhantomData,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparedWorkspaceState {
    ExpectedBefore,
    IntendedAfter,
    Missing,
    ThirdState,
}

/// Opaque owner of one populated verifier source copy and one distinct empty
/// verifier snapshot directory. Dropping the handle removes both directories.
pub struct TrustedSealedWorkspace {
    owned_parent: PathBuf,
    owned_root: PathBuf,
    source_root: PathBuf,
    snapshot_root: PathBuf,
    snapshot: WorkspaceSnapshotV1,
    source_copy_digest: String,
    snapshot_copy_digest: String,
}

impl fmt::Debug for TrustedSealedWorkspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedSealedWorkspace")
            .field("snapshot_digest", &self.snapshot.snapshot_digest)
            .finish_non_exhaustive()
    }
}

impl TrustedSealedWorkspace {
    pub fn source_root(&self) -> &Path {
        &self.source_root
    }

    pub fn snapshot_root(&self) -> &Path {
        &self.snapshot_root
    }

    pub fn snapshot(&self) -> &WorkspaceSnapshotV1 {
        &self.snapshot
    }

    pub fn source_copy_digest(&self) -> &str {
        &self.source_copy_digest
    }

    pub fn snapshot_copy_digest(&self) -> &str {
        &self.snapshot_copy_digest
    }

    pub fn cleanup(mut self) -> Result<(), WorkspaceCapabilityError> {
        if cleanup_owned_root(&self.owned_parent, &self.owned_root) {
            self.owned_root.clear();
            Ok(())
        } else {
            Err(WorkspaceCapabilityError::CleanupFailure)
        }
    }
}

impl Drop for TrustedSealedWorkspace {
    fn drop(&mut self) {
        if !self.owned_root.as_os_str().is_empty() {
            let _ = cleanup_owned_root(&self.owned_parent, &self.owned_root);
        }
    }
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
    initial_snapshot: WorkspaceSnapshotV1,
    recovery_token: Option<String>,
    durable_binding: Option<DurableLeaseBinding>,
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

    pub fn runtime_instance_id(&self) -> &str {
        &self.runtime_instance_id
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
            initial_snapshot: snapshot.clone(),
            recovery_token: None,
            durable_binding: None,
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

    /// Opens a deterministically named disposable workspace that may later be
    /// re-adopted only through a broker recovery permit minted by the durable
    /// runtime authority.
    #[allow(clippy::too_many_arguments)]
    pub fn open_recoverable_lease(
        &mut self,
        authority: &DurableExecutionAuthority,
        run_id: &RunId,
        expected_revision: u64,
        expected_state_digest: Option<&str>,
        execution: &RoleExecutionRequest,
        lease_id: impl Into<String>,
        workspace_id: impl Into<String>,
        recovery_token: impl Into<String>,
        seeds: impl IntoIterator<Item = WorkspaceSeedFile>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<TrustedWorkspaceLease, WorkspaceCapabilityError> {
        let _effect_guard = authority
            .enter_workspace_effect()
            .map_err(|_| WorkspaceCapabilityError::BackendFailure)?;
        let loaded = authority
            .load(run_id)
            .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
        if loaded.revision != expected_revision
            || loaded
                .envelope
                .engineer_verifier
                .as_ref()
                .map(|state| state.state_digest.as_str())
                != expected_state_digest
        {
            return Err(WorkspaceCapabilityError::InvalidLease);
        }
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
        let recovery_token = recovery_token.into();
        ovca_types::foundation::validate_stable_id(&lease_id, "lease_id")
            .and_then(|_| ovca_types::foundation::validate_stable_id(&workspace_id, "workspace_id"))
            .and_then(|_| {
                ovca_types::foundation::validate_stable_id(&recovery_token, "recovery_token")
            })
            .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
        if self.leases.contains_key(&lease_id)
            || self.leases.values().any(|record| {
                record.dto.workspace_id == workspace_id
                    || record.recovery_token.as_deref() == Some(recovery_token.as_str())
            })
        {
            return Err(WorkspaceCapabilityError::DuplicateIdentifier);
        }

        let root = self.workspace_parent.join(recovery_root_name(
            &recovery_token,
            &lease_id,
            &workspace_id,
        ));
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
        let registry_token = self.take_registry_token()?;
        let durable_binding = DurableLeaseBinding::pending(
            authority.clone(),
            run_id.clone(),
            expected_revision,
            expected_state_digest.map(str::to_owned),
            self.runtime_instance_id.clone(),
            recovery_token.clone(),
            dto.clone(),
            digest.clone(),
            snapshot.clone(),
        );
        self.leases.insert(
            lease_id,
            LeaseRecord {
                registry_token,
                dto: dto.clone(),
                canonical_bytes,
                digest: digest.clone(),
                invocation: execution.invocation.clone(),
                invocation_bytes,
                root,
                state: WorkspaceLeaseState::Active,
                snapshot: snapshot.clone(),
                initial_snapshot: snapshot.clone(),
                recovery_token: Some(recovery_token),
                durable_binding: Some(durable_binding),
            },
        );
        Ok(TrustedWorkspaceLease {
            broker_nonce: self.broker_nonce,
            registry_token,
            observation: dto,
            digest,
            initial_snapshot: snapshot,
        })
    }

    /// Re-adopts a deterministic workspace after a successful durable recovery
    /// fence. DTO observations alone cannot call this path.
    pub fn recover_lease(
        &mut self,
        permit: WorkspaceRecoveryPermit,
    ) -> Result<(TrustedWorkspaceLease, TrustedCapabilityGrant), WorkspaceCapabilityError> {
        let durable_binding = permit.binding.clone();
        let _effect_guard = durable_binding.enter()?;
        durable_binding.require_current()?;
        if permit.runtime_instance_id != self.runtime_instance_id
            || !self.leases.is_empty()
            || !self.grants.is_empty()
            || !self.idempotency.is_empty()
            || self.backend_calls != 0
            || self.next_sequence != 1
        {
            return Err(WorkspaceCapabilityError::InvalidLease);
        }
        permit
            .execution
            .validate()
            .map_err(|_| WorkspaceCapabilityError::InvalidInvocation)?;
        let root = self.workspace_parent.join(recovery_root_name(
            &permit.recovery_token,
            &permit.lease.lease_id,
            &permit.lease.workspace_id,
        ));
        let canonical_root = canonical_ordinary_directory(&root)
            .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
        if canonical_root != root
            || self
                .protected_roots
                .iter()
                .any(|protected| paths_overlap(&canonical_root, protected))
        {
            return Err(WorkspaceCapabilityError::InvalidWorkspace);
        }
        verify_ordinary_tree(&root, None)
            .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
        let observed_before = capture_snapshot(
            &root,
            &permit.lease.workspace_id,
            &permit.lease.lease_id,
            permit.current_snapshot.generation,
        )?;
        let observed = if observed_before == permit.current_snapshot {
            observed_before
        } else if let Some(prepared) = &permit.prepared_write {
            let observed_after = capture_snapshot(
                &root,
                &permit.lease.workspace_id,
                &permit.lease.lease_id,
                prepared.intended_after_snapshot.generation,
            )?;
            if observed_after != prepared.intended_after_snapshot {
                return Err(WorkspaceCapabilityError::InvalidWorkspace);
            }
            observed_after
        } else {
            return Err(WorkspaceCapabilityError::InvalidWorkspace);
        };

        let lease_token = self.take_registry_token()?;
        let lease_bytes = permit
            .lease
            .canonical_json_bytes()
            .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
        let lease_record = LeaseRecord {
            registry_token: lease_token,
            dto: permit.lease.clone(),
            canonical_bytes: lease_bytes,
            digest: permit.lease_digest.clone(),
            invocation: permit.execution.invocation.clone(),
            invocation_bytes: permit
                .execution
                .invocation
                .canonical_json_bytes()
                .map_err(|_| WorkspaceCapabilityError::InvalidInvocation)?,
            root,
            state: WorkspaceLeaseState::Active,
            snapshot: observed,
            initial_snapshot: permit.initial_snapshot.clone(),
            recovery_token: Some(permit.recovery_token.clone()),
            durable_binding: Some(durable_binding.clone()),
        };
        validate_registry_lease(&lease_record)?;
        let mut grant_binding_lease = lease_record.clone();
        grant_binding_lease.snapshot = grant_binding_lease.initial_snapshot.clone();
        validate_grant_binding(&permit.execution, &grant_binding_lease, &permit.grant)?;
        let grant_token = self.take_registry_token()?;
        let grant_bytes = permit
            .grant
            .canonical_json_bytes()
            .map_err(|_| WorkspaceCapabilityError::InvalidGrant)?;
        let grant_record = GrantRecord {
            registry_token: grant_token,
            dto: permit.grant.clone(),
            canonical_bytes: grant_bytes,
            digest: permit.grant_digest.clone(),
        };
        validate_registry_grant(&grant_record)?;
        self.next_sequence = permit.next_receipt_sequence;

        let lease = TrustedWorkspaceLease {
            broker_nonce: self.broker_nonce,
            registry_token: lease_token,
            observation: permit.lease.clone(),
            digest: permit.lease_digest,
            initial_snapshot: permit.initial_snapshot,
        };
        let grant = TrustedCapabilityGrant {
            broker_nonce: self.broker_nonce,
            registry_token: grant_token,
            observation: permit.grant.clone(),
            digest: permit.grant_digest,
        };
        self.leases
            .insert(permit.lease.lease_id.clone(), lease_record);
        self.grants.insert(permit.grant.grant_id, grant_record);
        Ok((lease, grant))
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
        let durable_binding = lease_record.durable_binding.clone();
        let _effect_guard = enter_durable_binding(durable_binding.as_ref())?;
        if let Some(binding) = &durable_binding {
            binding.require_operable()?;
        }
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
        if durable_binding.is_some() {
            self.leases
                .get_mut(&grant.lease_id)
                .and_then(|record| record.durable_binding.as_mut())
                .ok_or(WorkspaceCapabilityError::InvalidLease)?
                .set_grant(grant.clone(), digest.clone());
        }
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
        let durable_binding = self.live_lease_record(lease)?.durable_binding.clone();
        let _effect_guard = enter_durable_binding(durable_binding.as_ref())?;
        if let Some(binding) = &durable_binding {
            binding.require_current()?;
        }
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
            || lease.initial_snapshot != record.initial_snapshot
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

    pub fn next_receipt_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn active_root_count(&self) -> usize {
        self.leases
            .values()
            .filter(|record| record.root.exists())
            .count()
    }

    /// Proves absence of the deterministic owned root for a prior durable
    /// lease without exposing the host path or treating the DTO as authority.
    pub fn recoverable_root_is_absent(
        &self,
        recovery_token: &str,
        lease: &WorkspaceLeaseV1,
    ) -> Result<bool, WorkspaceCapabilityError> {
        ovca_types::foundation::validate_stable_id(recovery_token, "recovery_token")
            .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
        lease
            .validate()
            .map_err(|_| WorkspaceCapabilityError::InvalidLease)?;
        let root = self.workspace_parent.join(recovery_root_name(
            recovery_token,
            &lease.lease_id,
            &lease.workspace_id,
        ));
        if root.parent() != Some(self.workspace_parent.as_path())
            || self
                .protected_roots
                .iter()
                .any(|protected| paths_overlap(&root, protected))
        {
            return Err(WorkspaceCapabilityError::InvalidWorkspace);
        }
        Ok(!root.exists())
    }

    pub fn grant_is_live(&self, grant: &TrustedCapabilityGrant) -> bool {
        if grant.broker_nonce != self.broker_nonce {
            return false;
        }
        let Some(grant_record) = self.grants.get(&grant.observation.grant_id) else {
            return false;
        };
        let durable_binding = self
            .leases
            .get(&grant_record.dto.lease_id)
            .and_then(|record| record.durable_binding.clone());
        let Ok(_effect_guard) = enter_durable_binding(durable_binding.as_ref()) else {
            return false;
        };
        if durable_binding
            .as_ref()
            .is_some_and(|binding| binding.require_live_capability().is_err())
        {
            return false;
        }
        grant_record.registry_token == grant.registry_token
            && grant_record.dto == grant.observation
            && grant_record.digest == grant.digest
    }

    pub fn receipt_is_from_this_broker(&self, receipt: &TrustedToolReceipt) -> bool {
        receipt.broker_nonce == self.broker_nonce
            && receipt.observation.runtime_instance_id == self.runtime_instance_id
    }

    /// Checks the admitted physical target identity without invoking the native
    /// read/write backend or changing workspace generation.
    pub fn target_matches_current(
        &self,
        lease: &TrustedWorkspaceLease,
        logical_path: &str,
        content_sha256: &str,
        byte_length: u64,
    ) -> Result<bool, WorkspaceCapabilityError> {
        let durable_binding = self.live_lease_record(lease)?.durable_binding.clone();
        let _effect_guard = enter_durable_binding(durable_binding.as_ref())?;
        if let Some(binding) = &durable_binding {
            binding.require_target_check()?;
        }
        let record = self.live_lease_record(lease)?;
        validate_logical_path(logical_path)
            .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
        ovca_types::foundation::validate_sha256_digest(content_sha256, "content_sha256")
            .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
        verify_ordinary_tree(&record.root, Some(logical_path))
            .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
        let observed = capture_snapshot(
            &record.root,
            &record.dto.workspace_id,
            &record.dto.lease_id,
            record.snapshot.generation,
        )?;
        if observed != record.snapshot {
            return Err(WorkspaceCapabilityError::InvalidWorkspace);
        }
        Ok(observed.files.iter().any(|file| {
            file.logical_path == logical_path
                && file.sha256 == content_sha256
                && file.byte_length == byte_length
        }))
    }

    /// Classifies a durably prepared native write using exact physical snapshot
    /// identities and performs no broker backend call.
    pub fn inspect_prepared_write(
        &self,
        lease: &TrustedWorkspaceLease,
        prepared: &PreparedWriteEffectV1,
    ) -> Result<PreparedWorkspaceState, WorkspaceCapabilityError> {
        let durable_binding = self.live_lease_record(lease)?.durable_binding.clone();
        let _effect_guard = enter_durable_binding(durable_binding.as_ref())?;
        if let Some(binding) = &durable_binding {
            binding.require_prepared(prepared)?;
        }
        self.inspect_prepared_write_unlocked(lease, prepared)
    }

    fn inspect_prepared_write_unlocked(
        &self,
        lease: &TrustedWorkspaceLease,
        prepared: &PreparedWriteEffectV1,
    ) -> Result<PreparedWorkspaceState, WorkspaceCapabilityError> {
        prepared
            .validate()
            .map_err(|_| WorkspaceCapabilityError::InvalidRequest)?;
        let record = self.live_lease_record(lease)?;
        if prepared.expected_before_snapshot.workspace_id != record.dto.workspace_id
            || prepared.expected_before_snapshot.lease_id != record.dto.lease_id
            || prepared.intended_after_snapshot.workspace_id != record.dto.workspace_id
            || prepared.intended_after_snapshot.lease_id != record.dto.lease_id
        {
            return Err(WorkspaceCapabilityError::InvalidRequest);
        }
        if !record.root.exists() {
            return Ok(PreparedWorkspaceState::Missing);
        }
        if verify_ordinary_tree(&record.root, prepared.request.operation.logical_path()).is_err() {
            return Ok(PreparedWorkspaceState::ThirdState);
        }
        let before = capture_snapshot(
            &record.root,
            &record.dto.workspace_id,
            &record.dto.lease_id,
            prepared.expected_before_snapshot.generation,
        );
        if before.as_ref() == Ok(&prepared.expected_before_snapshot) {
            return Ok(PreparedWorkspaceState::ExpectedBefore);
        }
        let after = capture_snapshot(
            &record.root,
            &record.dto.workspace_id,
            &record.dto.lease_id,
            prepared.intended_after_snapshot.generation,
        );
        if after.as_ref() == Ok(&prepared.intended_after_snapshot) {
            return Ok(PreparedWorkspaceState::IntendedAfter);
        }
        Ok(PreparedWorkspaceState::ThirdState)
    }

    /// Accepts an exact intended-after physical state during recovery without
    /// constructing a trusted receipt or incrementing the backend counter.
    pub fn adopt_reconciled_write(
        &mut self,
        lease: &TrustedWorkspaceLease,
        prepared: &PreparedWriteEffectV1,
    ) -> Result<WorkspaceSnapshotV1, WorkspaceCapabilityError> {
        let durable_binding = self.live_lease_record(lease)?.durable_binding.clone();
        let _effect_guard = enter_durable_binding(durable_binding.as_ref())?;
        if let Some(binding) = &durable_binding {
            binding.require_prepared(prepared)?;
        }
        if self.inspect_prepared_write_unlocked(lease, prepared)?
            != PreparedWorkspaceState::IntendedAfter
        {
            return Err(WorkspaceCapabilityError::InvalidWorkspace);
        }
        let record = self
            .leases
            .get_mut(&lease.observation.lease_id)
            .ok_or(WorkspaceCapabilityError::InvalidLease)?;
        record.snapshot = prepared.intended_after_snapshot.clone();
        Ok(record.snapshot.clone())
    }

    /// Creates a populated ordinary source copy plus a distinct empty ordinary
    /// snapshot directory for the existing verifier. The private live workspace
    /// root is never exposed.
    pub fn seal_workspace(
        &self,
        lease: &TrustedWorkspaceLease,
        verifier_temp_parent: impl AsRef<Path>,
    ) -> Result<TrustedSealedWorkspace, WorkspaceCapabilityError> {
        let live_record = self.live_lease_record(lease)?;
        let durable_binding = live_record.durable_binding.clone();
        let durable_snapshot = live_record.snapshot.clone();
        let _effect_guard = enter_durable_binding(durable_binding.as_ref())?;
        if let Some(binding) = &durable_binding {
            binding.require_verifying(&durable_snapshot)?;
        }
        let record = self.live_lease_record(lease)?;
        verify_ordinary_tree(&record.root, None)
            .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
        let observed = capture_snapshot(
            &record.root,
            &record.dto.workspace_id,
            &record.dto.lease_id,
            record.snapshot.generation,
        )?;
        if observed != record.snapshot {
            return Err(WorkspaceCapabilityError::InvalidWorkspace);
        }
        let owned_parent = canonical_ordinary_directory(verifier_temp_parent.as_ref())?;
        if paths_overlap(&owned_parent, &record.root)
            || self
                .protected_roots
                .iter()
                .any(|protected| paths_overlap(&owned_parent, protected))
        {
            return Err(WorkspaceCapabilityError::InvalidConfiguration);
        }
        let owned_root = owned_parent.join(format!(
            "sealed-{}-{}",
            self.broker_nonce, lease.registry_token
        ));
        if owned_root.exists() {
            return Err(WorkspaceCapabilityError::InvalidWorkspace);
        }
        fs::create_dir(&owned_root).map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
        let setup = (|| {
            let source_root = owned_root.join("source");
            let snapshot_root = owned_root.join("snapshot");
            fs::create_dir(&source_root)
                .and_then(|_| fs::create_dir(&snapshot_root))
                .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
            let seeds = observed
                .files
                .iter()
                .map(|file| {
                    let path = record.root.join(logical_path_to_path(&file.logical_path));
                    let bytes =
                        fs::read(path).map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?;
                    if verification_sha256_hex(&bytes) != file.sha256
                        || usize_to_u64(bytes.len())? != file.byte_length
                    {
                        return Err(WorkspaceCapabilityError::InvalidWorkspace);
                    }
                    WorkspaceSeedFile::try_new(file.logical_path.clone(), bytes)
                })
                .collect::<Result<Vec<_>, _>>()?;
            materialize_seeds(&source_root, seeds)?;
            let copied = capture_snapshot(
                &source_root,
                &observed.workspace_id,
                &observed.lease_id,
                observed.generation,
            )?;
            if copied != observed
                || fs::read_dir(&snapshot_root)
                    .map_err(|_| WorkspaceCapabilityError::InvalidWorkspace)?
                    .next()
                    .is_some()
            {
                return Err(WorkspaceCapabilityError::InvalidWorkspace);
            }
            let source_copy_digest = copy_digest("ovca.verifier-source-copy.v1", &copied)?;
            let snapshot_copy_digest =
                verification_sha256_hex(b"ovca.verifier-empty-snapshot.v1\0");
            Ok((
                source_root,
                snapshot_root,
                source_copy_digest,
                snapshot_copy_digest,
            ))
        })();
        let (source_root, snapshot_root, source_copy_digest, snapshot_copy_digest) = match setup {
            Ok(value) => value,
            Err(error) => {
                cleanup_owned_root(&owned_parent, &owned_root);
                return Err(error);
            }
        };
        Ok(TrustedSealedWorkspace {
            owned_parent,
            owned_root,
            source_root,
            snapshot_root,
            snapshot: observed,
            source_copy_digest,
            snapshot_copy_digest,
        })
    }

    pub fn close_lease(
        &mut self,
        lease: &TrustedWorkspaceLease,
        reason: CleanupReason,
    ) -> Result<(), WorkspaceCapabilityError> {
        if lease.broker_nonce != self.broker_nonce {
            return Err(WorkspaceCapabilityError::ForeignHandle);
        }
        let durable_binding = self
            .leases
            .get(&lease.observation.lease_id)
            .ok_or(WorkspaceCapabilityError::InvalidLease)?
            .durable_binding
            .clone();
        let _effect_guard = enter_durable_binding(durable_binding.as_ref())?;
        if let Some(binding) = &durable_binding {
            binding.require_owned()?;
        }
        let record = self
            .leases
            .get_mut(&lease.observation.lease_id)
            .ok_or(WorkspaceCapabilityError::InvalidLease)?;
        if record.registry_token != lease.registry_token
            || record.dto != lease.observation
            || record.digest != lease.digest
            || record.initial_snapshot != lease.initial_snapshot
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
        let durable_binding = self
            .leases
            .get(&request.lease_id)
            .and_then(|record| record.durable_binding.clone());
        let _effect_guard = enter_durable_binding(durable_binding.as_ref())?;
        if let Some(binding) = &durable_binding {
            binding.require_request(&request, self.next_sequence)?;
        }
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

    fn live_lease_record(
        &self,
        lease: &TrustedWorkspaceLease,
    ) -> Result<&LeaseRecord, WorkspaceCapabilityError> {
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
            || lease.initial_snapshot != record.initial_snapshot
            || record.state != WorkspaceLeaseState::Active
        {
            return Err(WorkspaceCapabilityError::InvalidLease);
        }
        validate_registry_lease(record)?;
        Ok(record)
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
                let durable_binding = record.durable_binding.clone();
                let _effect_guard = match enter_durable_binding(durable_binding.as_ref()) {
                    Ok(guard) => guard,
                    Err(_) => continue,
                };
                if durable_binding
                    .as_ref()
                    .is_some_and(|binding| binding.require_owned().is_err())
                {
                    continue;
                }
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
        || record.initial_snapshot.snapshot_digest != record.dto.initial_snapshot_digest
        || record.initial_snapshot.workspace_id != record.dto.workspace_id
        || record.initial_snapshot.lease_id != record.dto.lease_id
        || record.initial_snapshot.generation != 0
        || record.snapshot.workspace_id != record.dto.workspace_id
        || record.snapshot.lease_id != record.dto.lease_id
        || record.snapshot.generation < record.initial_snapshot.generation
    {
        return Err(WorkspaceCapabilityError::InvalidLease);
    }
    record
        .initial_snapshot
        .validate()
        .and_then(|_| record.snapshot.validate())
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

fn validate_stable_runtime_id(value: &str) -> Result<(), WorkspaceCapabilityError> {
    ovca_types::foundation::validate_stable_id(value, "runtime_instance_id")
        .map_err(|_| WorkspaceCapabilityError::InvalidConfiguration)
}

fn recovery_root_name(recovery_token: &str, lease_id: &str, workspace_id: &str) -> String {
    let mut bytes = b"ovca.workspace-recovery-root.v1\0".to_vec();
    for value in [recovery_token, lease_id, workspace_id] {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    format!("workspace-recovery-{}", verification_sha256_hex(&bytes))
}

fn copy_digest(
    domain: &str,
    snapshot: &WorkspaceSnapshotV1,
) -> Result<String, WorkspaceCapabilityError> {
    let snapshot_bytes = snapshot
        .canonical_json_bytes()
        .map_err(|_| WorkspaceCapabilityError::Serialization)?;
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&snapshot_bytes);
    Ok(verification_sha256_hex(&bytes))
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

    #[cfg(windows)]
    #[test]
    fn missing_database_path_case_aliases_share_one_effect_coordinator() {
        let parent = tempfile::tempdir().unwrap();
        let upper = parent
            .path()
            .join("MissingRuntimeRoot")
            .join("state")
            .join("versioned-state.sqlite3");
        let lower = parent
            .path()
            .join("missingruntimeroot")
            .join("STATE")
            .join("VERSIONED-STATE.SQLITE3");
        let upper = workspace_effect_coordinator(&upper);
        let lower = workspace_effect_coordinator(&lower);
        assert!(Arc::ptr_eq(&upper.inner, &lower.inner));
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
