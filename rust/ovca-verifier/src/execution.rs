use ovca_types::{
    is_forbidden_verification_shell, verification_sha256_hex, VerificationCommand, WorkingDirectory,
};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const MAX_TIMEOUT_MILLIS: u64 = 86_400_000;
pub const MAX_STREAM_CAP_BYTES: u64 = 16_777_216;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionLimits {
    pub timeout_millis: u64,
    pub stdout_cap_bytes: u64,
    pub stderr_cap_bytes: u64,
}

impl ExecutionLimits {
    pub fn is_valid(self) -> bool {
        (1..=MAX_TIMEOUT_MILLIS).contains(&self.timeout_millis)
            && self.stdout_cap_bytes <= MAX_STREAM_CAP_BYTES
            && self.stderr_cap_bytes <= MAX_STREAM_CAP_BYTES
    }
}

#[derive(Clone)]
pub struct ExecutableProfile {
    pub executable_id: String,
    pub executable_path: PathBuf,
    pub sha256: String,
    pub enabled: bool,
    pub approved: bool,
    pub reviewed_offline: bool,
    pub allowed_environment_names: BTreeSet<String>,
}

#[derive(Clone, Default)]
pub struct ExecutableRegistry {
    pub profiles: BTreeMap<String, ExecutableProfile>,
}

#[derive(Clone, Default)]
pub struct EnvironmentBindings {
    pub values: BTreeMap<String, OsString>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePreflightFailure {
    UnknownOrDisallowedProfile,
    EnvironmentBlock,
    ExecutableUnavailable,
    ExecutableDigestMismatch,
}

#[derive(Clone)]
pub struct PreparedCommand {
    executable_path: PathBuf,
    executable_digest: String,
    environment: Vec<(String, OsString)>,
}

impl PreparedCommand {
    pub fn digest_matches(&self) -> bool {
        self.check_immediately_before_spawn().is_ok()
    }

    fn check_immediately_before_spawn(&self) -> Result<CheckedExecutable, RuntimePreflightFailure> {
        #[cfg(windows)]
        let (bytes, lease) = {
            use std::fs::OpenOptions;
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

            // Lease every ordinary ancestor before opening the final file.
            // All leases deny write/delete sharing through CreateProcess, so
            // no checked path component can be renamed or retargeted between
            // the byte digest and the command's own spawn.
            let ancestors = Win32ExecutableAncestors::acquire(&self.executable_path)?;
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            let mut file = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&self.executable_path)
                .map_err(|_| RuntimePreflightFailure::ExecutableUnavailable)?;
            let metadata = file
                .metadata()
                .map_err(|_| RuntimePreflightFailure::ExecutableUnavailable)?;
            if !metadata.is_file() || is_reparse_or_symlink(&metadata) {
                return Err(RuntimePreflightFailure::ExecutableUnavailable);
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|_| RuntimePreflightFailure::ExecutableUnavailable)?;
            (
                bytes,
                CheckedExecutable {
                    _file: file,
                    _ancestors: ancestors,
                },
            )
        };

        #[cfg(not(windows))]
        let (bytes, lease) = {
            let metadata = fs::symlink_metadata(&self.executable_path)
                .map_err(|_| RuntimePreflightFailure::ExecutableUnavailable)?;
            if !metadata.is_file() || is_reparse_or_symlink(&metadata) {
                return Err(RuntimePreflightFailure::ExecutableUnavailable);
            }
            (
                fs::read(&self.executable_path)
                    .map_err(|_| RuntimePreflightFailure::ExecutableUnavailable)?,
                CheckedExecutable,
            )
        };

        if verification_sha256_hex(&bytes) != self.executable_digest {
            return Err(RuntimePreflightFailure::ExecutableDigestMismatch);
        }
        Ok(lease)
    }
}

#[cfg(windows)]
struct CheckedExecutable {
    _file: fs::File,
    _ancestors: Win32ExecutableAncestors,
}

#[cfg(not(windows))]
struct CheckedExecutable;

#[cfg(windows)]
struct Win32ExecutableAncestors {
    handles: Vec<windows_sys::Win32::Foundation::HANDLE>,
}

#[cfg(windows)]
impl Win32ExecutableAncestors {
    fn acquire(path: &Path) -> Result<Self, RuntimePreflightFailure> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_SHARE_READ, OPEN_EXISTING,
        };

        let parent = path
            .parent()
            .ok_or(RuntimePreflightFailure::ExecutableUnavailable)?;
        let mut ancestors = parent
            .ancestors()
            .filter(|ancestor| !ancestor.as_os_str().is_empty())
            .collect::<Vec<_>>();
        ancestors.reverse();
        if ancestors.is_empty() {
            return Err(RuntimePreflightFailure::ExecutableUnavailable);
        }

        let mut lease = Self {
            handles: Vec::with_capacity(ancestors.len()),
        };
        for ancestor in ancestors {
            let mut wide = ancestor.as_os_str().encode_wide().collect::<Vec<_>>();
            if wide.contains(&0) {
                return Err(RuntimePreflightFailure::ExecutableUnavailable);
            }
            wide.push(0);
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    FILE_LIST_DIRECTORY,
                    FILE_SHARE_READ,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    std::ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(RuntimePreflightFailure::ExecutableUnavailable);
            }
            let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
            if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0
                || information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
                || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
                return Err(RuntimePreflightFailure::ExecutableUnavailable);
            }
            lease.handles.push(handle);
        }
        Ok(lease)
    }
}

#[cfg(windows)]
impl Drop for Win32ExecutableAncestors {
    fn drop(&mut self) {
        for handle in self.handles.drain(..).rev() {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionTermination {
    Completed,
    Timeout,
    OutputLimit,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEvidence {
    pub executable_digest: String,
    pub termination: ExecutionTermination,
    pub exit_code: Option<i32>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparedExecution {
    PreSpawn(RuntimePreflightFailure),
    SnapshotTamper,
    Executed(ExecutionEvidence),
}

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("failed to establish process-tree containment")]
    Containment,
    #[error("failed to spawn the reviewed executable")]
    Spawn,
    #[error("process execution I/O failed")]
    Io,
    #[error("process capture worker failed")]
    CaptureWorker,
}

impl ExecutableRegistry {
    pub fn validate_structure(&self) -> bool {
        self.profiles.iter().all(|(key, profile)| {
            key == &profile.executable_id
                && valid_executable_id(key)
                && valid_profile_path(&profile.executable_path)
                && valid_digest(&profile.sha256)
                && (!profile.enabled || profile.approved)
                && profile
                    .allowed_environment_names
                    .iter()
                    .all(|name| valid_environment_name(name))
        })
    }

    pub fn prepare(
        &self,
        command: &VerificationCommand,
        bindings: &EnvironmentBindings,
    ) -> Result<PreparedCommand, RuntimePreflightFailure> {
        let Some(profile) = self.profiles.get(&command.executable_id) else {
            return Err(RuntimePreflightFailure::UnknownOrDisallowedProfile);
        };
        if !profile.enabled || !profile.approved || !profile.reviewed_offline {
            return Err(RuntimePreflightFailure::UnknownOrDisallowedProfile);
        }
        let mut environment = Vec::new();
        for name in &command.environment_names {
            if !profile.allowed_environment_names.contains(name) {
                return Err(RuntimePreflightFailure::EnvironmentBlock);
            }
            let Some(value) = bindings.values.get(name) else {
                return Err(RuntimePreflightFailure::EnvironmentBlock);
            };
            environment.push((name.clone(), value.clone()));
        }
        let metadata = fs::symlink_metadata(&profile.executable_path)
            .map_err(|_| RuntimePreflightFailure::ExecutableUnavailable)?;
        if !metadata.is_file() || is_reparse_or_symlink(&metadata) {
            return Err(RuntimePreflightFailure::ExecutableUnavailable);
        }
        let bytes = fs::read(&profile.executable_path)
            .map_err(|_| RuntimePreflightFailure::ExecutableUnavailable)?;
        let executable_digest = verification_sha256_hex(&bytes);
        if executable_digest != profile.sha256 {
            return Err(RuntimePreflightFailure::ExecutableDigestMismatch);
        }
        Ok(PreparedCommand {
            executable_path: profile.executable_path.clone(),
            executable_digest,
            environment,
        })
    }
}

impl EnvironmentBindings {
    /// Bind declared environment values without serializing them into evidence.
    /// The binary envelope is domain separated and length prefixed so no host
    /// locale, separator, or map-order behavior affects the digest.
    pub fn digest_for(&self, names: &BTreeSet<String>) -> Option<String> {
        let mut bytes = b"ovca.environment-bindings.v1\0".to_vec();
        for name in names {
            let value = self.values.get(name)?;
            let name_bytes = name.as_bytes();
            let value_text = value.to_str()?;
            let value_bytes = value_text.as_bytes();
            bytes.extend_from_slice(&(name_bytes.len() as u64).to_be_bytes());
            bytes.extend_from_slice(name_bytes);
            bytes.extend_from_slice(&(value_bytes.len() as u64).to_be_bytes());
            bytes.extend_from_slice(value_bytes);
        }
        Some(verification_sha256_hex(&bytes))
    }
}

pub fn execute_prepared(
    prepared: &PreparedCommand,
    command: &VerificationCommand,
    snapshot_root: &Path,
    limits: ExecutionLimits,
) -> Result<PreparedExecution, ExecutionError> {
    let cwd_lease = match CheckedWorkingDirectory::acquire(snapshot_root, &command.cwd) {
        Some(value) => value,
        None => return Ok(PreparedExecution::SnapshotTamper),
    };
    let cwd = cwd_lease.path().to_path_buf();

    // This is the command's own byte check, not the earlier all-plan
    // preflight. On Windows the returned lease denies write/delete sharing
    // until CreateProcess has opened the exact checked path.
    let executable_lease = match prepared.check_immediately_before_spawn() {
        Ok(value) => value,
        Err(failure) => return Ok(PreparedExecution::PreSpawn(failure)),
    };
    let containment = ProcessContainment::new()?;
    let mut process = Command::new(&prepared.executable_path);
    process
        .args(&command.argv)
        .current_dir(cwd)
        .env_clear()
        .envs(prepared.environment.iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    containment.configure(&mut process)?;
    let started = Instant::now();
    let child = process.spawn().map_err(|_| ExecutionError::Spawn)?;
    let mut running = RunningChild::new(child, containment);
    drop(executable_lease);
    drop(cwd_lease);
    running.attach()?;
    running.resume()?;

    let stdout = running.child.stdout.take().ok_or(ExecutionError::Spawn)?;
    let stderr = running.child.stderr.take().ok_or(ExecutionError::Spawn)?;
    let capture = Arc::new(Mutex::new(CapturePair::new(
        limits.stdout_cap_bytes,
        limits.stderr_cap_bytes,
    )));
    let stdout_capture = Arc::clone(&capture);
    let stderr_capture = Arc::clone(&capture);
    let stdout_thread = thread::spawn(move || read_stream(stdout, stdout_capture, Stream::Stdout));
    let stderr_thread = thread::spawn(move || read_stream(stderr, stderr_capture, Stream::Stderr));

    let mut forced = None;
    let exit_status = loop {
        if capture
            .lock()
            .map_err(|_| ExecutionError::CaptureWorker)?
            .overflow
        {
            forced = Some(ExecutionTermination::OutputLimit);
            freeze(&capture)?;
            running.terminate_and_reap()?;
            break None;
        }
        if started.elapsed() >= Duration::from_millis(limits.timeout_millis) {
            forced = Some(ExecutionTermination::Timeout);
            freeze(&capture)?;
            running.terminate_and_reap()?;
            break None;
        }
        if let Some(status) = running.child.try_wait().map_err(|_| ExecutionError::Io)? {
            // A successful direct parent is not proof that its contained
            // descendants are gone. Terminate/reap the whole containment
            // before joining inherited pipes or publishing evidence.
            running.terminate_and_reap()?;
            break Some(status);
        }
        thread::sleep(Duration::from_millis(2));
    };

    stdout_thread
        .join()
        .map_err(|_| ExecutionError::CaptureWorker)??;
    stderr_thread
        .join()
        .map_err(|_| ExecutionError::CaptureWorker)??;

    let capture = Arc::try_unwrap(capture)
        .map_err(|_| ExecutionError::CaptureWorker)?
        .into_inner()
        .map_err(|_| ExecutionError::CaptureWorker)?;
    let output_limit = capture.overflow;
    let stdout_sha256 = verification_sha256_hex(&capture.stdout);
    let stderr_sha256 = verification_sha256_hex(&capture.stderr);
    let stdout_bytes = capture.stdout.len() as u64;
    let stderr_bytes = capture.stderr.len() as u64;

    let post_digest = fs::read(&prepared.executable_path)
        .ok()
        .map(|bytes| verification_sha256_hex(&bytes));
    let executable_changed = post_digest.as_deref() != Some(&prepared.executable_digest);
    let termination = if executable_changed {
        ExecutionTermination::Invalid
    } else if output_limit || forced == Some(ExecutionTermination::OutputLimit) {
        ExecutionTermination::OutputLimit
    } else if forced == Some(ExecutionTermination::Timeout) {
        ExecutionTermination::Timeout
    } else {
        ExecutionTermination::Completed
    };
    let exit_code = if matches!(
        termination,
        ExecutionTermination::Completed | ExecutionTermination::Invalid
    ) {
        exit_status.as_ref().and_then(exit_code)
    } else {
        None
    };
    Ok(PreparedExecution::Executed(ExecutionEvidence {
        executable_digest: prepared.executable_digest.clone(),
        termination,
        exit_code,
        stdout_sha256,
        stderr_sha256,
        stdout_bytes,
        stderr_bytes,
    }))
}

fn exit_code(status: &ExitStatus) -> Option<i32> {
    status.code().or_else(|| signal_exit_code(status))
}

#[cfg(unix)]
fn signal_exit_code(status: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal().map(|signal| -signal)
}

#[cfg(not(unix))]
fn signal_exit_code(_status: &ExitStatus) -> Option<i32> {
    None
}

struct CapturePair {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_cap: u64,
    stderr_cap: u64,
    frozen: bool,
    overflow: bool,
}

impl CapturePair {
    fn new(stdout_cap: u64, stderr_cap: u64) -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_cap,
            stderr_cap,
            frozen: false,
            overflow: false,
        }
    }
}

#[derive(Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

fn read_stream(
    mut stream: impl Read,
    capture: Arc<Mutex<CapturePair>>,
    target: Stream,
) -> Result<(), ExecutionError> {
    let mut byte = [0_u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                let mut pair = capture.lock().map_err(|_| ExecutionError::CaptureWorker)?;
                if pair.frozen {
                    continue;
                }
                let cap = match target {
                    Stream::Stdout => pair.stdout_cap,
                    Stream::Stderr => pair.stderr_cap,
                };
                let length = match target {
                    Stream::Stdout => pair.stdout.len(),
                    Stream::Stderr => pair.stderr.len(),
                };
                if length as u64 == cap {
                    pair.overflow = true;
                    pair.frozen = true;
                } else {
                    match target {
                        Stream::Stdout => pair.stdout.push(byte[0]),
                        Stream::Stderr => pair.stderr.push(byte[0]),
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ExecutionError::Io),
        }
    }
}

fn freeze(capture: &Arc<Mutex<CapturePair>>) -> Result<(), ExecutionError> {
    capture
        .lock()
        .map_err(|_| ExecutionError::CaptureWorker)?
        .frozen = true;
    Ok(())
}

struct RunningChild {
    child: Child,
    containment: ProcessContainment,
    attached: bool,
    finished: bool,
}

impl RunningChild {
    fn new(child: Child, containment: ProcessContainment) -> Self {
        Self {
            child,
            containment,
            attached: false,
            finished: false,
        }
    }

    fn attach(&mut self) -> Result<(), ExecutionError> {
        self.containment.attach(&self.child)?;
        self.attached = true;
        Ok(())
    }

    fn resume(&self) -> Result<(), ExecutionError> {
        self.containment.resume(&self.child)
    }

    fn terminate_and_reap(&mut self) -> Result<(), ExecutionError> {
        if self.finished {
            return Ok(());
        }
        let result = if self.attached {
            self.containment.terminate_and_reap(&mut self.child)
        } else {
            let _ = self.child.kill();
            self.child
                .wait()
                .map(|_| ())
                .map_err(|_| ExecutionError::Containment)
        };
        if result.is_ok() {
            self.finished = true;
        }
        result
    }
}

impl Drop for RunningChild {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.terminate_and_reap();
        }
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_executable_id(value: &str) -> bool {
    !value.is_empty()
        && value == value.to_ascii_lowercase()
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        && !is_forbidden_verification_shell(value)
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|first| {
        (first.is_ascii_uppercase() || first == b'_')
            && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    })
}

fn valid_profile_path(path: &Path) -> bool {
    let Some(basename) = normalized_profile_basename(path) else {
        return false;
    };
    path.is_absolute()
        && is_local_absolute_path(path)
        && !has_noncanonical_win32_component(path)
        && !basename.is_empty()
        && !is_forbidden_verification_shell(basename)
        && !is_forbidden_batch_basename(basename)
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

fn is_forbidden_batch_basename(value: &str) -> bool {
    Path::new(value)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("bat") || value.eq_ignore_ascii_case("cmd"))
}

fn normalized_profile_basename(path: &Path) -> Option<&str> {
    let value = path.file_name()?.to_str()?;
    #[cfg(windows)]
    {
        Some(value.trim_end_matches(['.', ' ']))
    }
    #[cfg(not(windows))]
    {
        Some(value)
    }
}

#[cfg(windows)]
fn has_noncanonical_win32_component(path: &Path) -> bool {
    path.components().any(|component| {
        let Component::Normal(value) = component else {
            return false;
        };
        match value.to_str() {
            Some(value) => {
                value.contains(':')
                    || value.contains('~')
                    || value.ends_with('.')
                    || value.ends_with(' ')
            }
            None => true,
        }
    })
}

#[cfg(not(windows))]
fn has_noncanonical_win32_component(_path: &Path) -> bool {
    false
}

#[cfg(windows)]
fn is_local_absolute_path(path: &Path) -> bool {
    use std::path::Prefix;
    matches!(
        path.components().next(),
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_))
    )
}

#[cfg(not(windows))]
fn is_local_absolute_path(path: &Path) -> bool {
    matches!(path.components().next(), Some(Component::RootDir))
}

#[cfg(windows)]
fn is_reparse_or_symlink(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_or_symlink(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

struct CheckedWorkingDirectory {
    path: PathBuf,
    #[cfg(windows)]
    handles: Vec<windows_sys::Win32::Foundation::HANDLE>,
}

impl CheckedWorkingDirectory {
    fn acquire(snapshot_root: &Path, cwd: &WorkingDirectory) -> Option<Self> {
        if !snapshot_root.is_absolute() {
            return None;
        }
        let mut component_paths = vec![snapshot_root.to_path_buf()];
        let mut effective = snapshot_root.to_path_buf();
        if let WorkingDirectory::Relative { path } = cwd {
            for component in Path::new(path).components() {
                let Component::Normal(part) = component else {
                    return None;
                };
                effective.push(part);
                component_paths.push(effective.clone());
            }
        }

        #[cfg(windows)]
        {
            Self::acquire_windows(effective, component_paths)
        }

        #[cfg(not(windows))]
        {
            if component_paths.iter().any(|path| {
                fs::symlink_metadata(path).map_or(true, |metadata| {
                    !metadata.is_dir() || metadata.file_type().is_symlink()
                })
            }) {
                return None;
            }
            Some(Self { path: effective })
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(windows)]
    fn acquire_windows(path: PathBuf, component_paths: Vec<PathBuf>) -> Option<Self> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_SHARE_READ, OPEN_EXISTING,
        };

        let mut lease = Self {
            path,
            handles: Vec::with_capacity(component_paths.len()),
        };
        for component in component_paths {
            let mut wide = component.as_os_str().encode_wide().collect::<Vec<_>>();
            if wide.contains(&0) {
                return None;
            }
            wide.push(0);
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    FILE_LIST_DIRECTORY,
                    FILE_SHARE_READ,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    std::ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return None;
            }
            let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
            if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0
                || information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
                || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
                return None;
            }
            lease.handles.push(handle);
        }
        Some(lease)
    }
}

#[cfg(windows)]
impl Drop for CheckedWorkingDirectory {
    fn drop(&mut self) {
        for handle in self.handles.drain(..).rev() {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
        }
    }
}

#[cfg(unix)]
struct ProcessContainment;

#[cfg(unix)]
impl ProcessContainment {
    fn new() -> Result<Self, ExecutionError> {
        Ok(Self)
    }

    fn configure(&self, command: &mut Command) -> Result<(), ExecutionError> {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
        Ok(())
    }

    fn attach(&self, _child: &Child) -> Result<(), ExecutionError> {
        Ok(())
    }

    fn resume(&self, _child: &Child) -> Result<(), ExecutionError> {
        Ok(())
    }

    fn terminate_and_reap(&self, child: &mut Child) -> Result<(), ExecutionError> {
        let pid = i32::try_from(child.id()).map_err(|_| ExecutionError::Containment)?;
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        child.wait().map_err(|_| ExecutionError::Containment)?;
        for _ in 0..5_000 {
            let result = unsafe { libc::kill(-pid, 0) };
            if result != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(1));
        }
        Err(ExecutionError::Containment)
    }
}

#[cfg(windows)]
struct ProcessContainment {
    job: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl ProcessContainment {
    fn new() -> Result<Self, ExecutionError> {
        use std::mem::size_of;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(ExecutionError::Containment);
        }
        let mut information: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&information).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
            return Err(ExecutionError::Containment);
        }
        Ok(Self { job })
    }

    fn configure(&self, command: &mut Command) -> Result<(), ExecutionError> {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED);
        Ok(())
    }

    fn attach(&self, child: &Child) -> Result<(), ExecutionError> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        let process = child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        if unsafe { AssignProcessToJobObject(self.job, process) } == 0 {
            return Err(ExecutionError::Containment);
        }
        Ok(())
    }

    fn resume(&self, child: &Child) -> Result<(), ExecutionError> {
        use std::mem::size_of;
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows_sys::Win32::System::Threading::{
            OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
        };

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(ExecutionError::Containment);
        }
        let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        let mut found = false;
        let mut current = unsafe { Thread32First(snapshot, &mut entry) };
        while current != 0 {
            if entry.th32OwnerProcessID == child.id() {
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if thread.is_null() {
                    unsafe { CloseHandle(snapshot) };
                    return Err(ExecutionError::Containment);
                }
                let resumed = unsafe { ResumeThread(thread) };
                unsafe { CloseHandle(thread) };
                // CREATE_SUSPENDED guarantees an initial count of exactly one.
                // Any other prior count means the race-free launch invariant
                // was not established, so fail closed without publication.
                if resumed != 1 {
                    unsafe { CloseHandle(snapshot) };
                    return Err(ExecutionError::Containment);
                }
                found = true;
                break;
            }
            current = unsafe { Thread32Next(snapshot, &mut entry) };
        }
        unsafe { CloseHandle(snapshot) };
        if !found {
            return Err(ExecutionError::Containment);
        }
        Ok(())
    }

    fn terminate_and_reap(&self, child: &mut Child) -> Result<(), ExecutionError> {
        use std::mem::size_of;
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject, TerminateJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        };
        if unsafe { TerminateJobObject(self.job, 1) } == 0 {
            return Err(ExecutionError::Containment);
        }
        child.wait().map_err(|_| ExecutionError::Containment)?;
        for _ in 0..5_000 {
            let mut information: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION =
                unsafe { std::mem::zeroed() };
            let queried = unsafe {
                QueryInformationJobObject(
                    self.job,
                    JobObjectBasicAccountingInformation,
                    std::ptr::from_mut(&mut information).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                )
            };
            if queried == 0 {
                return Err(ExecutionError::Containment);
            }
            if information.ActiveProcesses == 0 {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(1));
        }
        Err(ExecutionError::Containment)
    }
}

#[cfg(windows)]
impl Drop for ProcessContainment {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.job);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_shell_ids_use_the_same_frozen_name_set() {
        for executable_id in [
            "sh",
            "sh.exe",
            "bash",
            "bash.exe",
            "zsh",
            "zsh.exe",
            "cmd",
            "cmd.exe",
            "powershell",
            "powershell.exe",
            "pwsh",
            "pwsh.exe",
        ] {
            assert!(!valid_executable_id(executable_id));
        }
        assert!(valid_executable_id("reviewed-runner"));
    }

    #[cfg(windows)]
    #[test]
    fn executable_ancestor_lease_blocks_parent_rename_and_retarget() {
        let temporary = tempfile::tempdir().expect("temporary executable root");
        let reviewed_parent = temporary.path().join("reviewed-bin");
        fs::create_dir(&reviewed_parent).expect("create reviewed parent");
        let executable = reviewed_parent.join("runner.exe");
        fs::copy(
            std::env::current_exe().expect("current test executable"),
            &executable,
        )
        .expect("copy reviewed executable");
        let retargeted_parent = temporary.path().join("retargeted-bin");

        let lease = Win32ExecutableAncestors::acquire(&executable)
            .expect("lease all ordinary executable ancestors");
        assert!(
            fs::rename(&reviewed_parent, &retargeted_parent).is_err(),
            "held ancestor was renamed inside the pre-spawn boundary"
        );

        drop(lease);
        fs::rename(&reviewed_parent, &retargeted_parent)
            .expect("rename must become available after lease release");
        std::os::windows::fs::symlink_dir(&retargeted_parent, &reviewed_parent)
            .expect("retarget path after lease release");
        assert!(fs::symlink_metadata(&reviewed_parent)
            .expect("retarget metadata")
            .file_type()
            .is_symlink());
    }

    #[test]
    #[allow(clippy::zombie_processes)] // The outer verifier guard owns tree cleanup.
    fn cleanup_child_probe() {
        let Some(started) = std::env::var_os("OVCA_CLEANUP_STARTED") else {
            return;
        };
        let Some(survived) = std::env::var_os("OVCA_CLEANUP_SURVIVED") else {
            return;
        };
        let _descendant = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "execution::tests::cleanup_descendant_probe",
                "--nocapture",
            ])
            .env_clear()
            .env("OVCA_CLEANUP_SURVIVED", survived)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn contained descendant");
        fs::write(started, b"started").expect("write child start marker");
        thread::sleep(Duration::from_secs(5));
    }

    #[test]
    fn cleanup_descendant_probe() {
        let Some(survived) = std::env::var_os("OVCA_CLEANUP_SURVIVED") else {
            return;
        };
        thread::sleep(Duration::from_millis(400));
        fs::write(survived, b"survived").expect("write descendant survival marker");
    }

    fn return_error_after_confirmed_spawn(
        started: &Path,
        survived: &Path,
    ) -> Result<(), ExecutionError> {
        let containment = ProcessContainment::new()?;
        let mut process = Command::new(std::env::current_exe().map_err(|_| ExecutionError::Spawn)?);
        process
            .args([
                "--exact",
                "execution::tests::cleanup_child_probe",
                "--nocapture",
            ])
            .env_clear()
            .env("OVCA_CLEANUP_STARTED", started)
            .env("OVCA_CLEANUP_SURVIVED", survived)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        containment.configure(&mut process)?;
        let child = process.spawn().map_err(|_| ExecutionError::Spawn)?;
        let mut running = RunningChild::new(child, containment);
        running.attach()?;
        running.resume()?;

        for _ in 0..2_000 {
            if started.is_file() {
                return Err(ExecutionError::CaptureWorker);
            }
            thread::sleep(Duration::from_millis(1));
        }
        Err(ExecutionError::Spawn)
    }

    #[test]
    fn post_spawn_error_guard_terminates_and_reaps_process_tree() {
        let temporary = tempfile::tempdir().expect("temporary marker directory");
        let started = temporary.path().join("started.marker");
        let survived = temporary.path().join("survived.marker");

        assert!(matches!(
            return_error_after_confirmed_spawn(&started, &survived),
            Err(ExecutionError::CaptureWorker)
        ));
        assert!(
            started.is_file(),
            "child must run before the injected error"
        );
        thread::sleep(Duration::from_millis(600));
        assert!(
            !survived.exists(),
            "the cleanup guard must terminate and reap on every error return"
        );
    }

    #[test]
    fn environment_digest_is_order_stable_value_sensitive_and_secret_free() {
        let names = BTreeSet::from(["A".to_owned(), "B".to_owned()]);
        let first = EnvironmentBindings {
            values: BTreeMap::from([
                ("B".to_owned(), OsString::from("secret-b")),
                ("A".to_owned(), OsString::from("secret-a")),
            ]),
        };
        let second = EnvironmentBindings {
            values: BTreeMap::from([
                ("A".to_owned(), OsString::from("secret-a")),
                ("B".to_owned(), OsString::from("secret-b")),
            ]),
        };
        assert_eq!(first.digest_for(&names), second.digest_for(&names));
        let mut changed = second;
        changed
            .values
            .insert("B".to_owned(), OsString::from("different"));
        assert_ne!(first.digest_for(&names), changed.digest_for(&names));
        assert!(ExecutionLimits {
            timeout_millis: 1,
            stdout_cap_bytes: 0,
            stderr_cap_bytes: MAX_STREAM_CAP_BYTES,
        }
        .is_valid());
        assert!(!ExecutionLimits {
            timeout_millis: 0,
            stdout_cap_bytes: 0,
            stderr_cap_bytes: 0,
        }
        .is_valid());
    }
}
