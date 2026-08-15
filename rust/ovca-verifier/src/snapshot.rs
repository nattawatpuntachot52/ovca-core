use ovca_types::{verification_sha256_hex, LocalVerificationError};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use thiserror::Error;

const SOURCE_MANIFEST_VERSION: &str = "ovca.source-manifest.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFile {
    pub logical_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceManifest {
    pub files: Vec<SourceFile>,
}

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("invalid source manifest")]
    InvalidManifest,
    #[error("source root is not an absolute ordinary directory")]
    InvalidSourceRoot,
    #[error("snapshot root must be an absolute empty ordinary directory")]
    InvalidSnapshotRoot,
    #[error("source tree does not match the frozen manifest")]
    SourceMismatch,
    #[error("source changed while the snapshot was materialized")]
    SourceChanged,
    #[error("snapshot integrity does not match the frozen manifest")]
    SnapshotMismatch,
    #[error("snapshot I/O failed")]
    Io(#[source] io::Error),
}

impl From<LocalVerificationError> for SnapshotError {
    fn from(_: LocalVerificationError) -> Self {
        Self::InvalidManifest
    }
}

#[derive(Serialize)]
struct SourceManifestPayload<'a> {
    version: &'static str,
    files: &'a [SourceFile],
}

impl SourceManifest {
    pub fn validate(&self) -> Result<(), SnapshotError> {
        if self.files.is_empty() {
            return Err(SnapshotError::InvalidManifest);
        }
        let mut prior: Option<&str> = None;
        for file in &self.files {
            ovca_types::validate_logical_path(&file.logical_path)?;
            if prior.is_some_and(|value| value >= file.logical_path.as_str()) {
                return Err(SnapshotError::InvalidManifest);
            }
            if file.sha256.len() != 64
                || !file
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(SnapshotError::InvalidManifest);
            }
            prior = Some(&file.logical_path);
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, SnapshotError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(&SourceManifestPayload {
            version: SOURCE_MANIFEST_VERSION,
            files: &self.files,
        })
        .map_err(|error| SnapshotError::Io(io::Error::other(error)))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn fingerprint(&self) -> Result<String, SnapshotError> {
        Ok(verification_sha256_hex(&self.canonical_json_bytes()?))
    }

    pub fn preflight_roots(
        &self,
        source_root: &Path,
        snapshot_root: &Path,
    ) -> Result<String, SnapshotError> {
        self.validate()?;
        validate_root(source_root, false)?;
        validate_root(snapshot_root, true)?;
        let canonical_source = fs::canonicalize(source_root).map_err(SnapshotError::Io)?;
        let canonical_snapshot = fs::canonicalize(snapshot_root).map_err(SnapshotError::Io)?;
        if canonical_snapshot == canonical_source
            || canonical_snapshot.starts_with(&canonical_source)
            || canonical_source.starts_with(&canonical_snapshot)
        {
            return Err(SnapshotError::InvalidSnapshotRoot);
        }
        inspect_tree(source_root, self, TreeKind::Source)
    }
}

pub struct FrozenSnapshot {
    source_root: PathBuf,
    snapshot_root: PathBuf,
    manifest: SourceManifest,
    source_pre: String,
}

impl FrozenSnapshot {
    pub fn materialize(
        source_root: &Path,
        snapshot_root: &Path,
        manifest: &SourceManifest,
    ) -> Result<Self, SnapshotError> {
        let source_pre = manifest.preflight_roots(source_root, snapshot_root)?;

        for file in &manifest.files {
            let source = join_logical(source_root, &file.logical_path);
            let destination = join_logical(snapshot_root, &file.logical_path);
            ensure_destination_parent(snapshot_root, &file.logical_path)?;
            let mut input = fs::File::open(&source).map_err(|_| SnapshotError::SourceChanged)?;
            let mut output = fs::File::create_new(&destination).map_err(SnapshotError::Io)?;
            io::copy(&mut input, &mut output).map_err(SnapshotError::Io)?;
            let copied = hash_file(&destination).map_err(SnapshotError::Io)?;
            if copied != file.sha256 {
                return Err(SnapshotError::SourceChanged);
            }
        }

        let source_post =
            inspect_tree(source_root, manifest, TreeKind::Source).map_err(|error| match error {
                SnapshotError::SourceMismatch => SnapshotError::SourceChanged,
                other => other,
            })?;
        if source_pre != source_post {
            return Err(SnapshotError::SourceChanged);
        }
        inspect_tree(snapshot_root, manifest, TreeKind::Snapshot)?;
        Ok(Self {
            source_root: source_root.to_path_buf(),
            snapshot_root: snapshot_root.to_path_buf(),
            manifest: manifest.clone(),
            source_pre,
        })
    }

    pub fn root(&self) -> &Path {
        &self.snapshot_root
    }

    pub fn source_pre_fingerprint(&self) -> &str {
        &self.source_pre
    }

    pub fn source_post_fingerprint(&self) -> Result<String, SnapshotError> {
        inspect_tree(&self.source_root, &self.manifest, TreeKind::Source).map_err(|error| {
            match error {
                SnapshotError::SourceMismatch => SnapshotError::SourceChanged,
                other => other,
            }
        })
    }

    pub fn verify_snapshot_integrity(&self) -> Result<String, SnapshotError> {
        inspect_tree(&self.snapshot_root, &self.manifest, TreeKind::Snapshot)
    }
}

#[derive(Clone, Copy)]
enum TreeKind {
    Source,
    Snapshot,
}

fn validate_root(root: &Path, require_empty: bool) -> Result<(), SnapshotError> {
    if !root.is_absolute() {
        return Err(if require_empty {
            SnapshotError::InvalidSnapshotRoot
        } else {
            SnapshotError::InvalidSourceRoot
        });
    }
    let metadata = fs::symlink_metadata(root).map_err(|_| {
        if require_empty {
            SnapshotError::InvalidSnapshotRoot
        } else {
            SnapshotError::InvalidSourceRoot
        }
    })?;
    if !metadata.is_dir() || is_reparse_or_symlink(&metadata) {
        return Err(if require_empty {
            SnapshotError::InvalidSnapshotRoot
        } else {
            SnapshotError::InvalidSourceRoot
        });
    }
    if require_empty
        && fs::read_dir(root)
            .map_err(SnapshotError::Io)?
            .next()
            .is_some()
    {
        return Err(SnapshotError::InvalidSnapshotRoot);
    }
    Ok(())
}

fn inspect_tree(
    root: &Path,
    manifest: &SourceManifest,
    kind: TreeKind,
) -> Result<String, SnapshotError> {
    let mut discovered = Vec::new();
    visit(root, root, &mut discovered, kind)?;
    discovered.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    if discovered != manifest.files {
        return Err(match kind {
            TreeKind::Source => SnapshotError::SourceMismatch,
            TreeKind::Snapshot => SnapshotError::SnapshotMismatch,
        });
    }
    manifest.fingerprint()
}

fn visit(
    root: &Path,
    directory: &Path,
    discovered: &mut Vec<SourceFile>,
    kind: TreeKind,
) -> Result<(), SnapshotError> {
    let mut entries = fs::read_dir(directory)
        .map_err(SnapshotError::Io)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(SnapshotError::Io)?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let metadata = fs::symlink_metadata(entry.path()).map_err(SnapshotError::Io)?;
        if is_reparse_or_symlink(&metadata) {
            return Err(match kind {
                TreeKind::Source => SnapshotError::SourceMismatch,
                TreeKind::Snapshot => SnapshotError::SnapshotMismatch,
            });
        }
        if metadata.is_dir() {
            visit(root, &entry.path(), discovered, kind)?;
        } else if metadata.is_file() {
            let entry_path = entry.path();
            let relative = entry_path.strip_prefix(root).map_err(|_| match kind {
                TreeKind::Source => SnapshotError::SourceMismatch,
                TreeKind::Snapshot => SnapshotError::SnapshotMismatch,
            })?;
            let logical_path = relative
                .components()
                .map(|component| component.as_os_str().to_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
                .ok_or(match kind {
                    TreeKind::Source => SnapshotError::SourceMismatch,
                    TreeKind::Snapshot => SnapshotError::SnapshotMismatch,
                })?
                .join("/");
            ovca_types::validate_logical_path(&logical_path)?;
            discovered.push(SourceFile {
                logical_path,
                sha256: hash_file(&entry_path).map_err(SnapshotError::Io)?,
            });
        } else {
            return Err(match kind {
                TreeKind::Source => SnapshotError::SourceMismatch,
                TreeKind::Snapshot => SnapshotError::SnapshotMismatch,
            });
        }
    }
    Ok(())
}

fn join_logical(root: &Path, logical: &str) -> PathBuf {
    logical
        .split('/')
        .fold(root.to_path_buf(), |path, part| path.join(part))
}

fn ensure_destination_parent(root: &Path, logical: &str) -> Result<(), SnapshotError> {
    let mut current = root.to_path_buf();
    let mut parts = logical.split('/').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            break;
        }
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !is_reparse_or_symlink(&metadata) => {}
            Ok(_) => return Err(SnapshotError::SnapshotMismatch),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(SnapshotError::Io)?;
                let metadata = fs::symlink_metadata(&current).map_err(SnapshotError::Io)?;
                if !metadata.is_dir() || is_reparse_or_symlink(&metadata) {
                    return Err(SnapshotError::SnapshotMismatch);
                }
            }
            Err(error) => return Err(SnapshotError::Io(error)),
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(verification_sha256_hex(&bytes))
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn snapshot_is_exact_and_rejects_extra_source_or_nonempty_destination() {
        let source = tempdir().unwrap();
        let snapshot = tempdir().unwrap();
        fs::write(source.path().join("a.txt"), b"a").unwrap();
        let manifest = SourceManifest {
            files: vec![SourceFile {
                logical_path: "a.txt".to_owned(),
                sha256: verification_sha256_hex(b"a"),
            }],
        };
        manifest
            .preflight_roots(source.path(), snapshot.path())
            .unwrap();
        let frozen =
            FrozenSnapshot::materialize(source.path(), snapshot.path(), &manifest).unwrap();
        assert_eq!(
            frozen.verify_snapshot_integrity().unwrap(),
            manifest.fingerprint().unwrap()
        );

        let extra_source = tempdir().unwrap();
        let empty_snapshot = tempdir().unwrap();
        fs::write(extra_source.path().join("a.txt"), b"a").unwrap();
        fs::write(extra_source.path().join("extra.txt"), b"extra").unwrap();
        assert!(matches!(
            manifest.preflight_roots(extra_source.path(), empty_snapshot.path()),
            Err(SnapshotError::SourceMismatch)
        ));
        assert!(matches!(
            manifest.preflight_roots(source.path(), snapshot.path()),
            Err(SnapshotError::InvalidSnapshotRoot)
        ));
    }
}
