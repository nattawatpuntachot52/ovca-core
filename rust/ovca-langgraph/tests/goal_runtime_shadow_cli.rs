use ovca_types::verification_sha256_hex;
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_goal_runtime_shadow")
}

const PROTECTED_WORKSPACE_ENV: &str = "OVCA_PROTECTED_WORKSPACE";

fn binary_command(protected_workspace: Option<&Path>) -> Command {
    let mut command = Command::new(binary());
    command.env_remove(PROTECTED_WORKSPACE_ENV);
    if let Some(protected_workspace) = protected_workspace {
        command.env(PROTECTED_WORKSPACE_ENV, protected_workspace);
    }
    command
}

fn normalized_input(required_gate: &str, dispatch_outcome: &str) -> String {
    serde_json::to_string(&json!({
        "schema_version": 1,
        "request_correlation": "grs-0123456789abcdef",
        "task_kind": "code_change",
        "required_gate": required_gate,
        "dispatch_outcome": dispatch_outcome
    }))
    .unwrap()
}

fn schema_v2_input(request_id: &str) -> String {
    serde_json::to_string(&json!({
        "schema_version": 2,
        "request_correlation": "grs-0123456789abcdef",
        "task_kind": "code_change",
        "required_gate": "auditor",
        "dispatch_outcome": "success",
        "verification_request_id": request_id
    }))
    .unwrap()
}

fn structurally_rejected_request(source_root: &Path) -> Value {
    let digest = "d".repeat(64);
    json!({
        "schema_version": 1,
        "behavior": {
            "contract_version": 2,
            "contract_id": "behavior.v4a",
            "binding": {"type": "bound", "goal_id": "goal.v4a", "task_id": "task.v4a"},
            "criteria": []
        },
        "capabilities": [{
            "contract_version": 1,
            "capability_id": "capability.v4a",
            "revision": 1,
            "criterion_ids": [],
            "dependencies": [],
            "changed_path_selectors": [],
            "policy": {
                "local_only": true,
                "network": "denied",
                "provider": "denied",
                "telemetry": "denied",
                "egress": "denied",
                "external_evidence": "denied",
                "external_storage": "denied",
                "raw_shell": "forbidden",
                "inherit_environment": false,
                "fingerprint_algorithm": "sha256",
                "allowed_executable_ids": ["test-runner"],
                "allowed_environment_names": []
            },
            "commands": [{
                "command_id": "command.v4a",
                "executable_id": "test-runner",
                "argv": [],
                "cwd": {"type": "snapshot_root"},
                "environment_names": []
            }]
        }],
        "selection": {
            "contract_version": 1,
            "run_id": "run.v4a",
            "goal_id": "goal.v4a",
            "task_id": "task.v4a",
            "source_fingerprint": digest,
            "policy_digest": digest,
            "unknown_path_policy": "blocked",
            "registry_snapshot_digest": digest,
            "changed_path_manifest": {"entries": [{
                "kind": "modified",
                "path": "input.txt",
                "previous_path": null
            }]},
            "changed_path_manifest_digest": digest,
            "mode": "targeted",
            "unknown_paths": [],
            "capabilities": [{
                "capability_id": "capability.v4a",
                "revision": 1,
                "record_digest": digest
            }],
            "selection_digest": digest
        },
        "source_manifest": {"files": [{"logical_path": "input.txt", "sha256": digest}]},
        "source_root": source_root,
        "executable_profiles": [],
        "environment_bindings": [],
        "environment_digest": verification_sha256_hex(b"ovca.environment-bindings.v1\0"),
        "limits": {"timeout_millis": 5000, "stdout_cap_bytes": 16384, "stderr_cap_bytes": 16384},
        "implementation_actor": "engineer.implementation",
        "verifier_actor": "auditor.independent",
        "created_at": "2026-08-10T12:00:00Z",
        "failure_identities": [],
        "projection_expectation": {"state": "absent"}
    })
}

fn write_request(root: &Path, request: &Value) -> (String, Vec<u8>) {
    let bytes = serde_json::to_vec(request).unwrap();
    let request_id = format!("vreq.sha256.{}", verification_sha256_hex(&bytes));
    let request_root = root
        .join("goal-runtime-shadow")
        .join("verification-requests");
    fs::create_dir_all(&request_root).unwrap();
    fs::write(request_root.join(format!("{request_id}.json")), &bytes).unwrap();
    (request_id, bytes)
}

fn run_stdin_with_protected_workspace(
    root: &Path,
    input: &str,
    protected_workspace: Option<&Path>,
) -> Output {
    let mut child = binary_command(protected_workspace)
        .arg("--durable-root")
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn run_stdin(root: &Path, input: &str) -> Output {
    let protected_workspace = TempDir::new().unwrap();
    assert!(protected_workspace.path().is_absolute());
    run_stdin_with_protected_workspace(root, input, Some(protected_workspace.path()))
}

#[cfg(windows)]
fn run_stdin_from(root: &Path, input: &str, current_dir: &Path) -> Output {
    let protected_workspace = TempDir::new().unwrap();
    assert!(protected_workspace.path().is_absolute());
    let mut child = binary_command(Some(protected_workspace.path()))
        .arg("--durable-root")
        .arg(root)
        .current_dir(current_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[cfg(windows)]
fn existing_volume_alias(path: &Path) -> Option<(PathBuf, PathBuf)> {
    let canonical = fs::canonicalize(path).ok()?;
    let canonical_text = canonical.as_os_str().to_str()?.replace('/', "\\");
    let local = canonical_text
        .strip_prefix(r"\\?\")
        .unwrap_or(&canonical_text);
    let bytes = local.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return None;
    }
    let drive_root = PathBuf::from(&local[..3]);
    let system_root = std::env::var_os("SystemRoot").or_else(|| std::env::var_os("WINDIR"))?;
    let output = Command::new(
        PathBuf::from(system_root)
            .join("System32")
            .join("mountvol.exe"),
    )
    .arg(&drive_root)
    .arg("/L")
    .output()
    .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let volume_name = stdout.lines().map(str::trim).find(|line| {
        line.to_ascii_lowercase().starts_with(r"\\?\volume{") && line.ends_with('\\')
    })?;
    let relative = Path::new(local).strip_prefix(&drive_root).ok()?;
    let alias = PathBuf::from(volume_name).join(relative);
    if !alias.exists() {
        return None;
    }
    let alias_canonical = fs::canonicalize(&alias).ok()?;
    let alias_canonical_text = alias_canonical.as_os_str().to_str()?.replace('/', "\\");
    let alias_local = alias_canonical_text
        .strip_prefix(r"\\?\")
        .unwrap_or(&alias_canonical_text);
    let alias_bytes = alias_local.as_bytes();
    if alias_bytes.len() < 3
        || !alias_bytes[0].is_ascii_alphabetic()
        || alias_bytes[1] != b':'
        || alias_bytes[2] != b'\\'
    {
        return None;
    }
    Some((alias, alias_canonical))
}

fn run_input_file_with_protected_workspace(
    root: &Path,
    input_file: &Path,
    protected_workspace: Option<&Path>,
) -> Output {
    binary_command(protected_workspace)
        .arg("--durable-root")
        .arg(root)
        .arg("--input-file")
        .arg(input_file)
        .output()
        .unwrap()
}

fn run_input_file(root: &Path, input_file: &Path) -> Output {
    let protected_workspace = TempDir::new().unwrap();
    assert!(protected_workspace.path().is_absolute());
    run_input_file_with_protected_workspace(root, input_file, Some(protected_workspace.path()))
}

fn payload(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

fn files_below(root: &Path) -> Vec<PathBuf> {
    fn visit(path: &Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                visit(&path, files);
            } else {
                files.push(path);
            }
        }
    }

    let mut files = Vec::new();
    if root.exists() {
        visit(root, &mut files);
    }
    files.sort();
    files
}

#[test]
fn deterministic_output_matches_for_stdin_and_explicit_input_file() {
    let first = TempDir::new().unwrap();
    let second = TempDir::new().unwrap();
    let input = normalized_input("none", "success");
    let input_file = second.path().join("normalized-input.json");
    fs::write(&input_file, &input).unwrap();

    let stdin_output = run_stdin(&first.path().join("durable"), &input);
    let file_output = run_input_file(&second.path().join("durable"), &input_file);

    assert!(stdin_output.status.success());
    assert!(file_output.status.success());
    assert_eq!(stdin_output.stdout, file_output.stdout);
    assert!(stdin_output.stderr.is_empty());
    assert!(file_output.stderr.is_empty());
}

#[test]
fn protected_workspace_configuration_fails_closed_before_writes() {
    let temp = TempDir::new().unwrap();
    let durable_root = temp.path().join("durable");
    let input = normalized_input("none", "success");

    for (configured, error_code) in [
        (None, "protected_workspace_required"),
        (Some(Path::new("")), "protected_workspace_required"),
        (
            Some(Path::new("relative-protected-workspace")),
            "protected_workspace_not_absolute",
        ),
    ] {
        let output = run_stdin_with_protected_workspace(&durable_root, &input, configured);
        assert!(!output.status.success());
        assert_eq!(payload(&output)["error_code"], error_code);
        assert_eq!(payload(&output)["production_effect"], "none");
        assert!(!durable_root.exists());
    }

    let missing = temp.path().join("missing-protected-workspace");
    let output = run_stdin_with_protected_workspace(&durable_root, &input, Some(&missing));
    assert!(!output.status.success());
    assert_eq!(
        payload(&output)["error_code"],
        "protected_workspace_invalid"
    );
    assert!(!durable_root.exists());

    let protected_file = temp.path().join("protected-workspace-file");
    fs::write(&protected_file, b"not a directory").unwrap();
    let output = run_stdin_with_protected_workspace(&durable_root, &input, Some(&protected_file));
    assert!(!output.status.success());
    assert_eq!(
        payload(&output)["error_code"],
        "protected_workspace_invalid"
    );
    assert!(!durable_root.exists());
}

#[cfg(windows)]
#[test]
fn protected_workspace_unc_and_device_configuration_fail_without_lookup_or_writes() {
    let temp = TempDir::new().unwrap();
    let durable_root = temp.path().join("durable");
    let input = normalized_input("none", "success");
    let separator = char::from(b'\\');
    let unc = PathBuf::from(format!(
        "{separator}{separator}server{separator}share{separator}workspace"
    ));
    let device = fs::canonicalize(temp.path()).unwrap();

    for configured in [&unc, &device] {
        let output = run_stdin_with_protected_workspace(&durable_root, &input, Some(configured));
        assert!(!output.status.success());
        assert_eq!(
            payload(&output)["error_code"],
            "protected_workspace_unsupported"
        );
        assert_eq!(payload(&output)["production_effect"], "none");
        assert!(!durable_root.exists());
    }
}

#[test]
fn protected_workspace_and_normalized_descendants_are_rejected_before_writes() {
    let temp = TempDir::new().unwrap();
    let protected_workspace = temp.path().join("protected-workspace");
    fs::create_dir_all(&protected_workspace).unwrap();
    let normalized_descendant = protected_workspace
        .join("unused-segment")
        .join("..")
        .join("shadow");
    let mut roots = vec![
        protected_workspace.clone(),
        protected_workspace.join("shadow"),
        normalized_descendant,
    ];
    #[cfg(windows)]
    {
        roots.push(
            fs::canonicalize(&protected_workspace)
                .unwrap()
                .join("shadow"),
        );
        roots.push(
            PathBuf::from(protected_workspace.to_string_lossy().to_ascii_uppercase())
                .join("shadow"),
        );
    }

    for root in roots {
        let output = run_stdin_with_protected_workspace(
            &root,
            &normalized_input("none", "success"),
            Some(&protected_workspace),
        );
        assert!(
            !output.status.success(),
            "{} must be rejected",
            root.display()
        );
        assert_eq!(payload(&output)["error_code"], "protected_root");
        assert_eq!(payload(&output)["production_effect"], "none");
    }
    assert!(files_below(&protected_workspace).is_empty());
}

#[cfg(windows)]
#[test]
fn text_prefix_sibling_is_not_misclassified_as_protected() {
    let temp = TempDir::new().unwrap();
    let protected_workspace = temp.path().join("protected-workspace");
    fs::create_dir_all(&protected_workspace).unwrap();
    let sibling = temp.path().join("protected-workspace-sibling");
    let missing_input = temp.path().join("missing-input.json");
    let output = run_input_file_with_protected_workspace(
        &sibling,
        &missing_input,
        Some(&protected_workspace),
    );

    assert!(!output.status.success());
    assert_eq!(payload(&output)["error_code"], "input_unavailable");
}

#[test]
fn persistence_is_external_root_only_and_output_contains_no_paths() {
    let temp = TempDir::new().unwrap();
    let durable_root = temp.path().join("durable");
    let protected_workspace = temp.path().join("protected-workspace");
    fs::create_dir_all(&protected_workspace).unwrap();
    let output = run_stdin_with_protected_workspace(
        &durable_root,
        &normalized_input("none", "success"),
        Some(&protected_workspace),
    );
    assert!(output.status.success());

    let files = files_below(&durable_root);
    assert!(files.iter().all(|path| path.starts_with(&durable_root)));
    assert!(files.iter().any(|path| path.ends_with("events.jsonl")));
    assert!(files
        .iter()
        .any(|path| path.ends_with("versioned-state.sqlite3")));

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains(&durable_root.to_string_lossy().to_string()));
    assert!(!stdout.contains(&protected_workspace.to_string_lossy().to_string()));
    assert!(!stdout.contains(PROTECTED_WORKSPACE_ENV));
}

#[test]
fn missing_reviewer_or_auditor_evidence_never_becomes_success() {
    for (gate, required_roles) in [
        ("reviewer", json!(["Reviewer"])),
        ("auditor", json!(["Reviewer", "Auditor"])),
    ] {
        let temp = TempDir::new().unwrap();
        let output = run_stdin(
            &temp.path().join("durable"),
            &normalized_input(gate, "success"),
        );
        assert!(output.status.success());
        let value = payload(&output);
        assert_eq!(value["successful"], false);
        assert_eq!(value["evaluation_outcome"], "awaiting_review");
        assert_eq!(value["required_roles"], required_roles);
        assert_eq!(value["decision_evidence_recorded"], false);
    }
}

#[test]
fn r0_completion_remains_compatible_and_replay_complete() {
    let temp = TempDir::new().unwrap();
    let output = run_stdin(
        &temp.path().join("durable"),
        &normalized_input("none", "success"),
    );
    assert!(output.status.success());
    let value = payload(&output);

    assert_eq!(value["successful"], true);
    assert_eq!(value["evaluation_outcome"], "successful_completion");
    assert_eq!(value["trace_completeness"], 1.0);
    assert_eq!(value["replay_parity"], true);
    assert_eq!(value["event_count"], 8);
    assert_eq!(value["roles_observed"], json!(["Coordinator", "Engineer"]));
    assert_eq!(value["production_effect"], "none");
}

#[test]
fn raw_or_unknown_input_is_rejected_without_echoing_sensitive_values() {
    let temp = TempDir::new().unwrap();
    let sensitive = "sensitive-task-body-password-value";
    let input = json!({
        "schema_version": 1,
        "request_correlation": "grs-0123456789abcdef",
        "task_kind": "code_change",
        "required_gate": "none",
        "dispatch_outcome": "success",
        "raw_task_body": sensitive
    })
    .to_string();
    let output = run_stdin(&temp.path().join("durable"), &input);
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert_eq!(
        serde_json::from_str::<Value>(&stdout).unwrap()["error_code"],
        "input_invalid"
    );
    for excluded in [sensitive, "raw_task_body", "raw_provider_payload"] {
        assert!(!stdout.contains(excluded), "{excluded} leaked into output");
    }
}

#[test]
fn persisted_shadow_data_uses_only_public_roles_and_safe_fixed_content() {
    let temp = TempDir::new().unwrap();
    let durable_root = temp.path().join("durable");
    let output = run_stdin(&durable_root, &normalized_input("auditor", "success"));
    assert!(output.status.success());

    let mut persisted = Vec::new();
    for file in files_below(&durable_root) {
        persisted.extend(fs::read(file).unwrap());
    }
    let persisted = String::from_utf8_lossy(&persisted);
    for excluded in ["raw_provider_payload", "password", "api_key"] {
        assert!(
            !persisted.contains(excluded),
            "{excluded} leaked into durable data"
        );
    }
}

#[test]
fn schema_v2_loads_one_content_addressed_request_and_calls_real_verifier() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("durable");
    let source = temp.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("input.txt"), b"source").unwrap();
    let request = structurally_rejected_request(&source);
    let (request_id, _) = write_request(&root, &request);

    let output = run_stdin(&root, &schema_v2_input(&request_id));

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value = payload(&output);
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["status"], "observed");
    assert_eq!(value["verification_status"], "rejected");
    assert_eq!(value["rejection_code"], "invalid_contract");
    assert_eq!(value["completion_evidence_recorded"], false);
    assert_eq!(value["egress_enforcement"], "policy_only");
    assert_eq!(value["production_effect"], "none");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains(&request_id));
    assert!(!stdout.contains(&root.to_string_lossy().to_string()));
    assert!(!stdout.contains(&source.to_string_lossy().to_string()));
    assert!(!root
        .join("local-verification")
        .join("store.sqlite3")
        .exists());
    assert_eq!(
        fs::read_dir(root.join("goal-runtime-shadow").join("snapshots"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn schema_v2_hash_mismatch_invalid_utf8_and_unknown_input_are_bounded() {
    for mode in ["hash_mismatch", "invalid_utf8", "unknown_input"] {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("durable");
        let source = temp.path().join("source");
        fs::create_dir_all(&source).unwrap();
        let request_root = root
            .join("goal-runtime-shadow")
            .join("verification-requests");
        fs::create_dir_all(&request_root).unwrap();
        let (request_id, input) = match mode {
            "hash_mismatch" => {
                let request_id = format!("vreq.sha256.{}", "a".repeat(64));
                fs::write(request_root.join(format!("{request_id}.json")), b"{}").unwrap();
                (request_id.clone(), schema_v2_input(&request_id))
            }
            "invalid_utf8" => {
                let bytes = [0xff, 0xfe, 0xfd];
                let request_id = format!("vreq.sha256.{}", verification_sha256_hex(&bytes));
                fs::write(request_root.join(format!("{request_id}.json")), bytes).unwrap();
                (request_id.clone(), schema_v2_input(&request_id))
            }
            _ => {
                let request = structurally_rejected_request(&source);
                let (request_id, _) = write_request(&root, &request);
                let mut value: Value = serde_json::from_str(&schema_v2_input(&request_id)).unwrap();
                value["raw_task_body"] = json!("private-secret");
                (request_id, value.to_string())
            }
        };
        let output = run_stdin(&root, &input);
        assert!(output.status.success(), "{mode}");
        let value = payload(&output);
        assert_eq!(value["status"], "configuration_error", "{mode}");
        assert_eq!(value["verification_status"], "observer_error", "{mode}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(!stdout.contains(&request_id), "{mode}");
        assert!(!stdout.contains("private-secret"), "{mode}");
    }
}

#[test]
fn schema_v2_invalid_root_and_input_file_are_configuration_errors() {
    let request_id = format!("vreq.sha256.{}", "a".repeat(64));
    let relative = run_stdin(
        Path::new("relative-shadow-root"),
        &schema_v2_input(&request_id),
    );
    assert!(relative.status.success());
    assert_eq!(payload(&relative)["status"], "configuration_error");

    let temp = TempDir::new().unwrap();
    let root = temp.path().join("durable");
    fs::create_dir_all(&root).unwrap();
    let input_path = temp.path().join("v2-input.json");
    fs::write(&input_path, schema_v2_input(&request_id)).unwrap();
    let from_file = run_input_file(&root, &input_path);
    assert!(from_file.status.success());
    assert_eq!(payload(&from_file)["status"], "configuration_error");
}

#[test]
fn schema_v2_missing_protected_workspace_is_a_closed_configuration_error() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("durable");
    let request_id = format!("vreq.sha256.{}", "a".repeat(64));

    let output = run_stdin_with_protected_workspace(&root, &schema_v2_input(&request_id), None);

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(payload(&output)["status"], "configuration_error");
    assert_eq!(payload(&output)["verification_status"], "observer_error");
    assert_eq!(payload(&output)["production_effect"], "none");
    assert!(!root.exists());
}

#[cfg(windows)]
#[test]
fn schema_v2_device_namespaces_are_rejected_before_filesystem_side_effects() {
    let request_id = format!("vreq.sha256.{}", "a".repeat(64));
    for root in [
        r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\verification",
        r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\verification",
    ] {
        let current_dir = TempDir::new().unwrap();
        assert_eq!(fs::read_dir(current_dir.path()).unwrap().count(), 0);

        let output = run_stdin_from(
            Path::new(root),
            &schema_v2_input(&request_id),
            current_dir.path(),
        );

        assert!(output.status.success(), "{root}");
        assert!(output.stderr.is_empty(), "{root}");
        assert_eq!(payload(&output)["status"], "configuration_error", "{root}");
        assert_eq!(
            payload(&output)["verification_status"],
            "observer_error",
            "{root}"
        );
        assert_eq!(
            fs::read_dir(current_dir.path()).unwrap().count(),
            0,
            "{root} created a relative filesystem artifact"
        );
    }
}

#[cfg(windows)]
#[test]
fn schema_v2_existing_volume_alias_cannot_hide_behind_canonical_drive_root() {
    let durable_root = TempDir::new().unwrap();
    let source_root = TempDir::new().unwrap();
    let Some((raw_volume_alias, canonical_drive_root)) = existing_volume_alias(durable_root.path())
    else {
        eprintln!("SKIP: this Windows host does not expose a usable Volume GUID alias");
        return;
    };
    assert!(raw_volume_alias.exists());
    assert_eq!(
        fs::canonicalize(&raw_volume_alias).unwrap(),
        canonical_drive_root
    );
    let request = structurally_rejected_request(source_root.path());
    let (request_id, request_bytes) = write_request(&canonical_drive_root, &request);
    let request_path = canonical_drive_root
        .join("goal-runtime-shadow")
        .join("verification-requests")
        .join(format!("{request_id}.json"));
    let files_before = files_below(&canonical_drive_root);

    let output = run_stdin(&raw_volume_alias, &schema_v2_input(&request_id));

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(payload(&output)["status"], "configuration_error");
    assert_eq!(payload(&output)["verification_status"], "observer_error");
    assert_eq!(fs::read(&request_path).unwrap(), request_bytes);
    assert_eq!(files_below(&canonical_drive_root), files_before);
    assert!(!canonical_drive_root
        .join("goal-runtime-shadow")
        .join("snapshots")
        .exists());
    assert!(!canonical_drive_root.join("local-verification").exists());
    assert_eq!(
        files_before,
        vec![request_path],
        "fixture must contain only the immutable request before invocation"
    );
}

#[cfg(windows)]
#[test]
fn existing_volume_alias_cannot_hide_the_protected_workspace() {
    let protected_workspace = TempDir::new().unwrap();
    let Some((raw_volume_alias, _)) = existing_volume_alias(protected_workspace.path()) else {
        eprintln!("SKIP: this Windows host does not expose a usable Volume GUID alias");
        return;
    };
    let files_before = files_below(protected_workspace.path());

    let output = run_stdin_with_protected_workspace(
        &raw_volume_alias,
        &normalized_input("none", "success"),
        Some(protected_workspace.path()),
    );

    assert!(!output.status.success());
    assert_eq!(payload(&output)["error_code"], "protected_root");
    assert_eq!(payload(&output)["production_effect"], "none");
    assert_eq!(files_below(protected_workspace.path()), files_before);
}
