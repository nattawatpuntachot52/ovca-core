use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};
use ovca_llm_client::{latest_file_by_mtime, now_utc, parse_timestamp_value};
use ovca_storage::{append_jsonl, write_json_atomic};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub fn compute_ops_health_latest(root: &Path) -> Value {
    compute_ops_health_latest_at(root, now_utc())
}

pub fn ops_health_manifest_path(root: &Path) -> PathBuf {
    root.join("memory")
        .join("coordinator")
        .join("jobs_manifest.json")
}

pub fn ops_health_latest_path(root: &Path) -> PathBuf {
    root.join("logs").join("ops_health_latest.json")
}

pub fn ops_health_history_path(root: &Path) -> PathBuf {
    root.join("logs").join("ops_health_history.jsonl")
}

pub fn write_ops_health_snapshot(
    root: &Path,
    output_path: &Path,
    history_path: &Path,
) -> Result<Value> {
    let payload = compute_ops_health_latest(root);
    write_json_atomic(output_path, &payload)?;
    append_jsonl(
        history_path,
        &json!({
            "generated_at": payload
                .get("generated_at")
                .cloned()
                .unwrap_or_else(|| Value::String(iso_utc(now_utc()))),
            "overall_status": payload
                .get("overall_status")
                .cloned()
                .unwrap_or_else(|| Value::String("unknown".to_string())),
            "summary": payload.get("summary").cloned().unwrap_or_else(|| json!({})),
            "manifest_path": payload
                .get("manifest_path")
                .cloned()
                .unwrap_or_else(|| Value::String(ops_health_manifest_path(root).display().to_string())),
        }),
    )?;
    Ok(payload)
}

pub fn strict_exit_code(payload: &Value, strict: bool) -> i32 {
    if strict && payload.get("overall_status").and_then(Value::as_str) == Some("fail") {
        return 1;
    }
    0
}

fn compute_ops_health_latest_at(root: &Path, ref_now: DateTime<Utc>) -> Value {
    let manifest_path = ops_health_manifest_path(root);
    if !manifest_path.exists() {
        return json!({
            "generated_at": iso_utc(ref_now),
            "manifest_path": manifest_path.display().to_string(),
            "overall_status": "fail",
            "summary": {"ok": 0, "warn": 0, "fail": 1, "total": 1},
            "jobs": [
                {
                    "id": "manifest",
                    "type": "manifest",
                    "status": "fail",
                    "message": format!("Missing manifest file: {}", manifest_path.display()),
                    "checked_at": iso_utc(ref_now),
                }
            ],
        });
    }

    let manifest = match read_json_file(&manifest_path) {
        Ok(value) => value,
        Err(err) => {
            return json!({
                "generated_at": iso_utc(ref_now),
                "manifest_path": manifest_path.display().to_string(),
                "overall_status": "fail",
                "summary": {"ok": 0, "warn": 0, "fail": 1, "total": 1},
                "jobs": [
                    {
                        "id": "manifest",
                        "type": "manifest",
                        "status": "fail",
                        "message": format!("Invalid manifest file: {} ({})", manifest_path.display(), err),
                        "checked_at": iso_utc(ref_now),
                    }
                ],
            });
        }
    };

    let jobs = manifest
        .get("jobs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut results: Vec<Value> = Vec::new();
    for raw_job in jobs {
        if !raw_job.is_object() {
            continue;
        }
        let mut result = evaluate_job(root, &raw_job, ref_now);
        if let Some(description) = raw_job.get("description").and_then(Value::as_str) {
            result["description"] = Value::String(description.to_string());
        }
        if let Some(severity) = raw_job.get("severity").and_then(Value::as_str) {
            result["severity"] = Value::String(severity.to_string());
        } else {
            result["severity"] = Value::String("medium".to_string());
        }
        results.push(result);
    }

    let summary = json!({
        "ok": results.iter().filter(|row| status_of(row) == "ok").count(),
        "warn": results.iter().filter(|row| status_of(row) == "warn").count(),
        "fail": results.iter().filter(|row| status_of(row) == "fail").count(),
        "total": results.len(),
    });

    json!({
        "generated_at": iso_utc(ref_now),
        "manifest_path": manifest_path.display().to_string(),
        "overall_status": overall_status(&results),
        "summary": summary,
        "jobs": results,
    })
}

fn read_json_file(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|err| err.to_string())?;
    serde_json::from_str::<Value>(&text).map_err(|err| err.to_string())
}

fn iso_utc(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Secs, false)
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn resolve_path(root: &Path, raw_path: &str) -> PathBuf {
    let path = PathBuf::from(raw_path);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn status_of(row: &Value) -> &str {
    row.get("status").and_then(Value::as_str).unwrap_or("warn")
}

fn rank_status(status: &str) -> i32 {
    match status {
        "fail" => 3,
        "warn" => 2,
        _ => 1,
    }
}

fn overall_status(rows: &[Value]) -> &'static str {
    if rows.is_empty() {
        return "warn";
    }
    let worst = rows
        .iter()
        .map(|row| rank_status(status_of(row)))
        .max()
        .unwrap_or(2);
    match worst {
        3 => "fail",
        2 => "warn",
        _ => "ok",
    }
}

fn outcome_or_default(job: &Value, key: &str, default: &str) -> String {
    let value = job
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .trim()
        .to_ascii_lowercase();
    match value.as_str() {
        "ok" | "warn" | "fail" => value,
        _ => default.to_string(),
    }
}

fn build_missing_result(job: &Value, message: String, ref_now: DateTime<Utc>) -> Value {
    json!({
        "id": job.get("id").and_then(Value::as_str).unwrap_or("unknown"),
        "type": job.get("type").and_then(Value::as_str).unwrap_or("unknown"),
        "status": outcome_or_default(job, "on_missing", "fail"),
        "message": message,
        "checked_at": iso_utc(ref_now),
    })
}

fn deep_get<'a>(payload: &'a Value, dotted_key: &str) -> Option<&'a Value> {
    let mut current = payload;
    for key in dotted_key.split('.') {
        current = current.get(key)?;
    }
    Some(current)
}

fn value_as_f64(value: Option<&Value>, default: f64) -> f64 {
    value
        .and_then(|item| {
            item.as_f64()
                .or_else(|| item.as_i64().map(|num| num as f64))
        })
        .unwrap_or(default)
}

fn age_minutes(ref_now: DateTime<Utc>, ts: DateTime<Utc>) -> f64 {
    (ref_now - ts).num_milliseconds() as f64 / 60_000.0
}

fn evaluate_json_timestamp(root: &Path, job: &Value, ref_now: DateTime<Utc>) -> Value {
    let path = resolve_path(root, job.get("path").and_then(Value::as_str).unwrap_or(""));
    if !path.exists() {
        return build_missing_result(
            job,
            format!("Missing JSON file: {}", path.display()),
            ref_now,
        );
    }

    let payload = match read_json_file(&path) {
        Ok(value) => value,
        Err(err) => {
            return json!({
                "id": job.get("id").and_then(Value::as_str).unwrap_or("unknown"),
                "type": "json_timestamp",
                "status": "fail",
                "message": format!("Invalid JSON file: {} ({})", path.display(), err),
                "checked_at": iso_utc(ref_now),
            });
        }
    };

    let field = job
        .get("timestamp_field")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let raw_ts = if field.is_empty() {
        None
    } else {
        deep_get(&payload, field)
    };
    let ts = raw_ts.and_then(parse_timestamp_value);
    let Some(ts) = ts else {
        return json!({
            "id": job.get("id").and_then(Value::as_str).unwrap_or("unknown"),
            "type": "json_timestamp",
            "status": "fail",
            "message": format!("Missing/invalid timestamp_field '{}'", field),
            "checked_at": iso_utc(ref_now),
            "path": path.display().to_string(),
            "timestamp_raw": raw_ts.cloned().unwrap_or(Value::Null),
        });
    };

    let age = age_minutes(ref_now, ts);
    let max_age = value_as_f64(job.get("max_age_minutes"), 60.0);
    let warn_age = value_as_f64(job.get("warn_age_minutes"), max_age);
    let (status, message) = if age <= warn_age {
        (
            "ok".to_string(),
            format!("Timestamp fresh ({:.1}m <= {:.1}m)", age, warn_age),
        )
    } else if age <= max_age {
        (
            "warn".to_string(),
            format!(
                "Timestamp pre-limit warning ({:.1}m in {:.1}-{:.1}m)",
                age, warn_age, max_age
            ),
        )
    } else {
        (
            outcome_or_default(job, "on_stale", "fail"),
            format!("Timestamp stale ({:.1}m > {:.1}m)", age, max_age),
        )
    };

    let mut result = json!({
        "id": job.get("id").and_then(Value::as_str).unwrap_or("unknown"),
        "type": "json_timestamp",
        "status": status,
        "message": message,
        "checked_at": iso_utc(ref_now),
        "path": path.display().to_string(),
        "timestamp_field": field,
        "timestamp_value": iso_utc(ts),
        "age_minutes": round2(age),
        "max_age_minutes": max_age,
    });
    if warn_age < max_age {
        result["warn_age_minutes"] = json!(warn_age);
    }
    result
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let mut p = 0usize;
    let mut t = 0usize;
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0usize;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star_idx = Some(p);
            p += 1;
            match_idx = t;
        } else if let Some(star) = star_idx {
            p = star + 1;
            match_idx += 1;
            t = match_idx;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }

    p == pattern.len()
}

fn evaluate_latest_glob_mtime(root: &Path, job: &Value, ref_now: DateTime<Utc>) -> Value {
    let base = resolve_path(root, job.get("path").and_then(Value::as_str).unwrap_or(""));
    let pattern = job
        .get("pattern")
        .and_then(Value::as_str)
        .unwrap_or("*")
        .trim();
    let pattern = if pattern.is_empty() { "*" } else { pattern };

    if !base.exists() {
        return build_missing_result(
            job,
            format!("Missing directory: {}", base.display()),
            ref_now,
        );
    }

    let latest = if pattern == "*.jsonl" {
        latest_file_by_mtime(&base, ".jsonl")
    } else {
        fs::read_dir(&base)
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| wildcard_match(pattern, name))
                    .unwrap_or(false)
            })
            .filter_map(|path| {
                let modified = path.metadata().ok()?.modified().ok()?;
                Some((modified, path))
            })
            .max_by_key(|(modified, _)| *modified)
            .map(|(_, path)| path)
    };

    let Some(latest) = latest else {
        return build_missing_result(
            job,
            format!("No files matched: {}\\{}", base.display(), pattern),
            ref_now,
        );
    };

    let latest_dt: DateTime<Utc> = latest
        .metadata()
        .ok()
        .and_then(|meta| meta.modified().ok())
        .map(DateTime::<Utc>::from)
        .unwrap_or(ref_now);
    let age = age_minutes(ref_now, latest_dt);
    let max_age = value_as_f64(job.get("max_age_minutes"), 60.0);
    let status = if age <= max_age {
        "ok".to_string()
    } else {
        outcome_or_default(job, "on_stale", "warn")
    };
    let message = if status == "ok" {
        format!("Latest file fresh ({:.1}m <= {:.1}m)", age, max_age)
    } else {
        format!("Latest file stale ({:.1}m > {:.1}m)", age, max_age)
    };

    json!({
        "id": job.get("id").and_then(Value::as_str).unwrap_or("unknown"),
        "type": "latest_glob_mtime",
        "status": status,
        "message": message,
        "checked_at": iso_utc(ref_now),
        "path": base.display().to_string(),
        "pattern": pattern,
        "latest_file": latest.display().to_string(),
        "latest_mtime": iso_utc(latest_dt),
        "age_minutes": round2(age),
        "max_age_minutes": max_age,
    })
}

fn evaluate_file_mtime(root: &Path, job: &Value, ref_now: DateTime<Utc>) -> Value {
    let path = resolve_path(root, job.get("path").and_then(Value::as_str).unwrap_or(""));
    if !path.exists() {
        return build_missing_result(job, format!("Missing file: {}", path.display()), ref_now);
    }
    if !path.is_file() {
        return build_missing_result(
            job,
            format!("Path is not a file: {}", path.display()),
            ref_now,
        );
    }

    let modified_dt: DateTime<Utc> = path
        .metadata()
        .ok()
        .and_then(|meta| meta.modified().ok())
        .map(DateTime::<Utc>::from)
        .unwrap_or(ref_now);
    let age = age_minutes(ref_now, modified_dt);
    let max_age = value_as_f64(job.get("max_age_minutes"), 60.0);
    let status = if age <= max_age {
        "ok".to_string()
    } else {
        outcome_or_default(job, "on_stale", "warn")
    };
    let message = if status == "ok" {
        format!("File fresh ({:.1}m <= {:.1}m)", age, max_age)
    } else {
        format!("File stale ({:.1}m > {:.1}m)", age, max_age)
    };

    json!({
        "id": job.get("id").and_then(Value::as_str).unwrap_or("unknown"),
        "type": "file_mtime",
        "status": status,
        "message": message,
        "checked_at": iso_utc(ref_now),
        "path": path.display().to_string(),
        "mtime": iso_utc(modified_dt),
        "age_minutes": round2(age),
        "max_age_minutes": max_age,
    })
}

fn evaluate_job(root: &Path, job: &Value, ref_now: DateTime<Utc>) -> Value {
    let job_type = job
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match job_type.as_str() {
        "json_timestamp" => evaluate_json_timestamp(root, job, ref_now),
        "latest_glob_mtime" => evaluate_latest_glob_mtime(root, job, ref_now),
        "file_mtime" => evaluate_file_mtime(root, job, ref_now),
        _ => json!({
            "id": job.get("id").and_then(Value::as_str).unwrap_or("unknown"),
            "type": if job_type.is_empty() { "unknown" } else { job_type.as_str() },
            "status": "fail",
            "message": format!("Unsupported job type: {}", job_type),
            "checked_at": iso_utc(ref_now),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_json(path: &Path, value: Value) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    fn write_text(path: &Path, text: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, text).unwrap();
    }

    fn parse_ts(raw: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(raw)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn build_manifest(root: &Path, jobs: Vec<Value>) {
        write_json(
            &root
                .join("memory")
                .join("coordinator")
                .join("jobs_manifest.json"),
            json!({
                "version": 2,
                "updated_at": "2026-04-21T00:00:00+00:00",
                "jobs": jobs,
            }),
        );
    }

    fn file_mtime(path: &Path) -> DateTime<Utc> {
        path.metadata()
            .unwrap()
            .modified()
            .map(DateTime::<Utc>::from)
            .unwrap()
    }

    fn read_json(path: &Path) -> Value {
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn compute_latest_ignores_snapshot_summary_file() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        write_json(
            &root.join("logs").join("coordinator_last_report.json"),
            json!({"coordinator": {"last_tick_at": "2026-04-21T05:55:18+00:00"}}),
        );
        write_text(
            &root.join("logs").join("dispatch_runs.jsonl"),
            "{\"ok\":true}\n",
        );
        write_text(
            &root
                .join("logs")
                .join("reflection")
                .join("engineer")
                .join("2026-04-21.jsonl"),
            "{\"ts\":\"2026-04-21T05:55:18+00:00\"}\n",
        );
        write_json(
            &root.join("logs").join("ops_health_latest.json"),
            json!({"overall_status": "fail", "summary": {"ok": 0, "warn": 0, "fail": 99, "total": 99}}),
        );
        build_manifest(
            root,
            vec![
                json!({
                    "id": "coordinator_tick",
                    "type": "json_timestamp",
                    "path": "logs/coordinator_last_report.json",
                    "timestamp_field": "coordinator.last_tick_at",
                    "warn_age_minutes": 40,
                    "max_age_minutes": 45,
                    "on_missing": "fail",
                    "on_stale": "fail",
                }),
                json!({
                    "id": "dispatch_runs",
                    "type": "file_mtime",
                    "path": "logs/dispatch_runs.jsonl",
                    "max_age_minutes": 10080,
                    "on_missing": "warn",
                    "on_stale": "warn",
                }),
                json!({
                    "id": "engineer_reflection",
                    "type": "latest_glob_mtime",
                    "path": "logs/reflection/engineer",
                    "pattern": "*.jsonl",
                    "max_age_minutes": 10080,
                    "on_missing": "warn",
                    "on_stale": "warn",
                }),
            ],
        );

        let ref_now = parse_ts("2026-04-21T06:03:11+00:00");
        let latest = compute_ops_health_latest_at(root, ref_now);

        assert_eq!(latest["overall_status"], "ok");
        assert_eq!(latest["summary"]["ok"], 3);
        assert_eq!(latest["summary"]["fail"], 0);
        assert_eq!(latest["jobs"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn file_mtime_stale_honors_on_stale() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let target = root.join("logs").join("dispatch_runs.jsonl");
        write_text(&target, "{\"ok\":true}\n");
        let modified = file_mtime(&target);
        let ref_now = modified + chrono::Duration::minutes(25);

        let result = evaluate_file_mtime(
            root,
            &json!({
                "id": "dispatch_runs",
                "type": "file_mtime",
                "path": "logs/dispatch_runs.jsonl",
                "max_age_minutes": 10,
                "on_stale": "fail",
            }),
            ref_now,
        );

        assert_eq!(result["status"], "fail");
        assert_eq!(result["type"], "file_mtime");
        assert!(result["message"].as_str().unwrap().contains("File stale"));
    }

    #[test]
    fn latest_glob_mtime_missing_dir_honors_on_missing() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let ref_now = parse_ts("2026-04-21T06:03:11+00:00");

        let result = evaluate_latest_glob_mtime(
            root,
            &json!({
                "id": "engineer_reflection",
                "type": "latest_glob_mtime",
                "path": "logs/reflection/engineer",
                "pattern": "*.jsonl",
                "max_age_minutes": 10080,
                "on_missing": "warn",
            }),
            ref_now,
        );

        assert_eq!(result["status"], "warn");
        assert!(result["message"]
            .as_str()
            .unwrap()
            .contains("Missing directory"));
    }

    #[test]
    fn json_timestamp_invalid_field_fails_with_timestamp_raw() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        write_json(
            &root.join("logs").join("coordinator_last_report.json"),
            json!({"coordinator": {"last_tick_at": 123}}),
        );
        let ref_now = parse_ts("2026-04-21T06:03:11+00:00");

        let result = evaluate_json_timestamp(
            root,
            &json!({
                "id": "coordinator_tick",
                "type": "json_timestamp",
                "path": "logs/coordinator_last_report.json",
                "timestamp_field": "coordinator.last_tick_at",
            }),
            ref_now,
        );

        assert_eq!(result["status"], "fail");
        assert_eq!(result["timestamp_raw"], json!(123));
    }

    #[test]
    fn write_snapshot_updates_latest_and_history() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let dispatch_runs = root.join("logs").join("dispatch_runs.jsonl");
        write_text(&dispatch_runs, "{\"ok\":true}\n");
        build_manifest(
            root,
            vec![json!({
                "id": "dispatch_runs",
                "type": "file_mtime",
                "path": "logs/dispatch_runs.jsonl",
                "max_age_minutes": 60,
                "on_missing": "warn",
                "on_stale": "warn",
            })],
        );

        let output_path = root.join("logs").join("ops_health_latest.json");
        let history_path = root.join("logs").join("ops_health_history.jsonl");
        let payload = write_ops_health_snapshot(root, &output_path, &history_path).unwrap();

        let latest = read_json(&output_path);
        let history = fs::read_to_string(&history_path).unwrap();
        let history_row: Value = serde_json::from_str(history.lines().last().unwrap()).unwrap();

        assert_eq!(latest["overall_status"], payload["overall_status"]);
        assert_eq!(latest["summary"]["ok"], 1);
        assert_eq!(history_row["overall_status"], payload["overall_status"]);
        assert_eq!(history_row["summary"]["total"], 1);
    }

    #[test]
    fn strict_exit_code_only_fails_on_fail() {
        assert_eq!(strict_exit_code(&json!({"overall_status": "ok"}), true), 0);
        assert_eq!(
            strict_exit_code(&json!({"overall_status": "warn"}), true),
            0
        );
        assert_eq!(
            strict_exit_code(&json!({"overall_status": "fail"}), false),
            0
        );
        assert_eq!(
            strict_exit_code(&json!({"overall_status": "fail"}), true),
            1
        );
    }
}
