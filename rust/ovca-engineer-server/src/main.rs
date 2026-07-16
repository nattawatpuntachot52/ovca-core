mod ops_health;

use anyhow::anyhow;
use anyhow::Result;
use ovca_llm_client::{
    load_jsonl_values, parse_args, parse_timestamp, port_from_env, read_jsonl_tail_values,
    safe_json,
};
use ovca_mcp::init_tracing;
use ovca_mcp::server::{BoxFuture, McpServer};
use serde_json::{json, Value};
use std::env;
use std::path::{Path, PathBuf};
use tracing::info;

use crate::ops_health::{
    compute_ops_health_latest, ops_health_history_path, ops_health_latest_path, strict_exit_code,
    write_ops_health_snapshot,
};

const DEFAULT_PORT: u16 = 18784;

fn coordinator_state_path(root: &Path) -> PathBuf {
    root.join("memory").join("coordinator").join("state.json")
}

fn reflection_incidents_path(root: &Path) -> PathBuf {
    root.join("logs")
        .join("reflection_lane")
        .join("incidents.jsonl")
}

fn automation_status(root: &Path) -> Value {
    let ops = compute_ops_health_latest(root);
    let state = safe_json(&coordinator_state_path(root), json!({}));
    let workers = state
        .get("workers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let worker_rows = ["coordinator", "engineer", "reviewer", "auditor"]
        .iter()
        .map(|agent_id| {
            let worker = workers
                .get(*agent_id)
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            json!({
                "agent": agent_id,
                "enabled": worker.get("enabled").and_then(Value::as_bool).unwrap_or(false),
                "schedule_minutes": worker.get("schedule_minutes").cloned().unwrap_or(Value::Null),
                "last_run_at": worker.get("last_run_at").and_then(Value::as_str).unwrap_or(""),
                "last_result": worker.get("last_result").and_then(Value::as_str).unwrap_or(""),
            })
        })
        .collect::<Vec<_>>();

    json!({
        "ok": true,
        "overall_status": ops.get("overall_status").and_then(Value::as_str).unwrap_or("unknown"),
        "summary": ops.get("summary").cloned().unwrap_or_else(|| json!({})),
        "workers": worker_rows,
        "jobs": ops.get("jobs").cloned().unwrap_or_else(|| json!([])),
    })
}

fn spec_request_draft(args: Value) -> Value {
    let problem = args
        .get("problem")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if problem.is_empty() {
        return json!({"ok": false, "error": "problem is required"});
    }
    let inputs = args
        .get("inputs")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let outputs = args
        .get("outputs")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();

    let draft = format!(
        "# Engineer Spec Request\n\nProblem:\n- {}\n\nInputs:\n- {}\n\nExpected Outputs:\n- {}\n\nConstraints:\n- Keep flow stable\n- Preserve existing interfaces unless explicitly migrated\n- Add tests for new behavior\n\nRollback:\n- Revert touched files and rerun target tests\n",
        problem,
        if inputs.is_empty() { "TBD" } else { inputs },
        if outputs.is_empty() { "TBD" } else { outputs },
    );
    json!({
        "ok": true,
        "draft": draft,
    })
}

fn ops_health(root: &Path, args: Value) -> Value {
    let limit_history = args
        .get("limit_history")
        .and_then(Value::as_u64)
        .unwrap_or(20) as usize;
    json!({
        "ok": true,
        "latest": compute_ops_health_latest(root),
        "history": read_jsonl_tail_values(&ops_health_history_path(root), limit_history.clamp(1, 100)),
    })
}

fn read_reflection_incidents(root: &Path, agent: &str) -> Vec<Value> {
    load_jsonl_values(&reflection_incidents_path(root))
        .into_iter()
        .filter(|row| {
            row["agent"]
                .as_str()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case(agent)
        })
        .collect()
}

fn incident_log(root: &Path, args: Value) -> Value {
    let since_date = args
        .get("since_date")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
    let cutoff = parse_timestamp(since_date);

    let mut rows = read_reflection_incidents(root, "engineer")
        .into_iter()
        .filter(|row| {
            let ts = row
                .get("ts")
                .and_then(Value::as_str)
                .and_then(parse_timestamp);
            match (cutoff, ts) {
                (Some(cutoff), Some(ts)) => ts >= cutoff,
                _ => true,
            }
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        right["ts"]
            .as_str()
            .unwrap_or("")
            .cmp(left["ts"].as_str().unwrap_or(""))
    });

    if rows.is_empty() {
        let problem_rows =
            read_jsonl_tail_values(&ops_health_history_path(root), limit.clamp(1, 100))
                .into_iter()
                .filter(|row| {
                    matches!(
                        row["overall_status"]
                            .as_str()
                            .unwrap_or("")
                            .to_ascii_lowercase()
                            .as_str(),
                        "warn" | "fail"
                    )
                })
                .collect::<Vec<_>>();
        return json!({
            "ok": true,
            "count": problem_rows.len(),
            "items": problem_rows.into_iter().take(limit.clamp(1, 100)).collect::<Vec<_>>(),
        });
    }

    json!({
        "ok": true,
        "count": rows.len(),
        "items": rows.into_iter().take(limit.clamp(1, 100)).collect::<Vec<_>>(),
    })
}

#[derive(Debug)]
struct Cli {
    port: u16,
    root: PathBuf,
    ops_health_check: bool,
    strict: bool,
    output: Option<PathBuf>,
    history: Option<PathBuf>,
}

fn print_help() {
    println!(
        "Usage: ovca-engineer-server [--port 18784] [--root <path>] [--ops-health-check] [--strict] [--output <path>] [--history <path>]"
    );
}

fn parse_cli(default_port: u16) -> Result<Cli> {
    let (port, root) = parse_args(default_port);
    let mut cli = Cli {
        port,
        root,
        ops_health_check: false,
        strict: false,
        output: None,
        history: None,
    };

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                if args.next().is_none() {
                    return Err(anyhow!("--port requires a value"));
                }
            }
            "--root" => {
                let Some(value) = args.next() else {
                    return Err(anyhow!("--root requires a path"));
                };
                cli.root = PathBuf::from(value);
            }
            "--ops-health-check" => cli.ops_health_check = true,
            "--strict" => cli.strict = true,
            "--output" => {
                let Some(value) = args.next() else {
                    return Err(anyhow!("--output requires a path"));
                };
                cli.output = Some(PathBuf::from(value));
            }
            "--history" => {
                let Some(value) = args.next() else {
                    return Err(anyhow!("--history requires a path"));
                };
                cli.history = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(anyhow!("unknown argument: {other}")),
        }
    }

    Ok(cli)
}

fn build_router(root: PathBuf) -> axum::Router {
    let empty_schema = json!({"type": "object", "properties": {}});
    let spec_schema = json!({
        "type": "object",
        "properties": {
            "problem": {"type": "string"},
            "inputs": {"type": "string"},
            "outputs": {"type": "string"}
        },
        "required": ["problem"]
    });
    let ops_schema = json!({
        "type": "object",
        "properties": {
            "limit_history": {"type": "integer"}
        }
    });
    let incident_schema = json!({
        "type": "object",
        "properties": {
            "since_date": {"type": "string"},
            "limit": {"type": "integer"}
        }
    });

    let (router, _state) = McpServer::builder("oracle-engineer-mcp", "engineer")
        .tool(
            "engineer_automation_status",
            "Read Engineer automation and worker health.",
            empty_schema.clone(),
            {
                let root = root.clone();
                move |_args: Value| {
                    let root = root.clone();
                    Box::pin(async move { automation_status(&root) }) as BoxFuture<Value>
                }
            },
        )
        .tool(
            "engineer_spec_request_draft",
            "Draft a spec template for an engineering request.",
            spec_schema,
            move |args: Value| {
                Box::pin(async move { spec_request_draft(args) }) as BoxFuture<Value>
            },
        )
        .tool(
            "engineer_ops_health",
            "Read Engineer/Oracle ops health latest plus history tail.",
            ops_schema,
            {
                let root = root.clone();
                move |args: Value| {
                    let root = root.clone();
                    Box::pin(async move { ops_health(&root, args) }) as BoxFuture<Value>
                }
            },
        )
        .tool(
            "engineer_incident_log",
            "Read Engineer incident log or warn/fail ops history.",
            incident_schema,
            {
                let root = root.clone();
                move |args: Value| {
                    let root = root.clone();
                    Box::pin(async move { incident_log(&root, args) }) as BoxFuture<Value>
                }
            },
        )
        .into_router();

    router
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing("info");

    dotenvy::dotenv().ok();

    let default_port = port_from_env("MCP_ENGINEER_PORT", DEFAULT_PORT);
    let cli = parse_cli(default_port)?;
    info!(port = cli.port, root = %cli.root.display(), ops_health_check = cli.ops_health_check, "oracle-engineer-server starting");

    if cli.ops_health_check {
        let output_path = cli
            .output
            .unwrap_or_else(|| ops_health_latest_path(&cli.root));
        let history_path = cli
            .history
            .unwrap_or_else(|| ops_health_history_path(&cli.root));
        let payload = write_ops_health_snapshot(&cli.root, &output_path, &history_path)?;
        println!("{}", serde_json::to_string_pretty(&payload)?);
        let exit_code = strict_exit_code(&payload, cli.strict);
        if exit_code != 0 {
            std::process::exit(exit_code);
        }
        return Ok(());
    }

    let addr = format!("127.0.0.1:{}", cli.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("listening on http://{}", addr);
    axum::serve(listener, build_router(cli.root)).await?;
    Ok(())
}
