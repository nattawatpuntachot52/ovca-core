use anyhow::Result;
use ovca_mcp::init_tracing;
use tracing::info;

use ovca_policy_tools::http_server::build_router;

const DEFAULT_PORT: u16 = 8775;

fn parse_args(default_port: u16) -> (u16, String) {
    let argv: Vec<String> = std::env::args().collect();
    let mut port = std::env::var("MCP_POLICY_PORT")
        .ok()
        .and_then(|raw| raw.parse::<u16>().ok())
        .unwrap_or(default_port);
    let mut root = std::env::current_dir()
        .ok()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| ".".to_string());

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--port" => {
                if let Some(raw) = argv.get(i + 1) {
                    port = raw.parse::<u16>().unwrap_or(port);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--root" => {
                if let Some(raw) = argv.get(i + 1) {
                    root = raw.to_string();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }

    (port, root)
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing("info");
    dotenvy::dotenv().ok();

    let (port, root) = parse_args(DEFAULT_PORT);
    info!(port, root, "oracle-policy-tools starting");

    let addr = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("listening on http://{}", addr);
    axum::serve(listener, build_router()).await?;
    Ok(())
}
