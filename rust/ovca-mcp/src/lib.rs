/// Oracle MCP base server.
/// Axum router factory — every server binary calls McpServer::builder()
/// .tool(...).resource(...).into_router() then serves it on its port.
///
/// MCP protocol surface (matches Python base_server.py exactly):
///   GET  /health          → { ok, name, agent_id, tools, resources, prompts }
///   GET  /registry        → { name, tools: [...], resources: [...], prompts: [...] }
///   POST /tools/call      → McpToolCall → McpResponse
///   GET  /tools/list      → [ToolSpec, ...]
///   POST /resources/get   → McpResourceCall → McpResponse
///   GET  /resources/list  → [ResourceSpec, ...]
///   POST /prompts/get     → McpPromptCall → McpResponse
///   GET  /prompts/list    → [PromptSpec, ...]
///   GET  /sse             → Server-Sent Events stream
pub mod server;
pub mod sse;

pub use ovca_observability::init_tracing;
pub use server::{McpServer, McpServerBuilder, PromptSpec, ResourceSpec, ToolSpec};
