/// oracle-brain — in-memory brain cache, permission matrix, search, and MCP tools.
/// Sprint 2 of the Rust hotpath migration.
pub mod cache;
pub mod permissions;
pub mod search;
pub mod tools;

pub use cache::BrainCache;
