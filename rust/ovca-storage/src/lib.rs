/// Oracle file I/O layer.
/// All reads/writes go through here — consistent atomic writes, JSONL append safety,
/// brain markdown parser, SQLite helpers.
/// Functions are sync; callers use spawn_blocking if on async executor.
pub mod brain;
pub mod json;
pub mod jsonl;
pub mod sqlite;

pub use brain::{list_brain_nodes, parse_brain_node, write_brain_node};
pub use json::{read_json, write_json_atomic};
pub use jsonl::{append_jsonl, read_jsonl, read_jsonl_tail};
pub use sqlite::{acquire_task_lock, open_db, release_task_lock};
