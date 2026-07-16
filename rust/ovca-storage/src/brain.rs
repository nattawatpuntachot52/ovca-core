/// Brain node markdown parser and writer.
/// Extends graph_core::parse_simple_frontmatter to produce full BrainNode structs.
/// Format: YAML frontmatter between --- delimiters, then markdown body.
use anyhow::{Context, Result};
use ovca_types::{BrainLink, BrainNode};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

// ── Parser ────────────────────────────────────────────────────────────────

/// Parse a single brain node markdown file.
pub fn parse_brain_node(path: &Path) -> Result<BrainNode> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("parse_brain_node: {}", path.display()))?;
    parse_brain_node_text(&text, path)
}

pub fn parse_brain_node_text(text: &str, path: &Path) -> Result<BrainNode> {
    let (fm, body) = split_frontmatter(text);
    let mut node = BrainNode {
        body: body.trim().to_string(),
        ..BrainNode::default()
    };

    // Derive title from first heading if not in frontmatter
    let h1_title = body
        .lines()
        .find(|l| l.starts_with("# "))
        .map(|l| l.trim_start_matches("# ").trim().to_string());

    for (key, val) in &fm {
        match key.as_str() {
            "id" => node.id = scalar_str(val),
            "title" => node.title = scalar_str(val),
            "type" => node.node_type = scalar_str(val),
            "brain" => node.brain = scalar_str(val),
            "agent" => node.agent = scalar_str(val),
            "tags" => node.tags = str_array(val),
            "aliases" => node.aliases = str_array(val),
            "evidence_refs" => node.evidence_refs = str_array(val),
            "confidence" => {
                node.confidence = scalar_str(val).parse::<f64>().ok();
            }
            "math_score" => {
                node.math_score = scalar_str(val).parse::<f64>().ok();
            }
            "math_score_at" => {
                let s = scalar_str(val);
                if !s.is_empty() && s != "null" {
                    node.math_score_at = Some(s);
                }
            }
            "status" => node.status = scalar_str(val),
            "visibility" => node.visibility = scalar_str(val),
            "valid_from" => node.valid_from = Some(scalar_str(val)),
            "valid_to" => {
                let s = scalar_str(val);
                if !s.is_empty() && s != "null" {
                    node.valid_to = Some(s);
                }
            }
            "validity" => node.validity = scalar_str(val),
            "created" => node.created = scalar_str(val),
            "updated" => node.updated = scalar_str(val),
            "source_locator" => node.source_locator = Some(scalar_str(val)),
            "sensitivity" => node.sensitivity = Some(scalar_str(val)),
            "review_status" => node.review_status = Some(scalar_str(val)),
            "claim_ref" => node.claim_ref = Some(scalar_str(val)),
            "links" => {
                node.links = parse_links(val);
            }
            "summary" => node.summary = scalar_str(val),
            _ => {}
        }
    }

    // Fallback: derive id from filename if not set
    if node.id.is_empty() {
        if let Some(stem) = path.file_stem() {
            let s = stem.to_string_lossy();
            // "uuid_slug" -> take uuid part
            node.id = s.split('_').next().unwrap_or(&s).to_string();
        }
    }

    // Fallback: derive title from first H1 heading
    if node.title.is_empty() {
        if let Some(t) = h1_title {
            node.title = t;
        }
    }

    Ok(node)
}

/// Split raw text into (frontmatter_map, body).
fn split_frontmatter(text: &str) -> (HashMap<String, serde_json::Value>, String) {
    let text = text.replace("\r\n", "\n");
    let re = Regex::new(r"(?s)^---\n(.*?)\n---\n?(.*)$").expect("fm regex");
    let Some(cap) = re.captures(&text) else {
        return (HashMap::new(), text);
    };
    let fm_raw = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
    let body = cap
        .get(2)
        .map(|m| m.as_str())
        .unwrap_or_default()
        .to_string();
    (parse_yaml_frontmatter(fm_raw), body)
}

/// Minimal YAML parser for brain frontmatter.
/// Handles: scalar, inline list [a,b,c], block list (- item), and block map (links).
fn parse_yaml_frontmatter(fm: &str) -> HashMap<String, serde_json::Value> {
    let mut result: HashMap<String, serde_json::Value> = HashMap::new();
    let mut current_key = String::new();
    let mut in_links_block = false;
    let mut current_link: HashMap<String, String> = HashMap::new();

    for line in fm.lines() {
        let trimmed = line.trim_end();
        if trimmed.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let ls = trimmed.trim_start();

        // Detect links block entry (indented map under "links:")
        if in_links_block && indent >= 2 {
            if ls.starts_with("- ") {
                // Save previous link if any
                if !current_link.is_empty() {
                    push_link(&mut result, &current_link);
                    current_link.clear();
                }
                // First key-value on same line as "-"
                let rest = ls.trim_start_matches("- ").trim();
                if let Some((k, v)) = rest.split_once(':') {
                    current_link.insert(k.trim().to_string(), strip_scalar(v.trim()));
                }
            } else if indent >= 4 {
                // Additional key-values inside a link entry
                if let Some((k, v)) = ls.split_once(':') {
                    current_link.insert(k.trim().to_string(), strip_scalar(v.trim()));
                }
            } else {
                // End of links block
                if !current_link.is_empty() {
                    push_link(&mut result, &current_link);
                    current_link.clear();
                }
                in_links_block = false;
                current_key = String::new();
                // Fall through to normal parsing for this line
                parse_normal_line(ls, &mut current_key, &mut result);
            }
            continue;
        }

        // Block list item under current key
        if ls.starts_with('-') && !current_key.is_empty() {
            let item = strip_scalar(ls.trim_start_matches('-').trim());
            if !item.is_empty() {
                let entry = result
                    .entry(current_key.clone())
                    .or_insert_with(|| serde_json::Value::Array(vec![]));
                if let serde_json::Value::Array(arr) = entry {
                    arr.push(serde_json::Value::String(item));
                }
            }
            continue;
        }

        parse_normal_line(ls, &mut current_key, &mut result);

        // Detect start of links block.
        // parse_normal_line pre-inserts an empty Array for "links:" (empty value),
        // so we ALWAYS activate links block mode here — the Array check would always
        // match and prevent in_links_block from being set.
        if current_key == "links" {
            in_links_block = true;
            result.insert("links".to_string(), serde_json::Value::Array(vec![]));
        }
    }

    // Flush last link
    if in_links_block && !current_link.is_empty() {
        push_link(&mut result, &current_link);
    }

    result
}

fn parse_normal_line(
    ls: &str,
    current_key: &mut String,
    result: &mut HashMap<String, serde_json::Value>,
) {
    let Some((k, v)) = ls.split_once(':') else {
        return;
    };
    let key = k.trim().to_string();
    let value = v.trim();
    *current_key = key.clone();

    if value.is_empty() {
        // Will be filled by block list items or block map
        result
            .entry(key)
            .or_insert(serde_json::Value::Array(vec![]));
    } else if value.starts_with('[') && value.ends_with(']') {
        // Inline list
        let inner = &value[1..value.len().saturating_sub(1)];
        let items: Vec<serde_json::Value> = inner
            .split(',')
            .map(|s| strip_scalar(s.trim()))
            .filter(|s| !s.is_empty())
            .map(serde_json::Value::String)
            .collect();
        result.insert(key, serde_json::Value::Array(items));
    } else {
        result.insert(key, serde_json::Value::String(strip_scalar(value)));
    }
}

fn push_link(result: &mut HashMap<String, serde_json::Value>, link_map: &HashMap<String, String>) {
    let link = serde_json::json!({
        "id": link_map.get("id").cloned().unwrap_or_default(),
        "type": link_map.get("type").cloned().unwrap_or_default(),
        "brain": link_map.get("brain"),
        "why": link_map.get("why"),
    });
    let entry = result
        .entry("links".to_string())
        .or_insert(serde_json::Value::Array(vec![]));
    if let serde_json::Value::Array(arr) = entry {
        arr.push(link);
    }
}

fn strip_scalar(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len().saturating_sub(1)].trim().to_string()
    } else {
        s.to_string()
    }
}

fn scalar_str(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

fn str_array(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::Array(arr) => arr.iter().map(scalar_str).collect(),
        serde_json::Value::String(s) if !s.is_empty() => vec![s.clone()],
        _ => vec![],
    }
}

fn parse_links(v: &serde_json::Value) -> Vec<BrainLink> {
    let serde_json::Value::Array(arr) = v else {
        return vec![];
    };
    arr.iter()
        .filter_map(|item| {
            let obj = item.as_object()?;
            Some(BrainLink {
                id: obj.get("id")?.as_str()?.to_string(),
                link_type: obj.get("type")?.as_str()?.to_string(),
                brain: obj
                    .get("brain")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                why: obj
                    .get("why")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            })
        })
        .collect()
}

// ── Writer ────────────────────────────────────────────────────────────────

/// Write a BrainNode to `dir/{id}_{slug}.md`, returning the file path.
pub fn write_brain_node(dir: &Path, node: &BrainNode) -> Result<PathBuf> {
    fs::create_dir_all(dir)
        .with_context(|| format!("write_brain_node mkdir: {}", dir.display()))?;
    let slug: String = node
        .title
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .split('_')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    let filename = format!("{}_{}.md", node.id, slug);
    let path = dir.join(&filename);

    let content = render_brain_node(node);
    // Atomic write
    let tmp = path.with_extension("md.tmp");
    fs::write(&tmp, content.as_bytes())
        .with_context(|| format!("write_brain_node write tmp: {}", tmp.display()))?;
    fs::rename(&tmp, &path)
        .with_context(|| format!("write_brain_node rename: {}", path.display()))?;
    Ok(path)
}

fn render_brain_node(node: &BrainNode) -> String {
    let mut fm = String::from("---\n");
    fm.push_str(&format!("id: {}\n", node.id));
    fm.push_str(&format!("title: {}\n", node.title));
    fm.push_str(&format!("type: {}\n", node.node_type));
    fm.push_str(&format!("brain: {}\n", node.brain));
    fm.push_str(&format!("agent: {}\n", node.agent));

    if !node.tags.is_empty() {
        fm.push_str(&format!("tags: [{}]\n", node.tags.join(", ")));
    } else {
        fm.push_str("tags: []\n");
    }

    if !node.aliases.is_empty() {
        fm.push_str(&format!("aliases: [{}]\n", node.aliases.join(", ")));
    }

    if let Some(c) = node.confidence {
        fm.push_str(&format!("confidence: {:.2}\n", c));
    }
    if let Some(score) = node.math_score {
        fm.push_str(&format!("math_score: {:.3}\n", score));
    }
    if let Some(scored_at) = &node.math_score_at {
        fm.push_str(&format!("math_score_at: {}\n", scored_at));
    }

    fm.push_str(&format!("status: {}\n", node.status));
    fm.push_str(&format!("visibility: {}\n", node.visibility));

    if let Some(vf) = &node.valid_from {
        fm.push_str(&format!("valid_from: {}\n", vf));
    }
    if let Some(vt) = &node.valid_to {
        fm.push_str(&format!("valid_to: {}\n", vt));
    }
    if !node.validity.is_empty() {
        fm.push_str(&format!("validity: {}\n", node.validity));
    }

    fm.push_str(&format!("created: {}\n", node.created));
    fm.push_str(&format!("updated: {}\n", node.updated));

    if !node.summary.is_empty() {
        fm.push_str(&format!("summary: {}\n", node.summary));
    }

    if !node.links.is_empty() {
        fm.push_str("links:\n");
        for link in &node.links {
            fm.push_str(&format!(
                "  - id: {}\n    type: {}\n",
                link.id, link.link_type
            ));
            if let Some(b) = &link.brain {
                fm.push_str(&format!("    brain: {}\n", b));
            }
            if let Some(w) = &link.why {
                fm.push_str(&format!("    why: {}\n", w));
            }
        }
    }

    fm.push_str("---\n");
    fm.push_str(&format!("# {}\n\n{}\n", node.title, node.body));
    fm
}

/// List all brain node files in a directory.
pub fn list_brain_nodes(nodes_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(nodes_dir) else {
        return vec![];
    };
    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "md").unwrap_or(false))
        .collect();
    files.sort();
    files
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

    const SAMPLE_NODE: &str = r#"---
id: abc-001
title: Test Strategy
type: Strategy
brain: oracle
agent: coordinator
tags: [alpha, testing]
confidence: 0.85
math_score: 0.742
math_score_at: 2026-03-19
status: active
visibility: team
created: 2026-01-01T00:00:00Z
updated: 2026-01-02T00:00:00Z
links:
  - id: xyz-002
    type: supports
    why: direct evidence
---
# Test Strategy

This is the body.
"#;

    #[test]
    fn parse_sample_node() {
        let node =
            parse_brain_node_text(SAMPLE_NODE, Path::new("abc-001_test_strategy.md")).unwrap();
        assert_eq!(node.id, "abc-001");
        assert_eq!(node.title, "Test Strategy");
        assert_eq!(node.node_type, "Strategy");
        assert_eq!(node.tags, vec!["alpha", "testing"]);
        assert!((node.confidence.unwrap() - 0.85).abs() < 0.001);
        assert!((node.math_score.unwrap() - 0.742).abs() < 0.001);
        assert_eq!(node.math_score_at.as_deref(), Some("2026-03-19"));
        assert_eq!(node.links.len(), 1);
        assert_eq!(node.links[0].link_type, "supports");
        assert!(node.body.contains("This is the body."));
    }

    #[test]
    fn parse_inline_list() {
        let text = "---\nid: x\ntitle: T\ntype: Note\nbrain: oracle\ntags: [a, b, c]\ncreated: 2026-01-01T00:00:00Z\nupdated: 2026-01-01T00:00:00Z\n---\nbody\n";
        let node = parse_brain_node_text(text, Path::new("x.md")).unwrap();
        assert_eq!(node.tags, vec!["a", "b", "c"]);
    }

    #[test]
    fn parse_no_frontmatter_returns_node() {
        let text = "# Just a heading\n\nSome body text.";
        let node = parse_brain_node_text(text, Path::new("plain.md")).unwrap();
        assert!(node.id.is_empty() || !node.id.is_empty()); // no panic
    }

    #[test]
    fn write_and_read_roundtrip() {
        let dir = TempDir::new().unwrap();
        let nodes_dir = dir.path().join("nodes");
        let node = BrainNode {
            id: "rnd-001".into(),
            title: "Round Trip Test".into(),
            node_type: "Note".into(),
            brain: "oracle".into(),
            agent: "engineer".into(),
            tags: vec!["test".into()],
            math_score: Some(0.742),
            math_score_at: Some("2026-03-19".into()),
            created: "2026-01-01T00:00:00Z".into(),
            updated: "2026-01-01T00:00:00Z".into(),
            body: "Hello world.".into(),
            ..Default::default()
        };
        let path = write_brain_node(&nodes_dir, &node).unwrap();
        let restored = parse_brain_node(&path).unwrap();
        assert_eq!(restored.id, "rnd-001");
        assert_eq!(restored.title, "Round Trip Test");
        assert_eq!(restored.tags, vec!["test"]);
        assert!((restored.math_score.unwrap() - 0.742).abs() < 0.001);
        assert_eq!(restored.math_score_at.as_deref(), Some("2026-03-19"));
    }

    #[test]
    fn list_brain_nodes_returns_md_only() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("node1.md"), "").unwrap();
        std::fs::write(dir.path().join("node2.md"), "").unwrap();
        std::fs::write(dir.path().join("ignore.json"), "{}").unwrap();
        let files = list_brain_nodes(dir.path());
        assert_eq!(files.len(), 2);
    }
}
