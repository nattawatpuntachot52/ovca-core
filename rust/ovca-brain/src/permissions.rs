/// Brain permission matrix — mirrors brain_server.py BRAIN_PERMISSIONS.
///
/// The public runtime recognizes only Coordinator, Engineer, Reviewer, and Auditor.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Perm {
    ReadWrite,
    ReadOnly,
    Denied,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Returns `Some(error_msg)` if caller cannot read brain; `None` if allowed.
pub fn check_read(caller: &str, brain: &str) -> Option<String> {
    let c = caller.trim().to_lowercase();
    let b = brain.trim().to_lowercase();
    if perm_level(&c, &b) == Perm::Denied {
        Some(format!(
            "permission denied: caller={} brain={} action=read",
            c, b
        ))
    } else {
        None
    }
}

/// Returns `Some(error_msg)` if caller cannot write to brain; `None` if allowed.
pub fn check_write(caller: &str, brain: &str) -> Option<String> {
    let c = caller.trim().to_lowercase();
    let b = brain.trim().to_lowercase();
    if !can_write_impl(&c, &b) {
        Some(format!(
            "permission denied: caller={} brain={} action=write",
            c, b
        ))
    } else {
        None
    }
}

pub fn can_read(caller: &str, brain: &str) -> bool {
    check_read(caller, brain).is_none()
}

pub fn can_write(caller: &str, brain: &str) -> bool {
    check_write(caller, brain).is_none()
}

// ── Internal ──────────────────────────────────────────────────────────────────

fn perm_level(caller: &str, brain: &str) -> Perm {
    match brain {
        "oracle" => match caller {
            "owner" => Perm::ReadWrite,
            "coordinator" | "engineer" | "reviewer" | "auditor" => Perm::ReadOnly,
            _ => Perm::Denied,
        },
        "coordinator" => match caller {
            "owner" | "coordinator" => Perm::ReadOnly,
            _ => Perm::Denied,
        },
        "engineer" => match caller {
            "owner" | "coordinator" | "engineer" => Perm::ReadOnly,
            _ => Perm::Denied,
        },
        "reviewer" => match caller {
            "owner" | "coordinator" | "reviewer" => Perm::ReadOnly,
            _ => Perm::Denied,
        },
        "auditor" => match caller {
            "owner" | "coordinator" | "auditor" => Perm::ReadOnly,
            _ => Perm::Denied,
        },
        _ => Perm::Denied,
    }
}

fn can_write_impl(caller: &str, brain: &str) -> bool {
    // oracle brain: only "owner" can write (canonical library)
    // agent brains: that agent OR "owner" can write
    match brain {
        "oracle" => caller == "owner",
        "coordinator" | "engineer" | "reviewer" | "auditor" => caller == "owner" || caller == brain,
        _ => false,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinator_can_read_oracle() {
        assert!(can_read("coordinator", "oracle"));
    }

    #[test]
    fn engineer_can_read_oracle() {
        assert!(can_read("engineer", "oracle"));
    }

    #[test]
    fn owner_can_write_oracle() {
        assert!(can_write("owner", "oracle"));
    }

    #[test]
    fn coordinator_cannot_write_oracle() {
        assert!(!can_write("coordinator", "oracle"));
    }

    #[test]
    fn engineer_can_write_own_brain() {
        assert!(can_write("engineer", "engineer"));
    }

    #[test]
    fn engineer_cannot_write_coordinator_brain() {
        assert!(!can_write("engineer", "coordinator"));
    }

    #[test]
    fn unknown_caller_denied_read() {
        assert!(!can_read("unknown_bot", "oracle"));
        assert!(!can_read("unknown_bot", "engineer"));
    }

    #[test]
    fn unknown_caller_denied_write() {
        assert!(!can_write("unknown_bot", "oracle"));
        assert!(!can_write("unknown_bot", "engineer"));
        assert!(!can_write("", "oracle"));
    }

    #[test]
    fn coordinator_can_read_all_brains() {
        for brain in ["oracle", "coordinator", "engineer", "reviewer", "auditor"] {
            assert!(
                can_read("coordinator", brain),
                "coordinator should read {}",
                brain
            );
        }
    }

    #[test]
    fn agent_cannot_read_other_agent_brain() {
        assert!(!can_read("reviewer", "engineer"));
        assert!(!can_read("auditor", "reviewer"));
        assert!(!can_read("engineer", "auditor"));
    }

    #[test]
    fn owner_can_read_all_brains() {
        for brain in ["oracle", "coordinator", "engineer", "reviewer", "auditor"] {
            assert!(can_read("owner", brain), "owner should read {}", brain);
        }
    }

    #[test]
    fn unknown_brain_denied() {
        assert!(!can_read("coordinator", "nonexistent"));
        assert!(!can_write("owner", "nonexistent"));
    }
}
