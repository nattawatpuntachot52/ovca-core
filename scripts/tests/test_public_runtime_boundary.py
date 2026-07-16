from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[2]
PUBLIC_BINARIES = (
    "rust/ovca-policy-tools/src/main.rs",
    "rust/ovca-coordinator-server/src/main.rs",
    "rust/ovca-engineer-server/src/main.rs",
    "rust/ovca-reviewer-server/src/main.rs",
    "rust/ovca-auditor-server/src/main.rs",
)


def test_public_service_listener_defaults_are_loopback_only() -> None:
    for relative_path in PUBLIC_BINARIES:
        source = (ROOT / relative_path).read_text(encoding="utf-8")
        assert 'format!("127.0.0.1:' in source, relative_path
        assert "TcpListener::bind(&addr)" in source, relative_path
        assert "0.0.0.0" not in source, relative_path
