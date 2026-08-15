from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest

from scripts.diagnostic_normalizer import (
    DiagnosticNormalizationError,
    NORMALIZER_VERSION,
    normalize_diagnostics,
)


SYNTHETIC_WINDOWS_ROOT = "X:\\fixture\\oracle"
SYNTHETIC_POSIX_ROOT = "/fixture/oracle"

COMMAND_15_STDERR = (
    "error: failed to download `http-range-header v0.4.2`\n"
    "\n"
    "Caused by:\n"
    "  attempting to make an HTTP request, but --offline was specified\n"
).encode()

COMMAND_16_WINDOWS_STDOUT = (
    "Diff in X:\\fixture\\oracle\\rust\\ovca-hope-server\\src\\main.rs:19:\r\n"
    "-    let value = old_call();\r\n"
    "+    let value = new_call();\r\n"
    "Diff in X:\\fixture\\oracle\\rust\\ovca-registry-server\\src\\main.rs:41:\r\n"
    "-        registry.open();\r\n"
    "+        registry\r\n"
    "+            .open();\r\n"
).encode()

COMMAND_15_V1_SHA256 = (
    "6f682d5ad7134f9a9193379b4386b3c83c60d2f903f67b0026e75036739c03b4"
)
COMMAND_16_V1_SHA256 = (
    "d294cf5dde54d5190c09240399c03d317447102e534682561886f1c945a20edd"
)


def _normalize(
    *,
    exit_code: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    source_root: str = SYNTHETIC_WINDOWS_ROOT,
):
    return normalize_diagnostics(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        source_root=source_root,
    )


def _error_code(**kwargs: object) -> tuple[str, str | None, str | None]:
    with pytest.raises(DiagnosticNormalizationError) as captured:
        _normalize(**kwargs)  # type: ignore[arg-type]
    error = captured.value
    return error.code, error.stream, error.kind


def test_cross_platform_source_root_forms_produce_identical_bytes() -> None:
    cases = (
        (
            SYNTHETIC_WINDOWS_ROOT,
            b"at X:\\fixture\\oracle\\rust\\crate\\src\\lib.rs:7:2\r\n",
        ),
        (
            "\\\\?\\X:\\fixture\\oracle",
            b"at \\\\?\\X:\\fixture\\oracle\\rust\\crate\\src\\lib.rs:7:2\n",
        ),
        (
            "X:/fixture/oracle/",
            b"at X:/fixture/oracle/rust/crate/src/lib.rs:7:2\n",
        ),
        (
            SYNTHETIC_POSIX_ROOT,
            b"at /fixture/oracle/rust/crate/src/lib.rs:7:2\n",
        ),
    )

    normalized = [
        _normalize(stdout=stdout, source_root=root).canonical_bytes
        for root, stdout in cases
    ]
    assert len(set(normalized)) == 1
    assert b"<SOURCE_ROOT>/rust/crate/src/lib.rs:7:2" in normalized[0]


def test_windows_matching_is_ascii_case_insensitive_and_host_independent() -> None:
    upper = _normalize(
        stdout=b"X:/FIXTURE/ORACLE/rust/lib.rs\n",
        source_root="x:/fixture/oracle",
    )
    lower = _normalize(
        stdout=b"x:/fixture/oracle/rust/lib.rs\n",
        source_root="X:/FIXTURE/ORACLE",
    )
    assert upper == lower


def test_declared_unc_root_is_replaced_but_other_unc_is_blocked() -> None:
    accepted = _normalize(
        stdout=b"//fixture-host/share/oracle/rust/lib.rs\n",
        source_root="\\\\fixture-host\\share\\oracle",
    )
    assert b"<SOURCE_ROOT>/rust/lib.rs" in accepted.canonical_bytes
    assert _error_code(stdout=b"//other-host/share/file.rs\n") == (
        "undeclared_absolute_path",
        "stdout",
        "windows_unc",
    )


@pytest.mark.parametrize(
    ("ansi", "plain"),
    (
        (b"\x1b[31merror\x1b[0m\r\n", b"error\n"),
        (b"\x1b]0;build title\x07ready\r\n", b"ready\n"),
        (b"\x1b]0;build title\x1b\\ready\r\n", b"ready\n"),
    ),
)
def test_closed_ansi_and_eol_variants_are_identity_equivalent(
    ansi: bytes, plain: bytes
) -> None:
    assert _normalize(stderr=ansi) == _normalize(stderr=plain)


@pytest.mark.parametrize(
    ("value", "kind"),
    (
        (b"dangling \x1b", "unterminated_escape"),
        (b"unsupported \x1bPdata", "unsupported_escape"),
        (b"bad \x1b[31", "malformed_csi"),
        (b"bad \x1b]title", "unterminated_osc"),
        ("bad \u009b31m".encode(), "eight_bit_control"),
    ),
)
def test_malformed_or_unsupported_ansi_is_blocked(value: bytes, kind: str) -> None:
    assert _error_code(stderr=value) == ("invalid_ansi", "stderr", kind)


def test_source_root_boundary_never_replaces_sibling_prefix() -> None:
    assert _error_code(
        stdout=b"X:/fixture/oracle2/rust/lib.rs\n"
    ) == ("undeclared_absolute_path", "stdout", "windows_drive")


def test_posix_root_never_replaces_suffix_of_unc_representation() -> None:
    assert _error_code(
        stdout=b"//fixture/oracle/rust/lib.rs\n",
        source_root=SYNTHETIC_POSIX_ROOT,
    ) == ("undeclared_absolute_path", "stdout", "windows_unc")


@pytest.mark.parametrize(
    "value",
    (
        b"file:/fixture/oracle/rust/lib.rs\n",
        b"file:///fixture/oracle/rust/lib.rs\n",
        b"https://host.invalid/fixture/oracle/rust/lib.rs\n",
    ),
)
def test_uri_cannot_be_hidden_by_declared_source_root(value: bytes) -> None:
    assert _error_code(
        stdout=value,
        source_root=SYNTHETIC_POSIX_ROOT,
    ) == ("undeclared_absolute_path", "stdout", "uri")


@pytest.mark.parametrize(
    ("value", "source_root", "expected"),
    (
        (
            b"https:/outside/file.rs\n",
            SYNTHETIC_WINDOWS_ROOT,
            ("undeclared_absolute_path", "stdout", "uri"),
        ),
        (
            b"zip:X:/fixture/oracle/file.rs\n",
            SYNTHETIC_WINDOWS_ROOT,
            ("undeclared_absolute_path", "stdout", "uri"),
        ),
        (
            b"https:X:/fixture/oracle/file.rs\n",
            SYNTHETIC_WINDOWS_ROOT,
            ("undeclared_absolute_path", "stdout", "uri"),
        ),
        (
            b"C:relative/file.rs\n",
            SYNTHETIC_WINDOWS_ROOT,
            ("undeclared_absolute_path", "stdout", "windows_drive_relative"),
        ),
        (
            b"X:/fixture/oracle/../outside/file.rs\n",
            SYNTHETIC_WINDOWS_ROOT,
            ("source_root_traversal", "stdout", None),
        ),
        (
            b"prefix\\\\?\\C:\\outside\\file.rs\n",
            SYNTHETIC_WINDOWS_ROOT,
            ("undeclared_absolute_path", "stdout", "windows_device"),
        ),
    ),
)
def test_r1_path_smuggling_vectors_fail_closed(
    value: bytes,
    source_root: str,
    expected: tuple[str, str | None, str | None],
) -> None:
    assert _error_code(stdout=value, source_root=source_root) == expected


def test_ordinary_colon_labels_remain_valid() -> None:
    result = _normalize(stderr=b"error: failed\nCaused by:\n  offline mode\n")
    assert json.loads(result.canonical_bytes)["stderr"] == (
        "error: failed\nCaused by:\n  offline mode\n"
    )


@pytest.mark.parametrize(
    ("value", "kind"),
    (
        (b"///outside/file.rs\n", "multi_slash_absolute"),
        (b"//outside\n", "multi_slash_absolute"),
        (b"//server\n", "multi_slash_absolute"),
        (b"\\\\server\n", "multi_slash_absolute"),
        (b"C://outside/file.rs\n", "windows_drive_repeated_separator"),
        (b"path C:\n", "windows_bare_drive"),
        (b"C:\n", "windows_bare_drive"),
    ),
)
def test_r2_noncanonical_or_ambiguous_paths_fail_closed(
    value: bytes, kind: str
) -> None:
    assert _error_code(stdout=value) == (
        "undeclared_absolute_path",
        "stdout",
        kind,
    )


@pytest.mark.parametrize(
    "value",
    (
        b"1://server/share/file.rs\n",
        b"label:://server/share/file.rs\n",
        b":://server/share/file.rs\n",
        b"9:////server/share/file.rs\n",
        b"label:://server\n",
    ),
)
def test_r3_colon_prefixed_multi_slash_paths_fail_closed(value: bytes) -> None:
    assert _error_code(stdout=value) == (
        "undeclared_absolute_path",
        "stdout",
        "multi_slash_absolute",
    )


@pytest.mark.parametrize(
    "value",
    (
        b">/outside/file.rs\n",
        b"</outside/file.rs\n",
        b"context:>/outside/file.rs\n",
        b":/outside/file.rs\n",
    ),
)
def test_r2_posix_path_boundary_bypasses_fail_closed(value: bytes) -> None:
    assert _error_code(stdout=value) == (
        "undeclared_absolute_path",
        "stdout",
        "posix",
    )


def test_generated_source_root_token_path_is_the_only_angle_boundary_exception() -> None:
    result = _normalize(stdout=b"X:/fixture/oracle/rust/lib.rs\n")
    assert json.loads(result.canonical_bytes)["stdout"] == (
        "<SOURCE_ROOT>/rust/lib.rs\n"
    )


@pytest.mark.parametrize(
    ("value", "kind"),
    (
        (b"C:/outside/file.rs\n", "windows_drive"),
        (b"\\\\server\\share\\file.rs\n", "windows_unc"),
        (b"\\\\.\\pipe\\oracle\n", "windows_device"),
        (b"\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\file.rs\n", "windows_device"),
        (b"\\\\?\\C:\\outside\\file.rs\n", "windows_drive"),
        (b"file:///fixture/oracle/file.rs\n", "uri"),
        (b"https://example.invalid/report\n", "uri"),
        (b"/outside/file.rs\n", "posix"),
    ),
)
def test_undeclared_absolute_path_or_uri_is_blocked(value: bytes, kind: str) -> None:
    assert _error_code(stdout=value) == (
        "undeclared_absolute_path",
        "stdout",
        kind,
    )


@pytest.mark.parametrize("stream", ("stdout", "stderr"))
def test_invalid_utf8_is_blocked_per_stream(stream: str) -> None:
    assert _error_code(**{stream: b"\xff"}) == ("invalid_utf8", stream, None)


def test_reserved_source_root_token_is_blocked_in_raw_capture() -> None:
    assert _error_code(stdout=b"<SOURCE_ROOT>/already-normalized\n") == (
        "reserved_token",
        "stdout",
        None,
    )


def test_ansi_cannot_be_used_to_construct_reserved_source_root_token() -> None:
    assert _error_code(stdout=b"<SOURCE\x1b[0m_ROOT>/smuggled\n") == (
        "reserved_token",
        "stdout",
        None,
    )


@pytest.mark.parametrize(
    ("root", "kind"),
    (
        ("relative/root", "not_absolute"),
        ("/", "too_broad"),
        ("X:/", "too_broad"),
        ("", "syntax"),
        ("file:///fixture/oracle", "uri"),
        ("\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1", "unsupported_device"),
        ("X:/fixture/../oracle", "non_canonical_segment"),
        ("X:/fixture/./oracle", "non_canonical_segment"),
        ("X:/fixture//oracle", "non_canonical_segment"),
        ("X://fixture/oracle/file.rs", "non_canonical_segment"),
        ("X:/fixture\toracle", "syntax"),
        ("X:/fixture/\u0085oracle", "syntax"),
        ("X:/fixture/\u007foracle", "syntax"),
    ),
)
def test_invalid_source_root_is_blocked(root: str, kind: str) -> None:
    assert _error_code(source_root=root) == ("invalid_source_root", None, kind)


@pytest.mark.parametrize(
    ("root", "captured_path"),
    (
        (
            "X:/fixture/.cargo/foo..bar/oracle root",
            b"X:/fixture/.cargo/foo..bar/oracle root/rust/lib.rs\n",
        ),
        (
            "\\\\?\\X:\\fixture\\oracle root",
            b"\\\\?\\X:\\fixture\\oracle root\\rust\\lib.rs\n",
        ),
        (
            "\\\\fixture-host\\share\\oracle root",
            b"\\\\fixture-host\\share\\oracle root\\rust\\lib.rs\n",
        ),
    ),
)
def test_valid_dotted_space_device_and_unc_roots_are_supported(
    root: str, captured_path: bytes
) -> None:
    result = _normalize(source_root=root, stdout=captured_path)
    assert b"<SOURCE_ROOT>/rust/lib.rs" in result.canonical_bytes


def test_stream_type_and_exit_code_are_strict() -> None:
    assert _error_code(stdout=bytearray(b"not bytes")) == (
        "invalid_stream_type",
        "stdout",
        "bytes_required",
    )
    assert _error_code(exit_code=True) == (
        "invalid_exit_code",
        None,
        "int_required",
    )


def test_exit_stream_content_and_intra_stream_order_change_identity() -> None:
    base = _normalize(exit_code=1, stdout=b"alpha\nbeta\n", stderr=b"failure\n")
    variants = (
        _normalize(exit_code=2, stdout=b"alpha\nbeta\n", stderr=b"failure\n"),
        _normalize(exit_code=1, stdout=b"failure\n", stderr=b"alpha\nbeta\n"),
        _normalize(exit_code=1, stdout=b"alpha\ngamma\n", stderr=b"failure\n"),
        _normalize(exit_code=1, stdout=b"beta\nalpha\n", stderr=b"failure\n"),
    )
    assert all(variant.sha256 != base.sha256 for variant in variants)


def test_blank_lines_and_stream_trailing_newline_are_preserved() -> None:
    with_blank = _normalize(stdout=b"first\n\nsecond\n")
    without_blank = _normalize(stdout=b"first\nsecond\n")
    without_trailing = _normalize(stdout=b"first\n\nsecond")
    assert with_blank.sha256 != without_blank.sha256
    assert with_blank.sha256 != without_trailing.sha256
    assert json.loads(with_blank.canonical_bytes)["stdout"] == "first\n\nsecond\n"


def test_canonical_envelope_is_exact_compact_utf8_json_with_one_final_lf() -> None:
    result = _normalize(exit_code=7, stdout="พร้อม\n".encode(), stderr=b"failed\n")
    expected = (
        '{"version":"ovca.diagnostic-normalizer.v1","exit_code":7,'
        '"stdout":"พร้อม\\n","stderr":"failed\\n"}\n'
    ).encode()
    assert result.canonical_bytes == expected
    assert not result.canonical_bytes.startswith(b"\xef\xbb\xbf")
    assert result.canonical_bytes.endswith(b"\n")
    assert not result.canonical_bytes.endswith(b"\n\n")
    assert result.sha256 == hashlib.sha256(expected).hexdigest()
    assert len(result.sha256) == 64 and result.sha256 == result.sha256.lower()
    assert list(json.loads(expected)) == ["version", "exit_code", "stdout", "stderr"]
    assert json.loads(expected)["version"] == NORMALIZER_VERSION


def test_repeated_normalization_is_byte_identical() -> None:
    kwargs = {
        "exit_code": 101,
        "stdout": b"line one\r\nline two\r\n",
        "stderr": COMMAND_15_STDERR,
    }
    first = _normalize(**kwargs)
    assert all(_normalize(**kwargs) == first for _ in range(20))


def test_module_has_no_process_environment_filesystem_or_network_capability() -> None:
    source_path = Path(__file__).resolve().parents[1] / "diagnostic_normalizer.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_roots: set[str] = set()
    called_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            called_names.add(node.func.id)

    assert imported_roots <= {
        "__future__",
        "dataclasses",
        "hashlib",
        "json",
        "re",
        "typing",
    }
    assert called_names.isdisjoint(
        {"open", "exec", "eval", "compile", "input", "breakpoint"}
    )


def test_semantic_command_15_fixture_has_frozen_v1_identity() -> None:
    result = _normalize(exit_code=101, stderr=COMMAND_15_STDERR)
    assert result.sha256 == COMMAND_15_V1_SHA256


def test_semantic_command_16_fixture_has_frozen_v1_identity() -> None:
    result = _normalize(exit_code=1, stdout=COMMAND_16_WINDOWS_STDOUT)
    assert result.sha256 == COMMAND_16_V1_SHA256
