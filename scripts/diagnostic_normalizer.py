"""Pure deterministic normalization for local verifier diagnostics.

The caller owns command execution and guarantees that captured diagnostics are
secret-free.  This module only transforms caller-provided bytes; it does not
inspect the host, environment, filesystem, process table, or network.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Final


NORMALIZER_VERSION: Final = "ovca.diagnostic-normalizer.v1"
SOURCE_ROOT_TOKEN: Final = "<SOURCE_ROOT>"

_WINDOWS_DRIVE_ROOT = re.compile(r"^[A-Za-z]:/[^/]", re.ASCII)
_WINDOWS_UNC_ROOT = re.compile(r"^//[^/\s]+/[^/\s]+(?:/.*)?$", re.ASCII)
_WINDOWS_DRIVE_PATH = re.compile(r"[A-Za-z]:/(?!/)", re.ASCII)
_WINDOWS_DRIVE_REPEATED_SEPARATOR = re.compile(r"[A-Za-z]:/{2,}", re.ASCII)
_WINDOWS_DRIVE_RELATIVE_PATH = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z]:(?![/\s])[^/\s]+(?:/[^\s]*)?",
    re.ASCII,
)
_WINDOWS_BARE_DRIVE = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z]:(?=$|[\s,;)'\"\]}])", re.ASCII
)
_WINDOWS_DEVICE_PATH = re.compile(r"//[.?]/", re.ASCII)
_WINDOWS_UNC_PATH = re.compile(
    r"(?<![:/])//[^/\s]+/[^/\s]+", re.ASCII
)
_PATH_BEARING_SCHEME = re.compile(
    r"(?i)(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]+:"
    r"(?:/+|[A-Za-z]:/)",
    re.ASCII,
)
_MULTI_SLASH_ABSOLUTE_PATH = re.compile(
    r"(?<!/)/{2,}(?=$|[^/\s])", re.ASCII
)
_POSIX_ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9_./-])/(?![/\s])[^\s\x00-\x1f'\"<>]+",
    re.ASCII,
)


class DiagnosticNormalizationError(ValueError):
    """Fail-closed normalization error without captured diagnostic content."""

    def __init__(
        self,
        code: str,
        *,
        stream: str | None = None,
        kind: str | None = None,
    ) -> None:
        self.code = code
        self.stream = stream
        self.kind = kind
        fields = [code]
        if stream is not None:
            fields.append(stream)
        if kind is not None:
            fields.append(kind)
        super().__init__(":".join(fields))


@dataclass(frozen=True, slots=True)
class DiagnosticNormalizationResult:
    """Canonical bytes and their exact lowercase SHA-256 identity."""

    canonical_bytes: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class _SourceRoot:
    text: str
    case_insensitive: bool


def _normalize_separators_and_device_prefixes(text: str) -> str:
    normalized = text.replace("\\", "/")
    normalized = re.sub(r"(?i)(?<![A-Za-z0-9_])//\?/UNC/", "//", normalized)
    return re.sub(
        r"(?i)(?<![A-Za-z0-9_])//\?/(?=[A-Z]:/)", "", normalized
    )


def _source_root(source_root: str) -> _SourceRoot:
    if not isinstance(source_root, str):
        raise DiagnosticNormalizationError("invalid_source_root", kind="type")
    if (
        not source_root
        or any(
            ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
            for character in source_root
        )
        or SOURCE_ROOT_TOKEN in source_root
    ):
        raise DiagnosticNormalizationError("invalid_source_root", kind="syntax")

    normalized = _normalize_separators_and_device_prefixes(source_root)
    while normalized.endswith("/") and not re.fullmatch(
        r"(?:[A-Za-z]:/|/)", normalized, re.ASCII
    ):
        normalized = normalized[:-1]

    if _PATH_BEARING_SCHEME.search(normalized):
        raise DiagnosticNormalizationError("invalid_source_root", kind="uri")
    if _WINDOWS_DRIVE_REPEATED_SEPARATOR.search(normalized):
        raise DiagnosticNormalizationError(
            "invalid_source_root", kind="non_canonical_segment"
        )
    if normalized.startswith("///"):
        raise DiagnosticNormalizationError(
            "invalid_source_root", kind="non_canonical_segment"
        )
    if _WINDOWS_DEVICE_PATH.match(normalized):
        raise DiagnosticNormalizationError(
            "invalid_source_root", kind="unsupported_device"
        )

    is_windows_drive = bool(_WINDOWS_DRIVE_ROOT.match(normalized))
    is_windows_unc = bool(_WINDOWS_UNC_ROOT.fullmatch(normalized))
    is_posix = normalized.startswith("/") and not normalized.startswith("//")
    if normalized == "/" or re.fullmatch(r"[A-Za-z]:/", normalized, re.ASCII):
        raise DiagnosticNormalizationError("invalid_source_root", kind="too_broad")
    if not (is_windows_drive or is_windows_unc or is_posix):
        raise DiagnosticNormalizationError("invalid_source_root", kind="not_absolute")

    if is_windows_drive:
        lexical_segments = normalized[3:].split("/")
    elif is_windows_unc:
        lexical_segments = normalized[2:].split("/")
    else:
        lexical_segments = normalized[1:].split("/")
    if any(segment in ("", ".", "..") for segment in lexical_segments):
        raise DiagnosticNormalizationError(
            "invalid_source_root", kind="non_canonical_segment"
        )

    return _SourceRoot(
        text=normalized,
        case_insensitive=is_windows_drive or is_windows_unc,
    )


def _strip_ansi(text: str, stream: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(text):
        character = text[index]
        if character in ("\x9b", "\x9d"):
            raise DiagnosticNormalizationError(
                "invalid_ansi", stream=stream, kind="eight_bit_control"
            )
        if character != "\x1b":
            output.append(character)
            index += 1
            continue

        if index + 1 >= len(text):
            raise DiagnosticNormalizationError(
                "invalid_ansi", stream=stream, kind="unterminated_escape"
            )
        introducer = text[index + 1]
        if introducer == "[":
            index = _consume_csi(text, index + 2, stream)
            continue
        if introducer == "]":
            index = _consume_osc(text, index + 2, stream)
            continue
        raise DiagnosticNormalizationError(
            "invalid_ansi", stream=stream, kind="unsupported_escape"
        )
    return "".join(output)


def _consume_csi(text: str, index: int, stream: str) -> int:
    while index < len(text) and 0x30 <= ord(text[index]) <= 0x3F:
        index += 1
    while index < len(text) and 0x20 <= ord(text[index]) <= 0x2F:
        index += 1
    if index >= len(text) or not 0x40 <= ord(text[index]) <= 0x7E:
        raise DiagnosticNormalizationError(
            "invalid_ansi", stream=stream, kind="malformed_csi"
        )
    return index + 1


def _consume_osc(text: str, index: int, stream: str) -> int:
    while index < len(text):
        character = text[index]
        if character == "\x07":
            return index + 1
        if character == "\x1b":
            if index + 1 < len(text) and text[index + 1] == "\\":
                return index + 2
            raise DiagnosticNormalizationError(
                "invalid_ansi", stream=stream, kind="malformed_osc"
            )
        index += 1
    raise DiagnosticNormalizationError(
        "invalid_ansi", stream=stream, kind="unterminated_osc"
    )


def _replace_source_root(text: str, root: _SourceRoot) -> str:
    flags = re.ASCII | (re.IGNORECASE if root.case_insensitive else 0)
    pattern = re.compile(
        rf"(?<![A-Za-z0-9_./:-]){re.escape(root.text)}(?=$|/)",
        flags,
    )
    return pattern.sub(SOURCE_ROOT_TOKEN, text)


def _reject_uris(text: str, stream: str) -> None:
    if _PATH_BEARING_SCHEME.search(text):
        raise DiagnosticNormalizationError(
            "undeclared_absolute_path", stream=stream, kind="uri"
        )


def _reject_source_root_traversal(text: str, stream: str) -> None:
    for line in text.split("\n"):
        search_from = 0
        while True:
            token_index = line.find(SOURCE_ROOT_TOKEN, search_from)
            if token_index < 0:
                break
            suffix = line[token_index + len(SOURCE_ROOT_TOKEN) :]
            for segment in suffix.split("/")[1:]:
                if re.match(r"^\.{1,2}(?=$|[:;,)'\"\]}])", segment, re.ASCII):
                    raise DiagnosticNormalizationError(
                        "source_root_traversal", stream=stream
                    )
            search_from = token_index + len(SOURCE_ROOT_TOKEN)


def _reject_undeclared_absolute_paths(text: str, stream: str) -> None:
    checks = (
        ("windows_device", _WINDOWS_DEVICE_PATH),
        ("windows_drive_repeated_separator", _WINDOWS_DRIVE_REPEATED_SEPARATOR),
        ("windows_unc", _WINDOWS_UNC_PATH),
        ("multi_slash_absolute", _MULTI_SLASH_ABSOLUTE_PATH),
        ("windows_drive", _WINDOWS_DRIVE_PATH),
        ("windows_drive_relative", _WINDOWS_DRIVE_RELATIVE_PATH),
        ("windows_bare_drive", _WINDOWS_BARE_DRIVE),
    )
    for kind, pattern in checks:
        if pattern.search(text):
            raise DiagnosticNormalizationError(
                "undeclared_absolute_path", stream=stream, kind=kind
            )
    for match in _POSIX_ABSOLUTE_PATH.finditer(text):
        if text[: match.start()].endswith(SOURCE_ROOT_TOKEN):
            continue
        raise DiagnosticNormalizationError(
            "undeclared_absolute_path", stream=stream, kind="posix"
        )


def _decode_and_normalize(value: bytes, stream: str, root: _SourceRoot) -> str:
    if not isinstance(value, bytes):
        raise DiagnosticNormalizationError(
            "invalid_stream_type", stream=stream, kind="bytes_required"
        )
    try:
        text = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise DiagnosticNormalizationError("invalid_utf8", stream=stream) from error

    if SOURCE_ROOT_TOKEN in text:
        raise DiagnosticNormalizationError("reserved_token", stream=stream)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _strip_ansi(text, stream)
    if SOURCE_ROOT_TOKEN in text:
        raise DiagnosticNormalizationError("reserved_token", stream=stream)
    text = _normalize_separators_and_device_prefixes(text)
    _reject_uris(text, stream)
    text = _replace_source_root(text, root)
    _reject_source_root_traversal(text, stream)
    _reject_undeclared_absolute_paths(text, stream)
    return text


def normalize_diagnostics(
    *,
    exit_code: int,
    stdout: bytes,
    stderr: bytes,
    source_root: str,
) -> DiagnosticNormalizationResult:
    """Return a canonical v1 envelope and its SHA-256 identity.

    All arguments are keyword-only so stdout and stderr cannot be swapped by
    positional accident.  Captures remain separate and retain their exact line
    and blank-line order after the declared EOL/ANSI/path normalization.
    """

    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        raise DiagnosticNormalizationError("invalid_exit_code", kind="int_required")
    root = _source_root(source_root)
    normalized_stdout = _decode_and_normalize(stdout, "stdout", root)
    normalized_stderr = _decode_and_normalize(stderr, "stderr", root)
    payload = {
        "version": NORMALIZER_VERSION,
        "exit_code": exit_code,
        "stdout": normalized_stdout,
        "stderr": normalized_stderr,
    }
    canonical_bytes = (
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=False,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )
    return DiagnosticNormalizationResult(
        canonical_bytes=canonical_bytes,
        sha256=hashlib.sha256(canonical_bytes).hexdigest(),
    )


__all__ = [
    "DiagnosticNormalizationError",
    "DiagnosticNormalizationResult",
    "NORMALIZER_VERSION",
    "SOURCE_ROOT_TOKEN",
    "normalize_diagnostics",
]
