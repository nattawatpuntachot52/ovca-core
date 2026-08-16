from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
SAMPLES = CONTRACTS / "samples"
RUST_SOURCE = ROOT / "rust" / "ovca-types" / "src" / "control_plane.rs"
RUST_LIB = ROOT / "rust" / "ovca-types" / "src" / "lib.rs"
ADR = ROOT / "docs" / "adr" / "0002-versioned-four-role-control-plane-contracts.md"

SCHEMA_SAMPLE_PAIRS = {
    "event": (
        CONTRACTS / "control_plane_event.v1.schema.json",
        SAMPLES / "control_plane_event.v1.sample.json",
    ),
    "execution_budget": (
        CONTRACTS / "control_plane_execution_budget.v1.schema.json",
        SAMPLES / "control_plane_execution_budget.v1.sample.json",
    ),
    "role_invocation": (
        CONTRACTS / "control_plane_role_invocation.v1.schema.json",
        SAMPLES / "control_plane_role_invocation.v1.sample.json",
    ),
    "role_result": (
        CONTRACTS / "control_plane_role_result.v1.schema.json",
        SAMPLES / "control_plane_role_result.v1.sample.json",
    ),
    "state": (
        CONTRACTS / "control_plane_state.v1.schema.json",
        SAMPLES / "control_plane_state.v1.sample.json",
    ),
}

RESOURCE_PATHS = (
    CONTRACTS / "foundation_authority.v1.schema.json",
    CONTRACTS / "foundation_event_envelope.v1.schema.json",
    *(schema for schema, _ in SCHEMA_SAMPLE_PAIRS.values()),
)

OBJECT_FIELDS = {
    "event": ["contract_version", "envelope", "payload"],
    "execution_budget": ["contract_version", "max_attempts"],
    "role_invocation": [
        "contract_version",
        "invocation_id",
        "invoker",
        "target",
        "task_id",
        "run_id",
        "scope",
        "budget",
        "idempotency_key",
        "authority",
        "authority_digest",
        "input_digest",
        "invoked_at",
    ],
    "role_result": [
        "contract_version",
        "result_id",
        "invocation_id",
        "invocation_digest",
        "producer",
        "task_id",
        "run_id",
        "scope",
        "idempotency_key",
        "attempt",
        "state",
        "payload",
        "evidence_ids",
        "occurred_at",
    ],
}

PUBLIC_ROLES = ("owner", "coordinator", "engineer", "reviewer", "auditor")
ALLOWED_ROLE_PAIRS = {
    ("owner", "coordinator"),
    ("coordinator", "engineer"),
    ("coordinator", "reviewer"),
    ("coordinator", "auditor"),
}
STATE_VALUES = ["pending", "running", "completed", "failed", "cancelled"]
EVENT_TYPES = [
    "invocation_submitted",
    "attempt_started",
    "retry_scheduled",
    "invocation_completed",
    "invocation_failed",
    "invocation_cancelled",
]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, nested in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = nested
    return value


def _load(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
    )


def _registry() -> Registry:
    resources = []
    for path in RESOURCE_PATHS:
        contents = _load(path)
        resources.append((path.name, Resource.from_contents(contents)))
    return Registry().with_resources(resources)


def _validator(name: str) -> Draft202012Validator:
    schema = _load(SCHEMA_SAMPLE_PAIRS[name][0])
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        schema,
        registry=_registry(),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def _sample(name: str) -> Any:
    return _load(SCHEMA_SAMPLE_PAIRS[name][1])


def _assert_invalid(name: str, value: Any) -> None:
    assert list(_validator(name).iter_errors(value)), f"{name} accepted {value!r}"


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert not payload.startswith(b"\xef\xbb\xbf")
    assert not payload.endswith(b"\n")
    return hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize("name", sorted(SCHEMA_SAMPLE_PAIRS))
def test_draft_2020_12_schema_accepts_duplicate_aware_sample(name: str) -> None:
    schema = _load(SCHEMA_SAMPLE_PAIRS[name][0])
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["x-ovca-schema-role"] == "structural_wire_only"
    assert "ovca_types::control_plane" in schema["x-ovca-semantic-validator"]
    _validator(name).validate(_sample(name))


def test_offline_registry_is_finite_and_all_refs_are_local() -> None:
    allowed = {path.name for path in RESOURCE_PATHS}
    for schema_path, _ in SCHEMA_SAMPLE_PAIRS.values():
        text = schema_path.read_text(encoding="utf-8")
        refs = re.findall(r'"\$ref"\s*:\s*"([^"#]+)', text)
        assert set(refs) <= allowed
        assert "http://" not in text
        assert text.count("https://") == 1
        assert "https://json-schema.org/draft/2020-12/schema" in text


def test_duplicate_aware_loader_rejects_nested_duplicate_keys() -> None:
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        json.loads(
            '{"payload":{"type":"specialist","type":"owner_final"}}',
            object_pairs_hook=_reject_duplicate_keys,
        )


def test_top_level_wire_fields_and_scalar_state_are_exact() -> None:
    for name, expected in OBJECT_FIELDS.items():
        schema = _load(SCHEMA_SAMPLE_PAIRS[name][0])
        sample = _sample(name)
        assert schema["additionalProperties"] is False
        assert schema["required"] == expected
        assert list(schema["properties"]) == expected
        assert list(sample) == expected

    state_schema = _load(SCHEMA_SAMPLE_PAIRS["state"][0])
    assert state_schema["type"] == "string"
    assert state_schema["enum"] == STATE_VALUES
    assert _sample("state") == "completed"
    assert "additionalProperties" not in state_schema


def test_samples_have_exact_canonical_cross_linked_digests() -> None:
    invocation = _sample("role_invocation")
    result = _sample("role_result")
    event = _sample("event")
    assert _canonical_digest(invocation["authority"]) == invocation["authority_digest"]
    assert _canonical_digest(invocation) == result["invocation_digest"]
    assert result["invocation_digest"] == event["payload"]["invocation_digest"]
    assert _canonical_digest(result) == event["payload"]["result_digest"]
    assert _canonical_digest(event["payload"]) == event["envelope"]["payload_digest"]
    assert event["envelope"]["event_kind"] == (
        f"control.{event['payload']['type']}"
    )


def test_invocation_schema_closes_version_fields_budget_roles_and_authority_shape() -> None:
    sample = _sample("role_invocation")
    for field, value in (
        ("contract_version", 2),
        ("invocation_id", ""),
        ("authority_digest", "A" * 64),
        ("input_digest", "a" * 63),
    ):
        invalid = copy.deepcopy(sample)
        invalid[field] = value
        _assert_invalid("role_invocation", invalid)

    for role in PUBLIC_ROLES:
        candidate = copy.deepcopy(sample)
        candidate["target"]["role"] = role
        _validator("role_invocation").validate(candidate)
    invalid = copy.deepcopy(sample)
    invalid["target"]["role"] = "unknown"
    _assert_invalid("role_invocation", invalid)
    invalid = copy.deepcopy(sample)
    invalid["budget"]["max_attempts"] = 0
    _assert_invalid("role_invocation", invalid)
    invalid = copy.deepcopy(sample)
    invalid["unexpected"] = True
    _assert_invalid("role_invocation", invalid)


def test_all_role_pairs_are_declared_and_rust_owns_the_closed_matrix() -> None:
    assert len({(left, right) for left in PUBLIC_ROLES for right in PUBLIC_ROLES}) == 25
    assert ALLOWED_ROLE_PAIRS == {
        ("owner", "coordinator"),
        ("coordinator", "engineer"),
        ("coordinator", "reviewer"),
        ("coordinator", "auditor"),
    }
    source = RUST_SOURCE.read_text(encoding="utf-8")
    for left, right in ALLOWED_ROLE_PAIRS:
        assert f"PrincipalV1::{left.title()}" in source
        assert f"PrincipalV1::{right.title()}" in source
    assert "fn validate_role_pair(" in source
    assert "SelfInvocation" in source


def test_state_rejects_object_tag_unknown_and_wrong_case() -> None:
    for invalid in (
        {"type": "pending"},
        {"state": "pending"},
        "Pending",
        "terminal",
        1,
        None,
    ):
        _assert_invalid("state", invalid)


def test_result_schema_closes_payloads_evidence_and_terminal_shapes() -> None:
    completed = _sample("role_result")
    empty_evidence = copy.deepcopy(completed)
    empty_evidence["evidence_ids"] = []
    _assert_invalid("role_result", empty_evidence)
    duplicate_evidence = copy.deepcopy(completed)
    duplicate_evidence["evidence_ids"] = ["evidence.001", "evidence.001"]
    _assert_invalid("role_result", duplicate_evidence)

    failed = copy.deepcopy(completed)
    failed["state"] = "failed"
    failed["payload"] = {
        "type": "failure",
        "code": "execution_failed",
        "message": "Execution failed safely",
    }
    failed["evidence_ids"] = []
    _validator("role_result").validate(failed)

    cancelled = copy.deepcopy(completed)
    cancelled["state"] = "cancelled"
    cancelled["payload"] = {
        "type": "cancellation",
        "reason": "Cancelled by caller",
    }
    cancelled["evidence_ids"] = []
    _validator("role_result").validate(cancelled)

    for state, payload in (
        ("completed", failed["payload"]),
        ("failed", cancelled["payload"]),
        ("cancelled", completed["payload"]),
    ):
        invalid = copy.deepcopy(completed)
        invalid["state"] = state
        invalid["payload"] = payload
        _assert_invalid("role_result", invalid)


def test_event_schema_composes_one_foundation_envelope_and_closed_payload() -> None:
    schema = _load(SCHEMA_SAMPLE_PAIRS["event"][0])
    assert schema["properties"]["envelope"]["$ref"] == (
        "foundation_event_envelope.v1.schema.json"
    )
    assert set(schema["properties"]) == {"contract_version", "envelope", "payload"}
    for forbidden in (
        "event_id",
        "domain",
        "scope",
        "producer",
        "event_kind",
        "sequence",
        "previous_event_id",
        "occurred_at",
        "payload_digest",
    ):
        assert forbidden not in schema["properties"]

    sample = _sample("event")
    for event_type in EVENT_TYPES:
        assert event_type in json.dumps(schema)
    invalid = copy.deepcopy(sample)
    invalid["payload"]["type"] = "unknown"
    _assert_invalid("event", invalid)
    invalid = copy.deepcopy(sample)
    invalid["payload"]["extra"] = True
    _assert_invalid("event", invalid)
    invalid = copy.deepcopy(sample)
    invalid["envelope"]["domain"] = "governed_brain"
    _validator("event").validate(invalid)
    assert "domain control_plane" in schema["description"] or (
        "validate_against" in schema["x-ovca-semantic-validator"]
    )


def test_rust_source_freezes_wire_tags_validators_transitions_and_no_io() -> None:
    source = RUST_SOURCE.read_text(encoding="utf-8")
    assert '#[serde(rename_all = "snake_case")]\npub enum ControlPlaneState' in source
    assert source.count('tag = "type", rename_all = "snake_case"') == 2
    for event_type in EVENT_TYPES:
        rust_variant = "".join(part.title() for part in event_type.split("_"))
        assert rust_variant in source
        assert f'"control.{event_type}"' in source
    for token in (
        "validate_control_plane_replay",
        "canonical_authority_digest",
        "InvalidAuthorityBinding",
        "InvalidTransition",
        "InvalidTimestamp",
        "MissingTerminalResult",
    ):
        assert token in source
    for forbidden in (
        "std::fs",
        "std::process",
        "tokio::",
        "reqwest::",
        "Command::new",
    ):
        assert forbidden not in source


def test_module_is_additive_without_glob_export_or_legacy_edits() -> None:
    lib = RUST_LIB.read_text(encoding="utf-8")
    assert lib.count("pub mod control_plane;") == 1
    assert "pub use control_plane::*;" not in lib
    source = RUST_SOURCE.read_text(encoding="utf-8")
    assert "pub struct ExecutionBudget" in source
    assert "TryFrom<&RetryBudget> for ExecutionBudget" in source
    assert "TryFrom<&RoleResultV1> for CoordinatorFinalResponse" in source
    assert "TryFrom<&RoleResultV1> for SpecialistOutput" in source
    assert ADR.is_file()


def test_public_hygiene_has_no_private_identity_or_machine_contract() -> None:
    paths = [
        *(schema for schema, _ in SCHEMA_SAMPLE_PAIRS.values()),
        *(sample for _, sample in SCHEMA_SAMPLE_PAIRS.values()),
        RUST_SOURCE,
        ADR,
    ]
    forbidden = re.compile(
        r"(?i)(?:password|api[_-]?key|bearer\s|authorization:|"
        r"(?<![a-z])[a-z]:[\\/]|\\\\|"
        r"private[_ -]?identity|production[_ -]?endpoint)"
    )
    environment_value = re.compile(r"\$\{?[A-Z_][A-Z0-9_]*\}?")
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert forbidden.search(text) is None, path
        assert environment_value.search(text) is None, path
