from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
SAMPLES = CONTRACTS / "samples"
RUST_SOURCE = ROOT / "rust" / "ovca-types" / "src" / "foundation.rs"
RUST_LIB = ROOT / "rust" / "ovca-types" / "src" / "lib.rs"
ADR = ROOT / "docs" / "adr" / "0001-shared-authority-evidence-compatibility.md"
PUBLIC_PRINCIPAL_ROLES = frozenset(
    {"owner", "coordinator", "engineer", "reviewer", "auditor"}
)

SCHEMA_SAMPLE_PAIRS = {
    "authority": (
        CONTRACTS / "foundation_authority.v1.schema.json",
        SAMPLES / "foundation_authority.v1.sample.json",
    ),
    "decision": (
        CONTRACTS / "foundation_decision.v1.schema.json",
        SAMPLES / "foundation_decision.v1.sample.json",
    ),
    "event_envelope": (
        CONTRACTS / "foundation_event_envelope.v1.schema.json",
        SAMPLES / "foundation_event_envelope.v1.sample.json",
    ),
    "evidence_ref": (
        CONTRACTS / "foundation_evidence_ref.v1.schema.json",
        SAMPLES / "foundation_evidence_ref.v1.sample.json",
    ),
}

TOP_LEVEL_KEYS = {
    "authority": {
        "contract_version",
        "authority_id",
        "principal",
        "scope",
        "namespace",
        "permission_profile",
        "visibility",
        "sensitivity",
        "validity",
    },
    "evidence_ref": {
        "contract_version",
        "evidence_id",
        "kind",
        "digest",
        "producer",
        "scope",
        "namespace",
        "locator",
        "produced_at",
    },
    "decision": {
        "contract_version",
        "decision_id",
        "kind",
        "status",
        "namespace",
        "actor",
        "subject",
        "scope",
        "subject_digest",
        "evidence_ids",
        "decided_at",
        "supersedes_decision_id",
    },
    "event_envelope": {
        "contract_version",
        "event_id",
        "domain",
        "scope",
        "producer",
        "event_kind",
        "sequence",
        "previous_event_id",
        "occurred_at",
        "payload_digest",
    },
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, nested in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = nested
    return value


def _load(path: Path) -> dict[str, Any]:
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
    )


def _validator(name: str) -> Draft202012Validator:
    schema = _load(SCHEMA_SAMPLE_PAIRS[name][0])
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def _sample(name: str) -> dict[str, Any]:
    return _load(SCHEMA_SAMPLE_PAIRS[name][1])


def _assert_invalid(name: str, value: dict[str, Any]) -> None:
    errors = list(_validator(name).iter_errors(value))
    assert errors, f"{name} unexpectedly accepted {value!r}"


def _principal_identities(value: Any) -> list[dict[str, Any]]:
    identities: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if "principal_id" in value and "role" in value:
            identities.append(value)
        for nested in value.values():
            identities.extend(_principal_identities(nested))
    elif isinstance(value, list):
        for nested in value:
            identities.extend(_principal_identities(nested))
    return identities


@pytest.mark.parametrize("name", sorted(SCHEMA_SAMPLE_PAIRS))
def test_draft_2020_12_schema_accepts_duplicate_aware_sample(name: str) -> None:
    schema_path, sample_path = SCHEMA_SAMPLE_PAIRS[name]
    schema = _load(schema_path)
    sample = _load(sample_path)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    assert schema["x-ovca-schema-role"] == "structural_wire_only"
    assert schema["x-ovca-semantic-validator"].endswith("::validate")
    assert "Rust" in schema["description"]
    _validator(name).validate(sample)


def test_duplicate_aware_loader_rejects_duplicate_keys() -> None:
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        json.loads(
            '{"contract_version":1,"contract_version":1}',
            object_pairs_hook=_reject_duplicate_keys,
        )


def test_shared_closed_definitions_are_identical() -> None:
    schemas = [_load(path) for path, _ in SCHEMA_SAMPLE_PAIRS.values()]
    for definition in (
        "stableId",
        "sha256Digest",
        "logicalPath",
        "principalIdentity",
        "scope",
        "namespace",
        "permissionProfile",
        "validity",
        "locator",
    ):
        values = [schema["$defs"][definition] for schema in schemas]
        assert all(value == values[0] for value in values[1:]), definition

    assert schemas[0]["$defs"]["principalIdentity"]["additionalProperties"] is False
    assert schemas[0]["$defs"]["scope"]["additionalProperties"] is False
    assert schemas[0]["$defs"]["permissionProfile"]["additionalProperties"] is False
    assert schemas[0]["$defs"]["validity"]["additionalProperties"] is False

    permission_profile = schemas[0]["$defs"]["permissionProfile"]["properties"]
    for key in ("resource_keys", "write_keys"):
        assert permission_profile[key]["uniqueItems"] is True
        assert permission_profile[key]["x-ovca-semantic-order"] == (
            "strict_ordinal_ascending"
        )


def test_evidence_kind_is_the_exact_existing_closed_enum() -> None:
    schema = _load(SCHEMA_SAMPLE_PAIRS["evidence_ref"][0])
    assert schema["properties"]["kind"]["enum"] == [
        "artifact",
        "document",
        "test_result",
        "log",
        "review",
        "audit",
        "external_reference",
        "other",
    ]
    invalid = _sample("evidence_ref")
    invalid["kind"] = "made_up_kind"
    _assert_invalid("evidence_ref", invalid)


def test_decision_evidence_and_supersession_structure_is_closed() -> None:
    schema = _load(SCHEMA_SAMPLE_PAIRS["decision"][0])
    evidence_ids = schema["properties"]["evidence_ids"]
    assert evidence_ids["minItems"] == 1
    assert evidence_ids["uniqueItems"] is True
    assert evidence_ids["x-ovca-semantic-order"] == "strict_ordinal_ascending"

    for values in ([], ["evidence.001", "evidence.001"]):
        invalid = _sample("decision")
        invalid["evidence_ids"] = values
        _assert_invalid("decision", invalid)

    structurally_valid_but_semantically_unsorted = _sample("decision")
    structurally_valid_but_semantically_unsorted["evidence_ids"] = [
        "evidence.002",
        "evidence.001",
    ]
    _validator("decision").validate(structurally_valid_but_semantically_unsorted)

    missing_predecessor = _sample("decision")
    missing_predecessor["status"] = "superseded"
    _assert_invalid("decision", missing_predecessor)

    for status in ("pending", "approved", "rejected", "passed", "failed"):
        forbidden_predecessor = _sample("decision")
        forbidden_predecessor["status"] = status
        forbidden_predecessor["supersedes_decision_id"] = "decision.previous.001"
        _assert_invalid("decision", forbidden_predecessor)

    valid_supersession = _sample("decision")
    valid_supersession["status"] = "superseded"
    valid_supersession["supersedes_decision_id"] = "decision.previous.001"
    _validator("decision").validate(valid_supersession)


def test_top_level_schema_and_samples_use_only_the_frozen_fields() -> None:
    optional = {
        "decision": {"supersedes_decision_id"},
        "event_envelope": {"previous_event_id"},
    }
    for name, expected in TOP_LEVEL_KEYS.items():
        schema = _load(SCHEMA_SAMPLE_PAIRS[name][0])
        sample = _sample(name)
        assert set(schema["properties"]) == expected
        assert set(schema["required"]) == expected - optional.get(name, set())
        assert set(sample) <= expected
        assert set(sample) >= set(schema["required"])


@pytest.mark.parametrize("name", sorted(SCHEMA_SAMPLE_PAIRS))
def test_version_unknown_fields_and_unknown_principal_roles_fail_closed(name: str) -> None:
    sample = _sample(name)

    invalid = copy.deepcopy(sample)
    invalid["contract_version"] = 2
    _assert_invalid(name, invalid)

    invalid = copy.deepcopy(sample)
    invalid["unexpected"] = True
    _assert_invalid(name, invalid)

    principal_key = "principal" if name == "authority" else "producer"
    if name == "decision":
        principal_key = "actor"
    invalid = copy.deepcopy(sample)
    invalid[principal_key]["role"] = "administrator"
    _assert_invalid(name, invalid)


@pytest.mark.parametrize("name", sorted(SCHEMA_SAMPLE_PAIRS))
def test_scope_requires_project_and_exact_parent_chain(name: str) -> None:
    sample = _sample(name)

    missing_project = copy.deepcopy(sample)
    del missing_project["scope"]["project_id"]
    _assert_invalid(name, missing_project)

    missing_goal = copy.deepcopy(sample)
    del missing_goal["scope"]["goal_id"]
    _assert_invalid(name, missing_goal)

    missing_task = copy.deepcopy(sample)
    del missing_task["scope"]["task_id"]
    _assert_invalid(name, missing_task)


def test_id_digest_and_logical_path_negative_matrix() -> None:
    schema = _load(SCHEMA_SAMPLE_PAIRS["evidence_ref"][0])
    stable_id = Draft202012Validator(schema["$defs"]["stableId"])
    digest = Draft202012Validator(schema["$defs"]["sha256Digest"])
    logical_path = Draft202012Validator(schema["$defs"]["logicalPath"])

    assert stable_id.is_valid("stable.id:1")
    for value in ("", ".hidden", "white space", "line\nfeed", "a" * 129):
        assert not stable_id.is_valid(value), value

    assert digest.is_valid("a" * 64)
    for value in ("A" * 64, "a" * 63, ("a" * 64) + "\n"):
        assert not digest.is_valid(value), value

    assert logical_path.is_valid("contracts/samples/foundation.json")
    for value in (
        "/absolute",
        "trailing/",
        "double//segment",
        "dot/./segment",
        "dot/../segment",
        "C:/drive",
        r"unc\share",
        "https://example.invalid/file",
        "$WORKSPACE/file",
        "raw task body",
        ("a" * 129) + "/file",
    ):
        assert not logical_path.is_valid(value), value


def test_locator_is_exactly_tagged_stable_id_or_logical_path() -> None:
    sample = _sample("evidence_ref")
    validator = _validator("evidence_ref")

    stable = copy.deepcopy(sample)
    stable["locator"] = {"type": "stable_id", "value": "artifact.foundation.001"}
    validator.validate(stable)

    for locator in (
        {"type": "unknown", "value": "artifact.foundation.001"},
        {"type": "logical_path", "value": "C:/private"},
        {"type": "stable_id", "value": "artifact.foundation.001", "path": "extra"},
    ):
        invalid = copy.deepcopy(sample)
        invalid["locator"] = locator
        _assert_invalid("evidence_ref", invalid)


def test_decision_event_authority_and_evidence_enums_are_closed() -> None:
    changes = (
        ("authority", "visibility", "world"),
        ("decision", "kind", "completion"),
        ("event_envelope", "domain", "provider"),
        ("evidence_ref", "kind", "made_up_kind"),
        ("evidence_ref", "namespace", "general"),
    )
    for name, field, value in changes:
        invalid = _sample(name)
        invalid[field] = value
        _assert_invalid(name, invalid)


def _struct_fields(source: str, struct_name: str) -> list[str]:
    marker = f"pub struct {struct_name} {{"
    block = source.split(marker, 1)[1].split("\n}", 1)[0]
    return re.findall(r"^\s*pub ([a-z_]+):", block, flags=re.MULTILINE)


def test_rust_top_level_fields_and_closed_validation_surface_match_schema() -> None:
    source = RUST_SOURCE.read_text(encoding="utf-8")
    expected = {
        "FoundationAuthorityV1": list(TOP_LEVEL_KEYS["authority"]),
        "FoundationEvidenceRefV1": list(TOP_LEVEL_KEYS["evidence_ref"]),
        "FoundationDecisionV1": list(TOP_LEVEL_KEYS["decision"]),
        "FoundationEventEnvelopeV1": list(TOP_LEVEL_KEYS["event_envelope"]),
    }
    for struct_name, fields in expected.items():
        assert set(_struct_fields(source, struct_name)) == set(fields), struct_name
        block = source.split(f"impl {struct_name} {{", 1)[1]
        assert "pub fn validate(&self)" in block.split("\n}", 1)[0]

    for required in (
        "pub enum PrincipalV1",
        "pub struct PrincipalIdentityV1",
        "pub struct FoundationPermissionProfileV1",
        "pub fn validate_decision_transition",
        "pub fn validate_validity_transition",
        "pub fn validate_visibility_transition",
        "pub fn validate_logical_path",
        "pub fn validate_sha256_digest",
        "current_authority_digest",
        "owner_approval.namespace == authority.namespace",
        "owner_approval.scope == authority.scope",
        "owner_approval.subject == authority.principal",
        "owner_approval.subject_digest == current_authority_digest",
        "FoundationDecisionStatusV1::Superseded",
        "NonCanonicalIdentifierOrder",
    ):
        assert required in source

    lib_source = RUST_LIB.read_text(encoding="utf-8")
    assert "pub mod foundation;" in lib_source
    assert "pub use foundation::*" not in lib_source


def test_samples_are_synthetic_public_safe_and_payload_free() -> None:
    for _, sample_path in SCHEMA_SAMPLE_PAIRS.values():
        text = sample_path.read_text(encoding="utf-8")
        assert re.search(r"[A-Za-z]:[\\/]", text) is None
        assert "\\\\" not in text
        assert "http://" not in text and "https://" not in text
        sample = _load(sample_path)
        assert "payload" not in sample
        identities = _principal_identities(sample)
        assert identities
        for identity in identities:
            assert identity["role"] in PUBLIC_PRINCIPAL_ROLES
            assert identity["principal_id"] == f"principal.{identity['role']}"


def test_schema_urls_and_candidate_documentation_hygiene_are_bounded() -> None:
    for schema_path, _ in SCHEMA_SAMPLE_PAIRS.values():
        urls = re.findall(r"https?://[^\"\s]+", schema_path.read_text(encoding="utf-8"))
        assert urls == ["https://json-schema.org/draft/2020-12/schema"]

    production_rust = RUST_SOURCE.read_text(encoding="utf-8").split("#[cfg(test)]", 1)[0]
    adr = ADR.read_text(encoding="utf-8")
    for text in (production_rust, adr):
        assert re.search(r"[A-Za-z]:[\\/]", text) is None
        assert "\\\\" not in text
        assert re.search(r"https?://", text) is None


def test_existing_goal_runtime_contract_files_remain_separate() -> None:
    legacy_paths = (
        CONTRACTS / "behavioral_acceptance_contract.v1.schema.json",
        CONTRACTS / "capability_definition.v1.schema.json",
        CONTRACTS / "verification_bundle.v1.schema.json",
        CONTRACTS / "verification_failure.v1.schema.json",
        SAMPLES / "behavioral_acceptance_contract.v1.sample.json",
        SAMPLES / "capability_definition.v1.sample.json",
        SAMPLES / "verification_bundle.v1.sample.json",
        SAMPLES / "verification_failure.v1.sample.json",
    )
    assert all(path.is_file() for path in legacy_paths)
    assert all("foundation_" not in path.name for path in legacy_paths)
