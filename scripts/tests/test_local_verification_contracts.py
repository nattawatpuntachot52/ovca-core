from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Iterator

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
SAMPLES = CONTRACTS / "samples"

SCHEMA_SAMPLE_PAIRS = {
    "behavioral_acceptance_contract": (
        CONTRACTS / "behavioral_acceptance_contract.v1.schema.json",
        SAMPLES / "behavioral_acceptance_contract.v1.sample.json",
    ),
    "capability_definition": (
        CONTRACTS / "capability_definition.v1.schema.json",
        SAMPLES / "capability_definition.v1.sample.json",
    ),
    "verification_failure": (
        CONTRACTS / "verification_failure.v1.schema.json",
        SAMPLES / "verification_failure.v1.sample.json",
    ),
    "verification_bundle": (
        CONTRACTS / "verification_bundle.v1.schema.json",
        SAMPLES / "verification_bundle.v1.sample.json",
    ),
}

FAILURE_CATEGORIES = {
    "timeout",
    "policy_block",
    "contract_violation",
    "source_drift",
    "environment",
    "infrastructure",
    "test_failed_unclassified",
    "product_bug",
    "test_fragility",
}

SEMANTIC_ONLY_INVARIANTS = {
    "implementation_actor_must_differ_from_verifier_actor",
    "pass_source_pre_must_equal_source_post",
    "bundle_and_proof_run_goal_task_bindings_must_match",
    "current_pointer_digest_must_equal_bundle_digest",
    "expected_fingerprints_must_equal_bundle_fingerprints",
    "criterion_ids_text_kinds_and_declared_order_must_match",
    "capability_membership_dependencies_and_allowlists_must_close",
    "goal_criterion_ownership_must_be_unique_and_complete",
    "ordered_vectors_must_be_canonical_sorted_unique",
    "cross_field_equality_and_inequality_require_rust_validation",
    "duplicate_json_object_keys_require_duplicate_aware_deserialization",
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validator(name: str) -> Draft202012Validator:
    schema_path, _ = SCHEMA_SAMPLE_PAIRS[name]
    schema = _load(schema_path)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def _sample(name: str) -> dict[str, Any]:
    _, sample_path = SCHEMA_SAMPLE_PAIRS[name]
    return _load(sample_path)


def _assert_invalid(name: str, payload: dict[str, Any]) -> None:
    errors = list(_validator(name).iter_errors(payload))
    assert errors, f"{name} unexpectedly accepted {payload!r}"


def _refs(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key == "$ref":
                yield nested
            else:
                yield from _refs(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _refs(nested)


@pytest.mark.parametrize("name", sorted(SCHEMA_SAMPLE_PAIRS))
def test_offline_draft_2020_12_schema_accepts_sample(name: str) -> None:
    schema_path, _ = SCHEMA_SAMPLE_PAIRS[name]
    schema = _load(schema_path)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    assert schema["x-ovca-schema-role"] == "structural_wire_only"
    assert schema["x-ovca-semantic-validator"].endswith("::validate")
    assert "Schema success never admits evidence" in schema["description"]
    _validator(name).validate(_sample(name))
    assert all(ref.startswith("#/") for ref in _refs(schema))


def test_shared_id_digest_and_logical_path_definitions_are_identical() -> None:
    schemas = [_load(pair[0]) for pair in SCHEMA_SAMPLE_PAIRS.values()]
    for definition in ("stableId", "sha256Digest", "logicalPath"):
        values = [schema["$defs"][definition] for schema in schemas]
        assert all(value == values[0] for value in values[1:])

    digest_definition = schemas[0]["$defs"]["sha256Digest"]
    assert digest_definition["minLength"] == 64
    assert digest_definition["maxLength"] == 64
    assert digest_definition["pattern"] == "^[0-9a-f]{64}(?![\\s\\S])"
    logical_pattern = schemas[0]["$defs"]["logicalPath"]["pattern"]
    for forbidden_fragment in ("\\\\", ":", "\\.{1,2}", "//"):
        assert forbidden_fragment in logical_pattern


def test_shared_definitions_reject_controls_del_and_false_end_anchors() -> None:
    schemas = [_load(pair[0]) for pair in SCHEMA_SAMPLE_PAIRS.values()]
    for schema in schemas:
        stable_id = Draft202012Validator(schema["$defs"]["stableId"])
        digest = Draft202012Validator(schema["$defs"]["sha256Digest"])
        logical_path = Draft202012Validator(schema["$defs"]["logicalPath"])

        assert stable_id.is_valid("valid.id")
        assert not stable_id.is_valid("valid.id\n")
        assert digest.is_valid("a" * 64)
        assert not digest.is_valid(("a" * 64) + "\n")
        for unsafe_path in (
            "rust/\0file",
            "rust/\tfile",
            "rust/\nfile",
            "rust/\rfile",
            "rust/\x1ffile",
            "rust/\x7ffile",
        ):
            assert not logical_path.is_valid(unsafe_path), unsafe_path


def test_schema_metadata_documents_mandatory_semantic_admission_boundary() -> None:
    assert SEMANTIC_ONLY_INVARIANTS == {
        "implementation_actor_must_differ_from_verifier_actor",
        "pass_source_pre_must_equal_source_post",
        "bundle_and_proof_run_goal_task_bindings_must_match",
        "current_pointer_digest_must_equal_bundle_digest",
        "expected_fingerprints_must_equal_bundle_fingerprints",
        "criterion_ids_text_kinds_and_declared_order_must_match",
        "capability_membership_dependencies_and_allowlists_must_close",
        "goal_criterion_ownership_must_be_unique_and_complete",
        "ordered_vectors_must_be_canonical_sorted_unique",
        "cross_field_equality_and_inequality_require_rust_validation",
        "duplicate_json_object_keys_require_duplicate_aware_deserialization",
    }
    for schema_path, _ in SCHEMA_SAMPLE_PAIRS.values():
        schema = _load(schema_path)
        assert schema["x-ovca-schema-role"] == "structural_wire_only"
        assert "Rust" in schema["description"]


def test_policy_and_fingerprint_definitions_remain_closed_and_sha256_only() -> None:
    capability_schema = _load(SCHEMA_SAMPLE_PAIRS["capability_definition"][0])
    policy = capability_schema["$defs"]["localMachinePolicy"]
    properties = policy["properties"]
    assert properties["local_only"] == {"const": True}
    assert properties["inherit_environment"] == {"const": False}
    assert properties["raw_shell"] == {"const": "forbidden"}
    assert properties["fingerprint_algorithm"] == {"const": "sha256"}
    for denied in (
        "network",
        "provider",
        "telemetry",
        "egress",
        "external_evidence",
        "external_storage",
    ):
        assert properties[denied] == {"const": "denied"}

    bundle_schema = _load(SCHEMA_SAMPLE_PAIRS["verification_bundle"][0])
    fingerprints = bundle_schema["$defs"]["verificationFingerprints"]
    expected = {
        "source_pre",
        "source_post",
        "behavior_contract",
        "capability_set",
        "command",
        "policy",
        "environment",
    }
    assert set(fingerprints["required"]) == expected
    assert set(fingerprints["properties"]) == expected
    assert all(
        value == {"$ref": "#/$defs/sha256Digest"}
        for value in fingerprints["properties"].values()
    )


def test_behavior_schema_rejects_version_unknown_duplicate_and_invalid_binding() -> None:
    sample = _sample("behavioral_acceptance_contract")

    invalid = copy.deepcopy(sample)
    invalid["contract_version"] = 2
    _assert_invalid("behavioral_acceptance_contract", invalid)

    invalid = copy.deepcopy(sample)
    invalid["unknown"] = True
    _assert_invalid("behavioral_acceptance_contract", invalid)

    invalid = copy.deepcopy(sample)
    invalid["criteria"][0]["capability_ids"] = ["cap.core", "cap.core"]
    _assert_invalid("behavioral_acceptance_contract", invalid)

    invalid = copy.deepcopy(sample)
    invalid["binding"]["absolute_source"] = "C:/oracle"
    _assert_invalid("behavioral_acceptance_contract", invalid)

    assert [item["order"] for item in sample["criteria"]] == list(
        range(len(sample["criteria"]))
    )
    assert len({item["criterion_id"] for item in sample["criteria"]}) == len(
        sample["criteria"]
    )


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "C:/oracle/file",
        "/oracle/file",
        "//server/share",
        r"oracle\file",
        "https://example.test/file",
        "oracle//file",
        "oracle/./file",
        "oracle/../file",
    ],
)
def test_capability_schema_rejects_nonlogical_paths(unsafe_path: str) -> None:
    invalid = _sample("capability_definition")
    invalid["commands"][0]["cwd"] = {"type": "relative", "path": unsafe_path}
    _assert_invalid("capability_definition", invalid)


def test_capability_schema_accepts_tagged_root_and_relative_working_directories() -> None:
    sample = _sample("capability_definition")
    assert sample["commands"][0]["cwd"] == {"type": "snapshot_root"}
    _validator("capability_definition").validate(sample)

    relative = copy.deepcopy(sample)
    relative["commands"][0]["cwd"] = {"type": "relative", "path": "rust"}
    _validator("capability_definition").validate(relative)

    dot_segment = copy.deepcopy(sample)
    dot_segment["commands"][0]["cwd"] = {"type": "relative", "path": "."}
    _assert_invalid("capability_definition", dot_segment)

    legacy_string = copy.deepcopy(sample)
    legacy_string["commands"][0]["cwd"] = "."
    _assert_invalid("capability_definition", legacy_string)


@pytest.mark.parametrize(
    "unsafe_argument",
    [
        "C:/oracle/file",
        r"C:\oracle\file",
        "/absolute/file",
        r"\\server\share",
        "//server/share",
        "https://example.test/file",
        "file://local/file",
        "--path=C:/oracle/file",
        "--path=/absolute/file",
        "line\nbreak",
        "tab\tvalue",
        "delete\x7fvalue",
        "--path=x=C:/oracle/file",
        "file:/absolute/file",
        "file:C:/absolute/file",
        "--path=file:C:/absolute/file",
        "C:relative/path",
        "--path=C:relative/path",
        "relative/C:/absolute/file",
        "--path:C:relative/path",
        "-IC:relative/include",
        "--wrapper=-IC:relative/include",
        "--path=x=C:relative/path",
        "--path:c:relative/path",
        "-Iz:relative/include",
    ],
)
def test_capability_schema_rejects_unsafe_argv_tokens(unsafe_argument: str) -> None:
    invalid = _sample("capability_definition")
    invalid["commands"][0]["argv"] = [unsafe_argument]
    _assert_invalid("capability_definition", invalid)


def test_capability_schema_preserves_safe_argv_tokens() -> None:
    sample = _sample("capability_definition")
    sample["commands"][0]["argv"] = [
        "--manifest-path",
        "rust/Cargo.toml",
        "-p",
        "ovca-types",
        "foo::bar",
        "crate::module::test",
        "--cfg=foo::bar",
        "--feature=value",
        "C%3Arelative/path",
        "--path=C%3Arelative/path",
    ]
    _validator("capability_definition").validate(sample)


def test_capability_schema_rejects_unsafe_policy_shell_env_and_duplicates() -> None:
    sample = _sample("capability_definition")

    for field, unsafe in (
        ("local_only", False),
        ("network", "allowed"),
        ("egress", "allowed"),
        ("inherit_environment", True),
        ("raw_shell", "allowed"),
        ("fingerprint_algorithm", "sha1"),
    ):
        invalid = copy.deepcopy(sample)
        invalid["policy"][field] = unsafe
        _assert_invalid("capability_definition", invalid)

    invalid = copy.deepcopy(sample)
    invalid["commands"][0]["executable_id"] = "pwsh"
    _assert_invalid("capability_definition", invalid)

    for mixed_case in ("Cargo", "PwSh", "BASH", "PowerShell.EXE"):
        invalid = copy.deepcopy(sample)
        invalid["policy"]["allowed_executable_ids"] = [mixed_case]
        invalid["commands"][0]["executable_id"] = mixed_case
        _assert_invalid("capability_definition", invalid)

    invalid = copy.deepcopy(sample)
    invalid["commands"][0]["environment_names"] = ["Path"]
    _assert_invalid("capability_definition", invalid)

    invalid = copy.deepcopy(sample)
    invalid["commands"][0]["environment_names"] = ["VALID_ENV\n"]
    _assert_invalid("capability_definition", invalid)

    invalid = copy.deepcopy(sample)
    invalid["criterion_ids"].append(invalid["criterion_ids"][0])
    _assert_invalid("capability_definition", invalid)

    assert sample["criterion_ids"] == sorted(set(sample["criterion_ids"]))
    assert [command["command_id"] for command in sample["commands"]] == sorted(
        {command["command_id"] for command in sample["commands"]}
    )


def test_failure_schema_has_exact_taxonomy_and_confirmation_transition_shape() -> None:
    schema = _load(SCHEMA_SAMPLE_PAIRS["verification_failure"][0])
    assert set(schema["properties"]["category"]["enum"]) == FAILURE_CATEGORIES
    sample = _sample("verification_failure")

    direct_confirmation = copy.deepcopy(sample)
    direct_confirmation["confirmation"] = "confirmed"
    _assert_invalid("verification_failure", direct_confirmation)

    provisional_superseding = copy.deepcopy(sample)
    provisional_superseding["supersedes_failure_id"] = "failure.prior"
    _assert_invalid("verification_failure", provisional_superseding)

    later_confirmation = copy.deepcopy(sample)
    later_confirmation["failure_id"] = "failure.confirmed"
    later_confirmation["confirmation"] = "confirmed"
    later_confirmation["supersedes_failure_id"] = "failure.sample"
    _validator("verification_failure").validate(later_confirmation)

    auto_confirmable = copy.deepcopy(sample)
    auto_confirmable["category"] = "timeout"
    auto_confirmable["confirmation"] = "confirmed"
    _validator("verification_failure").validate(auto_confirmable)

    unknown = copy.deepcopy(sample)
    unknown["category"] = "retry"
    _assert_invalid("verification_failure", unknown)


def test_bundle_schema_rejects_bad_digest_unknown_pass_failure_and_empty_nonpass() -> None:
    sample = _sample("verification_bundle")

    invalid = copy.deepcopy(sample)
    invalid["fingerprints"]["source_pre"] = "ABC"
    _assert_invalid("verification_bundle", invalid)

    invalid = copy.deepcopy(sample)
    invalid["unknown"] = True
    _assert_invalid("verification_bundle", invalid)

    invalid = copy.deepcopy(sample)
    invalid["failures"] = [_sample("verification_failure")]
    _assert_invalid("verification_bundle", invalid)

    invalid = copy.deepcopy(sample)
    invalid["criterion_results"][0]["verdict"] = "fail"
    _assert_invalid("verification_bundle", invalid)

    invalid = copy.deepcopy(sample)
    invalid["verdict"] = "timeout"
    _assert_invalid("verification_bundle", invalid)

    assert [item["order"] for item in sample["criterion_results"]] == list(
        range(len(sample["criterion_results"]))
    )


def test_bundle_schema_enforces_expressible_verdict_failure_relationships() -> None:
    sample = _sample("verification_bundle")
    product_failure = _sample("verification_failure")

    timeout_with_product_only = copy.deepcopy(sample)
    timeout_with_product_only["verdict"] = "timeout"
    timeout_with_product_only["failures"] = [product_failure]
    _assert_invalid("verification_bundle", timeout_with_product_only)

    timeout = copy.deepcopy(sample)
    timeout["verdict"] = "timeout"
    timeout["failures"] = [
        {
            "contract_version": 1,
            "failure_id": "failure.timeout",
            "category": "timeout",
            "confirmation": "confirmed",
            "summary": "The local command timed out",
            "recorded_at": "2026-08-09T12:00:00Z",
        }
    ]
    _validator("verification_bundle").validate(timeout)


def test_schema_acceptance_is_deliberately_not_semantic_admission() -> None:
    sample = _sample("verification_bundle")

    same_actor = copy.deepcopy(sample)
    same_actor["verifier_actor"] = same_actor["implementation_actor"]
    _validator("verification_bundle").validate(same_actor)

    source_drift = copy.deepcopy(sample)
    source_drift["fingerprints"]["source_post"] = "9" * 64
    _validator("verification_bundle").validate(source_drift)

    duplicate_criterion_id = copy.deepcopy(sample)
    duplicate_criterion_id["criterion_results"][1]["criterion_id"] = (
        duplicate_criterion_id["criterion_results"][0]["criterion_id"]
    )
    _validator("verification_bundle").validate(duplicate_criterion_id)

    assert "cross_field_equality_and_inequality_require_rust_validation" in (
        SEMANTIC_ONLY_INVARIANTS
    )


def test_current_bundle_proof_is_separate_and_contains_all_currentness_assertions() -> None:
    schema = _load(SCHEMA_SAMPLE_PAIRS["verification_bundle"][0])
    proof = schema["$defs"]["currentBundleProof"]
    expected_fields = {
        "contract_version",
        "bundle_digest",
        "checksum_verified",
        "integrity_verified",
        "current_pointer_verified",
        "current_pointer_digest",
        "expected_run_id",
        "expected_goal_id",
        "expected_task_id",
        "expected_behavior_contract_digest",
        "expected_capability_set_digest",
        "expected_command_digest",
        "expected_policy_digest",
        "expected_source_digest",
        "expected_environment_digest",
    }
    assert set(proof["required"]) == expected_fields
    assert set(proof["properties"]) == expected_fields
    assert proof["properties"]["checksum_verified"] == {"const": True}
    assert proof["properties"]["integrity_verified"] == {"const": True}
    assert proof["properties"]["current_pointer_verified"] == {"const": True}
    assert "caller assertions" in proof["description"]
    assert "V4c" in proof["description"]
    assert "current" not in schema["properties"]
    assert "fresh" not in schema["properties"]
