from __future__ import annotations

import json
import sys
from datetime import datetime
from datetime import timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scripts.revision_loop as revision_loop


def _failure(
    category: revision_loop.VerificationFailureCategory | str,
    *,
    confirmation: revision_loop.FailureConfirmation | str = revision_loop.FailureConfirmation.PROVISIONAL,
    failure_id: str = "failure.v2",
    classifier_actor: str = "reviewer.classifier",
    supersedes_failure_id: str | None = None,
    criterion_id: str | None = "criterion.v2",
    contract_version: int = 1,
    summary: str = "verification failure",
    recorded_at: datetime = datetime(2026, 8, 10, tzinfo=timezone.utc),
) -> revision_loop.VerificationFailureRecord:
    return revision_loop.VerificationFailureRecord(
        failure_id=failure_id,
        category=category,
        confirmation=confirmation,
        classifier_actor=classifier_actor,
        supersedes_failure_id=supersedes_failure_id,
        criterion_id=criterion_id,
        contract_version=contract_version,
        summary=summary,
        recorded_at=recorded_at,
    )


def _bindings(**overrides: str | None) -> revision_loop.FailureOwnerBindings:
    values: dict[str, str | None] = {
        "implementation_actor": "engineer.implementation",
        "verifier_actor": "reviewer.verifier",
        "capability_owner": "engineer.capability",
        "test_owner": "auditor.tests",
        "coordinator": "coordinator.coordinator",
        "confirmation_owner": "auditor.confirmation",
    }
    values.update(overrides)
    return revision_loop.FailureOwnerBindings(**values)


def _assert_math_proof_scaffold(text: str) -> None:
    markers = [
        "## Math Proof",
        "### Assumptions",
        "### Derivation",
        "### Counterexample",
    ]
    positions = [text.index(marker) for marker in markers]
    assert positions == sorted(positions)


def test_generate_feedback_contains_score_gap_and_component_rows() -> None:
    feedback = revision_loop.generate_feedback(
        "demo_task",
        0.61,
        {"s1": 0.30, "s2": 0.90, "s3": 0.50, "s4": 0.70},
        1,
        3,
    )

    assert "Revision Required" in feedback
    assert "Math Score: 0.610" in feedback
    assert "gap: 0.140" in feedback
    assert "| s1 evidence_score | 0.30 | x0.25 |" in feedback
    assert "| s4 consistency_score | 0.70 | x0.20 |" in feedback
    _assert_math_proof_scaffold(feedback)


def test_append_feedback_to_task_preserves_required_math_proof_scaffold() -> None:
    feedback = revision_loop.generate_feedback(
        "demo_task",
        0.61,
        {"s1": 0.30, "s2": 0.40, "s3": 0.50, "s4": 0.70},
        1,
        3,
    )

    task_text = revision_loop.append_feedback_to_task("# demo_task\n\n## Objective\nRevise it.\n", feedback)

    assert "## Revision Loop Feedback" in task_text
    assert "Preserve the required `## Math Proof` scaffold" in task_text
    _assert_math_proof_scaffold(task_text)


def test_write_feedback_creates_revision_feedback_file(tmp_path: Path) -> None:
    path = revision_loop.write_feedback("demo_task", "hello", root=tmp_path)

    assert path == tmp_path / "tasks" / "inbox" / "demo_task" / "revision_feedback.md"
    assert path.read_text(encoding="utf-8") == "hello"


def test_should_retry_attempt_1_is_true() -> None:
    state = revision_loop.RevisionState(task_name="demo", attempt=1, max_attempts=3)

    assert revision_loop.should_retry(state) is True


def test_should_retry_attempt_3_is_true() -> None:
    state = revision_loop.RevisionState(task_name="demo", attempt=3, max_attempts=3)

    assert revision_loop.should_retry(state) is True


def test_should_retry_attempt_4_is_false() -> None:
    state = revision_loop.RevisionState(task_name="demo", attempt=4, max_attempts=3)

    assert revision_loop.should_retry(state) is False


def test_escalate_to_owner_writes_blocked_tasks_log(tmp_path: Path) -> None:
    state = revision_loop.RevisionState(task_name="demo_task", attempt=4, score_history=[0.62, 0.68, 0.71])

    revision_loop.escalate_to_owner(state, 0.71, root=tmp_path)

    log_path = tmp_path / "logs" / "blocked_tasks.jsonl"
    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert rows[-1]["task_name"] == "demo_task"
    assert rows[-1]["status"] == "ESCALATED_TO_OWNER"
    assert rows[-1]["attempts"] == 3
    assert rows[-1]["score_history"] == [0.62, 0.68, 0.71]


def test_log_revision_writes_revision_loop_log(tmp_path: Path) -> None:
    state = revision_loop.RevisionState(task_name="demo_task", attempt=2)

    revision_loop.log_revision("demo_task", state, 0.72, "WARN", root=tmp_path)

    log_path = tmp_path / "logs" / "revision_loop.jsonl"
    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert rows[-1]["task_name"] == "demo_task"
    assert rows[-1]["attempt"] == 2
    assert rows[-1]["score"] == 0.72
    assert rows[-1]["verdict"] == "WARN"
    assert rows[-1]["escalated"] is False


def test_generate_feedback_orders_actions_by_impact() -> None:
    feedback = revision_loop.generate_feedback(
        "impact_demo",
        0.50,
        {"s1": 0.10, "s2": 0.20, "s3": 0.74, "s4": 0.70, "s5": 1.0, "s6": 1.0},
        1,
        3,
    )

    first = feedback.index("1. **[s1]**")
    second = feedback.index("2. **[s2]**")
    third = feedback.index("3. **[s4]**")
    assert first < second < third


@pytest.mark.parametrize(
    ("category", "owner_binding", "target_owner"),
    [
        (
            revision_loop.VerificationFailureCategory.PRODUCT_BUG,
            revision_loop.FailureOwnerBinding.CAPABILITY_OWNER,
            "engineer.capability",
        ),
        (
            revision_loop.VerificationFailureCategory.TEST_FRAGILITY,
            revision_loop.FailureOwnerBinding.TEST_OWNER,
            "auditor.tests",
        ),
        (
            revision_loop.VerificationFailureCategory.SOURCE_DRIFT,
            revision_loop.FailureOwnerBinding.IMPLEMENTATION_ACTOR,
            "engineer.implementation",
        ),
        (
            revision_loop.VerificationFailureCategory.POLICY_BLOCK,
            revision_loop.FailureOwnerBinding.VERIFIER_ACTOR,
            "reviewer.verifier",
        ),
        (
            revision_loop.VerificationFailureCategory.CONTRACT_VIOLATION,
            revision_loop.FailureOwnerBinding.VERIFIER_ACTOR,
            "reviewer.verifier",
        ),
        (
            revision_loop.VerificationFailureCategory.TIMEOUT,
            revision_loop.FailureOwnerBinding.COORDINATOR,
            "coordinator.coordinator",
        ),
        (
            revision_loop.VerificationFailureCategory.ENVIRONMENT,
            revision_loop.FailureOwnerBinding.COORDINATOR,
            "coordinator.coordinator",
        ),
        (
            revision_loop.VerificationFailureCategory.INFRASTRUCTURE,
            revision_loop.FailureOwnerBinding.COORDINATOR,
            "coordinator.coordinator",
        ),
        (
            revision_loop.VerificationFailureCategory.TEST_FAILED_UNCLASSIFIED,
            revision_loop.FailureOwnerBinding.COORDINATOR,
            "coordinator.coordinator",
        ),
    ],
)
def test_failure_taxonomy_routes_only_to_caller_bound_owner(
    category: revision_loop.VerificationFailureCategory,
    owner_binding: revision_loop.FailureOwnerBinding,
    target_owner: str,
) -> None:
    prior = None
    failure = _failure(category)
    if category in {
        revision_loop.VerificationFailureCategory.PRODUCT_BUG,
        revision_loop.VerificationFailureCategory.TEST_FRAGILITY,
    }:
        prior = failure
        failure = _failure(
            category,
            confirmation=revision_loop.FailureConfirmation.CONFIRMED,
            failure_id="failure.confirmed",
            classifier_actor="auditor.classifier",
            supersedes_failure_id=prior.failure_id,
        )

    route = revision_loop.route_verification_failure(
        failure,
        revision_loop.RevisionState(task_name="v2", attempt=1),
        _bindings(),
        0.5,
        prior_failure=prior,
    )

    assert route.status is revision_loop.FailureRouteStatus.RETRY
    assert route.owner_binding == owner_binding
    assert route.target_owner == target_owner


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("category", "garbage"),
        ("confirmation", "garbage"),
        ("failure_id", "bad failure id"),
        ("classifier_actor", "bad actor"),
        ("criterion_id", "bad criterion"),
        ("supersedes_failure_id", "bad supersedes id"),
        ("contract_version", 2),
        ("summary", "  "),
        ("recorded_at", datetime(2026, 8, 10)),
    ],
)
def test_failure_wire_fields_fail_closed(field: str, value: object) -> None:
    values: dict[str, object] = {
        "category": revision_loop.VerificationFailureCategory.TIMEOUT,
        "confirmation": revision_loop.FailureConfirmation.CONFIRMED,
        "failure_id": "failure.v2",
        "classifier_actor": "reviewer.classifier",
        "supersedes_failure_id": None,
        "criterion_id": "criterion.v2",
        "contract_version": 1,
        "summary": "verification failure",
        "recorded_at": datetime(2026, 8, 10, tzinfo=timezone.utc),
    }
    values[field] = value
    failure = revision_loop.VerificationFailureRecord(**values)

    route = revision_loop.route_verification_failure(
        failure,
        revision_loop.RevisionState(task_name="v2", attempt=1),
        _bindings(),
        0.5,
    )

    assert route.directive is revision_loop.FailureRouteDirective.BLOCKED
    assert route.target_owner is None


def test_strict_rust_failure_wire_round_trip_and_rejects_drift() -> None:
    record = _failure(
        revision_loop.VerificationFailureCategory.TIMEOUT,
        confirmation=revision_loop.FailureConfirmation.CONFIRMED,
    )
    wire = revision_loop.verification_failure_record_to_wire(record)
    assert revision_loop.verification_failure_record_from_wire(wire) == record

    for invalid in [
        {**wire, "extra": True},
        {**wire, "failure": {**wire["failure"], "extra": True}},
        {**wire, "failure": {**wire["failure"], "category": "garbage"}},
        {**wire, "failure": {**wire["failure"], "confirmation": "garbage"}},
        {**wire, "failure": {**wire["failure"], "recorded_at": "2026-08-10"}},
        {**wire, "failure": {**wire["failure"], "recorded_at": "2026-08-10Z"}},
        {
            **wire,
            "failure": {
                **wire["failure"],
                "recorded_at": "2026-08-10T00:00:00+00:00",
            },
        },
        {**wire, "failure": {**wire["failure"], "recorded_at": "2026-08-10T00:00:00.1Z"}},
        {
            **wire,
            "failure": {
                **wire["failure"],
                "recorded_at": "2026-08-10T00:00:00.123456789Z",
            },
        },
    ]:
        with pytest.raises(ValueError):
            revision_loop.verification_failure_record_from_wire(invalid)

    for recorded_at in [
        "2026-08-10T00:00:00Z",
        "2026-08-10T00:00:00.123Z",
        "2026-08-10T00:00:00.123456Z",
    ]:
        canonical = {**wire, "failure": {**wire["failure"], "recorded_at": recorded_at}}
        decoded = revision_loop.verification_failure_record_from_wire(canonical)
        assert revision_loop.verification_failure_record_to_wire(decoded) == canonical


def test_malformed_prior_object_blocks_without_exception() -> None:
    route = revision_loop.route_verification_failure(
        _failure(revision_loop.VerificationFailureCategory.TIMEOUT),
        revision_loop.RevisionState(task_name="v2", attempt=1),
        _bindings(),
        0.5,
        prior_failure=object(),
    )

    assert route.directive is revision_loop.FailureRouteDirective.BLOCKED
    assert "prior" in route.reason


def test_non_sensitive_supersedes_is_valid_but_self_supersedes_blocks() -> None:
    valid = _failure(
        revision_loop.VerificationFailureCategory.TIMEOUT,
        confirmation=revision_loop.FailureConfirmation.CONFIRMED,
        failure_id="failure.new",
        supersedes_failure_id="failure.old",
    )
    accepted = revision_loop.route_verification_failure(
        valid,
        revision_loop.RevisionState(task_name="v2", attempt=1),
        _bindings(),
        0.5,
    )
    assert accepted.directive is revision_loop.FailureRouteDirective.RETRY

    self_superseding = _failure(
        revision_loop.VerificationFailureCategory.TIMEOUT,
        confirmation=revision_loop.FailureConfirmation.CONFIRMED,
        failure_id="failure.same",
        supersedes_failure_id="failure.same",
    )
    blocked = revision_loop.route_verification_failure(
        self_superseding,
        revision_loop.RevisionState(task_name="v2", attempt=1),
        _bindings(),
        0.5,
    )
    assert blocked.directive is revision_loop.FailureRouteDirective.BLOCKED


@pytest.mark.parametrize(
    "category",
    [
        revision_loop.VerificationFailureCategory.PRODUCT_BUG,
        revision_loop.VerificationFailureCategory.TEST_FRAGILITY,
    ],
)
def test_sensitive_provisional_awaits_confirmation_without_retry(
    category: revision_loop.VerificationFailureCategory,
) -> None:
    route = revision_loop.route_verification_failure(
        _failure(category),
        revision_loop.RevisionState(task_name="v2", attempt=1),
        _bindings(),
        0.5,
    )

    assert route.directive is revision_loop.FailureRouteDirective.AWAITING_CONFIRMATION
    assert route.owner_binding is revision_loop.FailureOwnerBinding.CONFIRMATION_OWNER
    assert route.target_owner == "auditor.confirmation"
    assert route.to_wire() == {
        "directive": "awaiting_confirmation",
        "category": category.value,
        "owner_binding": "confirmation_owner",
        "target_owner": "auditor.confirmation",
        "reason": "sensitive provisional failure requires independent confirmation",
    }

    missing = revision_loop.route_verification_failure(
        _failure(category),
        revision_loop.RevisionState(task_name="v2", attempt=1),
        _bindings(confirmation_owner=None),
        0.5,
    )
    assert missing.directive is revision_loop.FailureRouteDirective.BLOCKED

    same_actor = revision_loop.route_verification_failure(
        _failure(category),
        revision_loop.RevisionState(task_name="v2", attempt=1),
        _bindings(confirmation_owner="reviewer.classifier"),
        0.5,
    )
    assert same_actor.directive is revision_loop.FailureRouteDirective.BLOCKED
    assert "differ" in same_actor.reason


def test_missing_required_failure_owner_blocks_without_guessing() -> None:
    provisional = _failure(revision_loop.VerificationFailureCategory.TEST_FRAGILITY)
    confirmed = _failure(
        revision_loop.VerificationFailureCategory.TEST_FRAGILITY,
        confirmation=revision_loop.FailureConfirmation.CONFIRMED,
        failure_id="failure.confirmed",
        classifier_actor="auditor.classifier",
        supersedes_failure_id=provisional.failure_id,
    )

    route = revision_loop.route_verification_failure(
        confirmed,
        revision_loop.RevisionState(task_name="v2", attempt=1),
        _bindings(test_owner=None),
        0.5,
        prior_failure=provisional,
    )

    assert route.status is revision_loop.FailureRouteStatus.BLOCKED
    assert route.owner_binding is revision_loop.FailureOwnerBinding.TEST_OWNER
    assert route.target_owner is None
    assert "missing" in route.reason


@pytest.mark.parametrize(
    "category",
    [
        revision_loop.VerificationFailureCategory.PRODUCT_BUG,
        revision_loop.VerificationFailureCategory.TEST_FRAGILITY,
    ],
)
def test_sensitive_confirmation_requires_matching_provisional_and_independent_actor(
    category: revision_loop.VerificationFailureCategory,
) -> None:
    provisional = _failure(category)
    confirmed = _failure(
        category,
        confirmation=revision_loop.FailureConfirmation.CONFIRMED,
        failure_id="failure.confirmed",
        classifier_actor="auditor.classifier",
        supersedes_failure_id=provisional.failure_id,
    )
    accepted = revision_loop.route_verification_failure(
        confirmed,
        revision_loop.RevisionState(task_name="v2", attempt=1),
        _bindings(),
        0.5,
        prior_failure=provisional,
    )
    assert accepted.status is revision_loop.FailureRouteStatus.RETRY

    same_actor = revision_loop.VerificationFailureRecord(
        failure_id=confirmed.failure_id,
        category=confirmed.category,
        confirmation=confirmed.confirmation,
        classifier_actor=provisional.classifier_actor,
        supersedes_failure_id=confirmed.supersedes_failure_id,
        criterion_id=confirmed.criterion_id,
    )
    blocked = revision_loop.route_verification_failure(
        same_actor,
        revision_loop.RevisionState(task_name="v2", attempt=1),
        _bindings(),
        0.5,
        prior_failure=provisional,
    )
    assert blocked.status is revision_loop.FailureRouteStatus.BLOCKED
    assert "independent classifier" in blocked.reason

    missing = revision_loop.route_verification_failure(
        confirmed,
        revision_loop.RevisionState(task_name="v2", attempt=1),
        _bindings(),
        0.5,
    )
    assert missing.status is revision_loop.FailureRouteStatus.BLOCKED
    assert "matching provisional" in missing.reason

    predating = _failure(
        category,
        confirmation=revision_loop.FailureConfirmation.CONFIRMED,
        failure_id="failure.predating",
        classifier_actor="auditor.classifier",
        supersedes_failure_id=provisional.failure_id,
        recorded_at=datetime(2026, 8, 9, tzinfo=timezone.utc),
    )
    causal_block = revision_loop.route_verification_failure(
        predating,
        revision_loop.RevisionState(task_name="v2", attempt=1),
        _bindings(),
        0.5,
        prior_failure=provisional,
    )
    assert causal_block.directive is revision_loop.FailureRouteDirective.BLOCKED
    assert "predate" in causal_block.reason


def test_duplicate_failure_ids_in_pair_block_before_routing() -> None:
    prior = _failure(revision_loop.VerificationFailureCategory.TIMEOUT)
    current = _failure(
        revision_loop.VerificationFailureCategory.INFRASTRUCTURE,
        failure_id=prior.failure_id,
    )
    route = revision_loop.route_verification_failure(
        current,
        revision_loop.RevisionState(task_name="v2", attempt=1),
        _bindings(),
        0.5,
        prior_failure=prior,
    )
    assert route.directive is revision_loop.FailureRouteDirective.BLOCKED
    assert "duplicate failure_id" in route.reason


def test_failure_route_reuses_existing_retry_and_escalation(tmp_path: Path) -> None:
    state = revision_loop.RevisionState(task_name="v2", attempt=4, max_attempts=3)
    route = revision_loop.route_verification_failure(
        _failure(revision_loop.VerificationFailureCategory.INFRASTRUCTURE),
        state,
        _bindings(),
        0.42,
        root=tmp_path,
    )

    assert revision_loop.should_retry(state) is False
    assert route.status is revision_loop.FailureRouteStatus.ESCALATE_TO_OWNER
    assert route.target_owner == "coordinator.coordinator"
    rows = [
        json.loads(line)
        for line in (tmp_path / "logs" / "blocked_tasks.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert rows[-1]["task_name"] == "v2"


@pytest.mark.parametrize(
    ("state", "score"),
    [
        (revision_loop.RevisionState(task_name="v2", attempt=0), 0.5),
        (revision_loop.RevisionState(task_name="v2", attempt=4, max_attempts=0), 0.5),
        (revision_loop.RevisionState(task_name="v2", attempt=4), float("nan")),
        (revision_loop.RevisionState(task_name="v2", attempt=4), float("inf")),
        (revision_loop.RevisionState(task_name="bad task", attempt=4), 0.5),
        (
            revision_loop.RevisionState(task_name="v2", attempt=4, score_history=[float("nan")]),
            0.5,
        ),
        (
            revision_loop.RevisionState(task_name="v2", attempt=4, score_history=[1.1]),
            0.5,
        ),
        (
            revision_loop.RevisionState(task_name="v2", attempt=4, score_history=(0.5,)),
            0.5,
        ),
        (revision_loop.RevisionState(task_name="v2", attempt=4, blocked="false"), 0.5),
    ],
)
def test_invalid_state_or_score_blocks_before_escalation_side_effect(
    tmp_path: Path,
    state: revision_loop.RevisionState,
    score: float,
) -> None:
    route = revision_loop.route_verification_failure(
        _failure(revision_loop.VerificationFailureCategory.INFRASTRUCTURE),
        state,
        _bindings(),
        score,
        root=tmp_path,
    )

    assert route.directive is revision_loop.FailureRouteDirective.BLOCKED
    assert not (tmp_path / "logs" / "blocked_tasks.jsonl").exists()
