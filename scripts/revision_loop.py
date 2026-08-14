from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from datetime import timezone
from enum import Enum
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
THRESHOLD = 0.75
MAX_RETRIES = 3

COMPONENT_WEIGHTS = {
    "s1": 0.25,
    "s2": 0.20,
    "s3": 0.25,
    "s4": 0.20,
    "s5": 0.05,
    "s6": 0.05,
}

COMPONENT_LABELS = {
    "s1": ("evidence_score", "ไม่มี evidence_refs ใน frontmatter หรือ citation ใน handoff"),
    "s2": ("proof_score", "ไม่มี Math Proof section หรือ proof_report ไม่ผ่าน"),
    "s3": ("test_score", "ไม่มี 'N passed' ใน ## 4. PASS/FAIL Checklist"),
    "s4": ("consistency_score", "patch_verify ไม่ผ่าน หรือ git diff ไม่ตรงกับ files claimed"),
    "s5": ("recency_score", "handoff เก่าเกินไป"),
    "s6": ("agent_reliability", "agent reliability ต่ำ"),
}

ACTION_HINTS = {
    "s1": "เพิ่ม evidence_refs ใน YAML frontmatter หรือ URL citation ใน ## 3. Commands Run",
    "s2": "เพิ่ม Math Proof scaffold ที่บังคับ: Assumptions -> Derivation -> Counterexample",
    "s3": "รัน pytest จริง แล้ววาง output 'N passed, M failed' ใน ## 4. PASS/FAIL Checklist",
    "s4": "ตรวจสอบว่า files listed ใน ## 2. Files Changed ตรงกับไฟล์ที่แก้จริง",
    "s5": "ส่ง handoff ใหม่ให้เร็วขึ้น",
    "s6": "ทำให้ครบตาม acceptance criteria ทุกข้อ",
}

MATH_PROOF_SCAFFOLD = """\
## Math Proof
### Assumptions
- [fill]

### Derivation
- [fill]

### Counterexample
- [fill]
"""


@dataclass
class RevisionState:
    task_name: str
    attempt: int = 1
    max_attempts: int = MAX_RETRIES
    score_history: list[float] = field(default_factory=list)
    blocked: bool = False


class VerificationFailureCategory(str, Enum):
    TIMEOUT = "timeout"
    POLICY_BLOCK = "policy_block"
    CONTRACT_VIOLATION = "contract_violation"
    SOURCE_DRIFT = "source_drift"
    ENVIRONMENT = "environment"
    INFRASTRUCTURE = "infrastructure"
    TEST_FAILED_UNCLASSIFIED = "test_failed_unclassified"
    PRODUCT_BUG = "product_bug"
    TEST_FRAGILITY = "test_fragility"


class FailureConfirmation(str, Enum):
    PROVISIONAL = "provisional"
    CONFIRMED = "confirmed"


class FailureRouteDirective(str, Enum):
    RETRY = "retry"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    ESCALATE_TO_OWNER = "escalate_to_owner"
    BLOCKED = "blocked"


FailureRouteStatus = FailureRouteDirective


class FailureOwnerBinding(str, Enum):
    IMPLEMENTATION_ACTOR = "implementation_actor"
    VERIFIER_ACTOR = "verifier_actor"
    CAPABILITY_OWNER = "capability_owner"
    TEST_OWNER = "test_owner"
    COORDINATOR = "coordinator"
    CONFIRMATION_OWNER = "confirmation_owner"


@dataclass(frozen=True)
class VerificationFailureRecord:
    failure_id: str
    category: VerificationFailureCategory
    confirmation: FailureConfirmation
    classifier_actor: str
    supersedes_failure_id: str | None = None
    criterion_id: str | None = None
    contract_version: int = 1
    summary: str = "verification failure"
    recorded_at: datetime = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class FailureOwnerBindings:
    implementation_actor: str | None
    verifier_actor: str | None
    capability_owner: str | None
    test_owner: str | None
    coordinator: str | None
    confirmation_owner: str | None = None


@dataclass(frozen=True)
class FailureRoute:
    directive: FailureRouteDirective
    category: VerificationFailureCategory | None
    owner_binding: FailureOwnerBinding | None
    target_owner: str | None
    reason: str

    @property
    def status(self) -> FailureRouteDirective:
        """Compatibility view; canonical wire field is ``directive``."""

        return self.directive

    def to_wire(self) -> dict[str, object]:
        value: dict[str, object] = {
            "directive": self.directive.value,
            "category": self.category.value if self.category is not None else None,
            "reason": self.reason,
        }
        if self.owner_binding is not None:
            value["owner_binding"] = self.owner_binding.value
        if self.target_owner is not None:
            value["target_owner"] = self.target_owner
        return value


def should_retry(state: RevisionState) -> bool:
    return state.attempt <= state.max_attempts


_SYMBOLIC_ACTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*\Z")
_CANONICAL_UTC_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3}|\.\d{6})?Z\Z"
)


def _valid_symbolic_actor(value: object) -> bool:
    return isinstance(value, str) and bool(value and _SYMBOLIC_ACTOR.fullmatch(value))


def _canonical_utc_rfc3339(value: object) -> str | None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset().total_seconds() != 0
    ):
        return None
    utc_value = value.astimezone(timezone.utc)
    if utc_value.microsecond == 0:
        timespec = "seconds"
    elif utc_value.microsecond % 1000 == 0:
        timespec = "milliseconds"
    else:
        timespec = "microseconds"
    return utc_value.isoformat(timespec=timespec).replace("+00:00", "Z")


def _parse_canonical_utc_rfc3339(value: object) -> datetime:
    if not isinstance(value, str) or not _CANONICAL_UTC_RFC3339.fullmatch(value):
        raise ValueError("invalid recorded_at wire value")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError("invalid recorded_at wire value") from error
    if _canonical_utc_rfc3339(parsed) != value:
        raise ValueError("noncanonical recorded_at wire value")
    return parsed


def _revision_state_error(state: RevisionState) -> str | None:
    if not _valid_symbolic_actor(state.task_name):
        return "invalid revision task_name"
    if (
        type(state.attempt) is not int
        or type(state.max_attempts) is not int
        or state.attempt < 1
        or state.max_attempts < 1
    ):
        return "invalid revision attempt bounds"
    if type(state.blocked) is not bool:
        return "invalid revision blocked flag"
    if not isinstance(state.score_history, list):
        return "invalid revision score_history"
    for value in state.score_history:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0.0 <= value <= 1.0
        ):
            return "invalid revision score_history"
    return None


def _failure_record_error(failure: VerificationFailureRecord) -> str | None:
    if type(failure.contract_version) is not int or failure.contract_version != 1:
        return "unsupported or invalid contract_version"
    if not isinstance(failure.category, VerificationFailureCategory):
        return "invalid failure category"
    if not isinstance(failure.confirmation, FailureConfirmation):
        return "invalid failure confirmation"
    if not _valid_symbolic_actor(failure.failure_id):
        return "invalid failure_id"
    if not _valid_symbolic_actor(failure.classifier_actor):
        return "invalid classifier_actor"
    if failure.criterion_id is not None and not _valid_symbolic_actor(failure.criterion_id):
        return "invalid criterion_id"
    if failure.supersedes_failure_id is not None and not _valid_symbolic_actor(
        failure.supersedes_failure_id
    ):
        return "invalid supersedes_failure_id"
    if failure.supersedes_failure_id == failure.failure_id:
        return "failure cannot supersede itself"
    if not isinstance(failure.summary, str) or not failure.summary.strip() or "\x00" in failure.summary:
        return "invalid failure summary"
    if _canonical_utc_rfc3339(failure.recorded_at) is None:
        return "invalid recorded_at"

    sensitive = failure.category in {
        VerificationFailureCategory.PRODUCT_BUG,
        VerificationFailureCategory.TEST_FRAGILITY,
    }
    if not sensitive:
        return None
    if failure.confirmation is FailureConfirmation.PROVISIONAL:
        if failure.supersedes_failure_id is not None:
            return "provisional sensitive failure cannot supersede another record"
        return None
    if failure.supersedes_failure_id is None:
        return "confirmed sensitive failure requires supersedes_failure_id"
    return None


def _classification_error(
    failure: VerificationFailureRecord,
    prior_failure: VerificationFailureRecord | None,
) -> str | None:
    failure_error = _failure_record_error(failure)
    if failure_error is not None:
        return failure_error
    if prior_failure is not None:
        prior_error = _failure_record_error(prior_failure)
        if prior_error is not None:
            return f"invalid prior failure: {prior_error}"
        if prior_failure.failure_id == failure.failure_id:
            return "duplicate failure_id in classification collection"

    sensitive = failure.category in {
        VerificationFailureCategory.PRODUCT_BUG,
        VerificationFailureCategory.TEST_FRAGILITY,
    }
    if not sensitive or failure.confirmation is FailureConfirmation.PROVISIONAL:
        return None
    if prior_failure is None:
        return "confirmed sensitive failure requires the matching provisional record"
    if prior_failure.failure_id != failure.supersedes_failure_id:
        return "supersedes_failure_id does not identify the supplied provisional record"
    if prior_failure.confirmation is not FailureConfirmation.PROVISIONAL:
        return "superseded failure is not provisional"
    if prior_failure.category is not failure.category:
        return "superseded failure category does not match"
    if prior_failure.criterion_id != failure.criterion_id:
        return "superseded failure criterion does not match"
    if prior_failure.classifier_actor == failure.classifier_actor:
        return "confirmed sensitive failure requires an independent classifier actor"
    if prior_failure.recorded_at > failure.recorded_at:
        return "confirmed sensitive failure must not predate the provisional record"
    return None


def verification_failure_record_from_wire(payload: object) -> VerificationFailureRecord:
    """Decode the exact Rust ``ClassifiedVerificationFailure`` JSON shape."""

    if not isinstance(payload, dict) or set(payload) != {"failure", "classifier_actor"}:
        raise ValueError("invalid classified failure envelope")
    failure = payload["failure"]
    if not isinstance(failure, dict):
        raise ValueError("invalid failure object")
    required = {
        "contract_version",
        "failure_id",
        "category",
        "confirmation",
        "summary",
        "recorded_at",
    }
    optional = {"supersedes_failure_id", "criterion_id"}
    keys = set(failure)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        raise ValueError("invalid failure fields")
    category_wire = failure["category"]
    confirmation_wire = failure["confirmation"]
    if type(category_wire) is not str or type(confirmation_wire) is not str:
        raise ValueError("invalid failure enum wire type")
    try:
        category = VerificationFailureCategory(category_wire)
        confirmation = FailureConfirmation(confirmation_wire)
    except (TypeError, ValueError) as error:
        raise ValueError("invalid failure enum wire value") from error
    parsed_at = _parse_canonical_utc_rfc3339(failure["recorded_at"])
    record = VerificationFailureRecord(
        contract_version=failure["contract_version"],
        failure_id=failure["failure_id"],
        category=category,
        confirmation=confirmation,
        supersedes_failure_id=failure.get("supersedes_failure_id"),
        criterion_id=failure.get("criterion_id"),
        summary=failure["summary"],
        recorded_at=parsed_at,
        classifier_actor=payload["classifier_actor"],
    )
    if error := _failure_record_error(record):
        raise ValueError(error)
    return record


def verification_failure_record_to_wire(record: VerificationFailureRecord) -> dict[str, object]:
    if error := _failure_record_error(record):
        raise ValueError(error)
    failure: dict[str, object] = {
        "contract_version": record.contract_version,
        "failure_id": record.failure_id,
        "category": record.category.value,
        "confirmation": record.confirmation.value,
        "summary": record.summary,
        "recorded_at": _canonical_utc_rfc3339(record.recorded_at),
    }
    if record.supersedes_failure_id is not None:
        failure["supersedes_failure_id"] = record.supersedes_failure_id
    if record.criterion_id is not None:
        failure["criterion_id"] = record.criterion_id
    return {"failure": failure, "classifier_actor": record.classifier_actor}


def _required_owner_binding(category: VerificationFailureCategory) -> FailureOwnerBinding:
    if category is VerificationFailureCategory.PRODUCT_BUG:
        return FailureOwnerBinding.CAPABILITY_OWNER
    if category is VerificationFailureCategory.TEST_FRAGILITY:
        return FailureOwnerBinding.TEST_OWNER
    if category is VerificationFailureCategory.SOURCE_DRIFT:
        return FailureOwnerBinding.IMPLEMENTATION_ACTOR
    if category in {
        VerificationFailureCategory.POLICY_BLOCK,
        VerificationFailureCategory.CONTRACT_VIOLATION,
    }:
        return FailureOwnerBinding.VERIFIER_ACTOR
    if category in {
        VerificationFailureCategory.TIMEOUT,
        VerificationFailureCategory.ENVIRONMENT,
        VerificationFailureCategory.INFRASTRUCTURE,
        VerificationFailureCategory.TEST_FAILED_UNCLASSIFIED,
    }:
        return FailureOwnerBinding.COORDINATOR
    raise ValueError("unmapped verification failure category")


def route_verification_failure(
    failure: VerificationFailureRecord,
    state: RevisionState,
    bindings: FailureOwnerBindings,
    score: float,
    *,
    prior_failure: VerificationFailureRecord | None = None,
    root: Path | None = None,
) -> FailureRoute:
    """Route one typed verifier failure through the existing revision state.

    This function does not create a second retry loop. It asks ``should_retry``
    and, when attempts are exhausted, calls the existing ``escalate_to_owner``.
    Runtime/dispatch integration is intentionally deferred to V4.
    """

    raw_category = getattr(failure, "category", None)
    valid_category = raw_category if isinstance(raw_category, VerificationFailureCategory) else None

    def blocked(
        reason: str,
        owner_binding: FailureOwnerBinding | None = None,
    ) -> FailureRoute:
        return FailureRoute(
            directive=FailureRouteDirective.BLOCKED,
            category=valid_category,
            owner_binding=owner_binding,
            target_owner=None,
            reason=reason,
        )

    if not isinstance(failure, VerificationFailureRecord):
        return blocked("invalid verification failure record")
    if prior_failure is not None and not isinstance(prior_failure, VerificationFailureRecord):
        return blocked("invalid prior verification failure record")
    if not isinstance(bindings, FailureOwnerBindings):
        return blocked("invalid failure owner bindings")
    if not isinstance(state, RevisionState):
        return blocked("invalid revision state")

    classification_error = _classification_error(failure, prior_failure)
    if classification_error is not None:
        return blocked(classification_error)

    if state_error := _revision_state_error(state):
        return blocked(state_error)
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0.0 <= score <= 1.0
    ):
        return blocked("invalid finite score")

    if not _valid_symbolic_actor(bindings.implementation_actor):
        return blocked(
            "missing or invalid implementation_actor binding",
            FailureOwnerBinding.IMPLEMENTATION_ACTOR,
        )
    if not _valid_symbolic_actor(bindings.verifier_actor):
        return blocked(
            "missing or invalid verifier_actor binding",
            FailureOwnerBinding.VERIFIER_ACTOR,
        )
    if bindings.implementation_actor == bindings.verifier_actor:
        return blocked("implementation_actor and verifier_actor must differ")

    if failure.confirmation is FailureConfirmation.PROVISIONAL and failure.category in {
        VerificationFailureCategory.PRODUCT_BUG,
        VerificationFailureCategory.TEST_FRAGILITY,
    }:
        owner_binding = FailureOwnerBinding.CONFIRMATION_OWNER
        target_owner = bindings.confirmation_owner
        if not _valid_symbolic_actor(target_owner):
            return blocked(
                "missing or invalid confirmation_owner binding",
                owner_binding,
            )
        if target_owner == failure.classifier_actor:
            return blocked(
                "confirmation_owner must differ from classifier_actor",
                owner_binding,
            )
        return FailureRoute(
            directive=FailureRouteDirective.AWAITING_CONFIRMATION,
            category=failure.category,
            owner_binding=owner_binding,
            target_owner=target_owner,
            reason="sensitive provisional failure requires independent confirmation",
        )

    owner_binding = _required_owner_binding(failure.category)
    target_owner = getattr(bindings, owner_binding.value)
    if not _valid_symbolic_actor(target_owner):
        return blocked(
            f"missing or invalid {owner_binding.value} binding",
            owner_binding,
        )

    if should_retry(state):
        return FailureRoute(
            directive=FailureRouteDirective.RETRY,
            category=failure.category,
            owner_binding=owner_binding,
            target_owner=target_owner,
            reason="existing RevisionState permits another attempt",
        )

    escalate_to_owner(state, score, root=root)
    return FailureRoute(
        directive=FailureRouteDirective.ESCALATE_TO_OWNER,
        category=failure.category,
        owner_binding=owner_binding,
        target_owner=target_owner,
        reason="existing RevisionState exhausted its attempt budget",
    )


def generate_feedback(
    task_name: str,
    score: float,
    components: dict[str, float],
    attempt: int,
    max_attempts: int,
) -> str:
    gap = max(0.0, THRESHOLD - score)
    sorted_components = sorted(components.items(), key=lambda item: item[1])

    rows: list[str] = []
    for key, value in sorted_components:
        label, problem = COMPONENT_LABELS.get(key, (key, ""))
        weight = COMPONENT_WEIGHTS.get(key, 0.0)
        rows.append(f"| {key} {label} | {value:.2f} | x{weight:.2f} | {problem} |")

    impact = sorted(
        [(key, max(0.0, THRESHOLD - value) * COMPONENT_WEIGHTS.get(key, 0.0)) for key, value in components.items()],
        key=lambda item: (-item[1], item[0]),
    )
    actions: list[str] = []
    for index, (key, _impact_value) in enumerate(impact[:3], start=1):
        actions.append(f"{index}. **[{key}]** {ACTION_HINTS.get(key, '')}")

    projected_score = min(
        1.0,
        score + sum(COMPONENT_WEIGHTS.get(key, 0.0) * max(0.0, THRESHOLD - components.get(key, 0.0)) for key, _ in impact[:3]),
    )

    return (
        f"## Revision Required - Attempt {attempt}/{max_attempts}\n\n"
        f"Task: `{task_name}`\n\n"
        f"**Math Score: {score:.3f}** (threshold: {THRESHOLD:.2f} - gap: {gap:.3f})\n\n"
        "| Component | Score | Weight | Problem |\n"
        "|---|---|---|---|\n"
        f"{chr(10).join(rows)}\n\n"
        "**Required actions (เรียงตาม impact):**\n"
        f"{chr(10).join(actions)}\n\n"
        "**Required Math Proof block (copy into the next delivery and fill it):**\n"
        f"```md\n{MATH_PROOF_SCAFFOLD.rstrip()}\n```\n\n"
        f"ถ้าแก้ครบ top 3 actions คาดว่า score จะขึ้นไปถึง {projected_score:.2f}\n"
    )


def write_feedback(task_name: str, feedback: str, *, root: Path | None = None) -> Path:
    active_root = root or ROOT
    path = active_root / "tasks" / "inbox" / task_name / "revision_feedback.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(feedback, encoding="utf-8")
    return path


def append_feedback_to_task(task_text: str, feedback: str) -> str:
    return (
        f"{task_text.rstrip()}\n\n"
        "## Revision Loop Feedback\n\n"
        "Use the feedback below to revise the handoff before returning the next delivery.\n"
        "Preserve the required `## Math Proof` scaffold from the feedback when the delivery includes a handoff.\n\n"
        f"{feedback.rstrip()}\n"
    )


def log_revision(
    task_name: str,
    state: RevisionState,
    score: float,
    verdict: str,
    *,
    root: Path | None = None,
) -> None:
    active_root = root or ROOT
    log_path = active_root / "logs" / "revision_loop.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "task_name": task_name,
        "attempt": state.attempt,
        "score": round(score, 4),
        "verdict": str(verdict or "").strip().upper(),
        "escalated": not should_retry(state),
    }
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def escalate_to_owner(state: RevisionState, score: float, *, root: Path | None = None) -> None:
    if not isinstance(state, RevisionState):
        raise ValueError("invalid revision state")
    if state_error := _revision_state_error(state):
        raise ValueError(state_error)
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0.0 <= score <= 1.0
    ):
        raise ValueError("invalid finite score")
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "task_name": state.task_name,
        "attempts": state.attempt - 1,
        "final_score": round(score, 4),
        "score_history": [round(value, 4) for value in state.score_history],
        "status": "ESCALATED_TO_OWNER",
        "message": (
            f"Task '{state.task_name}' failed to reach math_score >= {THRESHOLD:.2f} "
            f"after {state.attempt - 1} attempts. Final score: {score:.3f}. "
            "Owner review required."
        ),
    }
    encoded = json.dumps(
        record,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )
    active_root = root or ROOT
    log_path = active_root / "logs" / "blocked_tasks.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(encoded + "\n")
