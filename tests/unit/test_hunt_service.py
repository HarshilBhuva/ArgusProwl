"""Unit tests for persistent hypothesis-driven hunt aggregates."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from argusprowl.hunting.hunt_service import HuntConflictError, HuntService
from argusprowl.models.hunt import (
    EvidenceRole,
    FindingDisposition,
    HuntConclusion,
    HuntEvidenceReference,
    HuntExecution,
    HuntFinding,
    HuntStatus,
)
from argusprowl.storage.sqlite_storage import SQLiteAdapter


@pytest.fixture
def storage(tmp_path):
    adapter = SQLiteAdapter(tmp_path / "hunts.db")
    yield adapter
    adapter.close()


def test_hunt_survives_service_restart_with_history_and_separate_evidence(storage) -> None:
    service = HuntService(storage)
    hunt = service.create_hunt(
        title="Credential abuse investigation",
        hypothesis="Repeated authentication failures precede successful remote access.",
        actor="analyst-a",
    )
    query_hunt = service.save_query(
        hunt.hunt_id,
        name="failed-logins",
        definition={"source_type": "windows", "event_type": "authentication_failure"},
        actor="analyst-a",
    )
    query = query_hunt.queries[0]

    updated = service.save_query(
        hunt.hunt_id,
        name="failed-logins",
        definition={"source_type": "windows", "event_type": "authentication_failure", "limit": 500},
        actor="analyst-a",
    )
    assert [item.version for item in updated.queries] == [1, 2]
    assert all(item.query_id == query.query_id for item in updated.queries)

    now = datetime.now(UTC)
    event_id = uuid4()
    execution = HuntExecution(
        query_id=query.query_id,
        query_version=2,
        started_at=now,
        completed_at=now + timedelta(seconds=2),
        result_count=1,
        data_sources=("windows",),
        evidence_event_ids=(event_id,),
    )
    service.record_execution(hunt.hunt_id, execution, "analyst-a")
    service.attach_evidence(
        hunt.hunt_id,
        HuntEvidenceReference(
            event_id=event_id,
            role=EvidenceRole.SUPPORTING,
            added_by="analyst-a",
            note="Successful remote logon follows the failures.",
        ),
    )
    service.add_finding(
        hunt.hunt_id,
        HuntFinding(
            title="Remote logon observed",
            description="The scoped host recorded a successful remote logon.",
            disposition=FindingDisposition.SUPPORTS,
            author="analyst-a",
            evidence_event_ids=(event_id,),
        ),
    )
    service.set_conclusion(
        hunt.hunt_id,
        HuntConclusion(
            summary="The evidence supports a credential-abuse hypothesis.",
            disposition=FindingDisposition.SUPPORTS,
            confidence=0.8,
            author="analyst-a",
        ),
    )
    service.transition_status(hunt.hunt_id, HuntStatus.ACTIVE, "analyst-a")
    service.transition_status(hunt.hunt_id, HuntStatus.COMPLETED, "analyst-a")

    recovered = HuntService(storage).get_hunt(hunt.hunt_id)
    assert recovered is not None
    assert recovered.status is HuntStatus.COMPLETED
    assert [item.version for item in recovered.queries] == [1, 2]
    assert recovered.executions[0].query_version == 2
    assert recovered.evidence_references[0].event_id == event_id
    assert recovered.findings[0].evidence_event_ids == (event_id,)
    assert recovered.conclusion is not None
    assert recovered.conclusion.confidence == 0.8
    actions = [entry.action for entry in recovered.audit_history]
    assert actions == [
        "HUNT_CREATED",
        "HUNT_QUERY_SAVED",
        "HUNT_QUERY_SAVED",
        "HUNT_QUERY_EXECUTION_RECORDED",
        "HUNT_EVIDENCE_ATTACHED",
        "HUNT_FINDING_RECORDED",
        "HUNT_CONCLUSION_UPDATED",
        "HUNT_STATUS_CHANGED",
        "HUNT_STATUS_CHANGED",
    ]


def test_execution_must_reference_exact_saved_query_version(storage) -> None:
    service = HuntService(storage)
    hunt = service.create_hunt(title="Test", hypothesis="Test hypothesis", actor="analyst")
    query = service.save_query(
        hunt.hunt_id, name="q", definition={"event_type": "login"}, actor="analyst"
    ).queries[0]
    now = datetime.now(UTC)
    with pytest.raises(HuntConflictError, match="saved query ID and version"):
        service.record_execution(
            hunt.hunt_id,
            HuntExecution(
                query_id=query.query_id,
                query_version=2,
                started_at=now,
                completed_at=now,
                result_count=0,
            ),
            "analyst",
        )


def test_finding_cannot_reference_evidence_not_attached_to_hunt(storage) -> None:
    service = HuntService(storage)
    hunt = service.create_hunt(title="Test", hypothesis="Test hypothesis", actor="analyst")
    with pytest.raises(HuntConflictError, match="already attached"):
        service.add_finding(
            hunt.hunt_id,
            HuntFinding(
                title="Unsupported",
                description="No linked evidence.",
                disposition=FindingDisposition.INCONCLUSIVE,
                author="analyst",
                evidence_event_ids=(uuid4(),),
            ),
        )


def test_invalid_lifecycle_transition_is_rejected_and_archive_is_read_only(storage) -> None:
    service = HuntService(storage)
    hunt = service.create_hunt(title="Test", hypothesis="Test hypothesis", actor="analyst")
    with pytest.raises(HuntConflictError, match="Invalid hunt status transition"):
        service.transition_status(hunt.hunt_id, HuntStatus.COMPLETED, "analyst")
    service.transition_status(hunt.hunt_id, HuntStatus.ARCHIVED, "analyst")
    with pytest.raises(HuntConflictError, match="read-only"):
        service.save_query(hunt.hunt_id, name="q", definition={}, actor="analyst")


def test_list_is_bounded_and_reports_count(storage) -> None:
    service = HuntService(storage)
    service.create_hunt(title="One", hypothesis="Hypothesis one", actor="analyst")
    service.create_hunt(title="Two", hypothesis="Hypothesis two", actor="analyst")
    assert len(service.list_hunts(limit=1)) == 1
    assert service.count_hunts() == 2
    with pytest.raises(ValueError):
        service.list_hunts(limit=501)
