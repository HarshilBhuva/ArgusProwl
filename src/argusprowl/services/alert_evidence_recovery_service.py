"""Replay durable alert/evidence recovery envelopes.

The outbox provides at-least-once replay. Evidence writes are idempotent by event
identity; the outbox row is removed only after every expected reference is verified.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from argusprowl.alerting.alert_persistence import AlertPersistence
from argusprowl.models.alert import Alert
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.telemetry_evidence_service import (
    PROVENANCE_CONTRIBUTING_EVENT,
    PROVENANCE_DETECTION_SOURCE,
    PROVENANCE_OBSERVED_CONTEXT,
    TelemetryEvidenceService,
)

logger = logging.getLogger(__name__)
_RECOVERY_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class EvidenceRecoveryReport:
    """Summary of one bounded outbox replay pass."""

    attempted: int
    completed: int
    failed: int
    pending: int

    def to_dict(self) -> dict[str, int]:
        return {
            "attempted": self.attempted,
            "completed": self.completed,
            "failed": self.failed,
            "pending": self.pending,
        }


class AlertEvidenceRecoveryService:
    """Build, replay, and verify alert/evidence recovery envelopes."""

    def __init__(
        self,
        alert_persistence: AlertPersistence,
        evidence_service: TelemetryEvidenceService,
    ) -> None:
        self._alert_persistence = alert_persistence
        self._evidence_service = evidence_service

    @staticmethod
    def build_payload(
        alert: Alert,
        source_event: NormalizedEvent,
        detection_result: DetectionResult,
        evidence_service: TelemetryEvidenceService,
    ) -> dict[str, Any] | None:
        """Capture referenced event payloads while they are still available."""
        expected: dict[UUID, str] = {}
        if alert.detection_source_event_id is not None:
            expected[alert.detection_source_event_id] = PROVENANCE_DETECTION_SOURCE
        for event_id in alert.contributing_event_ids:
            expected.setdefault(event_id, PROVENANCE_CONTRIBUTING_EVENT)
        if not expected:
            return None

        event_payloads: dict[UUID, dict[str, Any]] = {}
        if source_event.event_id in expected:
            event_payloads[source_event.event_id] = source_event.to_dict()
        for event_id in expected:
            if event_id in event_payloads:
                continue
            try:
                detail = evidence_service.get_detail(event_id)
            except Exception:
                logger.exception("Unable to snapshot contributing evidence event_id=%s", event_id)
                continue
            if detail is not None and detail.event is not None:
                event_payloads[event_id] = detail.event.to_dict()

        return {
            "schema_version": _RECOVERY_SCHEMA_VERSION,
            "detection_result_id": str(detection_result.result_id),
            "contributing_event_ids": [str(value) for value in alert.contributing_event_ids],
            "expected": [
                {"event_id": str(event_id), "provenance": provenance}
                for event_id, provenance in expected.items()
            ],
            "events": [
                {"event": event_payloads[event_id]}
                for event_id in event_payloads
            ],
        }

    def recover_pending(self, limit: int = 100) -> EvidenceRecoveryReport:
        """Replay pending envelopes and retain any row that cannot be verified."""
        pending = self._alert_persistence.list_pending_evidence_recovery(limit=limit)
        completed = failed = 0
        for item in pending:
            alert_id = UUID(str(item["alert_id"]))
            payload = item["payload"]
            try:
                self._replay_one(payload)
                if not self._alert_persistence.complete_evidence_recovery(alert_id):
                    raise RuntimeError("Recovery was verified but the outbox row could not be cleared")
                completed += 1
            except Exception as exc:
                failed += 1
                self._alert_persistence.record_evidence_recovery_failure(alert_id, str(exc))
                logger.exception("Evidence recovery remains pending alert_id=%s", alert_id)
        stats = self._alert_persistence.get_evidence_recovery_stats()
        return EvidenceRecoveryReport(
            attempted=len(pending),
            completed=completed,
            failed=failed,
            pending=int(stats.get("pending", 0)),
        )

    def _replay_one(self, raw_payload: object) -> None:
        if not isinstance(raw_payload, dict):
            raise ValueError("Evidence recovery envelope must be an object")
        payload = raw_payload
        if payload.get("schema_version") != _RECOVERY_SCHEMA_VERSION:
            raise ValueError("Unsupported evidence recovery schema version")

        result_id = UUID(str(payload["detection_result_id"]))
        raw_contributors = payload.get("contributing_event_ids", [])
        raw_expected = payload.get("expected", [])
        raw_events = payload.get("events", [])
        if not isinstance(raw_contributors, list) or not isinstance(raw_expected, list):
            raise ValueError("Evidence recovery references are malformed")
        if not isinstance(raw_events, list):
            raise ValueError("Evidence recovery event list is malformed")
        contributors = tuple(UUID(str(value)) for value in raw_contributors)
        expected_provenance = {
            UUID(str(reference["event_id"])): str(reference["provenance"])
            for reference in raw_expected
            if isinstance(reference, dict) and "event_id" in reference and "provenance" in reference
        }

        for item in raw_events:
            if not isinstance(item, dict) or not isinstance(item.get("event"), dict):
                raise ValueError("Evidence recovery event payload is malformed")
            event = NormalizedEvent.from_dict(item["event"])
            self._evidence_service.record_event(
                event,
                provenance=PROVENANCE_OBSERVED_CONTEXT,
            )
            provenance = expected_provenance.get(event.event_id)
            if provenance == PROVENANCE_DETECTION_SOURCE:
                self._evidence_service.record_provenance(
                    event_id=event.event_id,
                    provenance=PROVENANCE_DETECTION_SOURCE,
                    detection_result_id=result_id,
                    contributing_event_ids=contributors,
                )
            elif provenance == PROVENANCE_CONTRIBUTING_EVENT or event.event_id in contributors:
                self._evidence_service.record_provenance(
                    event_id=event.event_id,
                    provenance=PROVENANCE_CONTRIBUTING_EVENT,
                    detection_result_id=result_id,
                )

        missing: list[str] = []
        mismatched: list[str] = []
        for reference in raw_expected:
            if not isinstance(reference, dict):
                raise ValueError("Evidence recovery reference is malformed")
            event_id = UUID(str(reference["event_id"]))
            provenance = str(reference["provenance"])
            if provenance not in (PROVENANCE_DETECTION_SOURCE, PROVENANCE_CONTRIBUTING_EVENT):
                raise ValueError("Evidence recovery provenance is invalid")
            detail = self._evidence_service.get_detail(event_id)
            if detail is None or detail.event is None or detail.record is None:
                missing.append(str(event_id))
                continue
            if detail.status in ("UNAVAILABLE", "DEGRADED"):
                raise RuntimeError(f"Evidence store is {detail.status} for event_id={event_id}")
            if detail.record.provenance != provenance:
                self._evidence_service.record_provenance(
                    event_id=event_id,
                    provenance=provenance,
                    detection_result_id=result_id,
                    contributing_event_ids=contributors if provenance == PROVENANCE_DETECTION_SOURCE else (),
                )
                verified = self._evidence_service.get_detail(event_id)
                if verified is None or verified.record is None or verified.record.provenance != provenance:
                    mismatched.append(str(event_id))
                continue
        if missing or mismatched:
            raise RuntimeError(
                "Evidence recovery incomplete: "
                f"missing={missing}, provenance_mismatch={mismatched}"
            )
