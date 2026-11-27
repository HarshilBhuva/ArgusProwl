"""Read-only reconciliation diagnostics for persisted alerts and telemetry evidence.

The alert and evidence databases are independent SQLite stores. This service
reports broken or degraded references; it does not mutate either store or
pretend that cross-database commits are atomic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from argusprowl.alerting.alert_persistence import AlertPersistence
from argusprowl.services.telemetry_evidence_service import (
    PROVENANCE_CONTRIBUTING_EVENT,
    PROVENANCE_DETECTION_SOURCE,
    TelemetryEvidenceService,
)


@dataclass(frozen=True, slots=True)
class AlertEvidenceFinding:
    """Reconciliation result for one durable alert."""

    alert_id: UUID
    status: str
    referenced_events: int
    missing_event_ids: tuple[UUID, ...] = ()
    provenance_mismatch_event_ids: tuple[UUID, ...] = ()
    unavailable_event_ids: tuple[UUID, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": str(self.alert_id),
            "status": self.status,
            "referenced_events": self.referenced_events,
            "missing_event_ids": [str(value) for value in self.missing_event_ids],
            "provenance_mismatch_event_ids": [
                str(value) for value in self.provenance_mismatch_event_ids
            ],
            "unavailable_event_ids": [str(value) for value in self.unavailable_event_ids],
        }


@dataclass(frozen=True, slots=True)
class AlertEvidenceReconciliationReport:
    """Bounded, read-only consistency report across alert and evidence stores."""

    status: str
    alerts_checked: int
    complete: int
    incomplete: int
    degraded: int
    no_evidence_references: int
    findings: tuple[AlertEvidenceFinding, ...]
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "alerts_checked": self.alerts_checked,
            "complete": self.complete,
            "incomplete": self.incomplete,
            "degraded": self.degraded,
            "no_evidence_references": self.no_evidence_references,
            "reason": self.reason,
            "findings": [finding.to_dict() for finding in self.findings],
        }


class AlertEvidenceReconciliationService:
    """Compare durable alert references with evidence records without mutation."""

    def __init__(
        self,
        alert_persistence: AlertPersistence,
        evidence_service: TelemetryEvidenceService,
    ) -> None:
        self._alert_persistence = alert_persistence
        self._evidence_service = evidence_service

    def inspect(self) -> AlertEvidenceReconciliationReport:
        """Inspect every alert within the configured alert-retention bound."""
        query = self._alert_persistence.list_all()
        query_status = getattr(query.status, "value", str(query.status))
        if query_status == "UNAVAILABLE":
            return AlertEvidenceReconciliationReport(
                status="UNAVAILABLE",
                alerts_checked=0,
                complete=0,
                incomplete=0,
                degraded=0,
                no_evidence_references=0,
                findings=(),
                reason=query.reason or "Alert persistence could not be queried.",
            )

        findings: list[AlertEvidenceFinding] = []
        complete = incomplete = degraded = no_references = 0
        for alert in query.alerts:
            expected: dict[UUID, str] = {}
            if alert.detection_source_event_id is not None:
                expected[alert.detection_source_event_id] = PROVENANCE_DETECTION_SOURCE
            for event_id in alert.contributing_event_ids:
                expected.setdefault(event_id, PROVENANCE_CONTRIBUTING_EVENT)

            if not expected:
                no_references += 1
                findings.append(
                    AlertEvidenceFinding(
                        alert_id=alert.alert_id,
                        status="NO_EVIDENCE_REFERENCES",
                        referenced_events=0,
                    )
                )
                continue

            missing: list[UUID] = []
            mismatched: list[UUID] = []
            unavailable: list[UUID] = []
            degraded_reference = False
            for event_id, expected_provenance in expected.items():
                try:
                    detail = self._evidence_service.get_detail(event_id)
                except Exception:
                    unavailable.append(event_id)
                    continue
                if detail is None:
                    missing.append(event_id)
                    continue
                if detail.status == "UNAVAILABLE":
                    unavailable.append(event_id)
                    continue
                if detail.status == "DEGRADED":
                    degraded_reference = True
                if detail.event is None or detail.record is None:
                    missing.append(event_id)
                    continue
                if detail.record.provenance != expected_provenance:
                    mismatched.append(event_id)

            if unavailable:
                status = "UNAVAILABLE"
                degraded += 1
            elif missing or mismatched:
                status = "INCOMPLETE"
                incomplete += 1
            elif degraded_reference:
                status = "DEGRADED"
                degraded += 1
            else:
                status = "COMPLETE"
                complete += 1

            findings.append(
                AlertEvidenceFinding(
                    alert_id=alert.alert_id,
                    status=status,
                    referenced_events=len(expected),
                    missing_event_ids=tuple(missing),
                    provenance_mismatch_event_ids=tuple(mismatched),
                    unavailable_event_ids=tuple(unavailable),
                )
            )

        if any(item.status == "UNAVAILABLE" for item in findings):
            overall = "UNAVAILABLE"
        elif incomplete:
            overall = "INCOMPLETE"
        elif degraded or query_status == "DEGRADED":
            overall = "DEGRADED"
        else:
            overall = "COMPLETE"

        return AlertEvidenceReconciliationReport(
            status=overall,
            alerts_checked=len(query.alerts),
            complete=complete,
            incomplete=incomplete,
            degraded=degraded,
            no_evidence_references=no_references,
            findings=tuple(findings),
            reason=query.reason if query_status == "DEGRADED" else None,
        )
