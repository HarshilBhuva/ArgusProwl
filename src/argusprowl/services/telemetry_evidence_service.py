"""Telemetry evidence service for analyst investigation.

Bounded, thread-safe, process-local in-memory evidence store.
Provides provenance-aware insertion and read-only query capabilities
for NormalizedEvent telemetry.

DETECTION_SOURCE: The primary event that triggered a detection rule.
CONTRIBUTING_EVENT: Related events in multi-event/correlation detections.
OBSERVED_CONTEXT: Events observed but not directly evidencing a detection.

This service is completely isolated from detection, correlation,
incidents, persistence, and lifecycle. It never mutates any other state.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Any
from uuid import UUID

from argusprowl.models.normalized_event import NormalizedEvent

logger = logging.getLogger(__name__)

PROVENANCE_DETECTION_SOURCE = "DETECTION_SOURCE"
PROVENANCE_CONTRIBUTING_EVENT = "CONTRIBUTING_EVENT"
PROVENANCE_OBSERVED_CONTEXT = "OBSERVED_CONTEXT"
VALID_PROVENANCE = frozenset(
    {
        PROVENANCE_DETECTION_SOURCE,
        PROVENANCE_CONTRIBUTING_EVENT,
        PROVENANCE_OBSERVED_CONTEXT,
    }
)

_MAX_ENTITY_ID_LENGTH = 256
_MAX_EVENT_TYPE_LENGTH = 128
_MAX_SOURCE_TYPE_LENGTH = 128


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """Immutable evidence record linking an event to its provenance."""

    event_id: UUID
    provenance: str
    detection_result_id: UUID | None = None
    contributing_event_ids: tuple[UUID, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if object.__getattribute__(self, "provenance") not in VALID_PROVENANCE:
            raise ValueError(
                f"Invalid provenance {self.provenance!r}. "
                f"Must be one of {sorted(VALID_PROVENANCE)}."
            )
        if self.contributing_event_ids and not isinstance(self.contributing_event_ids, tuple):
            raise ValueError("contributing_event_ids must be a tuple of UUIDs.")
        if not all(isinstance(eid, UUID) for eid in self.contributing_event_ids):
            raise ValueError("contributing_event_ids must contain UUIDs.")


@dataclass(frozen=True, slots=True)
class EvidenceSearchResult:
    """Bounded result from an evidence search query."""

    records: tuple[EvidenceRecord, ...]
    events: dict[UUID, NormalizedEvent]
    status: str
    reason: str | None
    truncated: bool
    total_count: int
    returned_count: int


@dataclass(frozen=True, slots=True)
class EvidenceDetailResult:
    """Single evidence lookup without fabricating evicted telemetry."""

    event_id: UUID
    status: str
    reason: str | None
    event: NormalizedEvent | None
    record: EvidenceRecord | None


class TelemetryEvidenceService:
    """Bounded in-memory telemetry evidence store.

    Stores NormalizedEvent objects with provenance metadata.
    Deterministic FIFO eviction when the store is full.
    Thread-safe for concurrent read and write access.
    """

    def __init__(self, max_retained_events: int = 100_000) -> None:
        if not isinstance(max_retained_events, int) or isinstance(max_retained_events, bool):
            raise ValueError("max_retained_events must be a positive integer.")
        if max_retained_events <= 0:
            raise ValueError("max_retained_events must be positive.")

        self._max_retained = max_retained_events
        self._lock = Lock()
        # OrderedDict preserves insertion order for deterministic eviction.
        self._events: OrderedDict[UUID, NormalizedEvent] = OrderedDict()
        self._records: dict[UUID, EvidenceRecord] = {}
        # Retain only references that were explicitly contributing evidence.
        # This is bounded by the same configured capacity and never stores telemetry.
        self._evicted_contributing_records: OrderedDict[UUID, EvidenceRecord] = OrderedDict()
        self._eviction_count: int = 0

    # ------------------------------------------------------------------
    # Insertion
    # ------------------------------------------------------------------

    def record_event(
        self,
        event: NormalizedEvent,
        provenance: str = PROVENANCE_OBSERVED_CONTEXT,
    ) -> EvidenceRecord:
        """Insert or update an event in the evidence store.

        If the event already exists, its provenance is updated in place
        (DETECTION_SOURCE overrides OBSERVED_CONTEXT; DETECTION_SOURCE is
        never overwritten by OBSERVED_CONTEXT on a subsequent call).
        """
        if provenance not in VALID_PROVENANCE:
            raise ValueError(
                f"Invalid provenance {provenance!r}. Must be one of {sorted(VALID_PROVENANCE)}."
            )

        with self._lock:
            self._insert_event_unlocked(event, provenance)
            return self._records[event.event_id]

    def record_provenance(
        self,
        event_id: UUID,
        provenance: str,
        detection_result_id: UUID | None = None,
        contributing_event_ids: tuple[UUID, ...] = (),
    ) -> EvidenceRecord:
        """Record provenance metadata for an existing event.

        Does NOT insert a new event — only updates the provenance record.
        Must be called after the event has been inserted via record_event.
        """
        if provenance not in VALID_PROVENANCE:
            raise ValueError(
                f"Invalid provenance {provenance!r}. Must be one of {sorted(VALID_PROVENANCE)}."
            )
        if contributing_event_ids and not isinstance(contributing_event_ids, tuple):
            raise ValueError("contributing_event_ids must be a tuple.")

        with self._lock:
            if event_id not in self._events:
                raise ValueError(
                    f"Event {event_id} not found in evidence store. Call record_event() first."
                )
            # DETECTION_SOURCE takes precedence over existing provenance.
            existing = self._records[event_id]
            if provenance == PROVENANCE_DETECTION_SOURCE:
                new_record = EvidenceRecord(
                    event_id=event_id,
                    provenance=PROVENANCE_DETECTION_SOURCE,
                    detection_result_id=detection_result_id,
                    contributing_event_ids=contributing_event_ids,
                )
                self._records[event_id] = new_record
                return new_record

            # Existing provenance already takes precedence.
            if existing.provenance == PROVENANCE_DETECTION_SOURCE:
                return existing

            # For other provenance levels, only update if no record exists
            # or if the existing is OBSERVED_CONTEXT.
            if existing.provenance == PROVENANCE_OBSERVED_CONTEXT:
                new_record = EvidenceRecord(
                    event_id=event_id,
                    provenance=provenance,
                    detection_result_id=detection_result_id,
                    contributing_event_ids=contributing_event_ids,
                )
                self._records[event_id] = new_record
                return new_record

            return existing

    def _insert_event_unlocked(self, event: NormalizedEvent, provenance: str) -> None:
        """Insert an event, evicting oldest if necessary. Caller must hold lock."""
        # Evict if at capacity before inserting.
        while len(self._events) >= self._max_retained and self._events:
            oldest_id, _ = self._events.popitem(last=False)
            oldest_record = self._records.pop(oldest_id, None)
            if oldest_record is not None and oldest_record.provenance in (
                PROVENANCE_CONTRIBUTING_EVENT,
                PROVENANCE_DETECTION_SOURCE,
            ):
                self._evicted_contributing_records[oldest_id] = oldest_record
                while len(self._evicted_contributing_records) > self._max_retained:
                    self._evicted_contributing_records.popitem(last=False)
            self._eviction_count += 1

        self._evicted_contributing_records.pop(event.event_id, None)
        self._events[event.event_id] = event

        existing = self._records.get(event.event_id)
        if existing is None or existing.provenance != PROVENANCE_DETECTION_SOURCE:
            self._records[event.event_id] = EvidenceRecord(
                event_id=event.event_id,
                provenance=provenance,
            )
        # If already DETECTION_SOURCE, keep it unchanged.

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def search(
        self,
        *,
        limit: int = 100,
        event_id: UUID | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        domain: str | None = None,
        event_type: str | None = None,
        source_type: str | None = None,
    ) -> EvidenceSearchResult:
        """Query evidence with bounded filters.

        All filters are ANDed. Results are sorted by timestamp then event_id
        (stable tiebreak).
        """
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError(f"limit must be a positive integer, got {limit!r}")

        with self._lock:
            # Exact event ID lookup — O(1).
            if event_id is not None:
                event = self._events.get(event_id)
                if event is None:
                    return EvidenceSearchResult(
                        records=tuple(),
                        events={},
                        status="AVAILABLE",
                        reason=None,
                        truncated=False,
                        total_count=0,
                        returned_count=0,
                    )
                record = self._records[event_id]
                return EvidenceSearchResult(
                    records=tuple((record,)),
                    events={event_id: event},
                    status="AVAILABLE",
                    reason=None,
                    truncated=False,
                    total_count=1,
                    returned_count=1,
                )

            # Filtered scan — O(n) over in-memory store.
            matching_ids: list[UUID] = []
            for eid, ev in self._events.items():
                if start_time is not None and ev.timestamp < start_time:
                    continue
                if end_time is not None and ev.timestamp > end_time:
                    continue
                if entity_type is not None or entity_id is not None:
                    entity_match = self._match_entity(ev, entity_type, entity_id)
                    if not entity_match:
                        continue
                if src_ip is not None and ev.src_ip != src_ip:
                    continue
                if dst_ip is not None and ev.dst_ip != dst_ip:
                    continue
                if domain is not None:
                    host = ev.hostname or ""
                    if domain.lower() not in (
                        host.lower() + "." + (ev.dst_ip or "") + "." if False else host.lower()
                    ):
                        # Domain matching: check hostname and dst_ip context
                        domain_match = False
                        if host and domain.lower() in host.lower():
                            domain_match = True
                        if ev.dst_ip and domain.lower() in (ev.dst_ip.lower() + "."):
                            domain_match = True
                        if not domain_match:
                            continue
                if event_type is not None and ev.event_type != event_type:
                    continue
                if source_type is not None and ev.source_type != source_type:
                    continue
                matching_ids.append(eid)

            # Deterministic sort: timestamp asc, then event_id as tiebreak.
            sorted_ids = sorted(
                matching_ids,
                key=lambda eid: (self._events[eid].timestamp, eid),
            )

            total = len(sorted_ids)
            # Apply bounded limit.
            selected_ids = sorted_ids[:limit]
            truncated = total > limit

            records: list[EvidenceRecord] = []
            events: dict[UUID, NormalizedEvent] = {}
            for eid in selected_ids:
                rec = self._records[eid]
                evt = self._events[eid]
                records.append(rec)
                events[eid] = evt

            return EvidenceSearchResult(
                records=tuple(records),
                events=events,
                status="AVAILABLE",
                reason=None,
                truncated=truncated,
                total_count=total,
                returned_count=len(records),
            )

    def get_event(self, event_id: UUID) -> tuple[NormalizedEvent, EvidenceRecord] | None:
        """Get a retained event and its evidence record by ID."""
        with self._lock:
            event = self._events.get(event_id)
            if event is None:
                return None
            return event, self._records[event_id]

    def get_detail(self, event_id: UUID) -> EvidenceDetailResult | None:
        """Resolve retained or explicitly evicted contributing evidence by ID."""
        with self._lock:
            event = self._events.get(event_id)
            if event is not None:
                return EvidenceDetailResult(
                    event_id=event_id,
                    status="AVAILABLE",
                    reason=None,
                    event=event,
                    record=self._records[event_id],
                )

            record = self._evicted_contributing_records.get(event_id)
            if record is None:
                return None
            return EvidenceDetailResult(
                event_id=event_id,
                status="EVICTED",
                reason="Referenced contributing telemetry is no longer retained in memory.",
                event=None,
                record=record,
            )

    def resolve_referenced_status(self, event_ids: tuple[UUID, ...]) -> dict[UUID, str]:
        """Resolve availability for a known set of referenced event IDs.

        Unlike get_detail(), this method treats the supplied IDs as known
        references (e.g. Alert.contributing_event_ids). Retained events are
        AVAILABLE. Referenced IDs that are no longer in the store are EVICTED.
        Arbitrary unknown lookups must still use get_detail().
        """
        status: dict[UUID, str] = {}
        if not event_ids:
            return status

        with self._lock:
            for eid in event_ids:
                if eid in self._events:
                    status[eid] = "AVAILABLE"
                else:
                    status[eid] = "EVICTED"
        return status

    def get_stats(self) -> dict[str, Any]:
        """Return store statistics for health reporting."""
        with self._lock:
            return {
                "retained_events": len(self._events),
                "max_retained_events": self._max_retained,
                "eviction_count": self._eviction_count,
                "capacity_used_pct": round(len(self._events) / self._max_retained * 100, 2),
            }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _match_entity(
        event: NormalizedEvent,
        entity_type: str | None,
        entity_id: str | None,
    ) -> bool:
        """Match an event to an entity key.

        Supports common entity dimensions: hostname, src_ip, dst_ip.
        """
        if entity_type is None and entity_id is None:
            return True
        if entity_type is None or entity_id is None:
            return False

        entity_type_lower = entity_type.lower()
        entity_id_lower = entity_id.lower()

        # Hostname entity
        if entity_type_lower in ("hostname", "host"):
            return (event.hostname or "").lower() == entity_id_lower

        # IP entities
        if entity_type_lower in ("src_ip", "ip", "network"):
            return (event.src_ip or "").lower() == entity_id_lower or (
                event.dst_ip or ""
            ).lower() == entity_id_lower

        # Process entity
        if entity_type_lower == "process":
            return (event.process_name or "").lower() == entity_id_lower

        # Username entity
        if entity_type_lower == "user":
            return (event.username or "").lower() == entity_id_lower

        return False

    @property
    def eviction_count(self) -> int:
        with self._lock:
            return self._eviction_count
