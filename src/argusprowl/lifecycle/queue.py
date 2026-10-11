"""In-memory bounded alert queue with minimal analyst workflow.

The :class:`AlertQueue` is a small operational collection of immutable
:class:`~app.models.alert.Alert` objects. It provides:

* Bounded in-memory storage keyed by ``alert_id``.
* Analyst workflow operations (``acknowledge`` / ``close``) that delegate to
  the existing :func:`~app.lifecycle.transition.transition_lifecycle` rules.
* Listing/query operations that reuse the Phase 4.7.5B
  :func:`~app.lifecycle.filtering.filter_alerts` and
  :func:`~app.lifecycle.sorting.sort_alerts` functions.

Hard invariants
---------------

* The queue **never mutates** an ``Alert``. Lifecycle transitions replace
  the stored immutable object with the new immutable ``Alert`` returned by
  ``transition_lifecycle``.
* The queue does **not** introduce a new identity system. Lookup uses the
  existing ``Alert.alert_id``.
* The queue does **not** implement a competing deduplication system. Duplicate
  ``alert_id`` enqueues are rejected (see :meth:`AlertQueue.enqueue`).
* The queue is **not** persistent. Queue state is process-local and lost on
  restart.
"""

from __future__ import annotations

from collections.abc import Iterable
from threading import RLock
from typing import TYPE_CHECKING
from uuid import UUID

from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity
from argusprowl.lifecycle.filtering import filter_alerts
from argusprowl.lifecycle.sorting import sort_alerts
from argusprowl.lifecycle.transition import transition_lifecycle
from argusprowl.models.alert import Alert

if TYPE_CHECKING:
    from argusprowl.correlation.entity_correlation_service import EntityCorrelationService

__all__ = ["AlertNotFoundError", "AlertQueue", "AlertQueueError", "AlertQueueFullError"]


class AlertQueueError(Exception):
    """Base error for alert queue operational failures."""


class AlertQueueFullError(AlertQueueError):
    """Raised when enqueue is rejected because the queue is at capacity."""


class AlertNotFoundError(AlertQueueError):
    """Raised when an operation references an unknown alert_id."""


class AlertQueue:
    """Bounded in-memory operational alert queue.

    The queue stores immutable :class:`Alert` objects keyed by their existing
    ``alert_id``. It exposes a small analyst-workflow API that delegates
    lifecycle transitions to :func:`transition_lifecycle` and listing/query
    operations to :func:`filter_alerts` and :func:`sort_alerts`.

    Args:
        max_size: Maximum number of alerts the queue will hold. Must be a
            positive integer. When the queue is full, new enqueues are
            rejected with :class:`AlertQueueFullError` (reject-newest policy).
    """

    def __init__(
        self,
        max_size: int = 10_000,
        entity_correlation_service: EntityCorrelationService | None = None,
    ) -> None:
        if not isinstance(max_size, int) or max_size <= 0:
            raise ValueError(f"max_size must be a positive integer, got {max_size!r}")
        self._max_size = max_size
        # Insertion-ordered mapping: alert_id -> Alert. dict preserves order so
        # the oldest alert is the first inserted and can be evicted if needed.
        self._alerts: dict[UUID, Alert] = {}
        self._lock = RLock()
        self._entity_correlation_service = entity_correlation_service

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------
    @property
    def max_size(self) -> int:
        """Maximum number of alerts the queue can hold."""
        return self._max_size

    def __len__(self) -> int:
        with self._lock:
            return len(self._alerts)

    def __contains__(self, alert_id: object) -> bool:
        with self._lock:
            return alert_id in self._alerts

    # ------------------------------------------------------------------
    # Enqueue
    # ------------------------------------------------------------------
    def enqueue(self, alert: Alert) -> bool:
        """Add an alert to the queue.

        Duplicate ``alert_id`` semantics: an alert with an ``alert_id`` that is
        already present is **rejected** (returns ``False``). This intentionally
        does not implement a competing deduplication system — the existing
        :class:`~app.deduplication.engine.AlertDeduplicationEngine` owns
        fingerprint-based deduplication upstream. The queue only enforces
        uniqueness of the operational lookup key (``alert_id``).

        Capacity policy: when the queue is at capacity, the new alert is
        rejected (reject-newest). No existing alert is evicted. This is the
        smallest deterministic policy and avoids silently dropping older
        alerts that an analyst may already be triaging.

        Args:
            alert: The immutable alert to enqueue. The alert object itself is
                not mutated; the queue stores a reference to the same object.

        Returns:
            ``True`` if the alert was enqueued, ``False`` if a duplicate
            ``alert_id`` was already present.

        Raises:
            AlertQueueFullError: If the queue is at capacity and the alert cannot
                be enqueued.
        """
        with self._lock:
            if alert.alert_id in self._alerts:
                return False
            if len(self._alerts) >= self._max_size:
                raise AlertQueueFullError(
                    f"Alert queue is at capacity ({self._max_size}); "
                    f"rejecting new alert {alert.alert_id}"
                )
            self._alerts[alert.alert_id] = alert
            return True

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------
    def get(self, alert_id: UUID) -> Alert | None:
        """Return the alert with the given id, or ``None`` if not present.

        The returned alert is the same immutable object stored by the queue;
        callers must not mutate it.
        """
        with self._lock:
            return self._alerts.get(alert_id)

    # ------------------------------------------------------------------
    # Listing / query (delegates to 4.7.5B)
    # ------------------------------------------------------------------
    def list(
        self,
        *,
        min_priority: AlertPriority | None = None,
        min_severity: Severity | None = None,
        rule_id: str | None = None,
        host: str | None = None,
        lifecycle_state: AlertLifecycleState | None = None,
        entity_key: str | None = None,
        incident_id: str | None = None,
        sort: bool = True,
    ) -> list[Alert]:
        """Return a filtered, sorted view of the queued alerts.

        This delegates to :func:`filter_alerts` and :func:`sort_alerts` from
        Phase 4.7.5B; it does not duplicate their logic. The returned list is a
        new list and the queue's stored alerts are not mutated.

        Args:
            min_priority: Keep alerts with priority >= this value.
            min_severity: Keep alerts with severity >= this value.
            rule_id: Keep alerts whose metadata rule_id matches.
            host: Keep alerts whose entity_context.host matches.
            lifecycle_state: Keep alerts with this lifecycle state.
            entity_key: Keep alerts whose canonical entity key matches.
            incident_id: Keep alerts whose incident_id matches (as string).
            sort: If ``True`` (default), apply :func:`sort_alerts` for
                deterministic ordering. If ``False``, return alerts in
                insertion order after filtering.

        Returns:
            A new list of alerts matching all active filters.
        """
        with self._lock:
            snapshot: list[Alert] = list(self._alerts.values())

        filtered = filter_alerts(
            snapshot,
            min_priority=min_priority,
            min_severity=min_severity,
            rule_id=rule_id,
            host=host,
            lifecycle_state=lifecycle_state,
            entity_key=entity_key,
            incident_id=incident_id,
        )
        if sort:
            return sort_alerts(filtered)
        return filtered

    def values(self) -> list[Alert]:
        """Return all queued alerts in insertion order (unsorted, unfiltered).

        Convenience for callers that want the raw operational collection.
        """
        with self._lock:
            return list(self._alerts.values())

    # ------------------------------------------------------------------
    # Entity-centric and incident-centric queries (Phase 4.8.3)
    # ------------------------------------------------------------------
    def list_by_entity(
        self,
        entity_key: str,
        *,
        sort: bool = True,
    ) -> list[Alert]:
        """Return alerts matching the given entity key.

        Uses the canonical entity-key algorithm from
        :class:`~app.correlation.entity_correlation_service.EntityCorrelationService`
        when available. The entity key is computed from each alert's
        ``entity_context`` using the same precedence rules as incident
        association:

        1. host + process_name
        2. host + dst_ip
        3. host alone
        4. dst_ip alone
        5. stable fallback (unknown:<alert_id>)

        Args:
            entity_key: The deterministic entity key to match.
            sort: If ``True`` (default), apply :func:`sort_alerts` for
                deterministic ordering. If ``False``, return alerts in
                insertion order after filtering.

        Returns:
            A new list of alerts matching the entity key.
            Returns an empty list when there are no matches.
        """
        with self._lock:
            snapshot: list[Alert] = list(self._alerts.values())

        if self._entity_correlation_service is not None:
            filtered = [
                alert
                for alert in snapshot
                if self._entity_correlation_service.compute_entity_key(alert) == entity_key
            ]
        else:
            # Fallback: no service available, return empty
            filtered = []

        if sort:
            return sort_alerts(filtered)
        return filtered

    def list_by_incident(
        self,
        incident_id: UUID,
        *,
        sort: bool = True,
    ) -> list[Alert]:
        """Return alerts belonging to the given incident.

        Uses ``Alert.incident_id`` as the authoritative association.
        Does not derive incident membership from entity key or any other
        field.

        Args:
            incident_id: The incident ID to filter by.
            sort: If ``True`` (default), apply :func:`sort_alerts` for
                deterministic ordering. If ``False``, return alerts in
                insertion order after filtering.

        Returns:
            A new list of alerts whose ``incident_id`` matches.
            Returns an empty list when there are no matches.
        """
        with self._lock:
            snapshot: list[Alert] = list(self._alerts.values())

        filtered = [alert for alert in snapshot if alert.incident_id == incident_id]

        if sort:
            return sort_alerts(filtered)
        return filtered

    # ------------------------------------------------------------------
    # Analyst workflow (delegates to transition_lifecycle)
    # ------------------------------------------------------------------
    def acknowledge(self, alert_id: UUID) -> Alert:
        """Transition an alert from OPEN to ACKNOWLEDGED.

        Delegates to :func:`transition_lifecycle` and replaces the stored
        immutable alert with the returned immutable alert.

        Args:
            alert_id: The id of the alert to acknowledge.

        Returns:
            The new immutable alert with ``lifecycle_state=ACKNOWLEDGED``.

        Raises:
            AlertNotFoundError: If ``alert_id`` is not in the queue.
            ValueError: If the transition is invalid (e.g. CLOSED -> ACKNOWLEDGED).
        """
        return self._transition(alert_id, AlertLifecycleState.ACKNOWLEDGED)

    def close(self, alert_id: UUID) -> Alert:
        """Transition an alert to CLOSED.

        Valid from OPEN or ACKNOWLEDGED. Delegates to
        :func:`transition_lifecycle` and replaces the stored immutable alert
        with the returned immutable alert.

        Args:
            alert_id: The id of the alert to close.

        Returns:
            The new immutable alert with ``lifecycle_state=CLOSED``.

        Raises:
            AlertNotFoundError: If ``alert_id`` is not in the queue.
            ValueError: If the transition is invalid (e.g. CLOSED -> CLOSED).
        """
        return self._transition(alert_id, AlertLifecycleState.CLOSED)

    def _transition(self, alert_id: UUID, new_state: AlertLifecycleState) -> Alert:
        with self._lock:
            existing = self._alerts.get(alert_id)
            if existing is None:
                raise AlertNotFoundError(f"Alert {alert_id} is not in the queue")
            # Delegate to the existing transition rules. This raises ValueError
            # for invalid transitions (e.g. CLOSED -> OPEN).
            updated = transition_lifecycle(existing, new_state)
            # Replace the stored immutable alert with the new immutable alert.
            self._alerts[alert_id] = updated
            return updated

    # ------------------------------------------------------------------
    # Bulk helpers
    # ------------------------------------------------------------------
    def extend(self, alerts: Iterable[Alert]) -> list[Alert]:
        """Enqueue multiple alerts, returning the alerts that were accepted.

        Duplicate or capacity-rejected alerts are skipped (their exceptions
        for capacity are NOT raised here; duplicates return False and
        capacity-rejected alerts are simply skipped). This keeps bulk ingest
        deterministic and non-destructive.

        Returns:
            The list of alerts that were actually enqueued.
        """
        accepted: list[Alert] = []
        for alert in alerts:
            try:
                if self.enqueue(alert):
                    accepted.append(alert)
            except AlertQueueFullError:
                # Stop at capacity; remaining alerts are skipped.
                break
        return accepted
