"""Alert filtering functions.

Pure functions for filtering alert collections based on operational criteria.
Filtering is read-only and never mutates the input collection or individual alerts.
"""

from collections.abc import Iterable

from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity
from argusprowl.models.alert import Alert


def filter_alerts(
    alerts: Iterable[Alert],
    *,
    min_priority: AlertPriority | None = None,
    min_severity: Severity | None = None,
    rule_id: str | None = None,
    host: str | None = None,
    lifecycle_state: AlertLifecycleState | None = None,
    entity_key: str | None = None,
    incident_id: str | None = None,
) -> list[Alert]:
    """Filter alerts by operational criteria.

    All provided filters are applied with AND semantics. A filter value of
    ``None`` means that criterion is disabled.

    Args:
        alerts: The collection of alerts to filter.
        min_priority: Keep alerts with priority >= this value.
        min_severity: Keep alerts with severity >= this value.
        rule_id: Keep alerts whose metadata contains this rule_id.
        host: Keep alerts whose entity_context.host matches this value.
        lifecycle_state: Keep alerts with this lifecycle state.
            Legacy alerts without lifecycle_state are treated as OPEN.
        entity_key: Keep alerts whose canonical entity key matches.
        incident_id: Keep alerts whose incident_id matches (as string).

    Returns:
        A new list containing only the alerts that match all active filters.
        The original collection is not modified.
    """
    result: list[Alert] = []

    for alert in alerts:
        if not _matches_priority(alert, min_priority):
            continue
        if not _matches_severity(alert, min_severity):
            continue
        if not _matches_rule_id(alert, rule_id):
            continue
        if not _matches_host(alert, host):
            continue
        if not _matches_lifecycle(alert, lifecycle_state):
            continue
        if not _matches_entity_key(alert, entity_key):
            continue
        if not _matches_incident_id(alert, incident_id):
            continue
        result.append(alert)

    return result


def _matches_priority(alert: Alert, min_priority: AlertPriority | None) -> bool:
    """Check if alert meets minimum priority threshold."""
    if min_priority is None:
        return True
    alert_priority = alert.priority
    if alert_priority is None:
        return False
    return alert_priority.order >= min_priority.order


def _matches_severity(alert: Alert, min_severity: Severity | None) -> bool:
    """Check if alert meets minimum severity threshold."""
    if min_severity is None:
        return True
    return alert.severity >= min_severity


def _matches_rule_id(alert: Alert, rule_id: str | None) -> bool:
    """Check if alert matches the given rule_id."""
    if rule_id is None:
        return True
    metadata = alert.metadata
    if "rule_id" in metadata:
        return metadata["rule_id"] == rule_id
    if "detector" in metadata:
        return metadata["detector"] == rule_id
    return alert.source == rule_id


def _matches_host(alert: Alert, host: str | None) -> bool:
    """Check if alert matches the given host."""
    if host is None:
        return True
    entity_context = alert.entity_context
    if entity_context is not None:
        if isinstance(entity_context, dict):
            if entity_context.get("host") == host:
                return True
        elif hasattr(entity_context, "host") and entity_context.host == host:
            return True
    # Fallback to metadata evidence
    evidence = alert.metadata.get("evidence")
    return bool(isinstance(evidence, dict) and evidence.get("host") == host)


def _matches_lifecycle(alert: Alert, lifecycle_state: AlertLifecycleState | None) -> bool:
    """Check if alert matches the given lifecycle state."""
    if lifecycle_state is None:
        return True
    # Legacy alerts without lifecycle_state default to OPEN
    alert_state = alert.lifecycle_state
    if alert_state is None:
        alert_state = AlertLifecycleState.OPEN
    return alert_state == lifecycle_state


def _matches_entity_key(alert: Alert, entity_key: str | None) -> bool:
    """Check if alert matches the given canonical entity key."""
    if entity_key is None:
        return True
    from argusprowl.correlation.entity_correlation_service import EntityCorrelationService

    return EntityCorrelationService._compute_entity_key(alert) == entity_key


def _matches_incident_id(alert: Alert, incident_id: str | None) -> bool:
    """Check if alert matches the given incident ID."""
    if incident_id is None:
        return True
    alert_incident = str(alert.incident_id) if alert.incident_id else None
    return alert_incident == incident_id
