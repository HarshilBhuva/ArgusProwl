"""Alert sorting functions.

Pure functions for deterministic sorting of alert collections.
Sorting is read-only and never mutates the input collection or individual alerts.
"""

from collections.abc import Iterable

from argusprowl.models.alert import Alert


def sort_alerts(alerts: Iterable[Alert]) -> list[Alert]:
    """Sort alerts deterministically by operational criteria.

    Sort order (highest priority first):
    1. Priority descending (CRITICAL > HIGH > MEDIUM > LOW)
    2. Severity descending (CRITICAL > HIGH > MEDIUM > LOW > INFO)
    3. Contextual confidence descending (missing = 0.0)
    4. Created at descending (newest first)
    5. Alert ID ascending (deterministic tie-breaker)

    Args:
        alerts: The collection of alerts to sort.

    Returns:
        A new list containing alerts in sorted order.
        The original collection is not modified.
    """
    return sorted(
        list(alerts),
        key=_sort_key,
    )


def _sort_key(alert: Alert) -> tuple:
    """Generate a sort key tuple for an alert.

    Returns a tuple that produces the desired ordering when sorted in
    ascending order (hence the negations for descending fields).
    """
    # Priority descending: negate the order value
    # Legacy alerts without priority sort last
    priority_order = alert.priority.order if alert.priority is not None else -1

    # Severity descending: negate the integer value
    severity_value = alert.severity.value

    # Contextual confidence descending: negate, default to 0.0
    confidence = 0.0
    if alert.contextual_confidence is not None:
        confidence = alert.contextual_confidence

    # Created at descending: negate timestamp (use negative for sorting)
    created_at = alert.created_at

    # Alert ID ascending: use the UUID directly
    alert_id = alert.alert_id

    return (
        -priority_order,
        -severity_value,
        -confidence,
        -created_at.timestamp(),
        alert_id,
    )
