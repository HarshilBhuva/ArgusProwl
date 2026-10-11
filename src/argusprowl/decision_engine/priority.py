"""Priority derivation logic for the DecisionEngine.

Priority is an operational ordering signal derived from the final
alert severity. It is NOT a confidence or risk score and must not
participate in alert fingerprint identity.
"""

from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity

# Deterministic severity → priority mapping.
# Priority is downstream of severity; no contextual scoring is applied.
_SEVERITY_TO_PRIORITY: dict[Severity, AlertPriority] = {
    Severity.INFO: AlertPriority.LOW,
    Severity.LOW: AlertPriority.LOW,
    Severity.MEDIUM: AlertPriority.MEDIUM,
    Severity.HIGH: AlertPriority.HIGH,
    Severity.CRITICAL: AlertPriority.CRITICAL,
}


def determine_alert_priority(severity: Severity) -> AlertPriority:
    """Derive operational alert priority from the final severity.

    This is a pure, deterministic function. It does not consult
    contextual confidence, evidence weights, or any other scoring
    layer. Priority is strictly an operational ordering signal.

    Args:
        severity: The final alert severity (from assessment or legacy mapping).

    Returns:
        The corresponding AlertPriority.
    """
    return _SEVERITY_TO_PRIORITY[severity]
