"""Alert lifecycle transition validation.

Pure functions for validating and performing lifecycle state transitions
on immutable Alert objects.
"""

from dataclasses import replace
from typing import TYPE_CHECKING

from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.models.alert import Alert

if TYPE_CHECKING:
    pass

# Valid transitions: (from_state, to_state)
_VALID_TRANSITIONS: frozenset[tuple[AlertLifecycleState, AlertLifecycleState]] = frozenset(
    {
        (AlertLifecycleState.OPEN, AlertLifecycleState.ACKNOWLEDGED),
        (AlertLifecycleState.OPEN, AlertLifecycleState.CLOSED),
        (AlertLifecycleState.ACKNOWLEDGED, AlertLifecycleState.CLOSED),
    }
)


def transition_lifecycle(alert: Alert, new_state: AlertLifecycleState) -> Alert:
    """Transition an alert to a new lifecycle state.

    Returns a new Alert with the updated lifecycle state. The original
    Alert is not modified (alerts are immutable).

    Args:
        alert: The alert to transition.
        new_state: The target lifecycle state.

    Returns:
        A new Alert with the updated lifecycle state.

    Raises:
        ValueError: If the transition is invalid.
    """
    current_state = alert.lifecycle_state
    if (current_state, new_state) not in _VALID_TRANSITIONS:
        raise ValueError(
            f"Invalid lifecycle transition from '{current_state.value}' to '{new_state.value}'. "
            f"Valid transitions: OPEN->ACKNOWLEDGED, OPEN->CLOSED, ACKNOWLEDGED->CLOSED"
        )
    return replace(alert, lifecycle_state=new_state)
