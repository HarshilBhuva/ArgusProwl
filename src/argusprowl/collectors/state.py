"""Collector state machine.

Defines all valid lifecycle states for a collector and the allowed
state transitions as a data-driven mapping.
"""

from enum import StrEnum


class CollectorState(StrEnum):
    """Lifecycle states for a collector.

    State machine diagram::

        UNINITIALIZED ──initialize()──► INITIALIZING ──► STOPPED
                                                             │
                                        ┌──────start()───────┘
                                        ▼
                                     STARTING ──► RUNNING ◄─── RESUMING
                                                     │               ▲
                                               pause()│               │resume()
                                                     ▼               │
                                                  PAUSING ──► PAUSED─┘
                                                     │
                                               stop()│ (from any active state)
                                                     ▼
                                                  STOPPING ──► STOPPED
                                                     │
                                     any state ──► FAILED ──stop()──► STOPPED
    """

    UNINITIALIZED = "uninitialized"
    INITIALIZING = "initializing"
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    PAUSING = "pausing"
    PAUSED = "paused"
    RESUMING = "resuming"
    STOPPING = "stopping"
    FAILED = "failed"

    @classmethod
    def valid_transitions(cls) -> dict["CollectorState", frozenset["CollectorState"]]:
        """Return the complete set of allowed state transitions.

        Each key is the *current* state; the value is the frozenset of states
        that may legally follow it. Transitions not listed here are forbidden
        and raise :class:`~app.exceptions.exceptions.CollectorStateError`.

        Returns:
            Mapping of current state → allowed next states.
        """
        return {
            cls.UNINITIALIZED: frozenset({cls.INITIALIZING}),
            cls.INITIALIZING: frozenset({cls.STOPPED, cls.FAILED}),
            cls.STOPPED: frozenset({cls.STARTING}),
            cls.STARTING: frozenset({cls.RUNNING, cls.FAILED}),
            cls.RUNNING: frozenset({cls.PAUSING, cls.STOPPING, cls.FAILED}),
            cls.PAUSING: frozenset({cls.PAUSED, cls.FAILED}),
            cls.PAUSED: frozenset({cls.RESUMING, cls.STOPPING, cls.FAILED}),
            cls.RESUMING: frozenset({cls.RUNNING, cls.FAILED}),
            cls.STOPPING: frozenset({cls.STOPPED, cls.FAILED}),
            cls.FAILED: frozenset({cls.STOPPING, cls.STOPPED}),
        }

    def can_transition_to(self, next_state: "CollectorState") -> bool:
        """Return True if a transition to *next_state* is currently allowed.

        Args:
            next_state: The target state to test.

        Returns:
            True when the transition is in the allowed set.
        """
        return next_state in self.valid_transitions().get(self, frozenset())
