"""Abstract base class for all collectors.

Implements the full lifecycle state machine, metric tracking,
direct queue integration, and structured logging.  Concrete collectors sub-class
:class:`BaseCollector` and implement only the ``_do_*`` template-method hooks
— they never touch locks, state, or event publishing directly.

Lifecycle contract
------------------
::

    initialize(config) → start() → [pause() → resume()] → stop()

- ``initialize()`` must be called exactly once before ``start()``.
- ``stop()`` is idempotent when the collector is already STOPPED.
- ``close()`` is an alias for ``stop()`` to satisfy the Phase 1
  :class:`~app.interfaces.collector.Collector` contract.
- ``collect()`` is a generator that may only be called while RUNNING;
  calling it in any other state raises :class:`CollectorStateError`.
"""

import queue
import threading
from abc import abstractmethod
from collections.abc import Iterator
from typing import Any

from argusprowl.collectors.metrics import CollectorMetrics
from argusprowl.collectors.state import CollectorState
from argusprowl.constants.log_names import LogName
from argusprowl.exceptions.exceptions import (
    CollectorError,
    CollectorInitializationError,
    CollectorStartError,
    CollectorStateError,
)
from argusprowl.interfaces.collector import Collector
from argusprowl.logging.logger_factory import LoggerFactory
from argusprowl.models.collector_health import CollectorHealth
from argusprowl.models.event import Event
from argusprowl.models.normalized_event import NormalizedEvent


class BaseCollector(Collector):
    """Abstract lifecycle-aware collector.

    Provides thread-safe state management, structured logging, metric
    collection, and queue integration.  Sub-classes implement only the
    ``_do_*`` template methods.

    Args:
        event_queue: Optional queue for routing NormalizedEvents.
    """

    def __init__(self, event_queue: queue.Queue[NormalizedEvent] | None = None) -> None:
        self._event_queue = event_queue
        self._state = CollectorState.UNINITIALIZED
        self._lock = threading.Lock()
        self._config: dict[str, Any] = {}
        self._error_message: str = ""
        self._metrics = CollectorMetrics(self.name)
        self._logger = LoggerFactory.get_logger(LogName.COLLECTOR)

    # ------------------------------------------------------------------ Phase 1 contract

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique, human-readable collector identifier."""

    def collect(self) -> Iterator[Event]:
        """Yield events from the source; may only be called while RUNNING.

        Raises:
            CollectorStateError: If the collector is not in RUNNING state.
        """
        with self._lock:
            if self._state != CollectorState.RUNNING:
                raise CollectorStateError(
                    f"Collector '{self.name}' cannot collect in state {self._state!r}.",
                    {"collector": self.name, "state": str(self._state)},
                )
        yield from self._do_collect()

    def close(self) -> None:
        """Alias for :meth:`stop` — satisfies the Phase 1 Collector contract."""
        self.stop()

    # ------------------------------------------------------------------ lifecycle public API

    def initialize(self, config: dict[str, Any] | None = None) -> None:
        """Initialize the collector with the provided configuration.

        Transitions: ``UNINITIALIZED → INITIALIZING → STOPPED``

        Args:
            config: Collector-specific configuration mapping.

        Raises:
            CollectorStateError: If the collector is not UNINITIALIZED.
            CollectorInitializationError: If ``_do_initialize`` fails.
        """
        self._transition(CollectorState.INITIALIZING)
        self._config = config or {}
        try:
            self._do_initialize(self._config)
            self._transition(CollectorState.STOPPED)
            self._logger.info("Collector '%s' initialized.", self.name)
        except CollectorInitializationError:
            self._enter_failed(f"Initialization failed for '{self.name}'.")
            raise
        except Exception as exc:
            self._enter_failed(str(exc))
            raise CollectorInitializationError(
                f"Collector '{self.name}' initialization failed: {exc}",
                {"collector": self.name, "reason": str(exc)},
            ) from exc

    def start(self) -> None:
        """Start the collector.

        Transitions: ``STOPPED → STARTING → RUNNING``

        Raises:
            CollectorStateError: If the collector is not STOPPED.
            CollectorStartError: If ``_do_start`` fails.
        """
        self._transition(CollectorState.STARTING)
        try:
            self._do_start()
            self._transition(CollectorState.RUNNING)
            self._metrics.mark_running()
            self._logger.info("Collector '%s' started.", self.name)
        except CollectorStartError:
            self._enter_failed(f"Start failed for '{self.name}'.")
            raise
        except Exception as exc:
            self._enter_failed(str(exc))
            raise CollectorStartError(
                f"Collector '{self.name}' start failed: {exc}",
                {"collector": self.name, "reason": str(exc)},
            ) from exc

    def stop(self) -> None:
        """Stop the collector gracefully.

        Idempotent — calling ``stop()`` on an already-STOPPED collector is a
        no-op.

        Transitions: ``RUNNING|PAUSED|PAUSING|STARTING|FAILED → STOPPING → STOPPED``

        Raises:
            CollectorError: If ``_do_stop`` raises unexpectedly.
        """
        with self._lock:
            if self._state == CollectorState.STOPPED:
                return
            if self._state == CollectorState.UNINITIALIZED:
                return
        self._transition(CollectorState.STOPPING)
        self._metrics.mark_stopped()
        try:
            self._do_stop()
            self._transition(CollectorState.STOPPED)
            self._logger.info("Collector '%s' stopped.", self.name)
        except Exception as exc:
            self._enter_failed(str(exc))
            raise CollectorError(
                f"Collector '{self.name}' stop failed: {exc}",
                {"collector": self.name, "reason": str(exc)},
            ) from exc

    def pause(self) -> None:
        """Pause the collector without destroying resources.

        Transitions: ``RUNNING → PAUSING → PAUSED``

        Raises:
            CollectorStateError: If the collector is not RUNNING.
            CollectorError: If ``_do_pause`` raises unexpectedly.
        """
        self._transition(CollectorState.PAUSING)
        self._metrics.mark_stopped()
        try:
            self._do_pause()
            self._transition(CollectorState.PAUSED)
            self._logger.info("Collector '%s' paused.", self.name)
        except Exception as exc:
            self._enter_failed(str(exc))
            raise CollectorError(
                f"Collector '{self.name}' pause failed: {exc}",
                {"collector": self.name, "reason": str(exc)},
            ) from exc

    def resume(self) -> None:
        """Resume a paused collector.

        Transitions: ``PAUSED → RESUMING → RUNNING``

        Raises:
            CollectorStateError: If the collector is not PAUSED.
            CollectorError: If ``_do_resume`` raises unexpectedly.
        """
        self._transition(CollectorState.RESUMING)
        try:
            self._do_resume()
            self._transition(CollectorState.RUNNING)
            self._metrics.mark_running()
            self._logger.info("Collector '%s' resumed.", self.name)
        except Exception as exc:
            self._enter_failed(str(exc))
            raise CollectorError(
                f"Collector '{self.name}' resume failed: {exc}",
                {"collector": self.name, "reason": str(exc)},
            ) from exc

    # ------------------------------------------------------------------ observability

    def health(self) -> CollectorHealth:
        """Return an immutable health snapshot for this collector.

        Returns:
            :class:`~app.models.collector_health.CollectorHealth` dataclass.
        """
        with self._lock:
            state = self._state
            error_msg = self._error_message
        return CollectorHealth(
            name=self.name,
            state=state,
            metrics=self._metrics.snapshot(),
            error_message=error_msg,
        )

    def status(self) -> dict[str, object]:
        """Return a serializable status dictionary.

        Returns:
            Plain dict suitable for logging, CLI output, or REST APIs.
        """
        h = self.health()
        return h.to_dict()

    @property
    def state(self) -> CollectorState:
        """Current lifecycle state (snapshot, may change immediately)."""
        with self._lock:
            return self._state

    @property
    def metrics(self) -> CollectorMetrics:
        """Live metrics object (thread-safe)."""
        return self._metrics

    # ------------------------------------------------------------------ template methods

    def _do_initialize(self, config: dict[str, Any]) -> None:
        """Override to perform collector-specific initialization.

        Called once inside :meth:`initialize`, with state guards already applied.

        Args:
            config: Validated configuration mapping passed to :meth:`initialize`.

        Raises:
            CollectorInitializationError: On initialization failure.
        """

    def _do_start(self) -> None:
        """Override to start background threads or open source connections.

        Called inside :meth:`start`, with state guards already applied.

        Raises:
            CollectorStartError: On start failure.
        """

    def _do_stop(self) -> None:
        """Override to tear down connections and release resources.

        Called inside :meth:`stop`, with state guards already applied.
        """

    def _do_pause(self) -> None:
        """Override to suspend collection without releasing connections.

        Called inside :meth:`pause`, with state guards already applied.
        """

    def _do_resume(self) -> None:
        """Override to re-enable collection after a pause.

        Called inside :meth:`resume`, with state guards already applied.
        """

    @abstractmethod
    def _do_collect(self) -> Iterator[Event]:
        """Override to yield source events.

        Called inside :meth:`collect` only when the collector is RUNNING.

        Yields:
            :class:`~app.models.event.Event` instances.
        """

    # ------------------------------------------------------------------ internals

    def _transition(self, next_state: CollectorState) -> None:
        """Atomically validate and execute a state transition.

        Args:
            next_state: Desired next state.

        Raises:
            CollectorStateError: If the transition is not permitted.
        """
        with self._lock:
            current = self._state
            if not current.can_transition_to(next_state):
                raise CollectorStateError(
                    f"Collector '{self.name}' cannot transition from "
                    f"{current!r} to {next_state!r}.",
                    {
                        "collector": self.name,
                        "from_state": str(current),
                        "to_state": str(next_state),
                    },
                )
            self._state = next_state
            if next_state != CollectorState.FAILED:
                self._error_message = ""

        self._metrics.record_state_transition()

    def _enter_failed(self, reason: str) -> None:
        """Transition to FAILED state unconditionally, recording the error reason.

        Args:
            reason: Human-readable failure description.
        """
        with self._lock:
            self._state = CollectorState.FAILED
            self._error_message = reason
        self._metrics.record_error()
        self._metrics.record_state_transition()
        self._logger.error("Collector '%s' FAILED: %s", self.name, reason)

    def __repr__(self) -> str:
        """String representation."""
        return f"{type(self).__name__}(name={self.name!r}, state={self._state!r})"
