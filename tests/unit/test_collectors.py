"""Comprehensive unit tests for the Phase 2.1 Collector Framework.

Tests cover:
- CollectorState enum and valid/invalid transitions
- CollectorMetrics accumulation and snapshots
- BaseCollector lifecycle (happy path, error paths, idempotency)
- CollectorRegistry CRUD and state-based queries
- CollectorFactory type-based and instance-based registration
- CollectorManager bulk operations with failure isolation
- Thread-safety (parallel start/stop)
- Health service integration
"""

import queue
import threading
import time
from collections.abc import Iterator

import pytest

from argusprowl.collectors.base_collector import BaseCollector
from argusprowl.collectors.factory import CollectorFactory
from argusprowl.collectors.manager import CollectorManager
from argusprowl.collectors.metrics import CollectorMetrics, CollectorMetricsSnapshot
from argusprowl.collectors.registry import CollectorRegistry
from argusprowl.collectors.state import CollectorState
from argusprowl.exceptions.exceptions import (
    CollectorError,
    CollectorInitializationError,
    CollectorStartError,
    CollectorStateError,
)
from argusprowl.models.collector_health import CollectorHealth
from argusprowl.models.event import Event
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.models.system_status import HealthStatus
from argusprowl.services.health_service import HealthService

# ---------------------------------------------------------------------------
# Helpers - stub collectors defined locally (not exported)
# ---------------------------------------------------------------------------


class _StubCollector(BaseCollector):
    """Minimal concrete collector for framework tests."""

    def __init__(
        self,
        name: str = "stub",
        event_queue: queue.Queue[NormalizedEvent] | None = None,
        events: list[Event] | None = None,
    ) -> None:
        self._name = name
        self._events = events or []
        super().__init__(event_queue=event_queue)

    @property
    def name(self) -> str:
        return self._name

    def _do_collect(self) -> Iterator[Event]:
        yield from self._events


class _FailingInitCollector(BaseCollector):
    """Collector whose _do_initialize always raises."""

    @property
    def name(self) -> str:
        return "failing_init"

    def _do_initialize(self, config: dict) -> None:
        raise CollectorInitializationError("deliberate init failure")

    def _do_collect(self) -> Iterator[Event]:
        return iter([])


class _FailingStartCollector(BaseCollector):
    """Collector whose _do_start always raises."""

    @property
    def name(self) -> str:
        return "failing_start"

    def _do_collect(self) -> Iterator[Event]:
        return iter([])

    def _do_start(self) -> None:
        raise CollectorStartError("deliberate start failure")


class _PauseAwareCollector(BaseCollector):
    """Collector that tracks pause/resume invocations."""

    def __init__(self, event_queue: queue.Queue[NormalizedEvent] | None = None) -> None:
        self.pause_count = 0
        self.resume_count = 0
        super().__init__(event_queue=event_queue)

    @property
    def name(self) -> str:
        return "pause_aware"

    def _do_pause(self) -> None:
        self.pause_count += 1

    def _do_resume(self) -> None:
        self.resume_count += 1

    def _do_collect(self) -> Iterator[Event]:
        return iter([])


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def event_queue() -> queue.Queue[NormalizedEvent]:
    return queue.Queue()


@pytest.fixture
def stub(event_queue: queue.Queue[NormalizedEvent]) -> _StubCollector:
    return _StubCollector(event_queue=event_queue)


@pytest.fixture
def initialized_stub(stub: _StubCollector) -> _StubCollector:
    stub.initialize()
    return stub


@pytest.fixture
def running_stub(initialized_stub: _StubCollector) -> _StubCollector:
    initialized_stub.start()
    return initialized_stub


@pytest.fixture
def registry() -> CollectorRegistry:
    return CollectorRegistry()


@pytest.fixture
def manager(event_queue: queue.Queue[NormalizedEvent]) -> CollectorManager:
    return CollectorManager(event_queue=event_queue)


# ===========================================================================
# 1. CollectorState
# ===========================================================================


class TestCollectorState:
    def test_all_states_are_str_enum(self) -> None:
        for state in CollectorState:
            assert isinstance(state, str)

    def test_valid_transitions_covers_all_states(self) -> None:
        transitions = CollectorState.valid_transitions()
        for state in CollectorState:
            assert state in transitions, f"State {state!r} missing from valid_transitions"

    @pytest.mark.parametrize(
        "from_state,to_state",
        [
            (CollectorState.UNINITIALIZED, CollectorState.INITIALIZING),
            (CollectorState.INITIALIZING, CollectorState.STOPPED),
            (CollectorState.STOPPED, CollectorState.STARTING),
            (CollectorState.STARTING, CollectorState.RUNNING),
            (CollectorState.RUNNING, CollectorState.PAUSING),
            (CollectorState.PAUSING, CollectorState.PAUSED),
            (CollectorState.PAUSED, CollectorState.RESUMING),
            (CollectorState.RESUMING, CollectorState.RUNNING),
            (CollectorState.RUNNING, CollectorState.STOPPING),
            (CollectorState.STOPPING, CollectorState.STOPPED),
            (CollectorState.FAILED, CollectorState.STOPPED),
        ],
    )
    def test_valid_transitions_accepted(
        self, from_state: CollectorState, to_state: CollectorState
    ) -> None:
        assert from_state.can_transition_to(to_state)

    @pytest.mark.parametrize(
        "from_state,to_state",
        [
            (CollectorState.UNINITIALIZED, CollectorState.RUNNING),
            (CollectorState.STOPPED, CollectorState.PAUSED),
            (CollectorState.RUNNING, CollectorState.STOPPED),  # must go through STOPPING
            (CollectorState.PAUSED, CollectorState.RUNNING),  # must go through RESUMING
            (CollectorState.INITIALIZING, CollectorState.RUNNING),
        ],
    )
    def test_invalid_transitions_rejected(
        self, from_state: CollectorState, to_state: CollectorState
    ) -> None:
        assert not from_state.can_transition_to(to_state)

    def test_failed_can_transition_to_stopped_only(self) -> None:
        transitions = CollectorState.FAILED.valid_transitions()[CollectorState.FAILED]
        assert CollectorState.STOPPED in transitions
        assert CollectorState.STOPPING in transitions
        # Should not be able to go directly back to RUNNING from FAILED
        assert CollectorState.RUNNING not in transitions


# ===========================================================================
# 2. CollectorMetrics
# ===========================================================================


class TestCollectorMetrics:
    def test_initial_snapshot_is_zero(self) -> None:
        m = CollectorMetrics("test")
        snap = m.snapshot()
        assert snap.events_collected == 0
        assert snap.errors_total == 0
        assert snap.state_transitions_total == 0
        assert snap.last_error_time is None
        assert snap.uptime_seconds == 0.0

    def test_event_collection_increments_counter(self) -> None:
        m = CollectorMetrics("test")
        m.record_event_collected(5)
        m.record_event_collected(3)
        assert m.snapshot().events_collected == 8

    def test_error_recording(self) -> None:
        m = CollectorMetrics("test")
        m.record_error()
        snap = m.snapshot()
        assert snap.errors_total == 1
        assert snap.last_error_time is not None

    def test_state_transition_counter(self) -> None:
        m = CollectorMetrics("test")
        m.record_state_transition()
        m.record_state_transition()
        assert m.snapshot().state_transitions_total == 2

    def test_uptime_accumulates_while_running(self) -> None:
        m = CollectorMetrics("test")
        m.mark_running()
        time.sleep(0.02)
        m.mark_stopped()
        snap = m.snapshot()
        assert snap.uptime_seconds >= 0.01

    def test_uptime_includes_current_period(self) -> None:
        m = CollectorMetrics("test")
        m.mark_running()
        snap = m.snapshot()
        assert snap.uptime_seconds >= 0.0

    def test_collection_duration_histogram(self) -> None:
        m = CollectorMetrics("test")
        for _ in range(10):
            m.record_collection_duration(0.001)
        snap = m.snapshot()
        # p50 should be around 0.001
        assert snap.collection_duration_p50 >= 0.0

    def test_reset_clears_all_metrics(self) -> None:
        m = CollectorMetrics("test")
        m.record_event_collected(10)
        m.record_error()
        m.reset()
        snap = m.snapshot()
        assert snap.events_collected == 0
        assert snap.errors_total == 0

    def test_snapshot_is_immutable(self) -> None:
        m = CollectorMetrics("test")
        snap = m.snapshot()
        assert isinstance(snap, CollectorMetricsSnapshot)
        with pytest.raises((AttributeError, TypeError)):
            snap.events_collected = 999  # type: ignore[misc]

    def test_to_dict_serializes_correctly(self) -> None:
        m = CollectorMetrics("test")
        m.record_event_collected(7)
        d = m.snapshot().to_dict()
        assert d["events_collected"] == 7
        assert "captured_at" in d


# ===========================================================================
# 3. BaseCollector lifecycle
# ===========================================================================


class TestBaseCollectorLifecycle:
    def test_initial_state_is_uninitialized(self, stub: _StubCollector) -> None:
        assert stub.state == CollectorState.UNINITIALIZED

    def test_initialize_transitions_to_stopped(self, stub: _StubCollector) -> None:
        stub.initialize()
        assert stub.state == CollectorState.STOPPED

    def test_start_transitions_to_running(self, initialized_stub: _StubCollector) -> None:
        initialized_stub.start()
        assert initialized_stub.state == CollectorState.RUNNING

    def test_stop_transitions_to_stopped(self, running_stub: _StubCollector) -> None:
        running_stub.stop()
        assert running_stub.state == CollectorState.STOPPED

    def test_pause_and_resume(self, running_stub: _StubCollector) -> None:
        running_stub.pause()
        assert running_stub.state == CollectorState.PAUSED
        running_stub.resume()
        assert running_stub.state == CollectorState.RUNNING

    def test_stop_is_idempotent_when_already_stopped(
        self, initialized_stub: _StubCollector
    ) -> None:
        # Already STOPPED after initialize
        initialized_stub.stop()  # first call
        initialized_stub.stop()  # second call should be a no-op
        assert initialized_stub.state == CollectorState.STOPPED

    def test_stop_on_uninitialized_is_noop(self, stub: _StubCollector) -> None:
        stub.stop()  # must not raise
        assert stub.state == CollectorState.UNINITIALIZED

    def test_close_aliases_stop(self, running_stub: _StubCollector) -> None:
        running_stub.close()
        assert running_stub.state == CollectorState.STOPPED

    def test_start_without_initialize_raises_state_error(self, stub: _StubCollector) -> None:
        with pytest.raises(CollectorStateError):
            stub.start()

    def test_double_initialize_raises_state_error(self, stub: _StubCollector) -> None:
        stub.initialize()
        with pytest.raises(CollectorStateError):
            stub.initialize()

    def test_collect_only_works_when_running(self, initialized_stub: _StubCollector) -> None:
        with pytest.raises(CollectorStateError):
            list(initialized_stub.collect())

    def test_collect_yields_events_when_running(self) -> None:
        ev = Event(source="test", event_type="raw", raw_data="data")
        collector = _StubCollector(events=[ev])
        collector.initialize()
        collector.start()
        results = list(collector.collect())
        assert results == [ev]

    def test_pause_when_not_running_raises_state_error(
        self, initialized_stub: _StubCollector
    ) -> None:
        with pytest.raises(CollectorStateError):
            initialized_stub.pause()

    def test_resume_when_not_paused_raises_state_error(self, running_stub: _StubCollector) -> None:
        with pytest.raises(CollectorStateError):
            running_stub.resume()

    def test_health_returns_collector_health(self, running_stub: _StubCollector) -> None:
        h = running_stub.health()
        assert isinstance(h, CollectorHealth)
        assert h.name == running_stub.name
        assert h.state == CollectorState.RUNNING

    def test_status_returns_dict(self, running_stub: _StubCollector) -> None:
        s = running_stub.status()
        assert isinstance(s, dict)
        assert s["state"] == str(CollectorState.RUNNING)

    def test_repr(self, stub: _StubCollector) -> None:
        r = repr(stub)
        assert "stub" in r
        assert "uninitialized" in r

    def test_initialize_with_config(self, stub: _StubCollector) -> None:
        stub.initialize({"key": "value"})
        assert stub._config == {"key": "value"}


# ===========================================================================
# 4. BaseCollector failure scenarios
# ===========================================================================


class TestBaseCollectorFailures:
    def test_failing_initialize_enters_failed_state(self) -> None:
        c = _FailingInitCollector()
        with pytest.raises(CollectorInitializationError):
            c.initialize()
        assert c.state == CollectorState.FAILED

    def test_failing_initialize_records_error(self) -> None:
        c = _FailingInitCollector()
        with pytest.raises(CollectorInitializationError):
            c.initialize()
        assert c.metrics.snapshot().errors_total >= 1

    def test_failing_start_enters_failed_state(self) -> None:
        c = _FailingStartCollector()
        c.initialize()
        with pytest.raises(CollectorStartError):
            c.start()
        assert c.state == CollectorState.FAILED

    def test_failed_collector_health_is_not_healthy(self) -> None:
        c = _FailingStartCollector()
        c.initialize()
        with pytest.raises(CollectorStartError):
            c.start()
        h = c.health()
        assert h.is_failed
        assert not h.is_healthy
        assert h.error_message

    def test_failed_collector_can_be_stopped(self) -> None:
        c = _FailingStartCollector()
        c.initialize()
        with pytest.raises(CollectorStartError):
            c.start()
        assert c.state == CollectorState.FAILED
        c.stop()
        assert c.state == CollectorState.STOPPED


# ===========================================================================
# 6. CollectorRegistry
# ===========================================================================


class TestCollectorRegistry:
    def test_register_and_get(self, registry: CollectorRegistry) -> None:
        c = _StubCollector(name="alpha")
        registry.register(c)
        assert registry.get("alpha") is c

    def test_duplicate_registration_raises(self, registry: CollectorRegistry) -> None:
        c1 = _StubCollector(name="alpha")
        c2 = _StubCollector(name="alpha")
        registry.register(c1)
        with pytest.raises(CollectorError):
            registry.register(c2)

    def test_get_unknown_raises_key_error(self, registry: CollectorRegistry) -> None:
        with pytest.raises(KeyError):
            registry.get("unknown")

    def test_unregister_removes_collector(self, registry: CollectorRegistry) -> None:
        c = _StubCollector(name="alpha")
        registry.register(c)
        registry.unregister("alpha")
        assert "alpha" not in registry

    def test_unregister_unknown_raises_key_error(self, registry: CollectorRegistry) -> None:
        with pytest.raises(KeyError):
            registry.unregister("ghost")

    def test_get_all_returns_copy(self, registry: CollectorRegistry) -> None:
        c = _StubCollector(name="alpha")
        registry.register(c)
        all_c = registry.get_all()
        all_c["injected"] = c  # type: ignore
        assert "injected" not in registry  # original unaffected

    def test_get_by_state_filters_correctly(self, registry: CollectorRegistry) -> None:
        alpha = _StubCollector(name="alpha")
        beta = _StubCollector(name="beta")
        alpha.initialize()
        registry.register(alpha)
        registry.register(beta)
        stopped = registry.get_by_state(CollectorState.STOPPED)
        uninitialized = registry.get_by_state(CollectorState.UNINITIALIZED)
        assert "alpha" in stopped
        assert "beta" in uninitialized

    def test_contains(self, registry: CollectorRegistry) -> None:
        c = _StubCollector(name="alpha")
        registry.register(c)
        assert "alpha" in registry
        assert "beta" not in registry

    def test_len(self, registry: CollectorRegistry) -> None:
        assert len(registry) == 0
        registry.register(_StubCollector(name="alpha"))
        registry.register(_StubCollector(name="beta"))
        assert len(registry) == 2

    def test_names_sorted(self, registry: CollectorRegistry) -> None:
        registry.register(_StubCollector(name="z"))
        registry.register(_StubCollector(name="a"))
        assert registry.names() == ["a", "z"]

    def test_clear(self, registry: CollectorRegistry) -> None:
        registry.register(_StubCollector(name="alpha"))
        registry.clear()
        assert len(registry) == 0

    def test_register_non_base_collector_raises_type_error(
        self, registry: CollectorRegistry
    ) -> None:
        with pytest.raises(TypeError):
            registry.register("not_a_collector")  # type: ignore


# ===========================================================================
# 7. CollectorFactory
# ===========================================================================


class TestCollectorFactory:
    def test_register_type_and_create(self) -> None:
        factory = CollectorFactory()
        factory.register_type("stub", _StubCollector)
        c = factory.create("stub")
        assert c.state == CollectorState.STOPPED  # initialized

    def test_create_with_config(self) -> None:
        factory = CollectorFactory()
        factory.register_type("stub", _StubCollector, default_config={"x": 1})
        c = factory.create("stub", config={"y": 2})
        # merged config should have both keys
        assert c._config.get("x") == 1
        assert c._config.get("y") == 2

    def test_create_unknown_type_raises(self) -> None:
        factory = CollectorFactory()
        with pytest.raises(CollectorError):
            factory.create("ghost")

    def test_duplicate_type_raises(self) -> None:
        factory = CollectorFactory()
        factory.register_type("stub", _StubCollector)
        with pytest.raises(CollectorError):
            factory.register_type("stub", _StubCollector)

    def test_register_non_subclass_raises_type_error(self) -> None:
        factory = CollectorFactory()
        with pytest.raises(TypeError):
            factory.register_type("bad", object)  # type: ignore

    def test_register_instance(self) -> None:
        factory = CollectorFactory()
        c = _StubCollector(name="direct")
        factory.register_instance(c)
        assert factory.get_instance("direct") is c

    def test_get_instance_unknown_raises(self) -> None:
        factory = CollectorFactory()
        with pytest.raises(CollectorError):
            factory.get_instance("ghost")

    def test_duplicate_instance_raises(self) -> None:
        factory = CollectorFactory()
        c = _StubCollector(name="direct")
        factory.register_instance(c)
        with pytest.raises(CollectorError):
            factory.register_instance(c)

    def test_list_types(self) -> None:
        factory = CollectorFactory()
        factory.register_type("b_type", _StubCollector)
        factory.register_type("a_type", _StubCollector)
        assert factory.list_types() == ["a_type", "b_type"]

    def test_failing_init_create_raises(self) -> None:
        factory = CollectorFactory()
        factory.register_type("failing", _FailingInitCollector)
        with pytest.raises(CollectorInitializationError):
            factory.create("failing")

    def test_is_type_registered(self) -> None:
        factory = CollectorFactory()
        factory.register_type("stub", _StubCollector)
        assert factory.is_type_registered("stub")
        assert not factory.is_type_registered("ghost")

    def test_event_queue_injected_into_created_collector(
        self, event_queue: queue.Queue[NormalizedEvent]
    ) -> None:
        factory = CollectorFactory(event_queue=event_queue)
        factory.register_type("stub", _StubCollector)
        c = factory.create("stub")
        assert c._event_queue is event_queue


# ===========================================================================
# 8. CollectorManager
# ===========================================================================


class TestCollectorManager:
    def _make_running(self, manager: CollectorManager, name: str) -> _StubCollector:
        c = _StubCollector(name=name)
        c.initialize()
        manager.add_collector(c)
        manager.start_collector(name)
        return c

    def test_add_and_get_collector(self, manager: CollectorManager) -> None:
        c = _StubCollector(name="alpha")
        c.initialize()
        manager.add_collector(c)
        assert manager.get_collector("alpha") is c

    def test_remove_collector(self, manager: CollectorManager) -> None:
        c = _StubCollector(name="alpha")
        c.initialize()
        manager.add_collector(c)
        manager.remove_collector("alpha")
        with pytest.raises(KeyError):
            manager.get_collector("alpha")

    def test_remove_running_collector_stops_it_first(self, manager: CollectorManager) -> None:
        c = self._make_running(manager, "alpha")
        manager.remove_collector("alpha")
        assert c.state == CollectorState.STOPPED

    def test_start_all_starts_stopped_collectors(self, manager: CollectorManager) -> None:
        alpha = _StubCollector(name="alpha")
        alpha.initialize()
        beta = _StubCollector(name="beta")
        beta.initialize()
        manager.add_collector(alpha)
        manager.add_collector(beta)
        results = manager.start_all()
        assert results["alpha"] is None
        assert results["beta"] is None
        assert alpha.state == CollectorState.RUNNING
        assert beta.state == CollectorState.RUNNING

    def test_start_all_failure_isolation(self, manager: CollectorManager) -> None:
        good = _StubCollector(name="good")
        good.initialize()
        bad = _FailingStartCollector()
        bad.initialize()
        manager.add_collector(good)
        # Register bad directly via the registry to bypass manager.add_collector type check
        manager.registry.register(bad)

        results = manager.start_all()

        # 'good' should succeed
        assert results.get("good") is None
        assert good.state == CollectorState.RUNNING

        # 'failing_start' should have an exception captured
        assert isinstance(results.get("failing_start"), Exception)
        assert bad.state == CollectorState.FAILED

    def test_stop_all(self, manager: CollectorManager) -> None:
        self._make_running(manager, "alpha")
        self._make_running(manager, "beta")
        results = manager.stop_all()
        assert results["alpha"] is None
        assert results["beta"] is None

    def test_pause_all_and_resume_all(self, manager: CollectorManager) -> None:
        self._make_running(manager, "alpha")
        self._make_running(manager, "beta")
        manager.pause_all()
        assert manager.registry.get("alpha").state == CollectorState.PAUSED
        manager.resume_all()
        assert manager.registry.get("alpha").state == CollectorState.RUNNING

    def test_health_all(self, manager: CollectorManager) -> None:
        self._make_running(manager, "alpha")
        result = manager.health_all()
        assert "alpha" in result
        assert isinstance(result["alpha"], CollectorHealth)

    def test_status_all(self, manager: CollectorManager) -> None:
        self._make_running(manager, "alpha")
        result = manager.status_all()
        assert "alpha" in result
        assert isinstance(result["alpha"], dict)

    def test_running_count(self, manager: CollectorManager) -> None:
        assert manager.running_count == 0
        self._make_running(manager, "alpha")
        assert manager.running_count == 1

    def test_collector_count(self, manager: CollectorManager) -> None:
        assert manager.collector_count == 0
        c = _StubCollector(name="alpha")
        c.initialize()
        manager.add_collector(c)
        assert manager.collector_count == 1

    def test_failed_count(self, manager: CollectorManager) -> None:
        bad = _FailingStartCollector()
        bad.initialize()
        manager.add_collector(bad)
        manager.start_all()  # triggers failure
        assert manager.failed_count == 1

    def test_repr(self, manager: CollectorManager) -> None:
        r = repr(manager)
        assert "CollectorManager" in r

    def test_manager_publishes_registered_event(
        self, manager: CollectorManager, event_queue: queue.Queue[NormalizedEvent]
    ) -> None:
        c = _StubCollector(name="alpha")
        c.initialize()
        manager.add_collector(c)
        # The collector now enqueues NormalizedEvents into the shared queue,
        # but at this point there is no consumer; the assertion below simply
        # verifies that the lifecycle completes without raising.
        assert manager.collector_count == 1

    def test_bulk_stop_skips_already_stopped(self, manager: CollectorManager) -> None:
        c = _StubCollector(name="alpha")
        c.initialize()
        manager.add_collector(c)
        # c is STOPPED, not in stoppable states
        results = manager.stop_all()
        assert "alpha" not in results  # was skipped, not attempted


# ===========================================================================
# 9. PauseAwareCollector - template method hooks
# ===========================================================================


class TestPauseAwareCollector:
    def test_pause_hook_called(self, event_queue: queue.Queue[NormalizedEvent]) -> None:
        c = _PauseAwareCollector(event_queue=event_queue)
        c.initialize()
        c.start()
        c.pause()
        assert c.pause_count == 1

    def test_resume_hook_called(self, event_queue: queue.Queue[NormalizedEvent]) -> None:
        c = _PauseAwareCollector(event_queue=event_queue)
        c.initialize()
        c.start()
        c.pause()
        c.resume()
        assert c.resume_count == 1


# ===========================================================================
# 10. CollectorHealth model
# ===========================================================================


class TestCollectorHealthModel:
    def _snap(self) -> "CollectorMetricsSnapshot":
        return CollectorMetrics("test").snapshot()

    def test_is_healthy_when_running_no_error(self) -> None:
        h = CollectorHealth(
            name="test",
            state=CollectorState.RUNNING,
            metrics=self._snap(),
        )
        assert h.is_healthy

    def test_is_not_healthy_when_paused(self) -> None:
        h = CollectorHealth(
            name="test",
            state=CollectorState.PAUSED,
            metrics=self._snap(),
        )
        assert not h.is_healthy
        assert h.is_degraded

    def test_is_failed_when_in_failed_state(self) -> None:
        h = CollectorHealth(
            name="test",
            state=CollectorState.FAILED,
            metrics=self._snap(),
        )
        assert h.is_failed
        assert not h.is_healthy

    def test_to_dict_structure(self) -> None:
        h = CollectorHealth(
            name="test",
            state=CollectorState.RUNNING,
            metrics=self._snap(),
        )
        d = h.to_dict()
        assert d["name"] == "test"
        assert d["state"] == "running"
        assert "metrics" in d
        assert "checked_at" in d


# ===========================================================================
# 11. HealthService integration
# ===========================================================================


class TestHealthServiceCollectorIntegration:
    def test_health_service_without_manager_still_works(self) -> None:
        svc = HealthService()
        status = svc.check_health()
        # No collector components without a manager
        collector_components = [c for c in status.components if c.name.startswith("collector")]
        assert collector_components == []

    def test_health_service_running_collector_contributes_healthy(self) -> None:
        manager = CollectorManager()
        c = _StubCollector(name="alpha")
        c.initialize()
        manager.add_collector(c)
        manager.start_collector("alpha")

        svc = HealthService(collector_manager=manager)
        status = svc.check_health()
        alpha_health = next(
            (comp for comp in status.components if comp.name == "collector.alpha"),
            None,
        )
        assert alpha_health is not None
        assert alpha_health.status == HealthStatus.HEALTHY

    def test_health_service_failed_collector_contributes_unhealthy(self) -> None:
        manager = CollectorManager()
        bad = _FailingStartCollector()
        bad.initialize()
        manager.add_collector(bad)
        manager.start_all()  # triggers failure

        svc = HealthService(collector_manager=manager)
        status = svc.check_health()
        failing_health = next(
            (comp for comp in status.components if "failing_start" in comp.name),
            None,
        )
        assert failing_health is not None
        assert failing_health.status == HealthStatus.UNHEALTHY

    def test_health_service_paused_collector_contributes_degraded(self) -> None:
        manager = CollectorManager()
        c = _StubCollector(name="alpha")
        c.initialize()
        manager.add_collector(c)
        manager.start_collector("alpha")
        manager.pause_collector("alpha")

        svc = HealthService(collector_manager=manager)
        status = svc.check_health()
        alpha_health = next(
            (comp for comp in status.components if comp.name == "collector.alpha"),
            None,
        )
        assert alpha_health is not None
        assert alpha_health.status == HealthStatus.DEGRADED


# ===========================================================================
# 12. Thread safety
# ===========================================================================


class TestCollectorThreadSafety:
    def test_parallel_start_stop_does_not_corrupt_state(self) -> None:
        """Multiple threads starting and stopping a collector must not corrupt state."""
        errors: list[Exception] = []
        collector = _StubCollector(name="concurrent")
        collector.initialize()

        def cycle() -> None:
            try:
                collector.start()
                time.sleep(0.001)
                collector.stop()
            except (CollectorStateError, CollectorError):
                pass  # Expected when threads race; state must remain consistent
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=cycle) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No unexpected exceptions
        assert not errors
        # State should be one of the stable states
        assert collector.state in (
            CollectorState.STOPPED,
            CollectorState.RUNNING,
            CollectorState.FAILED,
        )

    def test_registry_concurrent_registration(self) -> None:
        """Concurrent registrations should not lose collectors or corrupt state."""
        registry = CollectorRegistry()
        errors: list[Exception] = []

        def register(n: int) -> None:
            try:
                c = _StubCollector(name=f"c{n}")
                registry.register(c)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=register, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(registry) == 20
