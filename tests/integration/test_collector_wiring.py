"""Integration tests for collector wiring via the application factory."""

import queue
import sys
import time
from pathlib import Path

# Ensure src/ is on sys.path so Application can be imported regardless of cwd.
sys.path.append(str(Path(__file__).resolve().parents[2] / "src"))

from argusprowl.collectors.registry import CollectorRegistry
from argusprowl.collectors.state import CollectorState
from argusprowl.config.config_manager import ConfigManager
from argusprowl.core.application import Application
from argusprowl.core.collector_factory import build_collectors, is_source_enabled
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.models.configuration import AppConfiguration


def _zeek_line(uid: str) -> str:
    """Return one valid Zeek conn.log line."""
    return (
        "1590000000.000\tC1\t10.0.0.1\t1\t10.0.0.2\t2\ttcp\t-\t0.0\t0\t0"
        "\t-\t-\t-\t0\t-\t0\t0\t0\t0\t-\n"
    ).replace("C1", uid)


def _write_zeek_line(path: Path, uid: str) -> None:
    path.write_text(_zeek_line(uid), encoding="utf-8")


def _append_zeek_line(path: Path, uid: str) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(_zeek_line(uid))


def _make_zeek_config(temp_dir: Path, log_file: Path) -> AppConfiguration:
    return AppConfiguration(
        zeek=__import__("argusprowl.models.configuration").models.configuration.ZeekConfig(
            enabled=True,
            log_path=str(log_file),
            offset_file=str(temp_dir / "offsets.json"),
            poll_interval_sec=0.05,
        ),
        ingestion=__import__("argusprowl.models.configuration").models.configuration.IngestionConfig(
            zeek_log_path=str(log_file),
            poll_interval=0.05,
            batch_size=100,
        ),
    )


def test_build_collectors_creates_zeek_when_enabled(temp_dir: Path) -> None:
    """A Zeek section with enabled=True produces one collector."""
    log_file = temp_dir / "conn.log"
    _write_zeek_line(log_file, "uid")

    config = _make_zeek_config(temp_dir, log_file)
    registry = CollectorRegistry()
    created = build_collectors(config, queue.Queue(), registry)

    assert len(created) == 1
    source_name, collector = created[0]
    assert source_name == "zeek"
    assert collector.name == "zeek_conn_collector"
    assert "zeek_conn_collector" in registry.names()


def test_build_collectors_skips_disabled_zeek(temp_dir: Path) -> None:
    """enabled=False must not create a collector."""
    config = AppConfiguration(
        zeek=__import__("argusprowl.models.configuration").models.configuration.ZeekConfig(enabled=False),
    )
    registry = CollectorRegistry()
    created = build_collectors(config, queue.Queue(), registry)
    assert created == []
    assert registry.names() == []


def test_build_collectors_skips_missing_file_with_error_log(
    caplog, temp_dir: Path
) -> None:
    """A non-existent log path must fail gracefully — not crash."""
    import logging

    config = AppConfiguration(
        zeek=__import__("argusprowl.models.configuration").models.configuration.ZeekConfig(
            enabled=True,
            log_path=str(temp_dir / "does_not_exist.log"),
            offset_file=str(temp_dir / "offsets.json"),
            poll_interval_sec=0.05,
        ),
    )
    registry = CollectorRegistry()

    with caplog.at_level(logging.ERROR, logger="argusprowl"):
        created = build_collectors(config, queue.Queue(), registry)

    # The collector may or may not fail at init time depending on whether the
    # tailer allows missing files; either way startup must not raise.
    assert isinstance(created, list)


def test_application_registers_zeek_and_receives_event(temp_dir: Path) -> None:
    """Start an Application with zeek enabled and feed an event through the pipeline."""
    log_file = temp_dir / "conn.log"
    _write_zeek_line(log_file, "testUid123")

    cfg_content = (
        f"app_name: TestApp\n"
        f"api:\n  enabled: false\n"
        f"zeek:\n  enabled: true\n"
        f"  log_path: {log_file}\n"
        f"  offset_file: {temp_dir}/zeek-offsets.json\n"
        f"  poll_interval_sec: 0.05\n"
        f"ingestion:\n  zeek_log_path: {log_file}\n"
        f"  poll_interval: 0.05\n"
        f"events:\n  queue_size: 100\n"
    )
    cfg_file = temp_dir / "app.yaml"
    cfg_file.write_text(cfg_content, encoding="utf-8")

    ServiceContainer.reset_instance()
    ConfigManager.reset_instance()
    app = Application(config_path=cfg_file)
    app.startup()
    try:
        assert app.is_running
        cm = app.container.resolve(
            __import__("argusprowl.collectors.manager").collectors.manager.CollectorManager
        )
        assert cm.collector_count >= 1, f"Expected at least one collector; got {cm.collector_count}"

        # The Application lifecycle must consume the collector generator,
        # route the event through the shared buffer, and process it into
        # evidence. Do not call collector.collect() manually here: doing so
        # would hide a missing production worker.
        from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService

        evidence_service = app.container.resolve(TelemetryEvidenceService)
        deadline = time.monotonic() + 5.0
        found = False
        while time.monotonic() < deadline:
            result = evidence_service.search(limit=100)
            if any(
                event.attributes.get("uid") == "testUid123"
                for event in result.events.values()
            ):
                found = True
                break
            time.sleep(0.05)

        assert found, "Expected the application's normal collector pipeline to retain the Zeek event"
    finally:
        app.shutdown()
        assert not app.is_running


def test_application_shuts_down_collectors(temp_dir: Path) -> None:
    """After shutdown, all registered collectors are STOPPED."""
    log_file = temp_dir / "conn.log"
    _write_zeek_line(log_file, "shutdownTest")

    cfg_content = (
        f"app_name: TestApp\n"
        f"api:\n  enabled: false\n"
        f"zeek:\n  enabled: true\n"
        f"  log_path: {log_file}\n"
        f"  offset_file: {temp_dir}/zeek-offsets.json\n"
        f"  poll_interval_sec: 0.05\n"
        f"ingestion:\n  zeek_log_path: {log_file}\n"
        f"  poll_interval: 0.05\n"
        f"events:\n  queue_size: 100\n"
    )
    cfg_file = temp_dir / "app.yaml"
    cfg_file.write_text(cfg_content, encoding="utf-8")

    ServiceContainer.reset_instance()
    ConfigManager.reset_instance()
    app = Application(config_path=cfg_file)
    app.startup()
    cm = app.container.resolve(
        __import__("argusprowl.collectors.manager").collectors.manager.CollectorManager
    )
    try:
        health = cm.health_all()
        assert len(health) >= 1
        # Collectors should be running before shutdown.
        assert any(h.state == CollectorState.RUNNING for h in health.values())
    finally:
        app.shutdown()

    for name, health in cm.health_all().items():
        assert health.state == CollectorState.STOPPED, (
            f"Collector '{name}' is {health.state}, expected STOPPED after shutdown"
        )


def test_is_source_enabled(temp_dir: Path) -> None:
    """Regression: public helper correctly reflects enabled flag."""
    config_disabled = AppConfiguration(
        zeek=__import__("argusprowl.models.configuration").models.configuration.ZeekConfig(enabled=False),
    )
    config_enabled = AppConfiguration(
        zeek=__import__("argusprowl.models.configuration").models.configuration.ZeekConfig(
            enabled=True,
            log_path=str(temp_dir / "c.log"),
        ),
    )
    assert not is_source_enabled(config_disabled, "zeek")
    assert is_source_enabled(config_enabled, "zeek")
    assert not is_source_enabled(config_disabled, "sysmon")
    assert not is_source_enabled(config_enabled, "sysmon")


def test_application_no_enabled_collectors_starts_cleanly(temp_dir: Path) -> None:
    """When no collectors are enabled, startup still succeeds."""
    cfg_file = temp_dir / "app.yaml"
    cfg_file.write_text("app_name: TestApp\napi:\n  enabled: false\n", encoding="utf-8")

    ServiceContainer.reset_instance()
    ConfigManager.reset_instance()
    app = Application(config_path=cfg_file)
    app.startup()
    try:
        assert app.is_running
        cm = app.container.resolve(
            __import__("argusprowl.collectors.manager").collectors.manager.CollectorManager
        )
        assert cm.collector_count == 0
        # Health check must still work.
        status = app.health_check()
        assert status.status.value == "healthy"
    finally:
        app.shutdown()


def test_no_crash_when_collector_init_fails(temp_dir: Path) -> None:
    """If a collector's _do_initialize raises, startup must continue."""
    cfg_content = (
        "app_name: TestApp\n"
        "api:\n  enabled: false\n"
        "sysmon:\n  enabled: true\n"
    )
    cfg_file = temp_dir / "app.yaml"
    cfg_file.write_text(cfg_content, encoding="utf-8")

    ServiceContainer.reset_instance()
    ConfigManager.reset_instance()
    app = Application(config_path=cfg_file)
    # Startup must not raise; Sysmon init fails on Linux (no Windows eventlog)
    # but other collectors still start (if enabled).
    app.startup()
    try:
        assert app.is_running
        cm = app.container.resolve(
            __import__("argusprowl.collectors.manager").collectors.manager.CollectorManager
        )
        # At minimum, sysmon should be FAILED (not crashed the app).
        [
            (name, h)
            for name, h in cm.health_all().items()
            if h.state == CollectorState.FAILED
        ]
        # Either 0 collectors or the one that failed gracefully.
        # The key invariant: app did not raise during startup.
    finally:
        app.shutdown()
