"""Composition root and lifecycle coordinator for the argusprowl platform.

Only this module wires concrete infrastructure to interfaces.  Use cases and
future plugins resolve contracts from the container rather than importing an
adapter directly.
"""

import contextlib
import queue
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Thread
from typing import Any

from argusprowl.alerting.alert_manager import AlertManager
from argusprowl.alerting.alert_persistence import AlertPersistence
from argusprowl.attck.enrichment_service import AttckEnrichmentService
from argusprowl.behavior.analyst_annotation_persistence import AnalystAnnotationPersistence
from argusprowl.behavior.analyst_annotation_service import AnalystAnnotationService
from argusprowl.behavior.entity_behavior_persistence import EntityBehaviorPersistence
from argusprowl.behavior.entity_behavior_service import EntityBehaviorService
from argusprowl.collectors.manager import CollectorManager
from argusprowl.collectors.registry import CollectorRegistry
from argusprowl.config.config_manager import ConfigManager
from argusprowl.constants.attck import AttckKnowledgeStatus
from argusprowl.constants.log_names import LogName
from argusprowl.constants.paths import ProjectPath
from argusprowl.correlation.correlator import EndpointCorrelator
from argusprowl.correlation.entity_correlation_service import EntityCorrelationService
from argusprowl.decision_engine.decision_engine import DecisionEngine
from argusprowl.deduplication.engine import AlertDeduplicationEngine
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.detection.detectors.beaconing_detector import BeaconingDetector
from argusprowl.detection.detectors.correlation_detector import CorrelationDetector
from argusprowl.detection.rule_loader import RuleLoader
from argusprowl.exceptions.exceptions import LifecycleError
from argusprowl.feature_engineering.feature_extractor import FeatureExtractor
from argusprowl.incident.incident_service import IncidentService
from argusprowl.intelligence.service import ContextualIntelligenceService
from argusprowl.interfaces.storage import Storage
from argusprowl.lifecycle.queue import AlertQueue
from argusprowl.logging.logger_factory import LoggerFactory
from argusprowl.metrics.collector import MetricsCollector
from argusprowl.models.configuration import AppConfiguration
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.models.system_status import SystemStatus
from argusprowl.reliability.buffer import BoundedIngestionBuffer
from argusprowl.services.alert_search_service import AlertSearchService
from argusprowl.services.health_service import HealthService
from argusprowl.storage.sqlite_storage import SQLiteAdapter
from argusprowl.temporal.engine import TemporalEngine


class Application:
    """Owns runtime dependencies and makes startup/shutdown idempotent."""

    def __init__(
        self, config_path: str | Path | None = None, *, container: ServiceContainer | None = None
    ) -> None:
        self._config_path = config_path
        self._start_time: datetime | None = None
        self._running = False
        self._config: AppConfiguration | None = None
        # Use the singleton container so routes (ServiceContainer.get_instance()) see the same services
        self._container = container or ServiceContainer.get_instance()
        self._config_manager = ConfigManager()
        self._logger = LoggerFactory.get_logger(LogName.CORE)
        self._processing_thread: Thread | None = None
        self._shutdown_event = Event()
        self._event_queue: queue.Queue[NormalizedEvent] = queue.Queue()
        self._api_server: Any = None
        self._api_thread: Thread | None = None
        self._api_startup_event: Event | None = None
        self._api_startup_error: Exception | None = None

    def startup(self, *, start_api: bool = True) -> None:
        if self._running:
            return
        try:
            self._config = self._config_manager.load(self._config_path)
            LoggerFactory.setup_logging(self._config.logging)
            self._logger = LoggerFactory.get_logger(LogName.CORE)
            self._start_time = datetime.now(UTC)
            self._register_services()
            self._running = True
            self._logger.info("%s started", self._config.app_name)
            if self._config.api.enabled:
                self._logger.info(
                    "API server running at: http://%s:%d",
                    self._config.api.host,
                    self._config.api.port,
                )
                self._logger.info(
                    "Interactive Docs available at: http://%s:%d/docs",
                    self._config.api.host,
                    self._config.api.port,
                )
            self._start_processing_loop()
            self._start_collectors()
            if start_api:
                self._start_api_server()
            else:
                if self._config.api.enabled:
                    from argusprowl.api.app import create_api_app

                    self._api_server = create_api_app(
                        cors_origins=self._config.api.cors_origins
                        if self._config.api.cors_origins
                        else None,
                    )
        except Exception as exc:
            self._safe_clear()
            raise LifecycleError("Application startup failed", {"reason": str(exc)}) from exc

    def shutdown(self) -> None:
        if not self._running:
            return
        try:
            # Signal the processing loop to exit before tearing down dependencies.
            self._shutdown_event.set()
            # Gracefully stop all collectors.
            try:
                collector_manager = self._container.resolve(CollectorManager)
                collector_manager.stop_all()
            except Exception:
                pass  # Manager not registered yet or already down - proceed.
            # Persist behavior state before shutdown
            try:
                behavior_service = self._container.resolve(EntityBehaviorService)
                if hasattr(behavior_service, "persist_state"):
                    behavior_service.persist_state()
            except Exception:
                pass  # Persistence not available or already down - proceed.
            # Close alert persistence if enabled
            try:
                alert_persistence = self._container.resolve(AlertPersistence)
                alert_persistence.close()
            except Exception:
                pass  # Not registered or already closed
        finally:
            # Wait for the processing thread to drain and exit.
            if self._processing_thread is not None and self._processing_thread.is_alive():
                self._processing_thread.join(timeout=5.0)
            # Stop the API server if running
            self._stop_api_server()
            self._running = False
            self._safe_clear()
            self._logger.info("Application shutdown complete")

    def _start_api_server(self) -> None:
        """Start the HTTP API server if enabled in configuration."""
        api_cfg = self._config.api
        if not api_cfg.enabled:
            return

        try:
            from argusprowl.api.app import create_api_app

            self._api_server = create_api_app(
                cors_origins=api_cfg.cors_origins if api_cfg.cors_origins else None,
            )
            self._api_startup_event = Event()
            self._api_startup_error = None
            self._api_thread = Thread(
                target=self._run_api_server,
                args=(api_cfg.host, api_cfg.port),
                daemon=True,
            )
            self._api_thread.start()

            # Wait for the API thread to either bind successfully or fail
            # before reporting startup.  This guarantees a startup failure
            # (e.g. missing module, port in use) is surfaced rather than
            # reported as a successful startup.
            ready = self._api_startup_event.wait(timeout=5.0)

            if not ready:
                raise LifecycleError("API server startup timed out", {"timeout": 5.0})

            if self._api_startup_error is not None:
                err = self._api_startup_error
                self._logger.error("Failed to start API server: %s", err, exc_info=True)
                raise LifecycleError("API server startup failed", {"reason": str(err)}) from err

            self._logger.info("API server started on http://%s:%d", api_cfg.host, api_cfg.port)
        except LifecycleError:
            raise
        except Exception as exc:
            self._logger.error("Failed to start API server: %s", exc, exc_info=True)
            raise LifecycleError("API server startup failed", {"reason": str(exc)}) from exc

    def _run_api_server(self, host: str, port: int) -> None:
        """Run the API server (called in a daemon thread).

        Uses uvicorn.Config + uvicorn.Server so readiness can be signaled after
        the socket is bound (``server.started``), not after ``run()`` returns.
        ``run()`` blocks until shutdown, so we invoke the serve lifecycle
        manually: startup -> signal -> main_loop -> shutdown.
        """
        import asyncio

        import uvicorn

        try:
            config = uvicorn.Config(
                app=self._api_server,
                host=host,
                port=port,
                log_level="warning",
                access_log=False,
            )
            config.load()  # required before using Server methods
            server = uvicorn.Server(config)
            server.lifespan = config.lifespan_class(config)  # required for startup()

            async def _serve_and_signal() -> None:
                await server.startup()
                if self._api_startup_event is not None:
                    self._api_startup_event.set()
                if not server.should_exit:
                    await server.main_loop()
                if server.started:
                    await server.shutdown()

            asyncio.run(_serve_and_signal())
        except Exception as exc:
            self._api_startup_error = exc
            if self._api_startup_event is not None:
                self._api_startup_event.set()
            # Do not re-raise from daemon thread to avoid PytestUnhandledThreadExceptionWarning

    def run_foreground(self, host: str, port: int) -> None:
        """Run the API server in the foreground (blocking).

        Replaces the daemon-thread pattern with a direct asyncio.run() call so
        the calling process stays alive until shutdown is requested.
        """
        import asyncio

        import uvicorn

        if self._api_server is None:
            from argusprowl.api.app import create_api_app

            self._api_server = create_api_app(
                cors_origins=self._config.api.cors_origins
                if self._config.api.cors_origins
                else None,
            )

        config = uvicorn.Config(
            app=self._api_server,
            host=host,
            port=port,
            log_level="warning",
            access_log=False,
        )
        config.load()
        server = uvicorn.Server(config)
        server.lifespan = config.lifespan_class(config)

        async def _serve() -> None:
            await server.startup()
            try:
                await server.main_loop()
            finally:
                if server.started:
                    await server.shutdown()

        with contextlib.suppress(KeyboardInterrupt):
            asyncio.run(_serve())

    def _stop_api_server(self) -> None:
        """Stop the API server if running."""
        if self._api_thread is not None and self._api_thread.is_alive():
            # Signal uvicorn to exit its main loop, then let the daemon thread drain
            if self._api_server is not None:
                self._api_server.should_exit = True
            self._api_thread.join(timeout=3.0)
            self._api_thread = None
            self._api_server = None
            self._logger.info("API server stopped")

    def _safe_clear(self) -> None:
        self._container.clear()

    def _register_services(self) -> None:
        assert self._config is not None
        self._container.register_singleton(ConfigManager, self._config_manager)
        metrics = MetricsCollector()
        self._container.register_singleton(MetricsCollector, metrics)
        reliability = self._config.reliability
        self._container.register_singleton(
            BoundedIngestionBuffer,
            BoundedIngestionBuffer(
                reliability.buffer.max_size, reliability.buffer.overflow_policy, metrics
            ),
        )
        self._container.register_singleton(
            AlertDeduplicationEngine,
            AlertDeduplicationEngine(
                cooldown=reliability.deduplication.default_cooldown,
                max_fingerprints=reliability.deduplication.max_fingerprints,
                metrics_collector=metrics,
            ),
        )
        # Existing detection wiring remains intact; normalized events are a
        # future boundary and deliberately do not alter Phase 1 detectors.
        self._container.register_singleton(
            DetectionManager, lambda: RuleLoader().build_detection_manager()
        )
        self._container.register_singleton(
            Storage, lambda: SQLiteAdapter(self._config.storage.database_path)
        )
        self._container.register_singleton(
            HealthService,
            lambda: HealthService(
                self._start_time,
                self._config_manager,
                self._container.resolve(Storage),
                event_queue=self._event_queue,
            ),
        )
        # Phase 2.1: Collector framework - registered after health so the
        # HealthService can optionally query it via the container.
        registry = CollectorRegistry()
        self._container.register_singleton(
            CollectorManager,
            lambda: CollectorManager(
                registry=registry,
                event_queue=self._event_queue,
                metrics_collector=metrics,
            ),
        )

        self._container.register_singleton(
            FeatureExtractor,
            lambda: FeatureExtractor(),
        )
        # Phase 4.3: Temporal engine for beaconing detection
        temporal_cfg = self._config.temporal
        self._container.register_singleton(
            TemporalEngine,
            lambda: TemporalEngine(
                max_keys=temporal_cfg.max_keys,
                max_observations_per_key=temporal_cfg.max_observations_per_key,
                window_duration=__import__("datetime").timedelta(
                    seconds=temporal_cfg.window_duration_seconds
                ),
            ),
        )
        self._container.register_singleton(
            DecisionEngine,
            lambda: DecisionEngine(),
        )
        # Phase 4.7.6: Register AlertQueue as singleton
        self._container.register_singleton(
            AlertQueue,
            lambda: AlertQueue(
                max_size=self._config.reliability.alert_queue.max_size,
                entity_correlation_service=self._container.resolve(EntityCorrelationService),
            ),
        )
        # Register AlertManager with queue dependency
        alert_persistence: AlertPersistence | None = None
        alert_persistence_cfg = self._config.alert_persistence
        if alert_persistence_cfg.enabled:
            alert_persistence = AlertPersistence(
                db_path=alert_persistence_cfg.db_path,
                max_alerts=alert_persistence_cfg.max_alerts,
            )
            alert_persistence.initialize()
            self._logger.info("Alert persistence enabled at %s", alert_persistence_cfg.db_path)
            self._container.register_singleton(AlertPersistence, alert_persistence)

        self._container.register_singleton(
            AlertManager,
            lambda: AlertManager(
                deduplication_engine=self._container.resolve(AlertDeduplicationEngine),
                alert_queue=self._container.resolve(AlertQueue),
                alert_persistence=alert_persistence,
                alert_search_service=self._container.resolve(AlertSearchService)
                if alert_persistence is not None
                else None,
                attck_enrichment_service=self._container.resolve(AttckEnrichmentService)
                if self._config.attck.enabled
                else None,
            ),
        )
        # Phase 5.5: Register AlertSearchService
        self._container.register_singleton(
            AlertSearchService,
            lambda: AlertSearchService(
                alert_queue=self._container.resolve(AlertQueue),
                alert_persistence=alert_persistence,
                entity_correlation_service=self._container.resolve(EntityCorrelationService),
            ),
        )
        # Phase 4.6D: Register ContextualIntelligenceService
        self._container.register_singleton(
            ContextualIntelligenceService,
            lambda: ContextualIntelligenceService(),
        )

        # Phase 4.8.2: Register incident correlation services
        self._container.register_singleton(
            EntityCorrelationService,
            lambda: EntityCorrelationService(),
        )
        self._container.register_singleton(
            IncidentService,
            lambda: IncidentService(),
        )
        # Phase 5.1.2: Register EntityBehaviorService for behavioral summaries
        baseline_cfg = self._config.baseline
        persistence_cfg = self._config.behavior_persistence

        # Register persistence layer if enabled
        persistence: EntityBehaviorPersistence | None = None
        if persistence_cfg.enabled:
            persistence = EntityBehaviorPersistence(
                db_path=persistence_cfg.db_path,
                max_profiles=persistence_cfg.max_profiles,
            )
            persistence.initialize()
            self._logger.info("Entity behavior persistence enabled at %s", persistence_cfg.db_path)

        # Create behavior service with persistence support
        behavior_service = EntityBehaviorService(
            max_profiles=100000,
            max_values_per_profile=1000,
            max_value_length=256,
            stale_timeout=__import__("datetime").timedelta(hours=24),
            maturity_min_observations=baseline_cfg.maturity_min_observations,
            maturity_window_seconds=baseline_cfg.maturity_window_seconds,
            baseline_rare_threshold=baseline_cfg.rare_threshold,
            future_skew_threshold_seconds=baseline_cfg.future_skew_threshold_seconds,
            baseline_stale_after_seconds=baseline_cfg.stale_after_seconds,
            metrics_collector=metrics,
            persistence=persistence,
        )

        self._container.register_singleton(
            EntityBehaviorService,
            lambda: behavior_service,
        )
        # Update DecisionEngine to use incident services and entity behavior
        self._container.register_singleton(
            DecisionEngine,
            lambda: DecisionEngine(
                incident_service=self._container.resolve(IncidentService),
                entity_correlation_service=self._container.resolve(EntityCorrelationService),
                entity_behavior_service=self._container.resolve(EntityBehaviorService),
            ),
        )
        # Phase 5.2: Register AnalystAnnotationService
        annotation_cfg = self._config.analyst_annotations
        annotation_persistence: AnalystAnnotationPersistence | None = None
        if annotation_cfg.enabled:
            annotation_persistence = AnalystAnnotationPersistence(
                db_path=annotation_cfg.db_path,
                max_total_annotations=annotation_cfg.max_total_annotations,
            )
            self._logger.info(
                "Analyst annotation persistence enabled at %s", annotation_cfg.db_path
            )

        self._container.register_singleton(
            AnalystAnnotationService,
            lambda: AnalystAnnotationService(
                persistence=annotation_persistence,
                max_annotations_per_target=annotation_cfg.max_annotations_per_target,
                max_total_annotations=annotation_cfg.max_total_annotations,
            ),
        )

        # Phase 7.4: Register InvestigationTimelineService
        from argusprowl.services.investigation_timeline_service import InvestigationTimelineService

        self._container.register_singleton(
            InvestigationTimelineService,
            lambda: InvestigationTimelineService(
                alert_search_service=self._container.resolve(AlertSearchService),
                incident_service=self._container.resolve(IncidentService),
                annotation_service=self._container.resolve(AnalystAnnotationService),
                behavior_query_service=analyst_behavior_service,
                entity_correlation_service=self._container.resolve(EntityCorrelationService),
            ),
        )
        # Phase 7.6: Register IocInvestigationService
        from argusprowl.services.ioc_investigation_service import IocInvestigationService

        self._container.register_singleton(
            IocInvestigationService,
            lambda: IocInvestigationService(
                alert_search_service=self._container.resolve(AlertSearchService),
                intelligence_service=self._container.resolve(ContextualIntelligenceService),
            ),
        )

        # Phase 7.8: Register TelemetryEvidenceService (independent, side-channel)
        evidence_cfg = self._config.telemetry_evidence
        if evidence_cfg.enabled:
            from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService

            self._container.register_singleton(
                TelemetryEvidenceService,
                lambda: TelemetryEvidenceService(
                    max_retained_events=evidence_cfg.max_retained_events,
                ),
            )

        # Phase 6.1/6.2: ATT&CK remains optional semantic enrichment only.
        # The registry has one authoritative source and is isolated from
        # detection, decision, alert, incident, and lifecycle semantics.
        attck_cfg = self._config.attck
        if attck_cfg.enabled:
            from argusprowl.attck.knowledge_service import AttckKnowledgeService
            from argusprowl.attck.mapping_registry import AttckMappingRegistry

            # Resolve relative paths against the project root, not the caller's CWD.
            snapshot_path = Path(attck_cfg.snapshot_path)
            if not snapshot_path.is_absolute():
                snapshot_path = ProjectPath.ROOT / snapshot_path

            previous_snapshot_path = (
                Path(attck_cfg.previous_snapshot_path)
                if attck_cfg.previous_snapshot_path
                else None
            )
            if previous_snapshot_path is not None and not previous_snapshot_path.is_absolute():
                previous_snapshot_path = ProjectPath.ROOT / previous_snapshot_path

            knowledge_service = AttckKnowledgeService(
                snapshot_path=snapshot_path,
                previous_snapshot_path=previous_snapshot_path,
                enabled=attck_cfg.enabled,
            )

            # ATT&CK data is an operator-installed local prerequisite, not a
            # bundled application asset. Core detection remains independent
            # when ATT&CK is disabled.
            if knowledge_service.get_status() == AttckKnowledgeStatus.EMPTY:
                raise RuntimeError(
                    "ATT&CK enrichment is enabled, but no local snapshot is installed. "
                    "Run `.venv/bin/python scripts/download_attck_snapshot.py` "
                    "from the project root, or set attck.snapshot_path to an "
                    "already imported snapshot."
                )

            self._container.register_singleton(AttckKnowledgeService, knowledge_service)
            self._container.register_singleton(
                AttckMappingRegistry,
                lambda: AttckMappingRegistry(knowledge_service=knowledge_service),
            )
            # Resolve immediately so an enabled deployment fails closed when
            # the authoritative mapping source or ATT&CK knowledge is invalid.
            mapping_registry = self._container.resolve(AttckMappingRegistry)

            self._container.register_singleton(
                AttckEnrichmentService,
                lambda: AttckEnrichmentService(
                    knowledge_service=knowledge_service,
                    mapping_registry=mapping_registry,
                    detection_manager=self._container.resolve(DetectionManager),
                ),
            )
            self._logger.info("ATT&CK knowledge service and mapping registry enabled")

        # Phase 5.3: Register InvestigationContextService
        from argusprowl.behavior.analyst_behavior_query_service import AnalystBehaviorQueryService
        from argusprowl.services.investigation_context_service import InvestigationContextService

        # Create analyst behavior query service wrapping EntityBehaviorService
        analyst_behavior_service = AnalystBehaviorQueryService(
            behavior_service=behavior_service,
        )
        self._container.register_singleton(
            AnalystBehaviorQueryService,
            lambda: analyst_behavior_service,
        )

        self._container.register_singleton(
            InvestigationContextService,
            lambda: InvestigationContextService(
                alert_queue=self._container.resolve(AlertQueue),
                behavior_query_service=analyst_behavior_service,
                annotation_service=self._container.resolve(AnalystAnnotationService),
                incident_service=self._container.resolve(IncidentService),
                alert_persistence=alert_persistence,
            ),
        )

        # Phase 4.3: Register beaconing detector if temporal is enabled
        if temporal_cfg.enabled:
            self._container.register_singleton(
                BeaconingDetector,
                lambda: BeaconingDetector(
                    temporal_engine=self._container.resolve(TemporalEngine),
                    min_observations=temporal_cfg.min_observations,
                    min_duration_seconds=temporal_cfg.min_duration_seconds,
                    periodicity_threshold=temporal_cfg.periodicity_threshold,
                ),
            )
        # Phase 4.4: Register endpoint correlator and correlation detector
        endpoint_corr_cfg = self._config.endpoint_correlation
        if endpoint_corr_cfg.enabled:
            self._container.register_singleton(
                EndpointCorrelator,
                lambda: EndpointCorrelator(
                    correlation_window_seconds=endpoint_corr_cfg.correlation_window_seconds,
                    max_processes=endpoint_corr_cfg.max_processes,
                    max_observations=endpoint_corr_cfg.max_observations,
                ),
            )
            self._container.register_singleton(
                CorrelationDetector,
                lambda: CorrelationDetector(
                    correlator=self._container.resolve(EndpointCorrelator),
                ),
            )

    def health_check(self) -> SystemStatus:
        if not self._running:
            raise LifecycleError("Application is not running")
        return self._container.resolve(HealthService).check_health()

    @property
    def container(self) -> ServiceContainer:
        return self._container

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def config(self) -> AppConfiguration:
        if self._config is None:
            raise LifecycleError("Application has not been started")
        return self._config

    @property
    def uptime_seconds(self) -> float:
        return (datetime.now(UTC) - self._start_time).total_seconds() if self._start_time else 0.0

    def _start_collectors(self) -> None:
        """Start all registered collectors and begin event ingestion."""
        collector_manager = self._container.resolve(CollectorManager)
        results = collector_manager.start_all()
        for collector_name, exc in results.items():
            if exc is not None:
                self._logger.error("Collector %s failed to start: %s", collector_name, exc)

    def _collector_callback(self, event: NormalizedEvent) -> None:
        """Callback for collectors to enqueue events for processing."""
        if not self._shutdown_event.is_set():
            self._event_queue.put(event)

    def _process_event(self, event: NormalizedEvent) -> None:
        """Process a single event through the detection pipeline."""
        try:
            self._logger.debug(
                "Processing event: %s, process_name=%s, pid=%s, dst_ip=%s",
                event.event_type,
                event.process_name,
                event.pid,
                event.dst_ip,
            )
            feature_extractor = self._container.resolve(FeatureExtractor)
            self._container.resolve(EntityBehaviorService)
            temporal_engine = self._container.resolve(TemporalEngine)
            endpoint_correlator = self._container.resolve(EndpointCorrelator)
            detection_manager = self._container.resolve(DetectionManager)
            decision_engine = self._container.resolve(DecisionEngine)
            alert_manager = self._container.resolve(AlertManager)
            intelligence_service = self._container.resolve(ContextualIntelligenceService)

            # Feed event to temporal engine for periodicity tracking
            temporal_engine.observe(event)

            # Feed event to endpoint correlator for process-network association
            endpoint_correlator.observe(event)

            # Record event for prevalence tracking
            intelligence_service.record_event(event)

            # Feature extraction
            feature_vector = feature_extractor.extract(event)

            # Detection via FeatureVector-based detectors
            detection_results: list[DetectionResult] = []
            if feature_vector is not None:
                detection_results = detection_manager.process_feature_vector(feature_vector)

            # Detection via NormalizedEvent-based detectors loaded by RuleLoader
            detection_results.extend(detection_manager.process_event(event))

            # Detection via NormalizedEvent-based detectors (temporal/correlation)
            # These operate on the raw event, not aggregated features
            try:
                beaconing_detector = self._container.resolve(BeaconingDetector)
                if beaconing_detector.is_enabled():
                    result = beaconing_detector.detect(event)
                    if result.matched:
                        detection_results.append(result)
            except Exception:
                pass  # BeaconingDetector not registered (temporal disabled)

            try:
                correlation_detector = self._container.resolve(CorrelationDetector)
                if correlation_detector.is_enabled():
                    result = correlation_detector.detect(event)
                    self._logger.debug(
                        "CorrelationDetector result: %s, matched: %s",
                        result.rule_id,
                        result.matched,
                    )
                    if result.matched:
                        detection_results.append(result)
            except Exception as exc:
                self._logger.error("Error in correlation detector: %s", exc, exc_info=True)

            # Decision and alerting
            for result in detection_results:
                # Enrich with contextual intelligence
                assessment = intelligence_service.evaluate(result, event)

                # Process detection result with contextual assessment, event=event
                alert = decision_engine.process_detection_result(result, assessment=assessment)
                if alert is not None:
                    alert_manager.send_alert(alert)

            # Phase 7.8: Insert event into evidence store (side-channel, never blocks)
            try:
                from argusprowl.services.telemetry_evidence_service import (
                    PROVENANCE_CONTRIBUTING_EVENT,
                    PROVENANCE_DETECTION_SOURCE,
                    PROVENANCE_OBSERVED_CONTEXT,
                    TelemetryEvidenceService,
                )

                if self._container.is_registered(TelemetryEvidenceService):
                    evidence_service = self._container.resolve(TelemetryEvidenceService)
                    evidence_service.record_event(event, provenance=PROVENANCE_OBSERVED_CONTEXT)
                    for result in detection_results:
                        if result.matched:
                            with contextlib.suppress(ValueError):
                                evidence_service.record_provenance(
                                    event_id=result.event_id,
                                    provenance=PROVENANCE_DETECTION_SOURCE,
                                    detection_result_id=result.result_id,
                                    contributing_event_ids=result.contributing_event_ids,
                                )

                            for contrib_id in result.contributing_event_ids:
                                with contextlib.suppress(ValueError):
                                    evidence_service.record_provenance(
                                        event_id=contrib_id,
                                        provenance=PROVENANCE_CONTRIBUTING_EVENT,
                                        detection_result_id=result.result_id,
                                    )
            except Exception:
                # Evidence store must never affect detection pipeline
                pass

        except Exception as exc:
            self._logger.error("Error processing event: %s", exc, exc_info=True)

    def _processing_loop(self) -> None:
        """Continuous processing loop for the detection pipeline."""
        self._logger.info("Starting continuous processing loop")
        while not self._shutdown_event.is_set():
            try:
                event = self._event_queue.get(timeout=0.1)
                self._process_event(event)
            except queue.Empty:
                continue
            except Exception as exc:
                self._logger.error("Error in processing loop: %s", exc, exc_info=True)

    def _start_processing_loop(self) -> None:
        """Start the continuous processing loop in a background thread."""
        self._processing_thread = Thread(target=self._processing_loop, daemon=True)
        self._processing_thread.start()
