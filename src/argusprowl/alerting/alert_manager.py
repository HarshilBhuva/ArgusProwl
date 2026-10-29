"""Alert manager implementation.

Orchestrates alert dispatch to registered alert providers.
"""

import time
from typing import TYPE_CHECKING, Any
from uuid import UUID

from argusprowl.constants.log_names import LogName
from argusprowl.deduplication.engine import AlertDeduplicationEngine
from argusprowl.interfaces.alert_provider import AlertProvider
from argusprowl.lifecycle.queue import AlertQueue, AlertQueueError, AlertQueueFullError
from argusprowl.logging.logger_factory import LoggerFactory
from argusprowl.models.alert import Alert

if TYPE_CHECKING:
    from argusprowl.alerting.alert_persistence import AlertPersistence
    from argusprowl.attck.enrichment_service import AttckEnrichmentService
    from argusprowl.attck.mapping_registry import MappingType
    from argusprowl.constants.lifecycle import AlertLifecycleState
    from argusprowl.constants.priority import AlertPriority
    from argusprowl.constants.severity import Severity
    from argusprowl.services.alert_search_service import (
        AlertSearchResult,
        AlertSearchService,
    )


class AlertManager:
    """Manages alert dispatch to registered alert providers."""

    def __init__(
        self,
        deduplication_engine: AlertDeduplicationEngine | None = None,
        alert_queue: AlertQueue | None = None,
        alert_persistence: "AlertPersistence | None" = None,
        alert_search_service: "AlertSearchService | None" = None,
        attck_enrichment_service: "AttckEnrichmentService | None" = None,
    ) -> None:
        self._providers: dict[str, AlertProvider] = {}
        self._total_alerts_dispatched = 0
        self._total_delivery_failures = 0
        self._deduplication_engine = deduplication_engine
        self._alert_queue = alert_queue
        self._alert_persistence = alert_persistence
        self._alert_search_service = alert_search_service
        self._attck_enrichment_service = attck_enrichment_service
        self._queue_dropped = 0
        self._total_persistence_successes = 0
        self._total_persistence_failures = 0
        self._last_queue_full_log_time = 0.0
        self._logger = LoggerFactory.get_logger(LogName.ALERT)

    def register_provider(self, provider: AlertProvider) -> None:
        if not isinstance(provider, AlertProvider):
            raise TypeError(f"Object must implement AlertProvider interface: {type(provider)}")
        name = provider.provider_name
        if name in self._providers:
            raise ValueError(f"Alert provider '{name}' is already registered.")
        self._providers[name] = provider

    def unregister_provider(self, name: str) -> None:
        if name not in self._providers:
            raise KeyError(f"Alert provider '{name}' not found.")
        del self._providers[name]

    def send_alert(self, alert: Alert) -> dict[str, bool]:
        if self._deduplication_engine is not None:
            decision = self._deduplication_engine.process(alert)
            if not decision.emit:
                return {}
            assert decision.alert is not None
            alert = decision.alert
        if self._attck_enrichment_service is not None:
            alert = self._attck_enrichment_service.enrich(alert)
        if self._alert_queue is not None:
            try:
                self._alert_queue.enqueue(alert)
            except AlertQueueFullError:
                self._queue_dropped += 1
                now = time.time()
                if now - self._last_queue_full_log_time > 60:
                    self._logger.warning(
                        "Alert queue is full (%d dropped); provider delivery continuing.",
                        self._queue_dropped,
                    )
                    self._last_queue_full_log_time = now
        if self._alert_persistence is not None:
            try:
                persisted = self._alert_persistence.save_alert(alert)
                if persisted:
                    self._total_persistence_successes += 1
                else:
                    self._total_persistence_failures += 1
                    self._logger.error(
                        "Alert persistence did not commit alert_id=%s status=%s reason=%s",
                        alert.alert_id,
                        self._alert_persistence.get_status(),
                        self._alert_persistence.get_status_reason(),
                    )
            except Exception:
                self._total_persistence_failures += 1
                self._logger.exception("Unexpected alert persistence error alert_id=%s", alert.alert_id)
        results: dict[str, bool] = {}
        for provider_name, provider in self._providers.items():
            try:
                if not provider.is_available():
                    results[provider_name] = False
                    self._total_delivery_failures += 1
                    continue
                success = provider.send(alert)
                results[provider_name] = success
                if success:
                    self._total_alerts_dispatched += 1
                else:
                    self._total_delivery_failures += 1
            except Exception as exc:
                print(f"Error sending alert via provider '{provider_name}': {exc}")
                results[provider_name] = False
                self._total_delivery_failures += 1
        return results

    def send_alert_async(self, alert: Alert) -> None:
        self.send_alert(alert)

    def get_provider(self, name: str) -> AlertProvider:
        if name not in self._providers:
            raise KeyError(f"Alert provider '{name}' not found.")
        return self._providers[name]

    def get_all_providers(self) -> dict[str, AlertProvider]:
        return self._providers.copy()

    def get_available_providers(self) -> dict[str, AlertProvider]:
        return {
            name: provider for name, provider in self._providers.items() if provider.is_available()
        }

    @property
    def provider_count(self) -> int:
        return len(self._providers)

    @property
    def total_alerts_dispatched(self) -> int:
        return self._total_alerts_dispatched

    @property
    def total_delivery_failures(self) -> int:
        return self._total_delivery_failures

    def get_statistics(self) -> dict[str, Any]:
        total_attempts = self._total_alerts_dispatched + self._total_delivery_failures
        success_rate = self._total_alerts_dispatched / total_attempts if total_attempts > 0 else 0.0
        stats: dict[str, Any] = {
            "registered_providers": self.provider_count,
            "total_alerts_dispatched": self._total_alerts_dispatched,
            "total_delivery_failures": self._total_delivery_failures,
            "success_rate": success_rate,
            "queue_dropped": self._queue_dropped,
            "alert_persistence_writes_succeeded": self._total_persistence_successes,
            "alert_persistence_writes_failed": self._total_persistence_failures,
        }
        if self._alert_queue is not None:
            stats.update(
                {
                    "queue_size": len(self._alert_queue),
                    "queue_capacity": self._alert_queue.max_size,
                    "queue_available": self._alert_queue.max_size - len(self._alert_queue),
                    "queue_open": len(self._alert_queue.list(lifecycle_state=None, sort=False)),
                    "queue_acknowledged": len(
                        self._alert_queue.list(lifecycle_state=None, sort=False)
                    ),
                    "queue_closed": len(self._alert_queue.list(lifecycle_state=None, sort=False)),
                }
            )
            all_alerts = self._alert_queue.list(sort=False)
            from argusprowl.constants.lifecycle import AlertLifecycleState

            stats["queue_open"] = sum(
                1 for a in all_alerts if a.lifecycle_state == AlertLifecycleState.OPEN
            )
            stats["queue_acknowledged"] = sum(
                1 for a in all_alerts if a.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED
            )
            stats["queue_closed"] = sum(
                1 for a in all_alerts if a.lifecycle_state == AlertLifecycleState.CLOSED
            )
        return stats

    def list_alerts(
        self,
        *,
        min_priority: "AlertPriority | None" = None,
        min_severity: "Severity | None" = None,
        rule_id: str | None = None,
        host: str | None = None,
        lifecycle_state: "AlertLifecycleState | None" = None,
        entity_key: str | None = None,
        incident_id: str | None = None,
        sort: bool = True,
    ) -> list[Alert]:
        if self._alert_queue is None:
            return []
        return self._alert_queue.list(
            min_priority=min_priority,
            min_severity=min_severity,
            rule_id=rule_id,
            host=host,
            lifecycle_state=lifecycle_state,
            entity_key=entity_key,
            incident_id=incident_id,
            sort=sort,
        )

    def search_alerts(
        self,
        *,
        limit: int = 100,
        min_priority: "AlertPriority | None" = None,
        min_severity: "Severity | None" = None,
        rule_id: str | None = None,
        host: str | None = None,
        lifecycle_state: "AlertLifecycleState | None" = None,
        entity_key: str | None = None,
        incident_id: str | None = None,
        technique_id: str | tuple[str, ...] | None = None,
        subtechnique_id: str | tuple[str, ...] | None = None,
        mapping_type: "MappingType | str | tuple[MappingType | str, ...] | None" = None,
        tactic: str | tuple[str, ...] | None = None,
    ) -> "AlertSearchResult":
        """Unified analyst search with optional exact ATT&CK observation filters.

        Ordinary filters and ATT&CK dimensions use AND semantics. Multiple
        values within one ATT&CK dimension use OR semantics. ATT&CK filters
        operate only on metadata observations already attached to the alert.
        """
        if self._alert_search_service is not None:
            return self._alert_search_service.search(
                limit=limit,
                min_priority=min_priority,
                min_severity=min_severity,
                rule_id=rule_id,
                host=host,
                lifecycle_state=lifecycle_state,
                entity_key=entity_key,
                incident_id=incident_id,
                technique_id=technique_id,
                subtechnique_id=subtechnique_id,
                mapping_type=mapping_type,
                tactic=tactic,
            )

        # Existing queue-only fallback remains compatible; ATT&CK filtering is
        # still applied locally without enriching or mutating the alert.
        from argusprowl.services.alert_search_service import (
            AlertSearchResult,
            AlertSearchService,
            AlertSearchStatus,
        )

        alerts = self.list_alerts(
            min_priority=min_priority,
            min_severity=min_severity,
            rule_id=rule_id,
            host=host,
            lifecycle_state=lifecycle_state,
            entity_key=entity_key,
            incident_id=incident_id,
            sort=False,
        )
        filtered = AlertSearchService._filter_attck(
            alerts,
            technique_ids=AlertSearchService._normalize_ids(technique_id, "technique_id"),
            subtechnique_ids=AlertSearchService._normalize_ids(subtechnique_id, "subtechnique_id"),
            mapping_types=AlertSearchService._normalize_mapping_types(mapping_type),
            tactics=AlertSearchService._normalize_strings(tactic, "tactic"),
        )
        from argusprowl.lifecycle.sorting import sort_alerts

        return AlertSearchResult(
            alerts=tuple(sort_alerts(filtered)[:limit]),
            status=AlertSearchStatus.AVAILABLE,
        )

    def acknowledge_alert(self, alert_id: UUID) -> Alert:
        if self._alert_queue is None:
            raise AlertQueueError("Alert queue is not available")
        return self._alert_queue.acknowledge(alert_id)

    def close_alert(self, alert_id: UUID) -> Alert:
        if self._alert_queue is None:
            raise AlertQueueError("Alert queue is not available")
        return self._alert_queue.close(alert_id)

    def __repr__(self) -> str:
        return f"AlertManager(providers={self.provider_count}, dispatched={self._total_alerts_dispatched}, failures={self._total_delivery_failures})"
