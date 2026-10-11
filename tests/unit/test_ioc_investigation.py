"""IOC investigation service (Phase 7.6).

Covers:
- GET /api/v1/iocs/{indicator} endpoint
- IOC investigation against threat intelligence and alert evidence
- Related IOC classification
- Prevalence lookup
- Investigation timeline
- Error handling and validation
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.behavior.analyst_annotation_service import AnalystAnnotationService
from argusprowl.behavior.analyst_behavior_query_service import AnalystBehaviorQueryService
from argusprowl.correlation.entity_correlation_service import EntityCorrelationService
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.incident.incident_service import IncidentService
from argusprowl.intelligence.service import ContextualIntelligenceService
from argusprowl.lifecycle.queue import AlertQueue
from argusprowl.models.alert import Alert
from argusprowl.models.context import (
    PrevalenceResult,
    ThreatIntelReputation,
    ThreatIntelVerdict,
)
from argusprowl.services.alert_search_service import (
    AlertSearchResult,
    AlertSearchService,
    AlertSearchStatus,
)
from argusprowl.services.ioc_investigation_service import IocInvestigationService


def _make_alert(
    *,
    entity_context: dict[str, Any] | None = None,
    alert_id: UUID | None = None,
    title: str = "Test Alert",
    severity: str = "HIGH",
    priority: str = "HIGH",
    lifecycle_state: str = "OPEN",
    source: str = "test-detector",
    metadata: dict[str, Any] | None = None,
) -> Alert:
    """Create a minimal Alert for testing."""
    return Alert(
        alert_id=alert_id or uuid4(),
        title=title,
        description="Test description",
        severity=severity,
        priority=priority,
        lifecycle_state=lifecycle_state,
        source=source,
        entity_context=entity_context,
        metadata=metadata or {},
    )


@pytest.fixture
def alert_queue() -> MagicMock:
    """Create a mock AlertQueue."""
    return MagicMock()


@pytest.fixture
def entity_correlation_service() -> EntityCorrelationService:
    """Create an EntityCorrelationService."""
    return EntityCorrelationService()


@pytest.fixture
def alert_search_service() -> MagicMock:
    """Create a mock AlertSearchService."""
    return MagicMock(spec=AlertSearchService)


@pytest.fixture
def behavior_query_service() -> MagicMock:
    """Create a mock AnalystBehaviorQueryService."""
    return MagicMock()


@pytest.fixture
def annotation_service() -> AnalystAnnotationService:
    """Create an AnalystAnnotationService."""
    return AnalystAnnotationService()


@pytest.fixture
def incident_service() -> IncidentService:
    """Create an IncidentService."""
    return IncidentService()


@pytest.fixture
def prevalence_tracker() -> MagicMock:
    """Create a mock prevalence tracker."""
    return MagicMock()


@pytest.fixture
def threat_intel_provider() -> MagicMock:
    """Create a mock threat intelligence provider."""
    return MagicMock()


@pytest.fixture
def intelligence_service(
    prevalence_tracker: MagicMock,
    threat_intel_provider: MagicMock,
) -> ContextualIntelligenceService:
    """Create a ContextualIntelligenceService with mocked dependencies."""
    service = ContextualIntelligenceService(
        prevalence_tracker=prevalence_tracker,
        threat_intel_provider=threat_intel_provider,
    )
    return service


@pytest.fixture
def ioc_investigation_service(
    alert_search_service: MagicMock,
    intelligence_service: ContextualIntelligenceService,
) -> IocInvestigationService:
    """Create an IocInvestigationService."""
    return IocInvestigationService(
        alert_search_service=alert_search_service,
        intelligence_service=intelligence_service,
    )


@pytest.fixture
def api_client(
    alert_search_service: MagicMock,
    alert_queue: MagicMock,
    behavior_query_service: MagicMock,
    annotation_service: AnalystAnnotationService,
    incident_service: IncidentService,
    entity_correlation_service: EntityCorrelationService,
    prevalence_tracker: MagicMock,
    threat_intel_provider: MagicMock,
) -> TestClient:
    """Create a TestClient with all required services registered."""
    container = ServiceContainer.get_instance()
    container.register_singleton(AlertSearchService, alert_search_service)
    container.register_singleton(AlertQueue, alert_queue)
    container.register_singleton(
        ContextualIntelligenceService,
        intelligence_service := ContextualIntelligenceService(
            prevalence_tracker=prevalence_tracker,
            threat_intel_provider=threat_intel_provider,
        ),
    )
    container.register_singleton(AnalystBehaviorQueryService, behavior_query_service)
    container.register_singleton(AnalystAnnotationService, annotation_service)
    container.register_singleton(IncidentService, incident_service)
    container.register_singleton(EntityCorrelationService, entity_correlation_service)
    container.register_singleton(
        IocInvestigationService,
        IocInvestigationService(
            alert_search_service=alert_search_service,
            intelligence_service=intelligence_service,
        ),
    )

    app = create_api_app()
    with TestClient(app) as client:
        yield client


# ---------------------------------------------------------------------------
# IOC Investigation Tests
# ---------------------------------------------------------------------------


class TestIocInvestigationEndpoint:
    """Tests for GET /api/v1/iocs/{indicator}."""

    def test_investigate_ip_returns_result(
        self,
        api_client: TestClient,
        alert_search_service: MagicMock,
        threat_intel_provider: MagicMock,
        prevalence_tracker: MagicMock,
    ) -> None:
        """Test that investigating an IP returns a valid result."""
        # Mock threat intelligence response
        threat_intel_provider.lookup_ip.return_value = ThreatIntelReputation(
            indicator="8.8.8.8",
            verdict=ThreatIntelVerdict.BENIGN,
            confidence=0.95,
            categories=(),
            source="in_memory_provider",
        )

        # Mock prevalence tracker response
        prevalence_tracker.get_prevalence.return_value = PrevalenceResult(
            dest_host_count=5,
            process_dest_count=3,
            is_rare_destination=False,
            is_environment_wide=True,
        )

        # Mock alert search response
        datetime.now(UTC)
        alert_search_service.search.return_value = AlertSearchResult(
            alerts=[
                _make_alert(
                    title="DNS query to google",
                    severity="LOW",
                    priority="LOW",
                    source="dns-proxy",
                    entity_context={"dst_ip": "8.8.8.8", "host": "workstation1"},
                    metadata={"rule_id": "dns-rule-001"},
                ),
                _make_alert(
                    title="HTTP connection",
                    severity="MEDIUM",
                    priority="MEDIUM",
                    source="proxy",
                    entity_context={
                        "dst_ip": "8.8.8.8",
                        "src_ip": "192.168.1.100",
                        "host": "workstation2",
                    },
                    metadata={"rule_id": "http-rule-002"},
                ),
            ],
            status=AlertSearchStatus.AVAILABLE,
            reason=None,
        )

        response = api_client.get("/api/v1/iocs/8.8.8.8")
        assert response.status_code == 200

        data = response.json()
        assert data["indicator"] == "8.8.8.8"
        assert data["ioc_type"] == "ip"
        assert data["reputation"]["verdict"] == "BENIGN"
        assert data["reputation"]["confidence"] == 0.95
        assert len(data["observations"]) == 2
        assert set(data["associated_alert_ids"]) == {
            str(data["observations"][0]["alert_id"]),
            str(data["observations"][1]["alert_id"]),
        }
        assert data["associated_hosts"] == ["workstation1", "workstation2"]
        assert data["associated_rule_ids"] == ["dns-rule-001", "http-rule-002"]
        assert len(data["related_iocs"]) == 1  # src_ip from second alert
        assert data["related_iocs"][0]["indicator"] == "192.168.1.100"
        assert data["related_iocs"][0]["ioc_type"] == "ip"
        assert data["related_iocs"][0]["field"] == "src_ip"
        assert data["prevalence"] is not None
        assert data["prevalence"]["dest_host_count"] == 5
        assert data["prevalence"]["is_environment_wide"] is True
        assert data["status"] == "AVAILABLE"
        assert data["truncated"] is False
        assert data["inspected_alert_count"] == 2

    def test_investigate_domain_returns_result(
        self,
        api_client: TestClient,
        alert_search_service: MagicMock,
        threat_intel_provider: MagicMock,
        prevalence_tracker: MagicMock,
    ) -> None:
        """Test that investigating a domain returns a valid result."""
        # Mock threat intelligence response
        threat_intel_provider.lookup_domain.return_value = ThreatIntelReputation(
            indicator="example.com",
            verdict=ThreatIntelVerdict.MALICIOUS,
            confidence=0.99,
            categories=("malware", "c2"),
            source="in_memory_provider",
        )

        # Mock prevalence tracker response
        prevalence_tracker.get_prevalence.return_value = PrevalenceResult(
            dest_host_count=10,
            process_dest_count=2,
            is_rare_destination=True,
            is_environment_wide=False,
        )

        # Mock alert search response
        datetime.now(UTC)
        alert_search_service.search.return_value = AlertSearchResult(
            alerts=[
                _make_alert(
                    title="HTTP request to example.com",
                    severity="HIGH",
                    priority="HIGH",
                    source="web-proxy",
                    entity_context={
                        "domain": "example.com",
                        "dst_ip": "93.184.216.34",
                        "host": "workstation1",
                    },
                    metadata={"rule_id": "web-rule-001"},
                ),
                _make_alert(
                    title="DNS lookup for example.com",
                    severity="MEDIUM",
                    priority="LOW",
                    source="dns-server",
                    entity_context={"domain": "example.com", "dst_ip": "93.184.216.34"},
                    metadata={"rule_id": "dns-rule-002"},
                ),
            ],
            status=AlertSearchStatus.AVAILABLE,
            reason=None,
        )

        response = api_client.get("/api/v1/iocs/example.com")
        assert response.status_code == 200

        data = response.json()
        assert data["indicator"] == "example.com"
        assert data["ioc_type"] == "domain"
        assert data["reputation"]["verdict"] == "MALICIOUS"
        assert data["reputation"]["confidence"] == 0.99
        assert data["reputation"]["categories"] == ["malware", "c2"]
        assert len(data["observations"]) == 2
        assert set(data["associated_alert_ids"]) == {
            str(data["observations"][0]["alert_id"]),
            str(data["observations"][1]["alert_id"]),
        }
        assert data["associated_hosts"] == ["workstation1"]
        # associated_rule_ids sorted alphabetically: ["dns-rule-002", "web-rule-001"]
        assert data["associated_rule_ids"] == ["dns-rule-002", "web-rule-001"]
        assert len(data["related_iocs"]) == 2  # dst_ip from both alerts
        related_indicators = [rel["indicator"] for rel in data["related_iocs"]]
        assert all(ip == "93.184.216.34" for ip in related_indicators)
        assert all(rel["ioc_type"] == "ip" for rel in data["related_iocs"])
        assert all(rel["field"] == "dst_ip" for rel in data["related_iocs"])
        assert data["prevalence"] is not None
        assert data["prevalence"]["dest_host_count"] == 10
        assert data["prevalence"]["is_rare_destination"] is True
        assert data["status"] == "AVAILABLE"

    def test_investigate_ip_no_alerts_returns_empty(
        self,
        api_client: TestClient,
        alert_search_service: MagicMock,
        threat_intel_provider: MagicMock,
        prevalence_tracker: MagicMock,
    ) -> None:
        """Test that investigating an IP with no matching alerts returns empty result."""
        # Mock threat intelligence response
        threat_intel_provider.lookup_ip.return_value = ThreatIntelReputation(
            indicator="1.1.1.1",
            verdict=ThreatIntelVerdict.BENIGN,
            confidence=0.9,
            categories=(),
            source="in_memory_provider",
        )

        # Mock prevalence tracker response (should be None since no dst_ip/domain matches)
        prevalence_tracker.get_prevalence.return_value = None

        # Mock alert search response with no matching alerts
        alert_search_service.search.return_value = AlertSearchResult(
            alerts=[
                Alert(
                    alert_id=uuid4(),
                    title="Unrelated alert",
                    description="Test description",
                    severity="LOW",
                    priority="LOW",
                    lifecycle_state="OPEN",
                    source="test",
                    entity_context={
                        "src_ip": "192.168.1.1",
                        "dst_ip": "10.0.0.1",
                    },
                ),
            ],
            status=AlertSearchStatus.AVAILABLE,
            reason=None,
        )

        response = api_client.get("/api/v1/iocs/1.1.1.1")
        assert response.status_code == 200

        data = response.json()
        assert data["indicator"] == "1.1.1.1"
        assert data["ioc_type"] == "ip"
        assert data["reputation"]["verdict"] == "BENIGN"
        assert len(data["observations"]) == 0
        assert data["associated_alert_ids"] == []
        assert data["associated_hosts"] == []
        assert data["associated_rule_ids"] == []
        assert data["related_iocs"] == []
        assert data["prevalence"] is None  # No dst_ip matches
        assert data["first_observed"] is None
        assert data["last_observed"] is None
        assert data["status"] == "AVAILABLE"

    def test_investigate_ip_with_prevalence_on_dst_ip(
        self,
        api_client: TestClient,
        alert_search_service: MagicMock,
        threat_intel_provider: MagicMock,
        prevalence_tracker: MagicMock,
    ) -> None:
        """Test that prevalence is looked up using dst_ip values when querying src_ip."""
        # Mock threat intelligence response
        threat_intel_provider.lookup_ip.return_value = ThreatIntelReputation(
            indicator="192.168.1.100",
            verdict=ThreatIntelVerdict.SUSPICIOUS,
            confidence=0.75,
            categories=(),
            source="in_memory_provider",
        )

        # Mock prevalence tracker to return a value when called with dst_ip
        prevalence_tracker.get_prevalence.return_value = PrevalenceResult(
            dest_host_count=3,
            process_dest_count=1,
            is_rare_destination=False,
            is_environment_wide=False,
        )

        # Mock alert search response where dst_ip matches
        alert_search_service.search.return_value = AlertSearchResult(
            alerts=[
                Alert(
                    alert_id=uuid4(),
                    title="Inbound connection",
                    description="Test description",
                    severity="MEDIUM",
                    priority="MEDIUM",
                    lifecycle_state="OPEN",
                    source="firewall",
                    entity_context={
                        "src_ip": "10.0.0.5",
                        "dst_ip": "192.168.1.100",  # This matches our query and is a destination
                        "host": "workstation1",
                    },
                    metadata={"rule_id": "firewall-rule-001"},
                ),
            ],
            status=AlertSearchStatus.AVAILABLE,
            reason=None,
        )

        response = api_client.get("/api/v1/iocs/192.168.1.100")
        assert response.status_code == 200

        data = response.json()
        assert data["indicator"] == "192.168.1.100"
        assert data["ioc_type"] == "ip"
        assert data["reputation"]["verdict"] == "SUSPICIOUS"
        assert len(data["observations"]) == 1
        assert data["observations"][0]["field"] == "dst_ip"
        assert data["observations"][0]["value"] == "192.168.1.100"
        # Prevalence should be looked up using the dst_ip value, not the query indicator
        prevalence_tracker.get_prevalence.assert_called_with(dst_ip="192.168.1.100")
        assert data["prevalence"] is not None
        assert data["prevalence"]["dest_host_count"] == 3

    def test_investigate_domain_with_prevalence_on_domain(
        self,
        api_client: TestClient,
        alert_search_service: MagicMock,
        threat_intel_provider: MagicMock,
        prevalence_tracker: MagicMock,
    ) -> None:
        """Test that prevalence is looked up using domain values when querying domain."""
        # Mock threat intelligence response
        threat_intel_provider.lookup_domain.return_value = ThreatIntelReputation(
            indicator="internal.example.com",
            verdict=ThreatIntelVerdict.BENIGN,
            confidence=0.8,
            categories=(),
            source="in_memory_provider",
        )

        # Mock prevalence tracker to return a value when called with domain
        prevalence_tracker.get_prevalence.return_value = PrevalenceResult(
            dest_host_count=7,
            process_dest_count=2,
            is_rare_destination=True,
            is_environment_wide=False,
        )

        # Mock alert search response where domain matches but we have dst_ip too
        alert_search_service.search.return_value = AlertSearchResult(
            alerts=[
                Alert(
                    alert_id=uuid4(),
                    title="DNS query",
                    description="Test description",
                    severity="LOW",
                    priority="LOW",
                    lifecycle_state="OPEN",
                    source="dns-resolver",
                    entity_context={
                        "domain": "internal.example.com",  # This matches our query
                        "dst_ip": "10.1.1.10",  # This exists but shouldn't be used for prevalence
                    },
                    metadata={"rule_id": "dns-rule-001"},
                ),
            ],
            status=AlertSearchStatus.AVAILABLE,
            reason=None,
        )

        response = api_client.get("/api/v1/iocs/internal.example.com")
        assert response.status_code == 200

        data = response.json()
        assert data["indicator"] == "internal.example.com"
        assert data["ioc_type"] == "domain"
        assert data["reputation"]["verdict"] == "BENIGN"
        assert len(data["observations"]) == 1
        assert data["observations"][0]["field"] == "domain"
        assert data["observations"][0]["value"] == "internal.example.com"
        # Prevalence should be looked up using the domain value
        prevalence_tracker.get_prevalence.assert_called_with(domain="internal.example.com")
        assert data["prevalence"] is not None
        assert data["prevalence"]["dest_host_count"] == 7

    def test_investigate_ip_invalid_indicator_returns_400(
        self,
        api_client: TestClient,
    ) -> None:
        """Test that invalid/empty indicator paths return 404 (no route match)."""
        response = api_client.get("/api/v1/iocs/")
        assert response.status_code == 404

        response = api_client.get("/api/v1/iocs/   ")
        assert response.status_code == 400

    def test_investigate_ip_too_long_returns_400(
        self,
        api_client: TestClient,
    ) -> None:
        """Test that overly long indicator returns 400."""
        long_indicator = "a" * 257
        response = api_client.get(f"/api/v1/iocs/{long_indicator}")
        assert response.status_code == 400
        assert "exceeds maximum length" in response.json()["detail"]

    def test_investigate_ip_invalid_format_returns_400(
        self,
        api_client: TestClient,
    ) -> None:
        """Test that invalid IP/domain format returns 400."""
        response = api_client.get("/api/v1/iocs/not-an-ip-or-domain")
        assert response.status_code == 400
        assert "Unsupported or invalid indicator type" in response.json()["detail"]

        response = api_client.get("/api/v1/iocs/192.168.1.256")  # Invalid IP
        assert response.status_code == 400
        assert "Unsupported or invalid indicator type" in response.json()["detail"]

    def test_investigate_ip_service_unavailable_returns_503(
        self,
        api_client: TestClient,
    ) -> None:
        """Test that missing service returns 503."""
        # Force re-resolution by resetting the singleton so the route handler can't find it
        container = ServiceContainer.get_instance()
        container.reset_instance()

        response = api_client.get("/api/v1/iocs/8.8.8.8")
        assert response.status_code == 503
        assert "IOC investigation service not available" in response.json()["detail"]

    def test_investigate_ip_search_degraded_returns_degraded_status(
        self,
        api_client: TestClient,
        alert_search_service: MagicMock,
        threat_intel_provider: MagicMock,
        prevalence_tracker: MagicMock,
    ) -> None:
        """Test that degraded search status propagates to investigation result."""
        # Mock threat intelligence response
        threat_intel_provider.lookup_ip.return_value = ThreatIntelReputation(
            indicator="8.8.8.8",
            verdict=ThreatIntelVerdict.UNKNOWN,
            confidence=0.0,
            categories=(),
            source="in_memory_provider",
        )

        # Mock prevalence tracker
        prevalence_tracker.get_prevalence.return_value = None

        # Mock alert search response with degraded status
        alert_search_service.search.return_value = AlertSearchResult(
            alerts=[],
            status=AlertSearchStatus.DEGRADED,
            reason="Persistence unavailable",
        )

        response = api_client.get("/api/v1/iocs/8.8.8.8")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "DEGRADED"
        assert data["reason"] == "Persistence unavailable"

    def test_investigate_ip_related_iocs_classification_correct(
        self,
        api_client: TestClient,
        alert_search_service: MagicMock,
        threat_intel_provider: MagicMock,
        prevalence_tracker: MagicMock,
    ) -> None:
        """Test that related IOCs are classified correctly based on field type."""
        # Mock threat intelligence response
        threat_intel_provider.lookup_ip.return_value = ThreatIntelReputation(
            indicator="10.0.0.5",
            verdict=ThreatIntelVerdict.BENIGN,
            confidence=0.5,
            categories=(),
            source="in_memory_provider",
        )

        # Mock prevalence tracker
        prevalence_tracker.get_prevalence.return_value = None

        # Mock alert search with multiple fields in same alert
        alert_search_service.search.return_value = AlertSearchResult(
            alerts=[
                Alert(
                    alert_id=uuid4(),
                    title="Multi-field alert",
                    description="Test description",
                    severity="HIGH",
                    priority="HIGH",
                    lifecycle_state="OPEN",
                    source="correlation-engine",
                    entity_context={
                        "src_ip": "192.168.1.100",
                        "dst_ip": "10.0.0.5",  # Matches our query
                        "domain": "example.com",
                    },
                    metadata={"rule_id": "multi-rule-001"},
                ),
            ],
            status=AlertSearchStatus.AVAILABLE,
            reason=None,
        )

        response = api_client.get("/api/v1/iocs/10.0.0.5")
        assert response.status_code == 200

        data = response.json()
        assert len(data["related_iocs"]) == 2

        # Find the src_ip related IOC
        src_ip_rel = next((rel for rel in data["related_iocs"] if rel["field"] == "src_ip"), None)
        assert src_ip_rel is not None
        assert src_ip_rel["indicator"] == "192.168.1.100"
        assert src_ip_rel["ioc_type"] == "ip"  # Should be IP because field is src_ip

        # Find the domain related IOC
        domain_rel = next((rel for rel in data["related_iocs"] if rel["field"] == "domain"), None)
        assert domain_rel is not None
        assert domain_rel["indicator"] == "example.com"
        assert domain_rel["ioc_type"] == "domain"  # Should be domain because field is domain

    def test_investigate_domain_related_iocs_classification_correct(
        self,
        api_client: TestClient,
        alert_search_service: MagicMock,
        threat_intel_provider: MagicMock,
        prevalence_tracker: MagicMock,
    ) -> None:
        """Test that related IOCs are classified correctly when querying a domain."""
        # Mock threat intelligence response
        threat_intel_provider.lookup_domain.return_value = ThreatIntelReputation(
            indicator="example.com",
            verdict=ThreatIntelVerdict.BENIGN,
            confidence=0.6,
            categories=(),
            source="in_memory_provider",
        )

        # Mock prevalence tracker
        prevalence_tracker.get_prevalence.return_value = None

        # Mock alert search with multiple fields in same alert
        alert_search_service.search.return_value = AlertSearchResult(
            alerts=[
                Alert(
                    alert_id=uuid4(),
                    title="Multi-field alert",
                    description="Test description",
                    severity="HIGH",
                    priority="HIGH",
                    lifecycle_state="OPEN",
                    source="correlation-engine",
                    entity_context={
                        "src_ip": "192.168.1.100",
                        "dst_ip": "10.0.0.5",
                        "domain": "example.com",  # Matches our query
                    },
                    metadata={"rule_id": "multi-rule-002"},
                ),
            ],
            status=AlertSearchStatus.AVAILABLE,
            reason=None,
        )

        response = api_client.get("/api/v1/iocs/example.com")
        assert response.status_code == 200

        data = response.json()
        assert len(data["related_iocs"]) == 2

        # Find the src_ip related IOC
        src_ip_rel = next((rel for rel in data["related_iocs"] if rel["field"] == "src_ip"), None)
        assert src_ip_rel is not None
        assert src_ip_rel["indicator"] == "192.168.1.100"
        assert src_ip_rel["ioc_type"] == "ip"  # Should be IP because field is src_ip

        # Find the dst_ip related IOC
        dst_ip_rel = next((rel for rel in data["related_iocs"] if rel["field"] == "dst_ip"), None)
        assert dst_ip_rel is not None
        assert dst_ip_rel["indicator"] == "10.0.0.5"
        assert dst_ip_rel["ioc_type"] == "ip"  # Should be IP because field is dst_ip

    def test_investigate_ip_bounds_enforced(
        self,
        api_client: TestClient,
        alert_search_service: MagicMock,
        threat_intel_provider: MagicMock,
        prevalence_tracker: MagicMock,
    ) -> None:
        """Test that investigation results respect bounds limits."""
        # Mock threat intelligence response
        threat_intel_provider.lookup_ip.return_value = ThreatIntelReputation(
            indicator="8.8.8.8",
            verdict=ThreatIntelVerdict.BENIGN,
            confidence=0.9,
            categories=(),
            source="in_memory_provider",
        )

        # Mock prevalence tracker
        prevalence_tracker.get_prevalence.return_value = None

        # Create more alerts than the bounds allow
        many_alerts = []
        for i in range(150):  # More than _MAX_OBSERVATIONS (100) and _MAX_RELATED_IOCS (50)
            alert_id = uuid4()
            # Alternate between two related IOs to test bounding
            src_ip = f"10.0.{i % 2}.{i % 254}"
            dst_ip = f"10.0.{i % 2 + 2}.{i % 254}" if i % 2 == 0 else "8.8.8.8"

            many_alerts.append(
                Alert(
                    alert_id=alert_id,
                    title=f"Alert {i}",
                    description="Test description",
                    severity="LOW",
                    priority="LOW",
                    lifecycle_state="OPEN",
                    source=f"source-{i % 5}",
                    entity_context={
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "host": f"host-{i % 10}",
                    },
                    metadata={"rule_id": f"rule-{i % 3}"},
                )
            )
            # Make every 10th alert match our query indicator
            if i % 10 == 0:
                many_alerts[-1].entity_context["dst_ip"] = "8.8.8.8"

        alert_search_service.search.return_value = AlertSearchResult(
            alerts=many_alerts,
            status=AlertSearchStatus.AVAILABLE,
            reason=None,
        )

        response = api_client.get("/api/v1/iocs/8.8.8.8")
        assert response.status_code == 200

        data = response.json()
        # Observations should be bounded to _MAX_OBSERVATIONS (100)
        assert len(data["observations"]) <= 100
        # Related IOCs should be bounded to _MAX_RELATED_IOCS (50)
        assert len(data["related_iocs"]) <= 50
        # Timeline should be bounded to _MAX_TIMELINE_ITEMS (100)
        assert len(data["timeline"]) <= 100

    def test_investigate_ip_timeline_construction(
        self,
        api_client: TestClient,
        alert_search_service: MagicMock,
        threat_intel_provider: MagicMock,
        prevalence_tracker: MagicMock,
    ) -> None:
        """Test that timeline is constructed correctly with observations first."""
        # Mock threat intelligence response
        threat_intel_provider.lookup_ip.return_value = ThreatIntelReputation(
            indicator="8.8.8.8",
            verdict=ThreatIntelVerdict.BENIGN,
            confidence=0.9,
            categories=(),
            source="test_source",
        )

        # Mock prevalence tracker
        prevalence_tracker.get_prevalence.return_value = None

        # Mock alert search with two alerts at different times
        early_time = datetime(2026, 9, 14, 10, 0, 0, tzinfo=UTC)
        late_time = datetime(2026, 9, 14, 12, 0, 0, tzinfo=UTC)
        alert_search_service.search.return_value = AlertSearchResult(
            alerts=[
                Alert(
                    alert_id=uuid4(),
                    title="Early alert",
                    description="Test description",
                    severity="LOW",
                    priority="LOW",
                    lifecycle_state="OPEN",
                    source="early-source",
                    created_at=early_time,
                    entity_context={
                        "dst_ip": "8.8.8.8",
                        "host": "early-host",
                    },
                    metadata={"rule_id": "early-rule"},
                ),
                Alert(
                    alert_id=uuid4(),
                    title="Late alert",
                    description="Test description",
                    severity="HIGH",
                    priority="HIGH",
                    lifecycle_state="OPEN",
                    source="late-source",
                    created_at=late_time,
                    entity_context={
                        "dst_ip": "8.8.8.8",
                        "host": "late-host",
                    },
                    metadata={"rule_id": "late-rule"},
                ),
            ],
            status=AlertSearchStatus.AVAILABLE,
            reason=None,
        )

        response = api_client.get("/api/v1/iocs/8.8.8.8")
        assert response.status_code == 200

        data = response.json()
        assert len(data["timeline"]) >= 2  # At least 2 observation items + 1 intelligence item

        # First items should be observations (sorted newest first)
        observation_items = [
            item for item in data["timeline"] if item["item_type"] == "OBSERVATION"
        ]
        assert len(observation_items) == 2
        # First observation should be the late alert (newest timestamp)
        assert observation_items[0]["title"] == "IOC observed as dst_ip"
        assert observation_items[0]["summary"].endswith(f"on {late_time.isoformat()}")
        assert "dst_ip=8.8.8.8" in observation_items[0]["summary"]
        # The timeline observations are sorted by timestamp (newest first)
        # Sort the observations by timestamp (newest first) to match
        sorted_obs = sorted(data["observations"], key=lambda obs: obs["timestamp"], reverse=True)
        assert observation_items[0]["source_id"] == sorted_obs[0]["alert_id"]

        # Should have one intelligence item
        intelligence_items = [
            item for item in data["timeline"] if item["item_type"] == "INTELLIGENCE"
        ]
        assert len(intelligence_items) == 1
        assert intelligence_items[0]["title"] == "Threat intelligence reputation"
        assert "BENIGN" in intelligence_items[0]["summary"]
        assert "confidence 0.9" in intelligence_items[0]["summary"]
        assert "from test_source" in intelligence_items[0]["summary"]
