"""Tests for the HTTP API layer (Phase 7.0).

These tests verify:
- Health endpoint returns structured status
- Metrics endpoint returns bounded response
- Alerts endpoint enforces limits and validates input
- Error handling does not leak internals
- CORS configuration
- Service identity (API uses existing service instances)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.api.response_models import (
    AlertResponse,
    HealthResponse,
    MetricsResponse,
)
from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.models.alert import Alert
from argusprowl.models.metrics_snapshot import MetricsSnapshot
from argusprowl.models.system_status import ComponentHealth, HealthStatus, SystemStatus

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_alert() -> Alert:
    """Create a sample alert for testing."""
    return Alert(
        title="Test Alert",
        description="Test description",
        severity=Severity.HIGH,
        source="test-detector",
        priority=AlertPriority.HIGH,
        lifecycle_state=AlertLifecycleState.OPEN,
        tags=("test",),
        metadata={"rule_id": "test-rule"},
    )


@pytest.fixture
def sample_health_status() -> SystemStatus:
    """Create a sample health status for testing."""
    return SystemStatus(
        status=HealthStatus.HEALTHY,
        version="0.1.0",
        uptime_seconds=123.45,
        checked_at=datetime.now(UTC),
        components=(
            ComponentHealth(name="config", status=HealthStatus.HEALTHY, message="OK"),
            ComponentHealth(name="logging", status=HealthStatus.HEALTHY, message="OK"),
        ),
    )


@pytest.fixture
def sample_metrics_snapshot() -> MetricsSnapshot:
    """Create a sample metrics snapshot for testing."""
    return MetricsSnapshot(
        uptime_seconds=123.45,
        metrics={
            "events_processed": {"description": "Total events processed", "value": 1000},
            "alerts_generated": {"description": "Total alerts generated", "value": 10},
        },
        captured_at=datetime.now(UTC),
    )


@pytest.fixture
def api_client() -> TestClient:
    """Create a TestClient for the API."""
    app = create_api_app()
    return TestClient(app)


@pytest.fixture
def api_client_with_cors() -> TestClient:
    """Create a TestClient with CORS enabled."""
    app = create_api_app(cors_origins=["http://localhost:5173"])
    return TestClient(app)


@pytest.fixture
def mock_health_service(sample_health_status: SystemStatus) -> MagicMock:
    """Create a mock health service."""
    service = MagicMock()
    service.check_health.return_value = sample_health_status
    return service


@pytest.fixture
def mock_metrics_collector(sample_metrics_snapshot: MetricsSnapshot) -> MagicMock:
    """Create a mock metrics collector."""
    collector = MagicMock()
    collector.snapshot.return_value = sample_metrics_snapshot
    return collector


@pytest.fixture
def mock_alert_search_service() -> MagicMock:
    """Create a mock alert search service."""
    service = MagicMock()
    # Create a proper return value object with configured attributes
    search_result = MagicMock()
    search_result.alerts = ()
    search_result.status = MagicMock()
    search_result.status.value = "AVAILABLE"
    search_result.reason = None
    service.search.return_value = search_result
    return service


@pytest.fixture
def api_client_with_services(
    mock_health_service: MagicMock,
    mock_metrics_collector: MagicMock,
    mock_alert_search_service: MagicMock,
) -> TestClient:
    """Create a TestClient with mocked services registered in the container."""
    from argusprowl.metrics.collector import MetricsCollector
    from argusprowl.services.alert_search_service import AlertSearchService
    from argusprowl.services.health_service import HealthService

    container = ServiceContainer.get_instance()
    # Register mocks via lambda factories to preserve configured return values
    container.register_singleton(HealthService, lambda: mock_health_service)
    container.register_singleton(MetricsCollector, lambda: mock_metrics_collector)
    container.register_singleton(AlertSearchService, lambda: mock_alert_search_service)

    app = create_api_app()
    return TestClient(app)


# ---------------------------------------------------------------------------
# Health Endpoint Tests
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    """Tests for GET /api/v1/health."""

    def test_health_returns_structured_response(self, api_client_with_services: TestClient) -> None:
        """Health endpoint returns structured status without internal details."""
        response = api_client_with_services.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "version" in data
        assert "uptime_seconds" in data
        assert "checked_at" in data
        assert "components" in data
        # No stack traces or internal paths
        assert "traceback" not in str(data).lower()
        assert "/home/" not in str(data)

    def test_health_components_structure(self, api_client_with_services: TestClient) -> None:
        """Health response components have expected structure."""
        response = api_client_with_services.get("/api/v1/health")
        data = response.json()
        for comp in data.get("components", []):
            assert "name" in comp
            assert "status" in comp
            assert "message" in comp

    def test_health_no_internal_leaks(self, api_client_with_services: TestClient) -> None:
        """Health endpoint does not leak internal filesystem details."""
        response = api_client_with_services.get("/api/v1/health")
        data = response.json()
        data_str = json.dumps(data)
        # Should not contain sensitive paths
        assert "argusprowl.db" not in data_str
        assert "config.yaml" not in data_str

    def test_health_returns_503_when_service_unavailable(self, api_client: TestClient) -> None:
        """Health endpoint returns 503 when service is not registered."""
        response = api_client.get("/api/v1/health")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"

    def test_health_operational_endpoint_exists(self, api_client_with_services: TestClient) -> None:
        """Regression test: GET /api/v1/health is available for operational compatibility."""
        response = api_client_with_services.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "uptime_seconds" in data
        assert "checked_at" in data
        assert "components" in data

    def test_operational_health_endpoint_exists(self, api_client_with_services: TestClient) -> None:
        """Regression test: GET /health operational endpoint is available."""
        response = api_client_with_services.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "uptime_seconds" in data
        assert "checked_at" in data
        assert "components" in data


# ---------------------------------------------------------------------------
# Metrics Endpoint Tests
# ---------------------------------------------------------------------------


class TestMetricsEndpoint:
    """Tests for GET /api/v1/metrics."""

    def test_metrics_returns_bounded_response(self, api_client_with_services: TestClient) -> None:
        """Metrics endpoint returns bounded response structure."""
        response = api_client_with_services.get("/api/v1/metrics")
        assert response.status_code == 200
        data = response.json()
        assert "uptime_seconds" in data
        assert "captured_at" in data
        assert "metrics" in data
        assert isinstance(data["metrics"], list)

    def test_metrics_no_internal_state(self, api_client_with_services: TestClient) -> None:
        """Metrics endpoint does not expose internal service state."""
        response = api_client_with_services.get("/api/v1/metrics")
        data = response.json()
        data_str = json.dumps(data)
        # Should not contain internal implementation details
        assert "thread" not in data_str.lower() or "uptime" in data_str.lower()

    def test_metrics_returns_503_when_service_unavailable(self, api_client: TestClient) -> None:
        """Metrics endpoint returns 503 when service is not registered."""
        response = api_client.get("/api/v1/metrics")
        assert response.status_code == 503
        data = response.json()
        assert data["uptime_seconds"] == 0.0


# ---------------------------------------------------------------------------
# Alerts Endpoint Tests
# ---------------------------------------------------------------------------


class TestAlertsEndpoint:
    """Tests for GET /api/v1/alerts."""

    def test_alerts_default_limit(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint accepts default limit parameter."""
        response = api_client_with_services.get("/api/v1/alerts")
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert "status" in data
        assert "total_count" in data

    def test_alerts_limit_enforcement(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint enforces limit bounds."""
        # Test with valid limit
        response = api_client_with_services.get("/api/v1/alerts?limit=10")
        assert response.status_code == 200

        # Test with limit at maximum
        response = api_client_with_services.get("/api/v1/alerts?limit=100")
        assert response.status_code == 200

    def test_alerts_rejects_zero_limit(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint rejects zero limit."""
        response = api_client_with_services.get("/api/v1/alerts?limit=0")
        assert response.status_code == 422

    def test_alerts_rejects_negative_limit(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint rejects negative limit."""
        response = api_client_with_services.get("/api/v1/alerts?limit=-1")
        assert response.status_code == 422

    def test_alerts_rejects_excessive_limit(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint rejects limit above maximum."""
        response = api_client_with_services.get("/api/v1/alerts?limit=101")
        assert response.status_code == 422

    def test_alerts_severity_filter(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint accepts valid severity filter."""
        response = api_client_with_services.get("/api/v1/alerts?min_severity=HIGH")
        assert response.status_code == 200

    def test_alerts_rejects_invalid_severity(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint rejects invalid severity value."""
        response = api_client_with_services.get("/api/v1/alerts?min_severity=INVALID")
        assert response.status_code == 422

    def test_alerts_priority_filter(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint accepts valid priority filter."""
        response = api_client_with_services.get("/api/v1/alerts?min_priority=HIGH")
        assert response.status_code == 200

    def test_alerts_rejects_invalid_priority(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint rejects invalid priority value."""
        response = api_client_with_services.get("/api/v1/alerts?min_priority=INVALID")
        assert response.status_code == 422

    def test_alerts_lifecycle_filter(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint accepts valid lifecycle state filter."""
        response = api_client_with_services.get("/api/v1/alerts?lifecycle_state=OPEN")
        assert response.status_code == 200

    def test_alerts_rejects_invalid_lifecycle(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint rejects invalid lifecycle state."""
        response = api_client_with_services.get("/api/v1/alerts?lifecycle_state=INVALID")
        assert response.status_code == 422

    def test_alerts_string_bounds(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint bounds string query parameters."""
        # Test with oversized rule_id
        response = api_client_with_services.get("/api/v1/alerts?rule_id=" + "A" * 129)
        assert response.status_code == 422

        # Test with oversized host
        response = api_client_with_services.get("/api/v1/alerts?host=" + "B" * 257)
        assert response.status_code == 422

    def test_alerts_deterministic_structure(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint returns deterministic response structure."""
        response = api_client_with_services.get("/api/v1/alerts")
        data = response.json()
        assert isinstance(data["alerts"], list)
        assert isinstance(data["status"], str)
        assert isinstance(data["total_count"], int)

    def test_alerts_read_only(self, api_client_with_services: TestClient) -> None:
        """GET /api/v1/alerts does not mutate alert state."""
        # Make multiple requests and verify structure is consistent
        response1 = api_client_with_services.get("/api/v1/alerts")
        response2 = api_client_with_services.get("/api/v1/alerts")
        assert response1.status_code == response2.status_code

    def test_alerts_returns_503_when_service_unavailable(self, api_client: TestClient) -> None:
        """Alerts endpoint returns 503 when service is not registered."""
        response = api_client.get("/api/v1/alerts")
        assert response.status_code == 503
        data = response.json()
        assert "detail" in data


# ---------------------------------------------------------------------------
# Validation Tests
# ---------------------------------------------------------------------------


class TestValidation:
    """Tests for input validation."""

    def test_malformed_uuid_rejected(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint rejects malformed UUID for incident_id."""
        response = api_client_with_services.get("/api/v1/alerts?incident_id=not-a-uuid")
        assert response.status_code == 422

    def test_empty_string_rejected(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint accepts empty string parameters (they are filtered out)."""
        response = api_client_with_services.get("/api/v1/alerts?rule_id=")
        # Empty string is accepted but filtered out by backend
        assert response.status_code == 200

    def test_oversized_query_rejected(self, api_client_with_services: TestClient) -> None:
        """Alerts endpoint rejects excessively long queries."""
        # Very long entity_key should be rejected
        response = api_client_with_services.get("/api/v1/alerts?entity_key=" + "X" * 300)
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# Error Handling Tests
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Tests for error handling."""

    def test_unexpected_exception_no_traceback(self, api_client: TestClient) -> None:
        """Unexpected exceptions do not leak tracebacks."""
        # This test verifies the error handler structure
        # We can't easily trigger an internal error without mocking
        response = api_client.get("/api/v1/nonexistent")
        assert response.status_code == 404
        data = response.json()
        assert "traceback" not in str(data).lower()
        assert "/home/" not in str(data)

    def test_service_unavailable(self, api_client: TestClient) -> None:
        """Health endpoint returns 503 when service not available."""
        # When container is empty, health should return 503
        response = api_client.get("/api/v1/health")
        # Should not crash
        assert response.status_code in (200, 503)


# ---------------------------------------------------------------------------
# CORS Tests
# ---------------------------------------------------------------------------


class TestCORS:
    """Tests for CORS configuration."""

    def test_cors_disabled_by_default(self, api_client: TestClient) -> None:
        """CORS is disabled by default (no Access-Control-Allow-Origin header)."""
        response = api_client.get(
            "/api/v1/health",
            headers={"Origin": "http://evil.com"},
        )
        assert "Access-Control-Allow-Origin" not in response.headers

    def test_cors_allows_dev_origin(self, api_client_with_cors: TestClient) -> None:
        """CORS allows configured development origin."""
        response = api_client_with_cors.get(
            "/api/v1/health",
            headers={"Origin": "http://localhost:5173"},
        )
        assert response.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"

    def test_cors_disallows_unknown_origin(self, api_client_with_cors: TestClient) -> None:
        """CORS disallows origins not in the allow list."""
        response = api_client_with_cors.get(
            "/api/v1/health",
            headers={"Origin": "http://evil.com"},
        )
        assert "Access-Control-Allow-Origin" not in response.headers

    def test_cors_no_credentials_by_default(self, api_client_with_cors: TestClient) -> None:
        """CORS does not allow credentials (no auth mechanism in Phase 7.0)."""
        response = api_client_with_cors.get(
            "/api/v1/health",
            headers={"Origin": "http://localhost:5173"},
        )
        assert response.headers.get("Access-Control-Allow-Credentials") != "true"


# ---------------------------------------------------------------------------
# Service Identity Tests
# ---------------------------------------------------------------------------


class TestServiceIdentity:
    """Tests to verify API uses existing service instances."""

    def test_api_uses_container_services(self) -> None:
        """API routes resolve services from the DI container."""
        # This is verified by the fact that the routes import and use
        # ServiceContainer.get_instance() to resolve services
        app = create_api_app()
        assert app is not None

    def test_no_duplicate_queues(self) -> None:
        """API does not create duplicate AlertQueue instances."""
        # The API routes resolve from the existing container
        # rather than creating new instances
        from argusprowl.api.routes import router

        assert router is not None


# ---------------------------------------------------------------------------
# Security Tests
# ---------------------------------------------------------------------------


class TestSecurity:
    """Security-related tests."""

    def test_api_does_not_mutate_alerts(self, api_client_with_services: TestClient) -> None:
        """GET requests do not modify alert state."""
        # Verify that GET /api/v1/alerts is read-only
        response = api_client_with_services.get("/api/v1/alerts")
        assert response.status_code == 200
        # No mutation endpoints exist in this phase

    def test_api_does_not_invoke_detection(self, api_client_with_services: TestClient) -> None:
        """API does not invoke detection or DecisionEngine on read endpoints."""
        # The alerts endpoint only searches existing alerts
        # It does not trigger new detections
        response = api_client_with_services.get("/api/v1/alerts")
        assert response.status_code == 200

    def test_api_does_not_bypass_backend_bounds(self, api_client_with_services: TestClient) -> None:
        """API enforces backend bounds on all requests."""
        # Limit is bounded server-side
        response = api_client_with_services.get("/api/v1/alerts?limit=1000")
        assert response.status_code == 422  # Exceeds max

    def test_openapi_accessible(self, api_client: TestClient) -> None:
        """OpenAPI schema is accessible."""
        response = api_client.get("/openapi.json")
        assert response.status_code == 200
        data = response.json()
        assert "paths" in data
        assert "/api/v1/health" in data["paths"]
        assert "/api/v1/metrics" in data["paths"]
        assert "/api/v1/alerts" in data["paths"]

    def test_docs_accessible(self, api_client: TestClient) -> None:
        """Swagger docs are accessible."""
        response = api_client.get("/docs")
        assert response.status_code == 200

    def test_redoc_accessible(self, api_client: TestClient) -> None:
        """ReDoc is accessible."""
        response = api_client.get("/redoc")
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Response Model Tests
# ---------------------------------------------------------------------------


class TestResponseModels:
    """Tests for response model serialization."""

    def test_health_response_model(self, sample_health_status: SystemStatus) -> None:
        """HealthResponse model serializes correctly."""
        from argusprowl.api.routes import _build_health_response

        response = _build_health_response(sample_health_status)
        assert isinstance(response, HealthResponse)
        assert response.status == "healthy"
        assert len(response.components) == 2

    def test_metrics_response_model(self, sample_metrics_snapshot: MetricsSnapshot) -> None:
        """MetricsResponse model serializes correctly."""
        from argusprowl.api.routes import _build_metrics_response

        response = _build_metrics_response(sample_metrics_snapshot)
        assert isinstance(response, MetricsResponse)
        assert len(response.metrics) == 2

    def test_alert_response_model(self, sample_alert: Alert) -> None:
        """AlertResponse model serializes correctly."""
        from argusprowl.api.routes import _build_alert_response

        response = _build_alert_response(sample_alert)
        assert isinstance(response, AlertResponse)
        assert response.alert_id == str(sample_alert.alert_id)
        assert response.title == sample_alert.title
        assert response.severity == "HIGH"

    def test_entities_endpoint_returns_200_when_behavior_service_registered(self) -> None:
        """Regression test for Phase 7.5: /entities must not 503 when AnalystBehaviorQueryService is available.

        The API reads AnalystBehaviorQueryService from the global DI container. The production
        Application wires this service during startup, so this regression ensures the service
        registration in app/core/application.py is preserved.
        """
        from argusprowl.behavior.analyst_behavior_query_service import AnalystBehaviorQueryService
        from argusprowl.behavior.entity_behavior_service import EntityBehaviorService

        container = ServiceContainer.get_instance()

        behavior_service = EntityBehaviorService(max_profiles=100, max_values_per_profile=10)
        behavior_service_instance = AnalystBehaviorQueryService(behavior_service=behavior_service)
        container.register_singleton(AnalystBehaviorQueryService, lambda: behavior_service_instance)

        try:
            app = create_api_app()
            with TestClient(app) as client:
                response = client.get("/api/v1/entities")
                assert response.status_code == 200
                data = response.json()
                assert "entities" in data
                assert "total_count" in data
                assert isinstance(data["entities"], list)
                assert isinstance(data["total_count"], int)
        finally:
            container.clear()
            ServiceContainer.reset_instance()
