import pytest
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.attck.mapping_registry import AttckMapping, AttckMappingRegistry, MappingType
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.detection.base_detector import BaseDetector
from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.detection.detector_registry import DetectorRegistry


class MockDetector(BaseDetector):
    def __init__(self, name, description, enabled, config, confidence, version):
        super().__init__(name, description, enabled, config, confidence, version)

    def process_event(self, event):
        return []

    def detect(self, event):
        return None


@pytest.fixture
def test_client():
    container = ServiceContainer.get_instance()
    container.clear()

    registry = DetectorRegistry()
    registry.register(
        MockDetector("port_scan", "Port Scan Description", True, {"min_ports": 10}, 0.8, 2)
    )
    registry.register(
        MockDetector("syn_scan", "Syn Scan Description", False, {"rate": 5.0}, 0.9, 1)
    )

    class MockDetectionManager:
        def get_registry(self):
            return registry

    container.register_singleton(DetectionManager, lambda: MockDetectionManager())

    class MockAttckRegistry:
        def __init__(self):
            self.mappings = []

        def register(self, m):
            self.mappings.append(m)

        def get_for_rule(self, rule_id):
            return [m for m in self.mappings if m.rule_id == rule_id]

    attck_registry = MockAttckRegistry()
    attck_registry.register(
        AttckMapping(
            rule_id="port_scan",
            technique_id="T1046",
            mapping_type=MappingType.DIRECT,
            subtechnique_id=None,
            rationale="Scans ports",
        )
    )
    container.register_singleton(AttckMappingRegistry, lambda: attck_registry)

    app = create_api_app()
    yield TestClient(app)

    container.clear()


def test_list_rules(test_client):
    response = test_client.get("/api/v1/rules")
    assert response.status_code == 200
    data = response.json()
    assert data["total_count"] == 2
    assert len(data["rules"]) == 2

    # Check sorting by rule_id
    assert data["rules"][0]["rule_id"] == "port_scan"
    assert data["rules"][1]["rule_id"] == "syn_scan"


def test_list_rules_with_filters(test_client):
    response = test_client.get("/api/v1/rules?enabled=true")
    assert response.status_code == 200
    data = response.json()
    assert data["total_count"] == 1
    assert data["rules"][0]["rule_id"] == "port_scan"


def test_get_rule_detail_with_attck(test_client):
    response = test_client.get("/api/v1/rules/port_scan")
    assert response.status_code == 200
    data = response.json()
    assert data["rule_id"] == "port_scan"
    assert data["name"] == "port_scan"
    assert data["enabled"] is True
    assert data["detector_class"] == "MockDetector"
    assert data["parameters"] == {"min_ports": 10}
    assert len(data["attck_mappings"]) == 1
    assert data["attck_mappings"][0]["technique_id"] == "T1046"


def test_get_rule_detail_not_found(test_client):
    response = test_client.get("/api/v1/rules/unknown_rule")
    assert response.status_code == 404
    assert response.json()["detail"] == "Rule not found"
