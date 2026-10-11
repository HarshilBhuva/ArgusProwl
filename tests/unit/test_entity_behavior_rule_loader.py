"""Tests for EntityBehaviorDetector RuleLoader integration."""

from pathlib import Path

import pytest
import yaml

from argusprowl.detection.rule_loader import RuleLoader
from argusprowl.exceptions.exceptions import DetectionError


class TestEntityBehaviorRuleLoader:
    """Tests for RuleLoader integration with EntityBehaviorDetector."""

    def test_load_valid_behavior_rule(self, tmp_path: Path) -> None:
        """Test loading a valid behavior rule."""
        rule_data = {
            "rule_id": "first_seen_host_process",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {
                "entity": {"type": "hostname"},
                "dimension": {"field": "process_name"},
            },
        }

        rule_file = tmp_path / "test_rule.yaml"
        with rule_file.open("w") as f:
            yaml.dump(rule_data, f)

        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()

        assert len(rules) == 1
        assert rules[0].rule_id == "first_seen_host_process"
        assert rules[0].detector == "EntityBehaviorDetector"

    def test_create_behavior_detector(self, tmp_path: Path) -> None:
        """Test creating EntityBehaviorDetector from rule."""
        rule_data = {
            "rule_id": "first_seen_host_process",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {
                "entity": {"type": "hostname"},
                "dimension": {"field": "process_name"},
            },
        }

        rule_file = tmp_path / "test_rule.yaml"
        with rule_file.open("w") as f:
            yaml.dump(rule_data, f)

        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()

        detector = loader.create_detector(rules[0])

        assert detector.name == "first_seen_host_process"
        assert detector.entity_type == "hostname"
        assert detector.dimension_field == "process_name"
        assert detector.is_enabled() is True

    def test_invalid_entity_type(self, tmp_path: Path) -> None:
        """Test creating detector with invalid entity type raises."""
        rule_data = {
            "rule_id": "invalid_rule",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {
                "entity": {"type": "invalid_type"},
                "dimension": {"field": "process_name"},
            },
        }

        rule_file = tmp_path / "test_rule.yaml"
        with rule_file.open("w") as f:
            yaml.dump(rule_data, f)

        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()

        # Error raised when creating detector, not loading rule
        with pytest.raises(DetectionError, match=r"Invalid entity\.type"):
            loader.create_detector(rules[0])

    def test_invalid_dimension_field(self, tmp_path: Path) -> None:
        """Test creating detector with invalid dimension field raises."""
        rule_data = {
            "rule_id": "invalid_rule",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {
                "entity": {"type": "hostname"},
                "dimension": {"field": "invalid_field"},
            },
        }

        rule_file = tmp_path / "test_rule.yaml"
        with rule_file.open("w") as f:
            yaml.dump(rule_data, f)

        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()

        # Error raised when creating detector, not loading rule
        with pytest.raises(DetectionError, match=r"Invalid dimension\.field"):
            loader.create_detector(rules[0])

    def test_load_valid_rare_rule(self, tmp_path: Path) -> None:
        """Test loading a valid rare-value rule."""
        rule_data = {
            "rule_id": "rare_host_process",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {
                "entity": {"type": "hostname"},
                "dimension": {"field": "process_name"},
                "rare": {
                    "threshold": 3,
                    "min_observations": 5,
                },
            },
        }

        rule_file = tmp_path / "rare_rule.yaml"
        with rule_file.open("w") as f:
            yaml.dump(rule_data, f)

        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()

        assert len(rules) == 1
        assert rules[0].rule_id == "rare_host_process"
        assert rules[0].detector == "EntityBehaviorDetector"

        detector = loader.create_detector(rules[0])
        assert detector.name == "rare_host_process"
        assert detector.entity_type == "hostname"
        assert detector.dimension_field == "process_name"
        assert detector.is_enabled() is True
        assert detector._rare_threshold == 3
        assert detector._rare_min_observations == 5

    def test_create_rare_detector(self, tmp_path: Path) -> None:
        """Test creating EntityBehaviorDetector with rare parameters."""
        rule_data = {
            "rule_id": "rare_host_process",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {
                "entity": {"type": "hostname"},
                "dimension": {"field": "process_name"},
                "rare": {
                    "threshold": 3,
                    "min_observations": 5,
                },
            },
        }

        rule_file = tmp_path / "rare_rule.yaml"
        with rule_file.open("w") as f:
            yaml.dump(rule_data, f)

        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()

        detector = loader.create_detector(rules[0])

        assert detector.name == "rare_host_process"
        assert detector.entity_type == "hostname"
        assert detector.dimension_field == "process_name"
        assert detector.is_enabled() is True
        assert detector._rare_threshold == 3
        assert detector._rare_min_observations == 5

    def test_invalid_rare_threshold(self, tmp_path: Path) -> None:
        """Test creating detector with invalid rare threshold raises."""
        rule_data = {
            "rule_id": "invalid_rare_rule",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {
                "entity": {"type": "hostname"},
                "dimension": {"field": "process_name"},
                "rare": {
                    "threshold": -1,
                    "min_observations": 5,
                },
            },
        }

        rule_file = tmp_path / "invalid_rare_rule.yaml"
        with rule_file.open("w") as f:
            yaml.dump(rule_data, f)

        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()

        # Error raised when creating detector, not loading rule
        with pytest.raises(DetectionError, match=r"rare\.threshold must be a positive integer"):
            loader.create_detector(rules[0])

    def test_invalid_min_observations(self, tmp_path: Path) -> None:
        """Test creating detector with invalid min_observations raises."""
        rule_data = {
            "rule_id": "invalid_rare_rule",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {
                "entity": {"type": "hostname"},
                "dimension": {"field": "process_name"},
                "rare": {
                    "threshold": 3,
                    "min_observations": 0,
                },
            },
        }

        rule_file = tmp_path / "invalid_rare_rule.yaml"
        with rule_file.open("w") as f:
            yaml.dump(rule_data, f)

        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()

        # Error raised when creating detector, not loading rule
        with pytest.raises(
            DetectionError, match=r"rare\.min_observations must be a positive integer"
        ):
            loader.create_detector(rules[0])

    def test_missing_entity_type(self, tmp_path: Path) -> None:
        """Test creating detector with missing entity type raises."""
        rule_data = {
            "rule_id": "invalid_rule",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {
                "entity": {},
                "dimension": {"field": "process_name"},
            },
        }

        rule_file = tmp_path / "test_rule.yaml"
        with rule_file.open("w") as f:
            yaml.dump(rule_data, f)

        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()

        # Error raised when creating detector, not loading rule
        with pytest.raises(DetectionError, match=r"entity\.type must be a non-empty string"):
            loader.create_detector(rules[0])

    def test_missing_dimension_field(self, tmp_path: Path) -> None:
        """Test creating detector with missing dimension field raises."""
        rule_data = {
            "rule_id": "invalid_rule",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {
                "entity": {"type": "hostname"},
                "dimension": {},
            },
        }

        rule_file = tmp_path / "test_rule.yaml"
        with rule_file.open("w") as f:
            yaml.dump(rule_data, f)

        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()

        # Error raised when creating detector, not loading rule
        with pytest.raises(DetectionError, match=r"dimension\.field must be a non-empty string"):
            loader.create_detector(rules[0])

    def test_disabled_behavior_rule(self, tmp_path: Path) -> None:
        """Test loading a disabled behavior rule."""
        rule_data = {
            "rule_id": "first_seen_host_process",
            "detector": "EntityBehaviorDetector",
            "enabled": False,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {
                "entity": {"type": "hostname"},
                "dimension": {"field": "process_name"},
            },
        }

        rule_file = tmp_path / "test_rule.yaml"
        with rule_file.open("w") as f:
            yaml.dump(rule_data, f)

        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()

        detector = loader.create_detector(rules[0])

        assert detector.is_enabled() is False

    def test_build_detection_manager_with_behavior_detector(self, tmp_path: Path) -> None:
        """Test DetectionManager can be built with behavior detector."""
        rule_data = {
            "rule_id": "first_seen_host_process",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {
                "entity": {"type": "hostname"},
                "dimension": {"field": "process_name"},
            },
        }

        rule_file = tmp_path / "test_rule.yaml"
        with rule_file.open("w") as f:
            yaml.dump(rule_data, f)

        loader = RuleLoader(rules_dir=tmp_path)
        manager = loader.build_detection_manager()

        assert manager is not None


class TestEntityBehaviorRuleLoaderValidCombinations:
    """Tests for valid entity/dimension combinations."""

    @pytest.mark.parametrize(
        "entity_type,dimension_field",
        [
            ("hostname", "process_name"),
            ("hostname", "dst_ip"),
            ("hostname", "username"),
            ("src_ip", "dst_ip"),
            ("src_ip", "dst_port"),
            ("src_ip", "process_name"),
            ("username", "process_name"),
            ("username", "dst_ip"),
        ],
    )
    def test_valid_combinations(
        self, tmp_path: Path, entity_type: str, dimension_field: str
    ) -> None:
        """Test all valid entity/dimension combinations."""
        rule_data = {
            "rule_id": f"test_{entity_type}_{dimension_field}",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {
                "entity": {"type": entity_type},
                "dimension": {"field": dimension_field},
            },
        }

        rule_file = tmp_path / "test_rule.yaml"
        with rule_file.open("w") as f:
            yaml.dump(rule_data, f)

        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()

        detector = loader.create_detector(rules[0])

        assert detector.entity_type == entity_type
        assert detector.dimension_field == dimension_field
