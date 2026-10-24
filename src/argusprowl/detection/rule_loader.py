"""YAML-backed detector rule loading.

Rules are deliberately limited to a fixed allow-list of detector classes.  A
rule file therefore supplies configuration, rather than executable code.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

import yaml

from argusprowl.behavior.entity_behavior_detector import EntityBehaviorDetector
from argusprowl.constants.paths import ProjectPath
from argusprowl.detection.cross_detector_correlator import CrossDetectorCorrelator
from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.detection.detector_registry import DetectorRegistry
from argusprowl.detection.detectors.beaconing_detector import BeaconingDetector
from argusprowl.detection.detectors.cardinality_correlation import CardinalityCorrelationDetector
from argusprowl.detection.detectors.connection_flood import ConnectionFloodDetector
from argusprowl.detection.detectors.correlation_detector import CorrelationDetector
from argusprowl.detection.detectors.event_count_correlation import EventCountCorrelationDetector
from argusprowl.detection.detectors.failed_connections import FailedConnectionsDetector
from argusprowl.detection.detectors.horizontal_scan import HorizontalScanDetector
from argusprowl.detection.detectors.long_connection import LongConnectionDetector
from argusprowl.detection.detectors.ordered_sequence_correlation import OrderedSequenceDetector
from argusprowl.detection.detectors.port_scan import PortScanDetector
from argusprowl.detection.detectors.syn_scan import SynScanDetector
from argusprowl.detection.detectors.tls_c2_detector import TLSC2Detector
from argusprowl.detection.detectors.vertical_scan import VerticalScanDetector
from argusprowl.exceptions.exceptions import DetectionError
from argusprowl.interfaces.detector import Detector


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """Validated configuration extracted from one detector rule file."""

    rule_id: str
    detector: str
    enabled: bool
    parameters: dict[str, Any]
    path: Path
    confidence: float = 0.0
    version: int = 1
    tactic: str | None = None
    technique: str | None = None


class RuleLoader:
    """Load validated YAML rules and construct configured detectors."""

    DETECTORS: ClassVar[dict[str, type[Detector]]] = {
        "BeaconingDetector": BeaconingDetector,
        "CardinalityCorrelationDetector": CardinalityCorrelationDetector,
        "ConnectionFloodDetector": ConnectionFloodDetector,
        "CorrelationDetector": CorrelationDetector,
        "EntityBehaviorDetector": EntityBehaviorDetector,
        "EventCountCorrelationDetector": EventCountCorrelationDetector,
        "FailedConnectionsDetector": FailedConnectionsDetector,
        "HorizontalScanDetector": HorizontalScanDetector,
        "LongConnectionDetector": LongConnectionDetector,
        "OrderedSequenceDetector": OrderedSequenceDetector,
        "PortScanDetector": PortScanDetector,
        "SynScanDetector": SynScanDetector,
        "TLSC2Detector": TLSC2Detector,
        "VerticalScanDetector": VerticalScanDetector,
    }

    def __init__(self, rules_dir: str | Path = ProjectPath.RULES_DIR) -> None:
        self._rules_dir = Path(rules_dir)

    def load_rules(self) -> list[RuleDefinition]:
        """Load every ``*.yaml`` rule in deterministic filename order."""
        if not self._rules_dir.is_dir():
            raise DetectionError(
                "Rules directory not found.", details={"path": str(self._rules_dir)}
            )

        rules = [self.load_rule(path) for path in sorted(self._rules_dir.glob("*.yaml"))]
        rule_ids = [rule.rule_id for rule in rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise DetectionError("Duplicate rule_id found in rule files.")
        return rules

    def load_rule(self, path: str | Path) -> RuleDefinition:
        """Load and validate a single rule file."""
        rule_path = Path(path)
        try:
            with rule_path.open(encoding="utf-8") as rule_file:
                data = yaml.safe_load(rule_file)
        except (OSError, yaml.YAMLError) as exc:
            raise DetectionError(
                "Unable to load detector rule.", details={"path": str(rule_path), "error": str(exc)}
            ) from exc

        if not isinstance(data, dict):
            raise DetectionError("Rule root must be a mapping.", details={"path": str(rule_path)})

        rule_id = data.get("rule_id")
        detector = data.get("detector")
        enabled = data.get("enabled", True)
        parameters = data.get("parameters", {})
        confidence = data.get("confidence_threshold", 0.0)
        version = data.get("version", 1)
        tactic = data.get("tactic")
        technique = data.get("technique")

        if not isinstance(rule_id, str) or not rule_id:
            raise DetectionError(
                "Rule must contain a non-empty rule_id.", details={"path": str(rule_path)}
            )
        if detector not in self.DETECTORS:
            raise DetectionError(
                "Rule references an unsupported detector.",
                details={"path": str(rule_path), "detector": detector},
            )
        if not isinstance(enabled, bool):
            raise DetectionError(
                "Rule enabled must be a boolean.", details={"path": str(rule_path)}
            )
        if not isinstance(parameters, dict):
            raise DetectionError(
                "Rule parameters must be a mapping.", details={"path": str(rule_path)}
            )
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            raise DetectionError(
                "Rule confidence_threshold must be a float in [0.0, 1.0].",
                details={"path": str(rule_path), "confidence": confidence},
            )
        if not isinstance(version, int) or version < 1:
            raise DetectionError(
                "Rule version must be a positive integer.",
                details={"path": str(rule_path), "version": version},
            )

        return RuleDefinition(
            rule_id,
            detector,
            enabled,
            parameters,
            rule_path,
            confidence,
            version,
            tactic,
            technique,
        )

    def create_detector(self, rule: RuleDefinition) -> Detector:
        """Create the detector selected by *rule* with its YAML parameters."""
        detector_class = self.DETECTORS[rule.detector]
        try:
            # Special handling for EntityBehaviorDetector
            if detector_class is EntityBehaviorDetector:
                params = self._parse_behavior_params(rule.parameters, rule.path)
                rare_params = rule.parameters.get("rare", {})
                rare_threshold = rare_params.get("threshold", 3)
                rare_min_observations = rare_params.get("min_observations", 5)
                detector = detector_class(
                    name=rule.rule_id,
                    enabled=rule.enabled,
                    config=rule.parameters,
                    confidence=rule.confidence,
                    version=rule.version,
                    rare_threshold=rare_threshold,
                    rare_min_observations=rare_min_observations,
                    **params,
                )
            # Special handling for EventCountCorrelationDetector
            elif detector_class is EventCountCorrelationDetector:
                params = self._parse_event_count_params(rule.parameters, rule.path)
                detector = detector_class(
                    name=rule.rule_id,
                    enabled=rule.enabled,
                    config=rule.parameters,
                    confidence=rule.confidence,
                    version=rule.version,
                    **params,
                )
            elif detector_class is CardinalityCorrelationDetector:
                params = self._parse_cardinality_params(rule.parameters, rule.path)
                detector = detector_class(
                    name=rule.rule_id,
                    enabled=rule.enabled,
                    config=rule.parameters,
                    confidence=rule.confidence,
                    version=rule.version,
                    **params,
                )
            elif detector_class is OrderedSequenceDetector:
                params = self._parse_sequence_params(rule.parameters, rule.path)
                detector = detector_class(
                    name=rule.rule_id,
                    enabled=rule.enabled,
                    config=rule.parameters,
                    confidence=rule.confidence,
                    version=rule.version,
                    **params,
                )
            else:
                detector = detector_class(
                    enabled=rule.enabled,
                    config=rule.parameters,
                    confidence=rule.confidence,
                    version=rule.version,
                    **rule.parameters,
                )
        except (TypeError, ValueError) as exc:
            raise DetectionError(
                "Invalid detector parameters.",
                details={"rule_id": rule.rule_id, "error": str(exc)},
            ) from exc

        if detector.name != rule.rule_id:
            raise DetectionError(
                "Rule ID must match its detector name.",
                details={"rule_id": rule.rule_id, "detector_name": detector.name},
            )
        return detector

    @staticmethod
    def _parse_event_count_params(parameters: dict[str, Any], rule_path: Path) -> dict[str, Any]:
        """Parse event-count correlation parameters from rule YAML.

        Args:
            parameters: Raw parameters from the rule file.
            rule_path: Path to the rule file (for error messages).

        Returns:
            Parsed parameters suitable for EventCountCorrelationDetector constructor.

        Raises:
            DetectionError: If parameters are invalid.
        """
        correlation = parameters.get("correlation", {})
        if not isinstance(correlation, dict):
            raise DetectionError(
                "correlation must be a mapping.",
                details={"path": str(rule_path)},
            )

        if correlation.get("type") != "event_count":
            raise DetectionError(
                "only 'event_count' correlation type is supported.",
                details={"path": str(rule_path)},
            )

        # Parse count
        count = correlation.get("count")
        if not isinstance(count, int) or count <= 0:
            raise DetectionError(
                "correlation.count must be a positive integer.",
                details={"path": str(rule_path), "count": count},
            )

        # Parse timespan
        timespan_str = correlation.get("timespan")
        if not timespan_str:
            raise DetectionError(
                "correlation.timespan is required.",
                details={"path": str(rule_path)},
            )
        timespan = EventCountCorrelationDetector.parse_timespan(timespan_str, rule_path)

        # Parse group_by
        group_by = correlation.get("group_by", ["src_ip"])
        if not isinstance(group_by, list) or not group_by:
            raise DetectionError(
                "correlation.group_by must be a non-empty list.",
                details={"path": str(rule_path)},
            )
        valid_fields = EventCountCorrelationDetector.VALID_GROUP_BY_FIELDS
        for field in group_by:
            if field not in valid_fields:
                raise DetectionError(
                    f"Invalid group_by field: {field}. Valid fields: {sorted(valid_fields)}",
                    details={"path": str(rule_path)},
                )

        # Parse filter
        filter_config = correlation.get("filter", {})
        if not isinstance(filter_config, dict):
            raise DetectionError(
                "correlation.filter must be a mapping.",
                details={"path": str(rule_path)},
            )
        valid_filter_fields = EventCountCorrelationDetector.VALID_FILTER_FIELDS
        for field in filter_config:
            if field not in valid_filter_fields:
                raise DetectionError(
                    f"Invalid filter field: {field}. Valid fields: {sorted(valid_filter_fields)}",
                    details={"path": str(rule_path)},
                )

        return {
            "count": count,
            "timespan": timespan,
            "group_by": group_by,
            "filter_config": filter_config,
        }

    @staticmethod
    def _parse_behavior_params(parameters: dict[str, Any], rule_path: Path) -> dict[str, Any]:
        """Parse entity behavior detection parameters from rule YAML.

        Args:
            parameters: Raw parameters from the rule file.
            rule_path: Path to the rule file (for error messages).

        Returns:
            Parsed parameters suitable for EntityBehaviorDetector constructor.

        Raises:
            DetectionError: If parameters are invalid.
        """
        # Valid entity types
        valid_entity_types = {
            "hostname",
            "src_ip",
            "dst_ip",
            "username",
            "process_name",
            "pid",
        }

        # Valid dimension fields
        valid_dimension_fields = {
            "process_name",
            "dst_ip",
            "dst_port",
            "protocol",
            "username",
            "event_type",
            "source_type",
            "command_line",
            "hostname",
            "src_ip",
        }

        # Parse entity configuration
        entity = parameters.get("entity", {})
        if not isinstance(entity, dict):
            raise DetectionError(
                "entity must be a mapping.",
                details={"path": str(rule_path)},
            )

        entity_type = entity.get("type")
        if not isinstance(entity_type, str) or not entity_type:
            raise DetectionError(
                "entity.type must be a non-empty string.",
                details={"path": str(rule_path)},
            )
        if entity_type not in valid_entity_types:
            raise DetectionError(
                f"Invalid entity.type: {entity_type}. Valid types: {sorted(valid_entity_types)}",
                details={"path": str(rule_path)},
            )

        # Parse dimension configuration
        dimension = parameters.get("dimension", {})
        if not isinstance(dimension, dict):
            raise DetectionError(
                "dimension must be a mapping.",
                details={"path": str(rule_path)},
            )

        dimension_field = dimension.get("field")
        if not isinstance(dimension_field, str) or not dimension_field:
            raise DetectionError(
                "dimension.field must be a non-empty string.",
                details={"path": str(rule_path)},
            )
        if dimension_field not in valid_dimension_fields:
            raise DetectionError(
                f"Invalid dimension.field: {dimension_field}. Valid fields: {sorted(valid_dimension_fields)}",
                details={"path": str(rule_path)},
            )

        # Parse rare configuration
        rare = parameters.get("rare", {})
        if rare:
            if not isinstance(rare, dict):
                raise DetectionError(
                    "rare must be a mapping.",
                    details={"path": str(rule_path)},
                )
            threshold = rare.get("threshold")
            if threshold is not None and (not isinstance(threshold, int) or threshold <= 0):
                raise DetectionError(
                    "rare.threshold must be a positive integer.",
                    details={"path": str(rule_path)},
                )
            min_observations = rare.get("min_observations")
            if min_observations is not None and (
                not isinstance(min_observations, int) or min_observations <= 0
            ):
                raise DetectionError(
                    "rare.min_observations must be a positive integer.",
                    details={"path": str(rule_path)},
                )

        return {
            "entity_type": entity_type,
            "dimension_field": dimension_field,
        }

    @staticmethod
    def _parse_cardinality_params(parameters: dict[str, Any], rule_path: Path) -> dict[str, Any]:
        """Parse cardinality correlation parameters from rule YAML.

        Args:
            parameters: Raw parameters from the rule file.
            rule_path: Path to the rule file (for error messages).

        Returns:
            Parsed parameters suitable for CardinalityCorrelationDetector constructor.

        Raises:
            DetectionError: If parameters are invalid.
        """
        correlation = parameters.get("correlation", {})
        if not isinstance(correlation, dict):
            raise DetectionError(
                "correlation must be a mapping.",
                details={"path": str(rule_path)},
            )

        if correlation.get("type") != "cardinality":
            raise DetectionError(
                "only 'cardinality' correlation type is supported for this detector.",
                details={"path": str(rule_path)},
            )

        # Parse threshold
        threshold = correlation.get("threshold")
        if not isinstance(threshold, int) or threshold <= 0:
            raise DetectionError(
                "correlation.threshold must be a positive integer.",
                details={"path": str(rule_path), "threshold": threshold},
            )

        # Parse cardinality_field
        cardinality_field = correlation.get("cardinality_field")
        if not isinstance(cardinality_field, str) or not cardinality_field:
            raise DetectionError(
                "correlation.cardinality_field must be a non-empty string.",
                details={"path": str(rule_path)},
            )

        # Parse timespan
        timespan_str = correlation.get("timespan")
        if not timespan_str:
            raise DetectionError(
                "correlation.timespan is required.",
                details={"path": str(rule_path)},
            )
        timespan = CardinalityCorrelationDetector.parse_timespan(timespan_str, rule_path)

        # Parse group_by
        group_by = correlation.get("group_by", ["src_ip"])
        if not isinstance(group_by, list) or not group_by:
            raise DetectionError(
                "correlation.group_by must be a non-empty list.",
                details={"path": str(rule_path)},
            )
        valid_fields = CardinalityCorrelationDetector.VALID_GROUP_BY_FIELDS
        for field in group_by:
            if field not in valid_fields:
                raise DetectionError(
                    f"Invalid group_by field: {field}. Valid fields: {sorted(valid_fields)}",
                    details={"path": str(rule_path)},
                )

        # Parse filter
        filter_config = correlation.get("filter", {})
        if not isinstance(filter_config, dict):
            raise DetectionError(
                "correlation.filter must be a mapping.",
                details={"path": str(rule_path)},
            )
        valid_filter_fields = CardinalityCorrelationDetector.VALID_FILTER_FIELDS
        for field in filter_config:
            if field not in valid_filter_fields:
                raise DetectionError(
                    f"Invalid filter field: {field}. Valid fields: {sorted(valid_filter_fields)}",
                    details={"path": str(rule_path)},
                )

        return {
            "threshold": threshold,
            "cardinality_field": cardinality_field,
            "timespan": timespan,
            "group_by": group_by,
            "filter_config": filter_config,
        }

    @staticmethod
    def _parse_sequence_params(parameters: dict[str, Any], rule_path: Path) -> dict[str, Any]:
        """Parse ordered sequence parameters from rule YAML.

        Args:
            parameters: Raw parameters from the rule file.
            rule_path: Path to the rule file (for error messages).

        Returns:
            Parsed parameters suitable for OrderedSequenceDetector constructor.

        Raises:
            DetectionError: If parameters are invalid.
        """
        correlation = parameters.get("correlation", {})
        if not isinstance(correlation, dict):
            raise DetectionError(
                "correlation must be a mapping.",
                details={"path": str(rule_path)},
            )

        if correlation.get("type") != "sequence":
            raise DetectionError(
                "only 'sequence' correlation type is supported for this detector.",
                details={"path": str(rule_path)},
            )

        # Parse sequence steps
        sequence = correlation.get("sequence", {})
        if not isinstance(sequence, dict):
            raise DetectionError(
                "correlation.sequence must be a mapping.",
                details={"path": str(rule_path)},
            )

        steps = sequence.get("steps", [])
        if not isinstance(steps, list) or len(steps) < 2:
            raise DetectionError(
                "correlation.sequence.steps must be a list with at least 2 steps.",
                details={"path": str(rule_path), "steps": steps},
            )

        # Validate each step
        valid_filter_fields = OrderedSequenceDetector.VALID_FILTER_FIELDS
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                raise DetectionError(
                    f"Step {i} must be a mapping.",
                    details={"path": str(rule_path)},
                )
            for field in step:
                if field not in valid_filter_fields:
                    raise DetectionError(
                        f"Invalid step field '{field}' in step {i}. Valid fields: {sorted(valid_filter_fields)}",
                        details={"path": str(rule_path)},
                    )

        # Parse timespan
        timespan_str = sequence.get("timespan")
        if not timespan_str:
            raise DetectionError(
                "correlation.sequence.timespan is required.",
                details={"path": str(rule_path)},
            )
        timespan = OrderedSequenceDetector.parse_timespan(timespan_str, rule_path)

        # Parse group_by
        group_by = sequence.get("group_by", ["src_ip"])
        if not isinstance(group_by, list) or not group_by:
            raise DetectionError(
                "correlation.sequence.group_by must be a non-empty list.",
                details={"path": str(rule_path)},
            )
        for field in group_by:
            if field not in OrderedSequenceDetector.VALID_GROUP_BY_FIELDS:
                raise DetectionError(
                    f"Invalid group_by field: {field}. Valid fields: {sorted(OrderedSequenceDetector.VALID_GROUP_BY_FIELDS)}",
                    details={"path": str(rule_path)},
                )

        return {
            "steps": steps,
            "timespan": timespan,
            "group_by": group_by,
        }

    def build_detection_manager(self) -> DetectionManager:
        """Create a manager containing every configured detector rule."""
        registry = DetectorRegistry()
        correlators: list[CrossDetectorCorrelator] = []
        for rule in self.load_rules():
            if rule.detector == "CrossDetectorCorrelator":
                correlators.append(self.create_correlator(rule))
            else:
                registry.register(self.create_detector(rule))
        manager = DetectionManager(registry)
        for correlator in correlators:
            manager.register_correlator(correlator)
        return manager

    def create_correlator(self, rule: RuleDefinition) -> CrossDetectorCorrelator:
        """Create a CrossDetectorCorrelator from a rule definition."""
        try:
            params = self._parse_cross_detector_params(rule.parameters, rule.path)
            correlator = CrossDetectorCorrelator(
                name=rule.rule_id,
                enabled=rule.enabled,
                config=rule.parameters,
                confidence=rule.confidence,
                version=rule.version,
                **params,
            )
        except (TypeError, ValueError) as exc:
            raise DetectionError(
                "Invalid correlator parameters.",
                details={"rule_id": rule.rule_id, "error": str(exc)},
            ) from exc

        if correlator.name != rule.rule_id:
            raise DetectionError(
                "Rule ID must match its correlator name.",
                details={"rule_id": rule.rule_id, "correlator_name": correlator.name},
            )
        return correlator

    @staticmethod
    def _parse_cross_detector_params(parameters: dict[str, Any], rule_path: Path) -> dict[str, Any]:
        """Parse cross-detector correlation parameters from rule YAML.

        Args:
            parameters: Raw parameters from the rule file.
            rule_path: Path to the rule file (for error messages).

        Returns:
            Parsed parameters suitable for CrossDetectorCorrelator constructor.

        Raises:
            DetectionError: If parameters are invalid.
        """
        correlation = parameters.get("correlation", {})
        if not isinstance(correlation, dict):
            raise DetectionError(
                "correlation must be a mapping.",
                details={"path": str(rule_path)},
            )

        if correlation.get("type") != "cross_detector":
            raise DetectionError(
                "only 'cross_detector' correlation type is supported for this correlator.",
                details={"path": str(rule_path)},
            )

        # Parse sequence (list of rule_ids)
        sequence = correlation.get("sequence", [])
        if not isinstance(sequence, list) or len(sequence) < 2:
            raise DetectionError(
                "correlation.sequence must be a list with at least 2 rule_ids.",
                details={"path": str(rule_path), "sequence": sequence},
            )

        # Parse timespan
        timespan_str = correlation.get("timespan")
        if not timespan_str:
            raise DetectionError(
                "correlation.timespan is required.",
                details={"path": str(rule_path)},
            )
        timespan = CrossDetectorCorrelator.parse_timespan(timespan_str, rule_path)

        # Parse group_by
        group_by = correlation.get("group_by", ["src_ip"])
        if not isinstance(group_by, list) or not group_by:
            raise DetectionError(
                "correlation.group_by must be a non-empty list.",
                details={"path": str(rule_path)},
            )
        valid_fields = CrossDetectorCorrelator.VALID_GROUP_BY_FIELDS
        for field in group_by:
            if field not in valid_fields:
                raise DetectionError(
                    f"Invalid group_by field: {field}. Valid fields: {sorted(valid_fields)}",
                    details={"path": str(rule_path)},
                )

        return {
            "sequence": sequence,
            "timespan": timespan,
            "group_by": group_by,
        }
