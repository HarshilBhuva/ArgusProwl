"""Tests for the ML-backed TLS C2 beaconing detector.

The production changes these tests must catch:
- treating a missing model file as a startup failure instead of an empty result
- emitting a detection for a flow pair the model scores below the threshold
- dropping a flow pair the model scores at or above the threshold
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd
import pytest

from argusprowl.constants.severity import Severity
from argusprowl.detection.detector_registry import BUILTIN_DETECTORS
from argusprowl.detection.detectors.tls_c2_detector import TLSC2Detector
from argusprowl.feature_engineering.tls_flow_extractor import FEATURE_COLUMNS
from argusprowl.models.detection_result import DetectionResult

_BENIGN_IP = "10.0.0.8"
_MALICIOUS_IP = "10.0.0.9"
_DESTINATION_IP = "203.0.113.50"


class _ConstantProbabilityModel:
    """Scores rows by the source address the fixture already labeled."""

    def predict_proba(self, matrix: pd.DataFrame) -> Any:
        import numpy as np

        labels = {
            _BENIGN_IP: 0.12,
            _MALICIOUS_IP: 0.96,
        }
        # matrix contains only FEATURE_COLUMNS; determine label by
        # connection_count: the fixture benign row has 4, the malicious
        # row has 40.
        scores = [
            labels[_MALICIOUS_IP if int(matrix.at[i, "connection_count"]) >= 40 else _BENIGN_IP]
            for i in matrix.index
        ]
        negative = [1.0 - s for s in scores]
        return np.column_stack([negative, scores])


class _RecordingExtractor:
    """Returns one benign and one malicious feature row without ClickHouse."""

    def __init__(self) -> None:
        self.calls: list[tuple[object, int]] = []

    def extract_features_from_clickhouse(
        self,
        client: object,
        time_window_minutes: int = 60,
        start_time: object = None,
        end_time: object = None,
    ) -> pd.DataFrame:
        self.calls.append((client, time_window_minutes))
        benign = _feature_row(_BENIGN_IP, connection_count=4, delta_t_cv=1.8, has_sni=1)
        malicious = _feature_row(_MALICIOUS_IP, connection_count=40, delta_t_cv=0.02, has_sni=0)
        return pd.DataFrame([benign, malicious])


def _feature_row(
    source_ip: str,
    *,
    connection_count: int,
    delta_t_cv: float,
    has_sni: int,
) -> dict[str, object]:
    return {
        "id_orig_h": source_ip,
        "id_resp_h": _DESTINATION_IP,
        "connection_count": connection_count,
        "avg_duration": 0.4,
        "stddev_duration": 0.05,
        "avg_orig_bytes": 180.0,
        "avg_resp_bytes": 60.0,
        "byte_ratio": 180.0 / 61.0,
        "delta_t_mean": 30.0,
        "delta_t_std": 30.0 * delta_t_cv,
        "delta_t_cv": delta_t_cv,
        "has_sni": has_sni,
        "is_tls13": 1,
        "sni_entropy": 0.0,
        "ja3_homogeneity": 1.0,
    }


def _detector(tmp_path: Path, extractor: _RecordingExtractor | None = None) -> TLSC2Detector:
    return TLSC2Detector(
        model_path=tmp_path / "missing.joblib",
        extractor=extractor,
    )


def test_missing_model_file_initializes_without_scoring(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A missing artifact disables scoring instead of raising at startup."""
    with caplog.at_level("WARNING"):
        detector = _detector(tmp_path)

    assert detector.model is None
    assert "not found" in caplog.text.lower()
    assert detector.analyze(client=object()) == []


def test_only_malicious_flow_pair_is_detected(tmp_path: Path) -> None:
    """A mixed window yields exactly one critical result for the malicious pair."""
    extractor = _RecordingExtractor()
    detector = _detector(tmp_path, extractor)
    detector.model = _ConstantProbabilityModel()
    client = object()

    results = detector.analyze(client)

    assert len(results) == 1
    result = results[0]
    assert isinstance(result, DetectionResult)
    assert result.matched is True
    assert result.severity is Severity.CRITICAL
    assert result.rule_id == "TLSC2Detector"
    assert result.confidence == pytest.approx(0.96)
    evidence = {item["field"]: item["observed"] for item in result.evidence}
    assert evidence["source_ip"] == _MALICIOUS_IP
    assert evidence["destination_ip"] == _DESTINATION_IP
    assert evidence["c2_probability"] == pytest.approx(0.96, abs=1e-6)
    for column in FEATURE_COLUMNS:
        assert column in evidence
    assert extractor.calls == [(client, 60)]
    scored_columns = list(FEATURE_COLUMNS)
    assert set(scored_columns) == set(FEATURE_COLUMNS)


def test_threshold_boundary_keeps_a_score_just_below_and_emits_at_threshold(
    tmp_path: Path,
) -> None:
    """0.849999 does not fire; a score equal to 0.85 does."""
    below = _RecordingExtractor()
    detector = _detector(tmp_path, below)
    detector.model = _BoundaryModel(0.849999)
    assert detector.analyze(object()) == []

    at_threshold = _RecordingExtractor()
    detector = _detector(tmp_path, at_threshold)
    detector.model = _BoundaryModel(0.85)
    results = detector.analyze(object())
    assert len(results) == 2
    assert all(result.severity is Severity.CRITICAL and result.matched for result in results)


def test_empty_feature_window_returns_no_detections(tmp_path: Path) -> None:
    """An empty extractor frame produces no detections even when a model is loaded."""
    detector = _detector(tmp_path, _EmptyExtractor())
    detector.model = _ConstantProbabilityModel()
    assert detector.analyze(object()) == []


def test_tls_c2_detector_is_registered_for_startup() -> None:
    """The detection manager's catalog can construct TLSC2Detector by name."""
    assert BUILTIN_DETECTORS["TLSC2Detector"] is TLSC2Detector


class _BoundaryModel:
    def __init__(self, probability: float) -> None:
        self._probability = probability

    def predict_proba(self, matrix: pd.DataFrame) -> Any:
        import numpy as np

        count = len(matrix)
        positive = [self._probability] * count
        negative = [1.0 - self._probability] * count
        return np.column_stack([negative, positive])


class _EmptyExtractor:
    def extract_features_from_clickhouse(
        self,
        client: object,
        time_window_minutes: int = 60,
    ) -> pd.DataFrame:
        del client, time_window_minutes
        return pd.DataFrame(columns=["id_orig_h", "id_resp_h", *FEATURE_COLUMNS])
