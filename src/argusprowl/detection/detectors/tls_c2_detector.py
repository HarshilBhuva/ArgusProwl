"""ML-backed detector for TLS 1.3 / ECH C2 beaconing.

Scores per-pair TLS flow features from ClickHouse with the trained
RandomForest at ``models/c2_tls_detector.joblib``. A missing model is
logged and disables scoring so application startup does not fail.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from uuid import uuid4

import pandas as pd
from joblib import load

from argusprowl.constants.severity import Severity
from argusprowl.detection.base_detector import BaseDetector
from argusprowl.feature_engineering.tls_flow_extractor import (
    FEATURE_COLUMNS,
    TLSFlowFeatureExtractor,
)
from argusprowl.models.detection_result import DetectionResult

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_MODEL_PATH = _REPO_ROOT / "models" / "c2_tls_detector.joblib"

_RULE_ID = "TLSC2Detector"
_TITLE = "Encrypted C2 Beaconing Detected (TLS 1.3 / ECH)"


class TLSC2Detector(BaseDetector):
    """Flags TLS flow pairs whose model score exceeds a probability threshold.

    ``detect`` satisfies the ``BaseDetector`` contract and returns a
    non-match: this detector scores ClickHouse windows, not single events.
    Call :meth:`analyze` with a ClickHouse client to score a lookback window.
    """

    def __init__(
        self,
        probability_threshold: float = 0.85,
        lookback_minutes: int = 60,
        model_path: str | Path | None = None,
        extractor: TLSFlowFeatureExtractor | None = None,
        **kwargs: Any,
    ) -> None:
        """Load the C2 model and store scoring parameters.

        Args:
            probability_threshold: Minimum ``predict_proba`` class-1 score
                that emits a detection. Must be in ``[0.0, 1.0]``.
            lookback_minutes: Minutes of ``raw_zeek_ssl`` history to score.
            model_path: Override for the joblib artifact. Defaults to
                ``models/c2_tls_detector.joblib`` at the repository root.
            extractor: Feature extractor. A new one is created when omitted.
            **kwargs: Forwarded to ``BaseDetector`` (``enabled``, ``config``,
                ``confidence``, ``version``).

        Raises:
            ValueError: If ``probability_threshold`` is outside ``[0.0, 1.0]``
                or ``lookback_minutes`` is not positive.
        """
        if not 0.0 <= probability_threshold <= 1.0:
            raise ValueError(
                f"probability_threshold must be in [0.0, 1.0], got {probability_threshold}"
            )
        if lookback_minutes <= 0:
            raise ValueError(f"lookback_minutes must be positive, got {lookback_minutes}")

        # RuleLoader requires detector.name == rule_id.
        super().__init__(
            name=kwargs.pop("name", _RULE_ID),
            description=kwargs.pop(
                "description",
                "ML detector for TLS 1.3 / ECH C2 beaconing",
            ),
            **kwargs,
        )
        self._probability_threshold = probability_threshold
        self._lookback_minutes = lookback_minutes
        self._model_path = Path(model_path) if model_path is not None else _DEFAULT_MODEL_PATH
        self._extractor = extractor or TLSFlowFeatureExtractor()
        self.model: Any = self._load_model(self._model_path)
        if self.model is not None and hasattr(self.model, "feature_names_in_"):
            expected = tuple(self.model.feature_names_in_)
            if expected != FEATURE_COLUMNS:
                raise ValueError(
                    f"Model feature order {expected} does not match FEATURE_COLUMNS {FEATURE_COLUMNS}"
                )

    @staticmethod
    def _load_model(path: Path) -> Any:
        """Load the joblib model, or return None when the file is absent."""
        try:
            model = load(path)
        except FileNotFoundError:
            logger.warning(
                "TLS C2 model not found at %s; detector will emit no findings",
                path,
            )
            return None
        if not hasattr(model, "predict_proba"):
            logger.warning(
                "TLS C2 artifact at %s has no predict_proba; detector disabled",
                path,
            )
            return None
        return model

    def detect(self, event: Any) -> DetectionResult:
        """Return a non-match. Window scoring goes through :meth:`analyze`."""
        event_id = getattr(event, "event_id", None) or getattr(event, "vector_id", None)
        if event_id is None:
            event_id = uuid4()
        return DetectionResult(
            rule_id=self.name,
            event_id=event_id,
            matched=False,
            severity=Severity.INFO,
            confidence=0.0,
            description="TLSC2Detector scores ClickHouse windows via analyze()",
        )

    def analyze(
        self,
        client: Any,
        start_time: Any | None = None,
        end_time: Any | None = None,
    ) -> list[DetectionResult]:
        """Score TLS flow pairs and return one result per malicious pair.

        Args:
            client: ClickHouse client exposing ``query(sql) -> rows``.
            start_time: Optional start timestamp mapped to query bounds.
            end_time: Optional end timestamp mapped to query bounds.

        Returns:
            Detection results for pairs at or above ``probability_threshold``.
            Empty when the model is missing, the window has no rows, or no
            pair meets the threshold.
        """
        if self.model is None or not self.is_enabled():
            return []

        try:
            features = self._extractor.extract_features_from_clickhouse(
                client,
                time_window_minutes=self._lookback_minutes,
                start_time=start_time,
                end_time=end_time,
            )
        except Exception:
            logger.exception("TLS C2 feature extraction failed")
            return []

        if features.empty:
            return []

        missing = [column for column in FEATURE_COLUMNS if column not in features.columns]
        if missing:
            logger.error("TLS C2 feature frame is missing columns: %s", missing)
            return []

        # Source/destination IPs are preserved in the scored matrix so the
        # model (or any post-scorer) can reference them; they are not part of
        # the feature vector itself.
        matrix = features[list(FEATURE_COLUMNS)].copy()
        # IP columns are retained in `features` for output evidence.
        try:
            probabilities = self.model.predict_proba(matrix)[:, 1]
        except Exception:
            logger.exception("TLS C2 model scoring failed")
            return []

        scored = features.copy()
        scored["c2_probability"] = probabilities
        malicious = scored[scored["c2_probability"] >= self._probability_threshold]

        return [self._result_for_row(row) for _, row in malicious.iterrows()]

    def _result_for_row(self, row: pd.Series) -> DetectionResult:
        """Build a critical detection for one scored flow pair."""
        probability = float(row["c2_probability"])
        source_ip = str(row["id_orig_h"])
        destination_ip = str(row["id_resp_h"])
        stats = {
            "connection_count": int(row["connection_count"]),
            "avg_duration": float(row["avg_duration"]),
            "stddev_duration": float(row["stddev_duration"]),
            "avg_orig_bytes": float(row["avg_orig_bytes"]),
            "avg_resp_bytes": float(row["avg_resp_bytes"]),
            "byte_ratio": float(row["byte_ratio"]),
            "delta_t_mean": float(row["delta_t_mean"]),
            "delta_t_std": float(row["delta_t_std"]),
            "delta_t_cv": float(row["delta_t_cv"]),
            "has_sni": int(row["has_sni"]),
            "is_tls13": int(row["is_tls13"]),
            "sni_entropy": float(row["sni_entropy"]),
            "ja3_homogeneity": float(row["ja3_homogeneity"]),
        }
        evidence: list[dict[str, object]] = [
            {"field": "source_ip", "observed": source_ip, "condition": "equals"},
            {"field": "destination_ip", "observed": destination_ip, "condition": "equals"},
            {
                "field": "c2_probability",
                "observed": round(probability, 6),
                "condition": "greater_than_or_equal",
            },
        ]
        evidence.extend(
            {"field": field, "observed": value, "condition": "equals"}
            for field, value in stats.items()
        )

        self._increment_detections()
        return DetectionResult(
            rule_id=self.name,
            event_id=uuid4(),
            matched=True,
            severity=Severity.CRITICAL,
            confidence=min(max(probability, 0.0), 1.0),
            description=_TITLE,
            explanation=(
                f"{source_ip} to {destination_ip} scored {probability:.3f} "
                f"for encrypted TLS 1.3 / ECH C2 beaconing "
                f"({stats['connection_count']} connections, "
                f"delta_t_cv={stats['delta_t_cv']:.4f}, "
                f"has_sni={stats['has_sni']}, is_tls13={stats['is_tls13']})."
            ),
            evidence=evidence,
            version=self.version,
            metadata={
                "title": _TITLE,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "c2_probability": probability,
                "flow_statistics": stats,
            },
        )
