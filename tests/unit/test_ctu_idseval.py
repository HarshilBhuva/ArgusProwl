"""Tests for CTU-IDSEVAL-6 evaluation metrics and archive safety."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest
from scripts.evaluation.ctu_idseval import (
    CTUIDSEvalRunner,
    EvaluationError,
    calculate_metrics,
)


def test_binary_metrics_exclude_background():
    result = calculate_metrics([
        ("Malicious", True), ("Malicious", False),
        ("Benign", True), ("Benign", False),
        ("Background", True),
    ])
    assert result == {
        "true_positive": 1, "false_positive": 1,
        "false_negative": 1, "true_negative": 1,
        "background_excluded": 1, "precision": 0.5,
        "recall": 0.5, "f1": 0.5, "false_positive_rate": 0.5,
    }


def test_metrics_report_undefined_denominators_as_none():
    result = calculate_metrics([("Background", False)])
    assert result["precision"] is None
    assert result["recall"] is None
    assert result["f1"] is None
    assert result["false_positive_rate"] is None


def test_metrics_reject_unknown_ground_truth_label():
    with pytest.raises(EvaluationError, match="Unsupported ground-truth label"):
        calculate_metrics([("Unknown", False)])


def test_runner_rejects_unrealistic_label_match_threshold(tmp_path: Path):
    with pytest.raises(ValueError, match="minimum_label_match"):
        CTUIDSEvalRunner(tmp_path / "work", tmp_path / "report.json", minimum_label_match=0.8)


def test_archive_extraction_rejects_path_traversal(tmp_path: Path):
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("../escape.txt", "no")
    with pytest.raises(EvaluationError, match="Unsafe archive member"):
        CTUIDSEvalRunner._safe_extract(archive, tmp_path / "extract")
